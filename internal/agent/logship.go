package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
	"github.com/okanetsolutions/oka-cyber-agent/internal/logs"
)

const (
	MaxBatchEvents       = 2000
	MaxSkippedSources    = 100
	MaxEventCount        = 1000000
	EmptyBatchEvery      = 5 * time.Minute
	DefaultFlushInterval = 30 * time.Second
	// UnsupportedRecheckEvery is how long the shipper stays idle after the server answered POST /logs with 404
	// (an Oka Core without log ingestion) before it tries again.
	UnsupportedRecheckEvery = time.Hour

	maxBatchBytes      = 4 << 20
	maxEventAge        = 7*24*time.Hour - time.Hour
	maxUploadBackoff   = 5 * time.Minute
	uploadsPerTick     = 20
	checkpointFileName = "logs.json"
	maxCheckpointSize  = 4 << 20
)

type LogClient interface {
	PostLogs(ctx context.Context, batch api.LogBatchRequest) (api.LogBatchResponse, error)
}

// LogShipper collects log events from the sources the server enabled, redacts and aggregates them, keeps
// them in the spool and uploads them in order, one batch at a time. Positions are committed only after the
// server acknowledged a batch.
type LogShipper struct {
	Client   LogClient
	StateDir string
	Options  logs.Options
	Logger   *slog.Logger
	Now      func() time.Time
	Start    logs.StartFunc
	Tick     time.Duration
	Spool    logs.Spool

	config chan api.LogCollection

	// pending is the latest configuration not applied yet, current the one applied last.
	pending          *api.LogCollection
	current          api.LogCollection
	unsupportedUntil time.Time
	configured       bool
	collector        *logs.Collector
	aggregator       *logs.Aggregator
	sources          []string
	flushInterval    time.Duration
	lastFlush        time.Time
	lastSent         time.Time
	retryAt          time.Time
	failures         int

	// badSkipped are skipped sources the server rejected, left out of later requests so they cannot get every
	// batch rejected, and droppedRejected is set when it rejected dropped_events.
	badSkipped      map[logs.SkippedSource]bool
	droppedRejected bool
	// bare is the batch_id of a one event batch sent again, right after it was rejected, without skipped
	// sources and dropped events, to find out whether the batch alone is rejected; bareOmitted are the skipped
	// sources left out of it.
	bare        string
	bareOmitted []logs.SkippedSource
	// switchedOff are sources switched off whose removal from the checkpoint could not be spooled yet.
	switchedOff map[string]bool
}

// NewLogShipper keeps its spool and positions under stateDir. When root runs the agent, the files it writes
// there are given to the owner of stateDir, like the state file (see SaveState).
func NewLogShipper(client LogClient, stateDir string, options logs.Options, logger *slog.Logger) (*LogShipper, error) {
	owner, err := stateOwner(stateDir)
	if err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	return &LogShipper{
		Client:   client,
		StateDir: stateDir,
		Options:  options,
		Logger:   logger,
		Spool:    logs.Spool{Dir: filepath.Join(stateDir, "spool"), MaxBytes: logs.DefaultSpoolBytes, Owner: owner},
		config:   make(chan api.LogCollection, 1),
	}, nil
}

// Configure hands over the log collection settings from a heartbeat or a logs response.
func (s *LogShipper) Configure(lc api.LogCollection) {
	for {
		select {
		case s.config <- lc:
			return
		default:
			select {
			case <-s.config:
			default:
			}
		}
	}
}

// Run ships logs until the context ends. It returns ErrRevoked when the server rejects the agent token.
func (s *LogShipper) Run(ctx context.Context) error {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Tick == 0 {
		s.Tick = time.Second
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	defer s.stopCollector()
	ticker := time.NewTicker(s.Tick)
	defer ticker.Stop()
	for {
		if err := s.Step(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Step runs one iteration: apply a new configuration, collect, flush when due and upload. While the server
// does not accept logs (see unsupported) it only takes a configuration that turns collection off.
func (s *LogShipper) Step(ctx context.Context) error {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	select {
	case lc := <-s.config:
		s.pending = &lc
	default:
	}
	idle := s.Now().Before(s.unsupportedUntil)
	if s.pending != nil && (!idle || len(s.pending.Sources) == 0) {
		lc := *s.pending
		s.pending = nil
		s.apply(ctx, lc)
	}
	if idle {
		return nil
	}
	if s.collector != nil {
		s.collect(ctx)
		now := s.Now()
		if s.aggregator.Pending() >= MaxBatchEvents || now.Sub(s.lastFlush) >= s.flushInterval {
			s.flush()
		}
		if s.Spool.Empty() && now.Sub(s.lastSent) >= EmptyBatchEvery {
			s.liveness()
		}
	}
	return s.upload(ctx)
}

func (s *LogShipper) apply(ctx context.Context, lc api.LogCollection) {
	s.current = lc
	s.flushInterval = DefaultFlushInterval
	if lc.FlushIntervalSeconds > 0 {
		s.flushInterval = min(max(time.Duration(lc.FlushIntervalSeconds)*time.Second, 5*time.Second), 5*time.Minute)
	}
	sources := slices.DeleteFunc(slices.Clone(lc.Sources), func(src string) bool {
		return !slices.Contains([]string{logs.SourceAuth, logs.SourceWeb, logs.SourceApp}, src)
	})
	slices.Sort(sources)
	sources = slices.Compact(sources)
	if s.configured && slices.Equal(sources, s.sources) && (s.collector != nil || len(sources) == 0) {
		return
	}
	s.configured = true
	if s.collector != nil {
		s.flush()
		s.stopCollector()
	}
	s.sources = sources
	if len(sources) == 0 {
		if err := s.Spool.Clear(); err != nil {
			s.Logger.Error("clear log spool", "error", err)
		}
		if err := os.Remove(filepath.Join(s.StateDir, checkpointFileName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.Logger.Error("delete log positions", "error", err)
		}
		s.Logger.Info("log collection is off")
		return
	}
	resume := s.resumeAt(sources)
	s.collector = logs.NewCollector(sources, s.Options, resume, s.Start, s.Now)
	s.aggregator = logs.NewAggregator()
	s.lastFlush = s.Now()
	if s.lastSent.IsZero() {
		s.lastSent = s.Now()
	}
	s.Logger.Info("log collection started", "sources", sources)
}

// resumeAt is where a collector for sources starts: the newest spooled checkpoint, or the committed one. The
// positions of a source that is off are void, so that switching it on again starts at the current end like a
// first enable, and lines written while it was off are never uploaded. A source the checkpoint lists but that
// is off now is taken out of it, and that is recorded at once in an empty batch with the new checkpoint, as
// the newest batch is where the next start resumes, also after a restart. Should the spool fail, the source is
// remembered here as switched off.
func (s *LogShipper) resumeAt(sources []string) logs.Checkpoint {
	resume := s.committed()
	if newest, ok := s.Spool.Newest(); ok {
		resume = newest.Checkpoint
	}
	if s.switchedOff == nil {
		s.switchedOff = map[string]bool{}
	}
	changed := false
	resume.Sources = slices.DeleteFunc(slices.Clone(resume.Sources), func(src string) bool {
		if !slices.Contains(sources, src) {
			s.switchedOff[src] = true
		}
		changed = changed || s.switchedOff[src]
		return s.switchedOff[src]
	})
	if !slices.Contains(resume.Sources, logs.SourceAuth) {
		resume.JournalCursor = ""
	}
	if changed && s.spoolBatch(nil, resume) {
		clear(s.switchedOff)
	}
	for _, src := range sources {
		delete(s.switchedOff, src)
	}
	return resume
}

func (s *LogShipper) stopCollector() {
	if s.collector != nil {
		s.collector.Close()
		s.collector = nil
	}
}

// collect redacts every event before it is aggregated or spooled. Events outside the window the server
// accepts (the last 7 days) are dropped and counted; timestamps from a clock ahead of ours are clamped.
func (s *LogShipper) collect(ctx context.Context) {
	now := s.Now().UTC()
	dropped := 0
	for _, e := range s.collector.Poll(ctx) {
		if now.Sub(e.LastAt) > maxEventAge {
			dropped++
			continue
		}
		if e.FirstAt.After(now) {
			e.FirstAt = now
		}
		if e.LastAt.After(now) {
			e.LastAt = now
		}
		s.aggregator.Add(logs.Redact(e))
	}
	if err := s.Spool.AddDropped(dropped); err != nil {
		s.Logger.Error("count dropped log events", "error", err)
	}
}

func (s *LogShipper) flush() {
	events := s.aggregator.Flush()
	s.lastFlush = s.Now()
	for len(events) > 0 {
		n := batchSize(events)
		s.spoolBatch(events[:n], s.collector.Checkpoint())
		events = events[n:]
	}
}

// liveness spools a batch so the server hears from the agent at least every EmptyBatchEvery. A batch carries
// the collector's current positions, which cover the events still in the aggregator, so those are flushed into
// it; an empty batch is only sent when nothing waits, or a restart would resume past unsent events.
func (s *LogShipper) liveness() {
	if s.aggregator.Pending() > 0 {
		s.flush()
		return
	}
	s.spoolBatch(nil, s.collector.Checkpoint())
}

// batchSize is how many events fit one batch: at most MaxBatchEvents and well under the 5 MB body limit.
func batchSize(events []logs.Event) int {
	size := 0
	for i, e := range events {
		data, _ := json.Marshal(e)
		size += len(data) + 1
		if i == MaxBatchEvents || (size > maxBatchBytes && i > 0) {
			return i
		}
	}
	return len(events)
}

func (s *LogShipper) spoolBatch(events []logs.Event, cp logs.Checkpoint) bool {
	if events == nil {
		events = []logs.Event{}
	}
	b := logs.Batch{ID: logs.NewBatchID(), Events: events, Checkpoint: cp, CreatedAt: s.Now().UTC()}
	if err := s.Spool.Append(b); err != nil {
		s.Logger.Error("spool log batch", "error", err, "events", len(events))
		return false
	}
	return true
}

// upload sends the spooled batches in order. A batch the server rejects is never dropped whole on the word of
// one response, since what made the request fail may be in the parts every request carries (skipped_sources)
// or in its size: see rejected.
func (s *LogShipper) upload(ctx context.Context) error {
	for range uploadsPerTick {
		if s.Now().Before(s.retryAt) {
			return nil
		}
		b, name, ok, err := s.Spool.Oldest()
		if err != nil {
			s.Logger.Error("read log spool", "error", err)
			return nil
		}
		if !ok {
			return nil
		}
		events, expired := outgoingEvents(b.Events, s.Now())
		if expired > 0 {
			s.Logger.Warn("dropping spooled log events older than the server accepts", "batch_id", b.ID, "events", expired)
			if !s.replace(name, b, events) {
				return nil
			}
			if err := s.Spool.AddDropped(expired); err != nil {
				s.Logger.Error("count dropped log events", "error", err)
			}
			continue
		}
		req := s.request(b, events)
		resp, err := s.Client.PostLogs(ctx, req)
		var httpErr *api.HTTPError
		switch {
		case errors.Is(err, api.ErrUnauthorized):
			return ErrRevoked
		case err == nil:
			s.accepted(req, resp)
			if err := s.acknowledged(name, b, req.DroppedEvents); err != nil {
				s.retryLater("save log positions", b, err, nil)
				return nil
			}
		case errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound:
			s.unsupported()
			return nil
		case errors.Is(err, api.ErrBodyTooLarge) || errors.As(err, &httpErr) && rejected(httpErr.StatusCode):
			if next, err := s.rejected(ctx, name, b, req, err); !next || err != nil {
				return err
			}
		case ctx.Err() != nil:
			return nil
		default:
			s.retryLater("log upload failed", b, err, httpErr)
			return nil
		}
	}
	return nil
}

// request is what is sent for a batch: its events with the skipped sources and the dropped events count,
// which go with every request, unless the batch is being sent bare (see rejected).
func (s *LogShipper) request(b logs.Batch, events []logs.Event) api.LogBatchRequest {
	req := api.LogBatchRequest{BatchID: b.ID, Events: events, SkippedSources: []logs.SkippedSource{}}
	if b.ID == s.bare {
		return req
	}
	req.SkippedSources = s.skipped()
	if !s.droppedRejected {
		req.DroppedEvents = s.Spool.Dropped()
	}
	return req
}

// accepted takes the configuration of a logs response. When the batch was accepted bare after it was rejected
// with skipped sources, those sources were what the server rejected.
func (s *LogShipper) accepted(req api.LogBatchRequest, resp api.LogBatchResponse) {
	if resp.LogCollection != nil {
		s.Configure(*resp.LogCollection)
	}
	if req.BatchID == s.bare {
		for _, src := range s.bareOmitted {
			s.leaveOut(src)
		}
		s.bare, s.bareOmitted = "", nil
	}
}

// rejected handles a 400, 413 or 422 (or a body over the client's limit) and tells whether upload goes on. When
// the server names the fields it rejected, only those go: an event, a skipped source, dropped_events. Otherwise
// a batch is split in halves until one event is left, which is then sent bare, without skipped sources and
// dropped events. It is dropped as poison only when the server rejects it alone while it accepts an empty
// request, so a server or proxy that rejects every request never makes the agent drop events. Positions are
// committed only for events the server accepted or that are dropped as poison, and those are counted in
// dropped_events.
func (s *LogShipper) rejected(ctx context.Context, name string, b logs.Batch, req api.LogBatchRequest, cause error) (bool, error) {
	var httpErr *api.HTTPError
	errors.As(cause, &httpErr)
	if httpErr != nil {
		if fixed, ok := s.fixRejectedFields(name, b, req, httpErr.Fields); ok {
			return fixed, nil
		}
	}
	switch {
	case len(req.Events) > 1:
		half := len(req.Events) / 2
		s.Logger.Warn("log batch rejected, splitting it", "batch_id", b.ID, "events", len(req.Events), "error", cause)
		first := logs.Batch{ID: logs.NewBatchID(), Events: req.Events[:half], Checkpoint: b.Checkpoint, Partial: true, CreatedAt: b.CreatedAt}
		second := logs.Batch{ID: logs.NewBatchID(), Events: req.Events[half:], Checkpoint: b.Checkpoint, Partial: b.Partial, CreatedAt: b.CreatedAt}
		if err := s.Spool.Replace(name, []logs.Batch{first, second}); err != nil {
			s.retryLater("split log batch", b, err, nil)
			return false, nil
		}
		return true, nil
	case len(req.SkippedSources) > 0 || req.DroppedEvents > 0:
		s.Logger.Warn("log batch rejected, sending it without skipped sources and dropped events", "batch_id", b.ID, "error", cause)
		s.bare, s.bareOmitted = b.ID, req.SkippedSources
		return true, nil
	case len(req.Events) == 0:
		s.retryLater("log request rejected", b, cause, httpErr)
		return false, nil
	}
	resp, err := s.Client.PostLogs(ctx, api.LogBatchRequest{BatchID: logs.NewBatchID(), Events: []logs.Event{}, SkippedSources: []logs.SkippedSource{}})
	var probeErr *api.HTTPError
	switch {
	case errors.Is(err, api.ErrUnauthorized):
		return false, ErrRevoked
	case errors.As(err, &probeErr) && probeErr.StatusCode == http.StatusNotFound:
		s.unsupported()
		return false, nil
	case err != nil:
		s.retryLater("log request rejected, and so is an empty one", b, cause, probeErr)
		return false, nil
	}
	if resp.LogCollection != nil {
		s.Configure(*resp.LogCollection)
	}
	s.Logger.Error("log event rejected on its own, dropping it", "batch_id", b.ID, "error", cause)
	return s.drop(name, b, len(req.Events)), nil
}

// fixRejectedFields leaves out what a validation error names: events (events.3.first_at), skipped sources
// (skipped_sources.0.path) or dropped_events, and gives the batch a new batch_id when that is what was named.
// ok is false when the error names nothing it can fix.
func (s *LogShipper) fixRejectedFields(name string, b logs.Batch, req api.LogBatchRequest, fields []string) (next, ok bool) {
	badEvents := map[int]bool{}
	var badSkipped []logs.SkippedSource
	droppedRejected, badID := false, false
	for _, field := range fields {
		switch {
		case field == "batch_id":
			badID = true
		case field == "dropped_events":
			droppedRejected = true
		case field == "skipped_sources":
			badSkipped = append(badSkipped, req.SkippedSources...)
		default:
			if i, ok := fieldIndex(field, "events", len(req.Events)); ok {
				badEvents[i] = true
			} else if i, ok := fieldIndex(field, "skipped_sources", len(req.SkippedSources)); ok {
				badSkipped = append(badSkipped, req.SkippedSources[i])
			}
		}
	}
	switch {
	case len(badEvents) > 0:
		var kept []logs.Event
		for i, e := range req.Events {
			if !badEvents[i] {
				kept = append(kept, e)
			}
		}
		s.Logger.Error("log events rejected by the server, dropping them", "batch_id", b.ID, "events", len(badEvents), "fields", fields)
		if !s.replace(name, b, kept) {
			return false, true
		}
		if err := s.Spool.AddDropped(len(badEvents)); err != nil {
			s.Logger.Error("count dropped log events", "error", err)
		}
		return true, true
	case len(badSkipped) > 0 || droppedRejected:
		s.Logger.Warn("log request rejected, leaving out what the server named", "batch_id", b.ID, "fields", fields)
		for _, src := range badSkipped {
			s.leaveOut(src)
		}
		s.droppedRejected = s.droppedRejected || droppedRejected
		return true, true
	case badID:
		b.ID = logs.NewBatchID()
		return s.replace(name, b, req.Events), true
	}
	return false, false
}

// fieldIndex reads the index of a row field such as events.3.first_at, when it is one of n rows.
func fieldIndex(field, list string, n int) (int, bool) {
	rest, ok := strings.CutPrefix(field, list+".")
	if !ok {
		return 0, false
	}
	index, _, _ := strings.Cut(rest, ".")
	i, err := strconv.Atoi(index)
	return i, err == nil && i >= 0 && i < n
}

func (s *LogShipper) leaveOut(src logs.SkippedSource) {
	if s.badSkipped == nil {
		s.badSkipped = map[logs.SkippedSource]bool{}
	}
	s.badSkipped[src] = true
}

// replace puts the batch back in the spool with other events, keeping its batch_id and checkpoint.
func (s *LogShipper) replace(name string, b logs.Batch, events []logs.Event) bool {
	if events == nil {
		events = []logs.Event{}
	}
	b.Events = events
	if err := s.Spool.Replace(name, []logs.Batch{b}); err != nil {
		s.retryLater("rewrite log batch", b, err, nil)
		return false
	}
	return true
}

// drop removes a batch of poison events from the spool, commits its positions and counts the events in
// dropped_events.
func (s *LogShipper) drop(name string, b logs.Batch, events int) bool {
	if err := s.acknowledged(name, b, 0); err != nil {
		s.retryLater("save log positions", b, err, nil)
		return false
	}
	if err := s.Spool.AddDropped(events); err != nil {
		s.Logger.Error("count dropped log events", "error", err)
	}
	return true
}

// outgoingEvents brings the events of a spooled batch within what the server accepts (see LogBatchValidator):
// count from 1 to MaxEventCount, first_at not after last_at, nothing in the future, src_ip a plain IP address.
// Events older than the server keeps, which waited too long in the spool, are left out and counted.
func outgoingEvents(events []logs.Event, now time.Time) ([]logs.Event, int) {
	now = now.UTC()
	earliest := now.Add(-maxEventAge)
	out := make([]logs.Event, 0, len(events))
	for _, e := range events {
		if e.LastAt.Before(earliest) {
			continue
		}
		if e.LastAt.After(now) {
			e.LastAt = now
		}
		if e.FirstAt.Before(earliest) {
			e.FirstAt = earliest
		}
		if e.FirstAt.After(e.LastAt) {
			e.FirstAt = e.LastAt
		}
		e.Count = min(max(e.Count, 1), MaxEventCount)
		if ip, err := netip.ParseAddr(e.SrcIP); e.SrcIP != "" && (err != nil || ip.Zone() != "") {
			e.SrcIP = ""
		}
		out = append(out, e)
	}
	return out, len(events) - len(out)
}

// retryLater backs off. A batch being sent bare is sent whole again after it, so that a bare request accepted
// once a broken server recovers does not blame the skipped sources.
func (s *LogShipper) retryLater(msg string, b logs.Batch, err error, httpErr *api.HTTPError) {
	s.bare, s.bareOmitted = "", nil
	s.failures++
	wait := uploadBackoff(s.failures)
	if httpErr != nil {
		wait = max(wait, httpErr.RetryAfter)
	}
	s.retryAt = s.Now().Add(wait)
	s.Logger.Warn(msg+", retrying", "batch_id", b.ID, "error", err, "retry_at", s.retryAt)
}

// unsupported stops collection after the server answered 404: an Oka Core that does not have log ingestion
// yet. What was read is kept in the spool with its positions, and collection and upload resume after
// UnsupportedRecheckEvery, from where they stopped.
func (s *LogShipper) unsupported() {
	if s.collector != nil {
		s.flush()
		s.stopCollector()
	}
	if s.pending == nil && s.configured {
		current := s.current
		s.pending = &current
	}
	s.configured = false
	s.unsupportedUntil = s.Now().Add(UnsupportedRecheckEvery)
	s.Logger.Warn("the server does not accept logs, log collection stays idle", "retry_at", s.unsupportedUntil)
}

// acknowledged commits the positions of a batch the server accepted, then removes it from the spool. In that
// order a stop in between leaves the batch spooled with its positions committed: it is sent again under the same
// batch_id, which the server recognises as its last batch and ignores, and collection resumes from the same
// positions. When the positions cannot be saved the batch stays in the spool and is sent again later. A partial
// batch commits nothing: its checkpoint also covers the parts after it.
func (s *LogShipper) acknowledged(name string, b logs.Batch, reportedDropped int) error {
	if !b.Partial {
		if err := s.commit(b.Checkpoint); err != nil {
			return err
		}
	}
	if err := s.Spool.AddDropped(-reportedDropped); err != nil {
		s.Logger.Error("count dropped log events", "error", err)
	}
	if err := s.Spool.Remove(name); err != nil {
		s.Logger.Error("remove sent log batch", "error", err)
	}
	s.lastSent = s.Now()
	s.failures = 0
	return nil
}

// rejected is a response that sending the same request again cannot fix.
func rejected(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge || status == http.StatusUnprocessableEntity
}

func uploadBackoff(failures int) time.Duration {
	ceiling := min(time.Second<<min(failures, 9), maxUploadBackoff)
	return ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
}

// skipped are the sources the collector cannot read, as the server accepts them and without those it rejected.
func (s *LogShipper) skipped() []logs.SkippedSource {
	out := []logs.SkippedSource{}
	if s.collector == nil {
		return out
	}
	for _, src := range s.collector.Skipped() {
		if src, ok := src.Sendable(); ok && !s.badSkipped[src] && len(out) < MaxSkippedSources {
			out = append(out, src)
		}
	}
	return out
}

// committed is the checkpoint of the last batch the server acknowledged. A missing or unusable file means
// no position: collection then starts at the current end of every source, as on first enable.
func (s *LogShipper) committed() logs.Checkpoint {
	var cp logs.Checkpoint
	data, err := config.ReadRegularFile(filepath.Join(s.StateDir, checkpointFileName), maxCheckpointSize)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.Logger.Warn("log positions cannot be read, starting at the end of every log", "error", err)
		}
		return cp
	}
	if err := json.Unmarshal(data, &cp); err != nil {
		s.Logger.Warn("log positions cannot be read, starting at the end of every log", "error", err)
		return logs.Checkpoint{}
	}
	return cp
}

func (s *LogShipper) commit(cp logs.Checkpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	if err := config.WriteFileAtomic(filepath.Join(s.StateDir, checkpointFileName), data, 0o600, s.Spool.Owner); err != nil {
		return fmt.Errorf("commit log checkpoint: %w", err)
	}
	// The rename must reach the disk before the batch leaves the spool, or a power loss could keep the removal
	// and lose the new positions.
	dir, err := os.Open(s.StateDir)
	if err != nil {
		return fmt.Errorf("commit log checkpoint: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("commit log checkpoint: %w", err)
	}
	return nil
}
