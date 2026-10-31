package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
	"github.com/okanetsolutions/oka-cyber-agent/internal/logs"
)

const (
	MaxBatchEvents       = 2000
	MaxSkippedSources    = 100
	EmptyBatchEvery      = 5 * time.Minute
	DefaultFlushInterval = 30 * time.Second

	maxBatchBytes      = 4 << 20
	maxEventAge        = 7*24*time.Hour - time.Hour
	maxUploadBackoff   = 5 * time.Minute
	uploadsPerTick     = 20
	checkpointFileName = "logs.json"
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

	configured    bool
	collector     *logs.Collector
	aggregator    *logs.Aggregator
	sources       []string
	flushInterval time.Duration
	lastFlush     time.Time
	lastSent      time.Time
	retryAt       time.Time
	failures      int
}

func NewLogShipper(client LogClient, stateDir string, options logs.Options, logger *slog.Logger) *LogShipper {
	return &LogShipper{
		Client:   client,
		StateDir: stateDir,
		Options:  options,
		Logger:   logger,
		Spool:    logs.Spool{Dir: filepath.Join(stateDir, "spool"), MaxBytes: logs.DefaultSpoolBytes},
		config:   make(chan api.LogCollection, 1),
	}
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

// Step runs one iteration: apply a new configuration, collect, flush when due and upload.
func (s *LogShipper) Step(ctx context.Context) error {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	select {
	case lc := <-s.config:
		s.apply(ctx, lc)
	default:
	}
	if s.collector != nil {
		s.collect(ctx)
		now := s.Now()
		if s.aggregator.Pending() >= MaxBatchEvents || now.Sub(s.lastFlush) >= s.flushInterval {
			s.flush()
		}
		if s.Spool.Empty() && now.Sub(s.lastSent) >= EmptyBatchEvery {
			s.spoolBatch(nil)
		}
	}
	return s.upload(ctx)
}

func (s *LogShipper) apply(ctx context.Context, lc api.LogCollection) {
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
		os.Remove(filepath.Join(s.StateDir, checkpointFileName))
		s.Logger.Info("log collection is off")
		return
	}
	resume := s.committed()
	if newest, ok := s.Spool.Newest(); ok {
		resume = newest.Checkpoint
	}
	s.collector = logs.NewCollector(sources, s.Options, resume, s.Start, s.Now)
	s.aggregator = logs.NewAggregator()
	s.lastFlush = s.Now()
	if s.lastSent.IsZero() {
		s.lastSent = s.Now()
	}
	s.Logger.Info("log collection started", "sources", sources)
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
		s.spoolBatch(events[:n])
		events = events[n:]
	}
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

func (s *LogShipper) spoolBatch(events []logs.Event) {
	if events == nil {
		events = []logs.Event{}
	}
	b := logs.Batch{ID: logs.NewBatchID(), Events: events, Checkpoint: s.collector.Checkpoint(), CreatedAt: s.Now().UTC()}
	if err := s.Spool.Append(b); err != nil {
		s.Logger.Error("spool log batch", "error", err, "events", len(events))
	}
}

func (s *LogShipper) upload(ctx context.Context) error {
	for range uploadsPerTick {
		if s.Now().Before(s.retryAt) {
			return nil
		}
		b, path, ok, err := s.Spool.Oldest()
		if err != nil {
			s.Logger.Error("read log spool", "error", err)
			return nil
		}
		if !ok {
			return nil
		}
		dropped := s.Spool.Dropped()
		resp, err := s.Client.PostLogs(ctx, api.LogBatchRequest{BatchID: b.ID, Events: b.Events, SkippedSources: s.skipped(), DroppedEvents: dropped})
		var httpErr *api.HTTPError
		switch {
		case errors.Is(err, api.ErrUnauthorized):
			return ErrRevoked
		case err == nil:
			s.acknowledged(path, b, dropped)
			if resp.LogCollection != nil {
				s.Configure(*resp.LogCollection)
			}
		case errors.As(err, &httpErr) && rejected(httpErr.StatusCode):
			s.Logger.Error("log batch rejected, dropping it", "batch_id", b.ID, "events", len(b.Events), "error", err)
			s.acknowledged(path, b, 0)
			if err := s.Spool.AddDropped(len(b.Events)); err != nil {
				s.Logger.Error("count dropped log events", "error", err)
			}
		case ctx.Err() != nil:
			return nil
		default:
			s.failures++
			s.retryAt = s.Now().Add(uploadBackoff(s.failures))
			s.Logger.Warn("log upload failed, retrying", "batch_id", b.ID, "error", err, "retry_at", s.retryAt)
			return nil
		}
	}
	return nil
}

func (s *LogShipper) acknowledged(path string, b logs.Batch, reportedDropped int) {
	if err := s.Spool.Remove(path); err != nil {
		s.Logger.Error("remove sent log batch", "error", err)
	}
	if err := s.Spool.AddDropped(-reportedDropped); err != nil {
		s.Logger.Error("count dropped log events", "error", err)
	}
	if err := s.commit(b.Checkpoint); err != nil {
		s.Logger.Error("save log positions", "error", err)
	}
	s.lastSent = s.Now()
	s.failures = 0
}

// rejected is a response that retrying the same batch cannot fix.
func rejected(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge || status == http.StatusUnprocessableEntity
}

func uploadBackoff(failures int) time.Duration {
	ceiling := min(time.Second<<min(failures, 9), maxUploadBackoff)
	return ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
}

func (s *LogShipper) skipped() []logs.SkippedSource {
	out := []logs.SkippedSource{}
	if s.collector != nil {
		out = append(out, s.collector.Skipped()...)
	}
	if len(out) > MaxSkippedSources {
		out = out[:MaxSkippedSources]
	}
	return out
}

func (s *LogShipper) committed() logs.Checkpoint {
	var cp logs.Checkpoint
	data, err := os.ReadFile(filepath.Join(s.StateDir, checkpointFileName))
	if err == nil {
		_ = json.Unmarshal(data, &cp)
	}
	return cp
}

func (s *LogShipper) commit(cp logs.Checkpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	if err := config.WriteFileAtomic(filepath.Join(s.StateDir, checkpointFileName), data, 0o600); err != nil {
		return fmt.Errorf("commit log checkpoint: %w", err)
	}
	return nil
}
