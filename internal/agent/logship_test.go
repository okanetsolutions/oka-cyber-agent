package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/logs"
)

type fakeLogClient struct {
	batches  []api.LogBatchRequest
	accepted []api.LogBatchRequest
	failWith []error
	// validate, when set, answers each request that failWith does not, like the server's validation.
	validate func(api.LogBatchRequest) error
	reply    *api.LogCollection
	// onAccept runs after a request is accepted, before the shipper acknowledges it.
	onAccept func(api.LogBatchRequest)
}

func (f *fakeLogClient) PostLogs(_ context.Context, b api.LogBatchRequest) (api.LogBatchResponse, error) {
	f.batches = append(f.batches, b)
	if len(f.failWith) > 0 {
		err := f.failWith[0]
		f.failWith = f.failWith[1:]
		if err != nil {
			return api.LogBatchResponse{}, err
		}
	} else if f.validate != nil {
		if err := f.validate(b); err != nil {
			return api.LogBatchResponse{}, err
		}
	}
	f.accepted = append(f.accepted, b)
	if f.onAccept != nil {
		f.onAccept(b)
	}
	return api.LogBatchResponse{Accepted: len(b.Events), LogCollection: f.reply}, nil
}

// validateLikeTheServer applies the rules of LogBatchValidator that these tests need, in its order, and names
// the first rejected field like a Laravel 422: an event rejectEvent refuses, then a skipped source whose path
// is not absolute, is longer than 1024 characters or holds NUL, CR or LF, or that rejectSkipped refuses.
func validateLikeTheServer(rejectEvent func(logs.Event) bool, rejectSkipped func(logs.SkippedSource) bool) func(api.LogBatchRequest) error {
	return func(b api.LogBatchRequest) error {
		for i, e := range b.Events {
			if rejectEvent != nil && rejectEvent(e) {
				return &api.HTTPError{StatusCode: http.StatusUnprocessableEntity, Fields: []string{fmt.Sprintf("events.%d.message", i)}}
			}
		}
		for i, src := range b.SkippedSources {
			if !strings.HasPrefix(src.Path, "/") || utf8.RuneCountInString(src.Path) > 1024 || strings.ContainsAny(src.Path, "\x00\r\n") || rejectSkipped != nil && rejectSkipped(src) {
				return &api.HTTPError{StatusCode: http.StatusUnprocessableEntity, Fields: []string{fmt.Sprintf("skipped_sources.%d.path", i)}}
			}
		}
		return nil
	}
}

// commandOf is the executable of a sudo event, which names the test lines: they run commands without arguments.
func commandOf(e logs.Event) string {
	command, _ := e.Fields["command"].(string)
	return strings.TrimSuffix(command, " [0 args]")
}

type shipperHost struct {
	t        *testing.T
	root     string
	stateDir string
	clock    *clock
	client   *fakeLogClient
}

func newShipperHost(t *testing.T) *shipperHost {
	h := &shipperHost{t: t, root: t.TempDir(), stateDir: t.TempDir(), clock: &clock{now: time.Date(2026, 10, 31, 19, 0, 0, 0, time.UTC)}, client: &fakeLogClient{}}
	h.appendLog("")
	return h
}

func (h *shipperHost) appendLog(line string) {
	h.t.Helper()
	path := filepath.Join(h.root, "var", "log", "auth.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	if line != "" {
		f.WriteString(line + "\n")
	}
}

func (h *shipperHost) shipper() *LogShipper {
	s, err := NewLogShipper(h.client, h.stateDir, logs.Options{Root: h.root, HasJournalctl: func() bool { return false }}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		h.t.Fatal(err)
	}
	s.Now = h.clock.Now
	return s
}

func (h *shipperHost) step(s *LogShipper) {
	h.t.Helper()
	if err := s.Step(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

func (h *shipperHost) advance(d time.Duration) { h.clock.now = h.clock.now.Add(d) }

func syslogAt(at time.Time, rest string) string {
	return at.Format("2006-01-02T15:04:05.000000-07:00") + " web-1 " + rest
}

func TestShipperDoesNothingUntilConfigured(t *testing.T) {
	h := newShipperHost(t)
	s := h.shipper()
	h.appendLog(syslogAt(h.clock.now, "sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2"))
	for range 3 {
		h.step(s)
		h.advance(10 * time.Minute)
	}
	if len(h.client.batches) != 0 {
		t.Fatalf("batches = %d, logs must not be collected before the server enables a source", len(h.client.batches))
	}
}

func TestShipperRedactsAggregatesAndCommitsAfterAck(t *testing.T) {
	h := newShipperHost(t)
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/history"))
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 30})
	h.step(s)

	for i := range 5 {
		h.appendLog(syslogAt(h.clock.now, "sshd[2]: Failed password for invalid user Hunter2! from 203.0.113.7 port "+string(rune('1'+i))+" ssh2"))
	}
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/mysql -pS3cret"))
	h.step(s)
	if len(h.client.batches) != 0 {
		t.Fatal("events must wait for the flush interval")
	}
	h.advance(31 * time.Second)
	h.step(s)
	if len(h.client.batches) != 1 {
		t.Fatalf("batches = %d", len(h.client.batches))
	}
	b := h.client.batches[0]
	if len(b.Events) != 2 || b.DroppedEvents != 0 || b.SkippedSources == nil || len(b.BatchID) != 36 {
		t.Fatalf("batch = %+v", b)
	}
	sudo, ssh := b.Events[0], b.Events[1]
	if sudo.Kind != logs.KindSudoCommand || strings.Contains(sudo.Message, "S3cret") || sudo.Fields["command"] != "/usr/bin/mysql [1 arg]" {
		t.Fatalf("sudo = %+v", sudo)
	}
	if ssh.Kind != logs.KindSSHLoginFailed || ssh.Count != 5 || ssh.Username != logs.Redacted || strings.Contains(ssh.Message, "Hunter2") {
		t.Fatalf("ssh = %+v", ssh)
	}
	if _, err := os.Stat(filepath.Join(h.stateDir, checkpointFileName)); err != nil {
		t.Fatalf("the checkpoint must be committed after the ack: %v", err)
	}
	if !s.Spool.Empty() {
		t.Fatal("an acknowledged batch must leave the spool")
	}
}

func TestShipperRetriesTheSameBatchAndStopsOn401(t *testing.T) {
	h := newShipperHost(t)
	h.client.failWith = []error{&api.HTTPError{StatusCode: http.StatusServiceUnavailable}, nil}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(s)
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/id"))
	h.advance(6 * time.Second)
	h.step(s)
	h.step(s)
	if len(h.client.batches) != 1 {
		t.Fatalf("batches = %d, want no retry before the backoff", len(h.client.batches))
	}
	if _, err := os.Stat(filepath.Join(h.stateDir, checkpointFileName)); err == nil {
		t.Fatal("nothing may be committed before the server acknowledges")
	}
	h.advance(maxUploadBackoff)
	h.step(s)
	if len(h.client.batches) != 2 || h.client.batches[1].BatchID != h.client.batches[0].BatchID {
		t.Fatalf("a retry must reuse the batch_id: %+v", h.client.batches)
	}

	h.client.failWith = []error{api.ErrUnauthorized}
	h.advance(EmptyBatchEvery)
	if err := s.Step(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
}

// TestShipperDropsOnlyTheEventTheServerRejects checks that a 422 naming one event drops that event alone: the
// others of its batch are sent, and the dropped event is reported with the one too old to send.
func TestShipperDropsOnlyTheEventTheServerRejects(t *testing.T) {
	h := newShipperHost(t)
	h.client.validate = validateLikeTheServer(func(e logs.Event) bool { return commandOf(e) == "/usr/bin/poison" }, nil)
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(s)
	for _, command := range []string{"/usr/bin/a", "/usr/bin/poison", "/usr/bin/b"} {
		h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND="+command))
	}
	h.appendLog(syslogAt(h.clock.now.Add(-8*24*time.Hour), "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/old"))
	h.advance(6 * time.Second)
	h.step(s)
	if got := storedCommands(h.client.accepted, 0); strings.Join(got, ",") != "/usr/bin/a,/usr/bin/b" {
		t.Fatalf("stored = %v, want the events around the rejected one", got)
	}
	if len(h.client.batches) != 2 || h.client.accepted[0].DroppedEvents != 2 {
		t.Fatalf("requests = %d, dropped_events = %d, want the rejected event reported with the 8 day old one", len(h.client.batches), h.client.accepted[0].DroppedEvents)
	}
	if !s.Spool.Empty() || h.committedOffset() == 0 || s.Spool.Dropped() != 0 {
		t.Fatal("the batch must be acknowledged, its positions committed and its dropped events reported")
	}
}

// TestShipperFindsAPoisonEventTheServerDoesNotName checks a rejection that names nothing (a proxy answering 400
// to one request body): the batch is split until the event is alone, sent without the skipped sources, and
// dropped only once an empty request is accepted. The skipped sources, which were not the cause, are still sent.
func TestShipperFindsAPoisonEventTheServerDoesNotName(t *testing.T) {
	h := newShipperHost(t)
	h.client.validate = func(b api.LogBatchRequest) error {
		for _, e := range b.Events {
			if commandOf(e) == "/usr/bin/poison" {
				return &api.HTTPError{StatusCode: http.StatusBadRequest}
			}
		}
		return nil
	}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth", "web"}, FlushIntervalSeconds: 5})
	h.step(s)
	for _, command := range []string{"/usr/bin/a", "/usr/bin/b", "/usr/bin/poison", "/usr/bin/c", "/usr/bin/d"} {
		h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND="+command))
	}
	h.advance(6 * time.Second)
	h.step(s)
	h.advance(EmptyBatchEvery)
	h.step(s)
	if got := storedCommands(h.client.accepted, 0); strings.Join(got, ",") != "/usr/bin/a,/usr/bin/b,/usr/bin/c,/usr/bin/d" {
		t.Fatalf("stored = %v, want every event but the rejected one, in order", got)
	}
	reported := 0
	for _, b := range h.client.accepted {
		reported += b.DroppedEvents
	}
	last := h.client.batches[len(h.client.batches)-1]
	if reported != 1 || s.Spool.Dropped() != 0 || len(last.SkippedSources) != 1 || last.SkippedSources[0].Path != "/var/log/nginx" {
		t.Fatalf("reported %d dropped, last request = %+v, want the dropped event reported and the skipped web logs still sent", reported, last)
	}
	if !s.Spool.Empty() || h.committedOffset() == 0 {
		t.Fatal("everything must be acknowledged in the end")
	}
}

// TestShipperKeepsEventsWhenTheServerRejectsEveryRequest checks that a server or proxy that rejects every
// request, an empty one too, never makes the agent drop events or commit their positions.
func TestShipperKeepsEventsWhenTheServerRejectsEveryRequest(t *testing.T) {
	h := newShipperHost(t)
	broken := true
	h.client.validate = func(api.LogBatchRequest) error {
		if broken {
			return &api.HTTPError{StatusCode: http.StatusBadRequest}
		}
		return nil
	}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth", "web"}, FlushIntervalSeconds: 5})
	h.step(s)
	for _, command := range []string{"/usr/bin/a", "/usr/bin/b", "/usr/bin/c"} {
		h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND="+command))
	}
	for range 10 {
		h.advance(maxUploadBackoff)
		h.step(s)
	}
	if len(h.client.accepted) != 0 || s.Spool.Dropped() != 0 || h.committedOffset() != 0 || s.Spool.Empty() {
		t.Fatalf("accepted %d, dropped %d, committed %d: nothing may be dropped or committed", len(h.client.accepted), s.Spool.Dropped(), h.committedOffset())
	}
	broken = false
	for range 3 {
		h.advance(maxUploadBackoff)
		h.step(s)
	}
	if got := storedCommands(h.client.accepted, 0); strings.Join(got, ",") != "/usr/bin/a,/usr/bin/b,/usr/bin/c" {
		t.Fatalf("stored = %v once the server accepts again", got)
	}
	if len(h.client.accepted[0].SkippedSources) != 1 {
		t.Fatalf("skipped sources = %+v, the rejections did not name them", h.client.accepted[0].SkippedSources)
	}
}

// TestShipperFindsASkippedSourceTheServerDoesNotName checks a rejection that names nothing but comes from the
// skipped sources every request carries: the one event left is accepted bare, so the skipped sources are left
// out from then on, and no event is dropped.
func TestShipperFindsASkippedSourceTheServerDoesNotName(t *testing.T) {
	h := newShipperHost(t)
	h.client.validate = func(b api.LogBatchRequest) error {
		if len(b.SkippedSources) > 0 {
			return &api.HTTPError{StatusCode: http.StatusBadRequest}
		}
		return nil
	}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth", "web"}, FlushIntervalSeconds: 5})
	h.step(s)
	for _, command := range []string{"/usr/bin/a", "/usr/bin/b", "/usr/bin/c"} {
		h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND="+command))
	}
	h.advance(6 * time.Second)
	h.step(s)
	if got := storedCommands(h.client.accepted, 0); strings.Join(got, ",") != "/usr/bin/a,/usr/bin/b,/usr/bin/c" || s.Spool.Dropped() != 0 {
		t.Fatalf("stored = %v, dropped %d", got, s.Spool.Dropped())
	}
	if !s.Spool.Empty() || h.committedOffset() == 0 {
		t.Fatal("everything must be acknowledged")
	}
	sent := len(h.client.batches)
	h.advance(EmptyBatchEvery)
	h.step(s)
	if len(h.client.batches) != sent+1 || len(h.client.accepted[len(h.client.accepted)-1].SkippedSources) != 0 {
		t.Fatal("the skipped sources must stay out of later requests")
	}
}

// TestShipperSplitsABatchTheServerFindsTooLarge checks that a 413 (a proxy body limit) splits the batch until
// each part goes through, and that positions are committed only once every event of the batch was accepted.
func TestShipperSplitsABatchTheServerFindsTooLarge(t *testing.T) {
	h := newShipperHost(t)
	h.client.validate = func(b api.LogBatchRequest) error {
		if len(b.Events) > 1 {
			return &api.HTTPError{StatusCode: http.StatusRequestEntityTooLarge}
		}
		return nil
	}
	var committedAt []int64
	h.client.onAccept = func(api.LogBatchRequest) { committedAt = append(committedAt, h.committedOffset()) }
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(s)
	for _, command := range []string{"/usr/bin/a", "/usr/bin/b", "/usr/bin/c", "/usr/bin/d", "/usr/bin/e"} {
		h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND="+command))
	}
	h.advance(6 * time.Second)
	h.step(s)
	if got := storedCommands(h.client.accepted, 0); strings.Join(got, ",") != "/usr/bin/a,/usr/bin/b,/usr/bin/c,/usr/bin/d,/usr/bin/e" {
		t.Fatalf("stored = %v", got)
	}
	ids := map[string]bool{}
	for _, b := range h.client.accepted {
		ids[b.BatchID] = true
	}
	if len(ids) != 5 || s.Spool.Dropped() != 0 || !s.Spool.Empty() {
		t.Fatalf("batch ids %d, dropped %d: each part needs its own batch_id and nothing may be dropped", len(ids), s.Spool.Dropped())
	}
	for i, offset := range committedAt {
		if offset != 0 {
			t.Fatalf("positions committed after part %d of 5, before the rest of the batch was accepted", i+1)
		}
	}
	if h.committedOffset() == 0 {
		t.Fatal("the last part must commit the positions")
	}
}

// TestShipperSendsSkippedSourcesTheServerAccepts checks the case of a log_paths entry the server would reject
// as a skipped path (over 1024 characters, a line feed in it): it is cut and cleaned before it is sent, so it
// never gets the batches rejected. A skipped source the server still rejects for a reason of its own is left
// out of the requests, and no event is lost.
func TestShipperSendsSkippedSourcesTheServerAccepts(t *testing.T) {
	long := "/var/www/" + strings.Repeat("a", 1500) + ".log"
	for name, rejectApp := range map[string]bool{"cleaned": false, "rejected anyway": true} {
		t.Run(name, func(t *testing.T) {
			h := newShipperHost(t)
			var rejectSkipped func(logs.SkippedSource) bool
			if rejectApp {
				rejectSkipped = func(src logs.SkippedSource) bool { return src.Source == logs.SourceApp }
			}
			h.client.validate = validateLikeTheServer(nil, rejectSkipped)
			s, err := NewLogShipper(h.client, h.stateDir, logs.Options{Root: h.root, AppPaths: []string{long, "/var/www/a\nb.log"}, HasJournalctl: func() bool { return false }}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			s.Now = h.clock.Now
			s.Configure(api.LogCollection{Sources: []string{"auth", "app"}, FlushIntervalSeconds: 5})
			h.step(s)
			h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/a"))
			h.advance(6 * time.Second)
			h.step(s)
			if got := storedCommands(h.client.accepted, 0); strings.Join(got, ",") != "/usr/bin/a" || s.Spool.Dropped() != 0 {
				t.Fatalf("stored = %v, dropped %d", got, s.Spool.Dropped())
			}
			sent := h.client.accepted[0].SkippedSources
			if rejectApp {
				// The server names the first rejected source only, so each takes one request.
				if len(h.client.batches) != 3 || len(sent) != 0 {
					t.Fatalf("requests %d, skipped sources %+v, want a retry without each rejected source", len(h.client.batches), sent)
				}
				h.advance(EmptyBatchEvery)
				h.step(s)
				if last := h.client.batches[len(h.client.batches)-1]; len(h.client.batches) != 4 || len(last.SkippedSources) != 0 {
					t.Fatalf("requests %d, the rejected sources must stay out", len(h.client.batches))
				}
				return
			}
			if len(h.client.batches) != 1 || len(sent) != 2 || len(sent[0].Path) != 1024 || sent[1].Path != "/var/www/a\uFFFDb.log" {
				t.Fatalf("requests %d, skipped sources %+v", len(h.client.batches), sent)
			}
		})
	}
}

func TestOutgoingEventsStayWithinTheServerLimits(t *testing.T) {
	now := time.Date(2026, 10, 31, 19, 0, 0, 0, time.UTC)
	events := []logs.Event{
		{Kind: "a", FirstAt: now.Add(-time.Minute), LastAt: now, Count: 2_000_000, SrcIP: "203.0.113.7"},
		{Kind: "b", FirstAt: now.Add(time.Hour), LastAt: now.Add(2 * time.Hour), Count: 0, SrcIP: "not-an-ip"},
		{Kind: "c", FirstAt: now.Add(-8 * 24 * time.Hour), LastAt: now.Add(-time.Hour), Count: 1, SrcIP: "fe80::1%eth0"},
		{Kind: "d", FirstAt: now.Add(-8 * 24 * time.Hour), LastAt: now.Add(-8 * 24 * time.Hour), Count: 1},
	}
	got, expired := outgoingEvents(events, now)
	if expired != 1 || len(got) != 3 {
		t.Fatalf("kept %d, expired %d", len(got), expired)
	}
	if got[0].Count != MaxEventCount || got[0].SrcIP != "203.0.113.7" {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].Count != 1 || got[1].SrcIP != "" || !got[1].FirstAt.Equal(now) || !got[1].LastAt.Equal(now) {
		t.Fatalf("second = %+v", got[1])
	}
	if got[2].SrcIP != "" || !got[2].FirstAt.Equal(now.Add(-maxEventAge)) {
		t.Fatalf("third = %+v", got[2])
	}
	if events[0].Count != 2_000_000 {
		t.Fatal("the spooled events must not change")
	}
}

func TestShipperSendsEmptyBatchesAsLiveness(t *testing.T) {
	h := newShipperHost(t)
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}})
	h.step(s)
	h.advance(EmptyBatchEvery - time.Second)
	h.step(s)
	if len(h.client.batches) != 0 {
		t.Fatal("too early for an empty batch")
	}
	h.advance(time.Second)
	h.step(s)
	if len(h.client.batches) != 1 || len(h.client.batches[0].Events) != 0 {
		t.Fatalf("batches = %+v", h.client.batches)
	}
}

// A quiet host: flushes find nothing, then a line arrives just before the liveness batch is due and after the
// last flush. The liveness batch carries the positions past that line, so it must carry the event too, or a
// restart before the next flush would resume past an event that was never sent.
func TestLivenessBatchNeverSkipsUnflushedEventsAcrossARestart(t *testing.T) {
	h := newShipperHost(t)
	first := h.shipper()
	first.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 30})
	h.step(first)
	h.advance(45 * time.Second)
	for h.step(first); h.clock.now.Before(time.Date(2026, 10, 31, 19, 4, 45, 0, time.UTC)); h.step(first) {
		h.advance(30 * time.Second)
	}
	if len(h.client.batches) != 0 {
		t.Fatalf("batches = %d before the liveness batch is due", len(h.client.batches))
	}
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/id"))
	h.advance(15 * time.Second)
	h.step(first)
	if len(h.client.batches) != 1 {
		t.Fatalf("batches = %d, want the liveness batch at 5 minutes", len(h.client.batches))
	}
	first.stopCollector()

	second := h.shipper()
	second.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 30})
	for range 12 {
		h.step(second)
		h.advance(30 * time.Second)
	}
	var commands []string
	for _, b := range h.client.batches {
		for _, e := range b.Events {
			commands = append(commands, commandOf(e))
		}
	}
	if strings.Join(commands, ",") != "/usr/bin/id" {
		t.Fatalf("commands = %v, want the line sent exactly once", commands)
	}
}

func TestShipperWaitsAsLongAsRetryAfter(t *testing.T) {
	h := newShipperHost(t)
	h.client.failWith = []error{&api.HTTPError{StatusCode: http.StatusTooManyRequests, RetryAfter: 120 * time.Second}, &api.HTTPError{StatusCode: http.StatusServiceUnavailable, RetryAfter: 30 * time.Minute}}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(s)
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/id"))
	h.advance(6 * time.Second)
	h.step(s)
	for range 119 {
		h.advance(time.Second)
		h.step(s)
	}
	if len(h.client.batches) != 1 {
		t.Fatalf("batches = %d, want no retry within the 120 s the server asked for", len(h.client.batches))
	}
	h.advance(time.Second)
	h.step(s)
	if len(h.client.batches) != 2 {
		t.Fatalf("batches = %d, want a retry once Retry-After passed", len(h.client.batches))
	}
	h.advance(30 * time.Minute)
	h.step(s)
	if len(h.client.batches) != 3 || !s.Spool.Empty() {
		t.Fatalf("batches = %d, want the retry after 30 minutes to succeed", len(h.client.batches))
	}
}

func TestShipperStopsAndDeletesSpoolWhenDisabled(t *testing.T) {
	h := newShipperHost(t)
	h.client.failWith = []error{&api.HTTPError{StatusCode: http.StatusBadGateway}}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(s)
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/id"))
	h.advance(6 * time.Second)
	h.step(s)
	if s.Spool.Empty() {
		t.Fatal("the failed batch must wait in the spool")
	}
	s.Configure(api.LogCollection{Sources: []string{}})
	h.step(s)
	if !s.Spool.Empty() || s.collector != nil {
		t.Fatal("disabling collection must stop the collector and delete the spool")
	}
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/id"))
	h.advance(time.Hour)
	h.step(s)
	if len(h.client.batches) != 1 {
		t.Fatalf("batches = %d, nothing may be sent while collection is off", len(h.client.batches))
	}
}

func TestShipperFollowsSourceChangesFromTheLogsResponse(t *testing.T) {
	h := newShipperHost(t)
	h.client.reply = &api.LogCollection{Sources: []string{"auth", "web"}, FlushIntervalSeconds: 30}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}})
	h.step(s)
	h.advance(EmptyBatchEvery)
	h.step(s)
	h.step(s)
	if got := s.sources; len(got) != 2 || got[1] != "web" {
		t.Fatalf("sources = %v", got)
	}
}

func TestShipperResumesAfterRestartWithoutDuplicates(t *testing.T) {
	h := newShipperHost(t)
	h.client.failWith = []error{&api.HTTPError{StatusCode: http.StatusBadGateway}}
	first := h.shipper()
	first.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(first)
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/first"))
	h.advance(6 * time.Second)
	h.step(first)
	first.stopCollector()

	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/second"))
	second := h.shipper()
	second.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.advance(maxUploadBackoff)
	h.step(second)
	h.advance(6 * time.Second)
	h.step(second)
	var commands []string
	for _, b := range h.client.batches[1:] {
		for _, e := range b.Events {
			commands = append(commands, commandOf(e))
		}
	}
	if strings.Join(commands, ",") != "/usr/bin/first,/usr/bin/second" {
		t.Fatalf("commands = %v, want each line once and in order", commands)
	}
}

func TestBatchSizeRespectsLimits(t *testing.T) {
	small := make([]logs.Event, MaxBatchEvents+10)
	if n := batchSize(small); n != MaxBatchEvents {
		t.Fatalf("batch size = %d", n)
	}
	big := make([]logs.Event, 10)
	for i := range big {
		big[i] = logs.Event{Message: strings.Repeat("x", 1<<20)}
	}
	if n := batchSize(big); n != 3 {
		t.Fatalf("batch size = %d, want 3 events of 1 MB under the 4 MB cap", n)
	}
}

func TestAgentStopsWhenLogUploadIsUnauthorized(t *testing.T) {
	h := newShipperHost(t)
	h.client.failWith = []error{api.ErrUnauthorized}
	shipper := h.shipper()
	shipper.Tick = time.Millisecond
	shipper.Now = time.Now
	if err := shipper.Spool.Append(logs.Batch{ID: logs.NewBatchID(), Events: []logs.Event{}}); err != nil {
		t.Fatal(err)
	}
	client := &fakeClient{}
	a, _ := newTestAgent(t, client, &[]collect.Package{})
	a.Logs = shipper
	heartbeats := 0
	a.Client = heartbeatWithLogs{client, &heartbeats}
	a.Wait = func(ctx context.Context, d time.Duration) error {
		<-ctx.Done()
		return ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- a.Run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRevoked) {
			t.Fatalf("Run = %v, want ErrRevoked", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not stop")
	}
}

type heartbeatWithLogs struct {
	*fakeClient
	count *int
}

func (h heartbeatWithLogs) Heartbeat(ctx context.Context, req api.HeartbeatRequest) (api.HeartbeatResponse, error) {
	*h.count++
	resp, err := h.fakeClient.Heartbeat(ctx, req)
	resp.LogCollection = &api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5}
	return resp, err
}

func TestShipperStaysIdleWhenTheServerHasNoLogsEndpoint(t *testing.T) {
	h := newShipperHost(t)
	h.client.failWith = []error{&api.HTTPError{StatusCode: http.StatusNotFound}}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(s)
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/first"))
	h.advance(6 * time.Second)
	h.step(s)
	if len(h.client.batches) != 1 || s.collector != nil {
		t.Fatalf("batches = %d, collector running = %v; a 404 must stop collection", len(h.client.batches), s.collector != nil)
	}
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/second"))
	for range 5 {
		s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
		h.advance(10 * time.Minute)
		h.step(s)
	}
	if len(h.client.batches) != 1 || s.collector != nil || s.Spool.Empty() {
		t.Fatalf("batches = %d, collector running = %v, spool empty = %v; the shipper must stay idle and keep its spool", len(h.client.batches), s.collector != nil, s.Spool.Empty())
	}
	h.advance(UnsupportedRecheckEvery)
	h.step(s)
	h.advance(6 * time.Second)
	h.step(s)
	var commands []string
	for _, b := range h.client.batches[1:] {
		for _, e := range b.Events {
			commands = append(commands, commandOf(e))
		}
	}
	if strings.Join(commands, ",") != "/usr/bin/first,/usr/bin/second" {
		t.Fatalf("commands = %v, want the spooled event, then the line written while idle", commands)
	}
}

func TestShipperTurnsOffWhileIdle(t *testing.T) {
	h := newShipperHost(t)
	h.client.failWith = []error{&api.HTTPError{StatusCode: http.StatusNotFound}}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(s)
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/id"))
	h.advance(6 * time.Second)
	h.step(s)
	s.Configure(api.LogCollection{Sources: []string{}})
	h.advance(time.Minute)
	h.step(s)
	if !s.Spool.Empty() {
		t.Fatal("turning collection off must delete the spool even while the server does not accept logs")
	}
	h.advance(UnsupportedRecheckEvery)
	h.step(s)
	if len(h.client.batches) != 1 || s.collector != nil {
		t.Fatalf("batches = %d, collector running = %v", len(h.client.batches), s.collector != nil)
	}
}

func TestAgentStopsLogShippingWhenTheConfigurationChanges(t *testing.T) {
	h := newShipperHost(t)
	shipper := h.shipper()
	shipper.Tick = time.Millisecond
	shipper.Now = time.Now
	client := &fakeClient{}
	a, _ := newTestAgent(t, client, &[]collect.Package{})
	a.Logs = shipper
	heartbeats := 0
	a.Client = heartbeatWithLogs{client, &heartbeats}
	a.Wait = func(context.Context, time.Duration) error { return nil }
	a.ConfigChanged = func() (bool, error) { return true, nil }
	done := make(chan error, 1)
	go func() { done <- a.Run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrConfigChanged) {
			t.Fatalf("Run = %v, want ErrConfigChanged", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not stop")
	}
	if shipper.collector != nil {
		t.Fatal("Run returned before the log shipper stopped")
	}
}

// storedCommands is what the server keeps of the batches it received: like LogIngestionService it ignores a
// batch whose batch_id is the last one it stored.
func storedCommands(batches []api.LogBatchRequest, failed int) []string {
	var commands []string
	last := ""
	for _, b := range batches[failed:] {
		if b.BatchID == last {
			continue
		}
		last = b.BatchID
		for _, e := range b.Events {
			commands = append(commands, commandOf(e))
		}
	}
	return commands
}

func (h *shipperHost) committedOffset() int64 {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.stateDir, checkpointFileName))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var cp logs.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		h.t.Fatal(err)
	}
	return cp.Files["/var/log/auth.log"].Offset
}

func (h *shipperHost) spoolFiles() map[string][]byte {
	h.t.Helper()
	entries, err := os.ReadDir(filepath.Join(h.stateDir, "spool"))
	if err != nil {
		h.t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(h.stateDir, "spool", e.Name()))
		if err != nil {
			h.t.Fatal(err)
		}
		files[e.Name()] = data
	}
	return files
}

// TestShipperStopsAroundTheAck stops the agent at the points of acknowledging a batch: after its positions
// are committed but before it leaves the spool, and when the commit fails (the moment the batch was already
// gone from the spool when it was removed first). Each line must be stored by the server exactly once, any
// resend must reuse the batch_id, and the committed positions must never go back.
func TestShipperStopsAroundTheAck(t *testing.T) {
	tests := map[string]func(t *testing.T, h *shipperHost, first *LogShipper){
		"after the commit, before the removal": func(t *testing.T, h *shipperHost, first *LogShipper) {
			spooled := h.spoolFiles()
			h.advance(maxUploadBackoff)
			h.step(first)
			if !first.Spool.Empty() || h.committedOffset() == 0 {
				t.Fatal("the acknowledged batch must be committed and removed")
			}
			for name, data := range spooled {
				if err := os.WriteFile(filepath.Join(h.stateDir, "spool", name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		},
		"at the commit, where removing first had already emptied the spool": func(t *testing.T, h *shipperHost, first *LogShipper) {
			checkpoint := filepath.Join(h.stateDir, checkpointFileName)
			if err := os.MkdirAll(filepath.Join(checkpoint, "blocked"), 0o700); err != nil {
				t.Fatal(err)
			}
			h.advance(maxUploadBackoff)
			h.step(first)
			if first.Spool.Empty() {
				t.Error("a batch whose positions were not committed must stay in the spool")
			}
			if err := os.RemoveAll(checkpoint); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, stop := range tests {
		t.Run(name, func(t *testing.T) {
			h := newShipperHost(t)
			h.client.failWith = []error{&api.HTTPError{StatusCode: http.StatusBadGateway}}
			first := h.shipper()
			first.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
			h.step(first)
			h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/a"))
			h.advance(6 * time.Second)
			h.step(first)
			if len(h.client.batches) != 1 || first.Spool.Empty() {
				t.Fatal("the first upload must fail and keep the batch in the spool")
			}
			stop(t, h, first)
			first.stopCollector()
			acked := h.client.batches[1].BatchID

			h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/b"))
			second := h.shipper()
			second.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
			offset := h.committedOffset()
			for range 6 {
				h.advance(maxUploadBackoff)
				h.step(second)
				if next := h.committedOffset(); next < offset {
					t.Fatalf("committed offset went back from %d to %d", offset, next)
				} else {
					offset = next
				}
			}
			if got := h.client.batches[2]; got.BatchID != acked {
				t.Fatalf("the batch left in the spool was sent as %s, want its batch_id %s", got.BatchID, acked)
			}
			if got := storedCommands(h.client.batches, 1); strings.Join(got, ",") != "/usr/bin/a,/usr/bin/b" {
				t.Fatalf("stored commands = %v, want each line once and in order", got)
			}
			if !second.Spool.Empty() {
				t.Fatal("everything must be acknowledged in the end")
			}
		})
	}
}

func (h *shipperHost) appendAccessLog(path string) {
	h.t.Helper()
	file := filepath.Join(h.root, "var", "log", "nginx", "access.log")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		h.t.Fatal(err)
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	if path != "" {
		fmt.Fprintf(f, "172.17.0.1 - - [%s] \"GET %s HTTP/1.1\" 404 153 \"-\" \"curl/8.18.0\" \"-\"\n", h.clock.now.Format("02/Jan/2006:15:04:05 -0700"), path)
	}
}

func (h *shipperHost) sentPaths() []string {
	var paths []string
	for _, b := range h.client.accepted {
		for _, e := range b.Events {
			if path, ok := e.Fields["path"].(string); ok {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

// Switching web off and on again within minutes, with no batch committed in between (the server is
// unreachable), must start web at the end again: the lines written while it was off are history. That holds
// across a restart, and when the spool cannot record the change.
func TestShipperStartsAtTheEndWhenASourceIsSwitchedOnAgain(t *testing.T) {
	for _, mode := range []string{"running", "restart", "spool fails"} {
		t.Run(mode, func(t *testing.T) {
			h := newShipperHost(t)
			h.appendAccessLog("")
			s := h.shipper()
			s.Configure(api.LogCollection{Sources: []string{"auth", "web"}, FlushIntervalSeconds: 5})
			h.step(s)
			h.appendAccessLog("/before")
			h.advance(6 * time.Second)
			h.step(s)
			if got := h.sentPaths(); strings.Join(got, ",") != "/before" {
				t.Fatalf("paths = %v before web is switched off", got)
			}

			h.client.validate = func(api.LogBatchRequest) error { return &api.HTTPError{StatusCode: http.StatusBadGateway} }
			spoolDir := s.Spool.Dir
			if mode == "spool fails" {
				blocker := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(blocker, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				s.Spool.Dir = filepath.Join(blocker, "spool")
			}
			s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
			h.step(s)
			s.Spool.Dir = spoolDir
			for i := range 3 {
				h.appendAccessLog(fmt.Sprintf("/while-off-%d", i))
				h.advance(time.Minute)
				h.step(s)
			}
			if mode == "restart" {
				s.stopCollector()
				s = h.shipper()
			}
			h.client.validate = nil
			s.Configure(api.LogCollection{Sources: []string{"auth", "web"}, FlushIntervalSeconds: 5})
			h.advance(maxUploadBackoff)
			h.step(s)
			h.appendAccessLog("/after")
			h.advance(6 * time.Second)
			h.step(s)
			h.step(s)
			if got := h.sentPaths(); strings.Join(got, ",") != "/before,/after" {
				t.Fatalf("paths = %v, want none of the lines written while web was off", got)
			}
		})
	}
}
