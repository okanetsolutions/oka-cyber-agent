package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/logs"
)

type fakeLogClient struct {
	batches  []api.LogBatchRequest
	failWith []error
	reply    *api.LogCollection
}

func (f *fakeLogClient) PostLogs(_ context.Context, b api.LogBatchRequest) (api.LogBatchResponse, error) {
	f.batches = append(f.batches, b)
	if len(f.failWith) > 0 {
		err := f.failWith[0]
		f.failWith = f.failWith[1:]
		if err != nil {
			return api.LogBatchResponse{}, err
		}
	}
	return api.LogBatchResponse{Accepted: len(b.Events), LogCollection: f.reply}, nil
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
	if sudo.Kind != logs.KindSudoCommand || strings.Contains(sudo.Message, "S3cret") || strings.Contains(sudo.Fields["command"].(string), "S3cret") {
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

func TestShipperDropsRejectedBatchesAndReportsThem(t *testing.T) {
	h := newShipperHost(t)
	h.client.failWith = []error{&api.HTTPError{StatusCode: http.StatusUnprocessableEntity}}
	s := h.shipper()
	s.Configure(api.LogCollection{Sources: []string{"auth"}, FlushIntervalSeconds: 5})
	h.step(s)
	h.appendLog(syslogAt(h.clock.now, "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/id"))
	h.appendLog(syslogAt(h.clock.now.Add(-8*24*time.Hour), "sudo:    alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/old"))
	h.advance(6 * time.Second)
	h.step(s)
	h.advance(EmptyBatchEvery)
	h.step(s)
	if len(h.client.batches) != 2 {
		t.Fatalf("batches = %d", len(h.client.batches))
	}
	if got := h.client.batches[1]; len(got.Events) != 0 || got.DroppedEvents != 2 {
		t.Fatalf("next batch = %+v, want an empty batch reporting the rejected event and the 8 day old one", got)
	}
	if s.Spool.Dropped() != 0 {
		t.Fatalf("dropped = %d after reporting", s.Spool.Dropped())
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
			commands = append(commands, e.Fields["command"].(string))
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
			commands = append(commands, e.Fields["command"].(string))
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
			commands = append(commands, e.Fields["command"].(string))
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
			commands = append(commands, e.Fields["command"].(string))
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
