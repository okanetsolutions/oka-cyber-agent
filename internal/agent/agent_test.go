package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

type fakeClient struct {
	heartbeats   int
	inventories  []json.RawMessage
	heartbeatErr error
	inventoryErr error
	interval     int
}

func (f *fakeClient) Heartbeat(_ context.Context, req api.HeartbeatRequest) (api.HeartbeatResponse, error) {
	f.heartbeats++
	if req.AgentVersion != Version {
		return api.HeartbeatResponse{}, errors.New("wrong version")
	}
	return api.HeartbeatResponse{ReportIntervalSeconds: f.interval}, f.heartbeatErr
}

func (f *fakeClient) PutInventory(_ context.Context, snapshot json.RawMessage) (api.InventoryResponse, error) {
	if f.inventoryErr != nil {
		return api.InventoryResponse{}, f.inventoryErr
	}
	f.inventories = append(f.inventories, snapshot)
	return api.InventoryResponse{Changed: true, ReportIntervalSeconds: f.interval}, nil
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newTestAgent(t *testing.T, client *fakeClient, packages *[]collect.Package) (*Agent, *clock) {
	t.Helper()
	c := &clock{now: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	return &Agent{
		Config:   config.Config{ServerID: "42", ReportIntervalSeconds: 300},
		StateDir: t.TempDir(),
		Client:   client,
		Collect: func(context.Context) (*collect.Inventory, error) {
			return &collect.Inventory{Packages: slices.Clone(*packages)}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    c.Now,
	}, c
}

func TestCycleSendsInventoryOnlyWhenChangedOrDaily(t *testing.T) {
	client := &fakeClient{}
	packages := []collect.Package{{Ecosystem: "Debian:12", Name: "bash", Version: "5.2.15-2+b7"}}
	a, clk := newTestAgent(t, client, &packages)
	ctx := context.Background()

	steps := []struct {
		advance       time.Duration
		change        bool
		wantSentTotal int
	}{
		{0, false, 1},
		{5 * time.Minute, false, 1},
		{5 * time.Minute, true, 2},
		{FullInventoryEvery - time.Minute, false, 2},
		{time.Minute, false, 3},
	}
	for i, step := range steps {
		clk.now = clk.now.Add(step.advance)
		if step.change {
			packages[0].Version = "5.2.15-2+b8"
		}
		if err := a.Cycle(ctx); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if len(client.inventories) != step.wantSentTotal {
			t.Fatalf("step %d: inventories sent = %d, want %d", i, len(client.inventories), step.wantSentTotal)
		}
	}
	if client.heartbeats != len(steps) {
		t.Fatalf("heartbeats = %d, want one per cycle", client.heartbeats)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	client := &fakeClient{}
	packages := []collect.Package{{Ecosystem: "Debian:12", Name: "bash", Version: "1"}}
	a, clk := newTestAgent(t, client, &packages)
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted := &Agent{Config: a.Config, StateDir: a.StateDir, Client: client, Collect: a.Collect, Logger: a.Logger, Now: clk.Now}
	if err := restarted.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.inventories) != 1 {
		t.Fatalf("inventories = %d, an unchanged inventory must not be resent after a restart", len(client.inventories))
	}
	info, err := os.Stat(filepath.Join(a.StateDir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v", info.Mode().Perm())
	}
}

func TestReenrolledServerStartsFromAFreshState(t *testing.T) {
	client := &fakeClient{interval: 3600}
	packages := []collect.Package{{Ecosystem: "Debian:12", Name: "bash", Version: "1"}}
	a, clk := newTestAgent(t, client, &packages)
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}

	client.interval = 0
	reenrolled := config.Config{ServerID: "43", ReportIntervalSeconds: 300}
	b := &Agent{Config: reenrolled, StateDir: a.StateDir, Client: client, Collect: a.Collect, Logger: a.Logger, Now: clk.Now}
	if err := b.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.inventories) != 2 {
		t.Fatalf("inventories = %d, want the new server to get its first inventory at once", len(client.inventories))
	}
	if got := b.interval(); got != 300*time.Second {
		t.Fatalf("interval = %v, want the new server's 300s, not the previous server's 3600s", got)
	}
	state, err := LoadState(a.StateDir, "43")
	if err != nil || state.ServerID != "43" || state.LastInventoryAt.IsZero() {
		t.Fatalf("state = %+v, err = %v; want it saved for the new server", state, err)
	}
	if old, _ := LoadState(a.StateDir, "42"); !old.LastInventoryAt.IsZero() {
		t.Fatalf("state for the previous server = %+v, want it ignored", old)
	}
}

func TestFailedHeartbeatSkipsInventoryAndIsRecorded(t *testing.T) {
	client := &fakeClient{heartbeatErr: errors.New("connection refused")}
	packages := []collect.Package{}
	a, _ := newTestAgent(t, client, &packages)
	if err := a.Cycle(context.Background()); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("Cycle = %v, want the heartbeat failure returned", err)
	}
	if len(client.inventories) != 0 {
		t.Fatal("inventory must wait for a successful heartbeat")
	}
	state, err := LoadState(a.StateDir, a.Config.ServerID)
	if err != nil || state.LastError == "" || state.LastErrorAt.IsZero() {
		t.Fatalf("state = %+v, err = %v; want the error recorded", state, err)
	}

	client.heartbeatErr = nil
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, _ := LoadState(a.StateDir, a.Config.ServerID); state.LastError != "" {
		t.Fatalf("last error = %q, want it cleared after a successful cycle", state.LastError)
	}
}

func TestFailedInventoryIsResentNextCycle(t *testing.T) {
	inventoryErr := errors.New("HTTP 502")
	client := &fakeClient{inventoryErr: inventoryErr}
	packages := []collect.Package{{Ecosystem: "Debian:12", Name: "bash", Version: "1"}}
	a, _ := newTestAgent(t, client, &packages)
	if err := a.Cycle(context.Background()); !errors.Is(err, inventoryErr) {
		t.Fatalf("Cycle = %v, want the inventory failure returned", err)
	}
	client.inventoryErr = nil
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.inventories) != 1 {
		t.Fatalf("inventories = %d, want the failed one resent", len(client.inventories))
	}
}

func TestCollectFailureSendsNothingAndRetries(t *testing.T) {
	client := &fakeClient{}
	packages := []collect.Package{{Ecosystem: "Debian:12", Name: "bash", Version: "1"}}
	a, _ := newTestAgent(t, client, &packages)
	collected := a.Collect
	failures := []error{
		errors.New("rpm collector: dnf history: permission denied"),
		fmt.Errorf("normalize: %w", collect.ErrTooManyOSPackages),
	}
	a.Collect = func(ctx context.Context) (*collect.Inventory, error) {
		if len(failures) > 0 {
			err := failures[0]
			failures = failures[1:]
			return nil, err
		}
		return collected(ctx)
	}
	a.Wait = func(context.Context, time.Duration) error {
		if len(client.inventories) != 0 {
			return context.Canceled
		}
		if state, _ := LoadState(a.StateDir, a.Config.ServerID); state.LastError == "" {
			t.Fatal("a failed collection must be visible in the status")
		}
		return nil
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run = %v, want the agent to keep running after a failed collection", err)
	}
	if client.heartbeats != 3 || len(client.inventories) != 1 {
		t.Fatalf("cycles = %d, inventories = %d, want two failed cycles then one inventory", client.heartbeats, len(client.inventories))
	}
	if state, _ := LoadState(a.StateDir, a.Config.ServerID); state.LastError != "" {
		t.Fatalf("LastError = %q, want it cleared by the successful cycle", state.LastError)
	}
}

func TestRevokedTokenStopsTheAgent(t *testing.T) {
	client := &fakeClient{heartbeatErr: api.ErrUnauthorized}
	a, _ := newTestAgent(t, client, &[]collect.Package{})
	if err := a.Run(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Run = %v, want ErrRevoked", err)
	}
	if state, _ := LoadState(a.StateDir, a.Config.ServerID); state.LastError == "" {
		t.Fatal("the revocation must be visible in the status")
	}
}

func TestRunWaitsTheServerIntervalAndStopsOnCancel(t *testing.T) {
	client := &fakeClient{interval: 600}
	a, _ := newTestAgent(t, client, &[]collect.Package{})
	ctx, cancel := context.WithCancel(context.Background())
	var waited time.Duration
	a.Wait = func(_ context.Context, d time.Duration) error {
		if d > ConfigCheckEvery {
			t.Fatalf("wait step = %v, want at most %v so a changed configuration is seen", d, ConfigCheckEvery)
		}
		if client.heartbeats == 2 {
			cancel()
			return context.Canceled
		}
		waited += d
		return nil
	}
	if err := a.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want nil on cancel", err)
	}
	if waited < 600*time.Second || waited > 660*time.Second {
		t.Fatalf("wait between reports = %v, want the 600s server interval plus at most 10%% jitter", waited)
	}
}

func TestRunStopsWhenTheConfigChanges(t *testing.T) {
	client := &fakeClient{}
	a, _ := newTestAgent(t, client, &[]collect.Package{})
	a.Wait = func(context.Context, time.Duration) error { return nil }
	checks := []struct {
		changed bool
		err     error
	}{{false, nil}, {false, errors.New("config.yaml: server_id is required")}, {true, nil}}
	a.ConfigChanged = func() (bool, error) {
		check := checks[0]
		checks = checks[1:]
		return check.changed, check.err
	}
	if err := a.Run(context.Background()); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("Run = %v, want ErrConfigChanged", err)
	}
	if len(checks) != 0 || client.heartbeats != 1 {
		t.Fatalf("checks left = %d, heartbeats = %d; want a broken edit ignored and a stop at the next valid change", len(checks), client.heartbeats)
	}
}

func TestUnreadableOrCorruptStateStartsFresh(t *testing.T) {
	tests := map[string]func(path string) error{
		"corrupt": func(path string) error { return os.WriteFile(path, []byte("{not json"), 0o600) },
		"unreadable": func(path string) error {
			if os.Geteuid() == 0 {
				t.Skip("root can read a file with mode 0000")
			}
			if err := os.WriteFile(path, []byte(`{"server_id":"42"}`), 0o600); err != nil {
				return err
			}
			return os.Chmod(path, 0)
		},
	}
	for name, breakState := range tests {
		t.Run(name, func(t *testing.T) {
			client := &fakeClient{}
			packages := []collect.Package{{Ecosystem: "Debian:12", Name: "bash", Version: "1"}}
			a, _ := newTestAgent(t, client, &packages)
			path := filepath.Join(a.StateDir, stateFileName)
			if err := breakState(path); err != nil {
				t.Fatal(err)
			}
			if state, err := LoadState(a.StateDir, "42"); err == nil || state != (State{ServerID: "42"}) {
				t.Fatalf("LoadState = %+v, %v; want an empty state and an error to warn about", state, err)
			}
			if err := a.Cycle(context.Background()); err != nil {
				t.Fatalf("Cycle = %v, want the agent to start from an empty state", err)
			}
			if len(client.inventories) != 1 {
				t.Fatalf("inventories = %d, want 1", len(client.inventories))
			}
			if state, err := LoadState(a.StateDir, "42"); err != nil || state.LastInventoryAt.IsZero() {
				t.Fatalf("state = %+v, err = %v; want the state file replaced", state, err)
			}
		})
	}
}

func TestStateSavedByRootBelongsToTheStateDirOwner(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file owners are read on Linux only")
	}
	dir := t.TempDir()
	var chowned []string
	previousEuid, previousChown := geteuid, chown
	geteuid = func() int { return 0 }
	chown = func(path string, uid, gid int) error {
		chowned = append(chowned, fmt.Sprintf("%s %d:%d", path, uid, gid))
		return nil
	}
	t.Cleanup(func() { geteuid, chown = previousEuid, previousChown })

	if err := SaveState(dir, State{ServerID: "42"}); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%s %d:%d", filepath.Join(dir, stateFileName), os.Getuid(), os.Getgid())
	if os.Getuid() == 0 {
		want = ""
	}
	if got := strings.Join(chowned, ","); got != want {
		t.Fatalf("chown = %q, want %q", got, want)
	}

	chown = func(string, int, int) error { return fs.ErrPermission }
	if os.Getuid() != 0 {
		if err := SaveState(dir, State{ServerID: "42"}); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("SaveState = %v, want the chown failure reported", err)
		}
	}
}

func TestServerIntervalIsClamped(t *testing.T) {
	for _, tt := range []struct{ server, want int }{{1, config.MinReportIntervalSeconds}, {10_000_000, config.MaxReportIntervalSeconds}, {0, 300}} {
		a, _ := newTestAgent(t, &fakeClient{interval: tt.server}, &[]collect.Package{})
		if err := a.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := a.interval(); got != time.Duration(tt.want)*time.Second {
			t.Errorf("server interval %d: interval = %v, want %ds", tt.server, got, tt.want)
		}
	}
}
