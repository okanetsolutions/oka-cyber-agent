package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
		Config:   config.Config{ReportIntervalSeconds: 300},
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

func TestFailedHeartbeatSkipsInventoryAndIsRecorded(t *testing.T) {
	client := &fakeClient{heartbeatErr: errors.New("connection refused")}
	packages := []collect.Package{}
	a, _ := newTestAgent(t, client, &packages)
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatalf("a transient failure must not stop the agent: %v", err)
	}
	if len(client.inventories) != 0 {
		t.Fatal("inventory must wait for a successful heartbeat")
	}
	state, err := LoadState(a.StateDir)
	if err != nil || state.LastError == "" || state.LastErrorAt.IsZero() {
		t.Fatalf("state = %+v, err = %v; want the error recorded", state, err)
	}

	client.heartbeatErr = nil
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, _ := LoadState(a.StateDir); state.LastError != "" {
		t.Fatalf("last error = %q, want it cleared after a successful cycle", state.LastError)
	}
}

func TestFailedInventoryIsResentNextCycle(t *testing.T) {
	client := &fakeClient{inventoryErr: errors.New("HTTP 502")}
	packages := []collect.Package{{Ecosystem: "Debian:12", Name: "bash", Version: "1"}}
	a, _ := newTestAgent(t, client, &packages)
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.inventoryErr = nil
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.inventories) != 1 {
		t.Fatalf("inventories = %d, want the failed one resent", len(client.inventories))
	}
}

func TestCollectFailureSendsNothing(t *testing.T) {
	client := &fakeClient{}
	a, _ := newTestAgent(t, client, &[]collect.Package{})
	a.Collect = func(context.Context) (*collect.Inventory, error) {
		return nil, errors.New("dpkg status: permission denied")
	}
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.inventories) != 0 {
		t.Fatal("a failed collection must not send an inventory")
	}
}

func TestRevokedTokenStopsTheAgent(t *testing.T) {
	client := &fakeClient{heartbeatErr: api.ErrUnauthorized}
	a, _ := newTestAgent(t, client, &[]collect.Package{})
	if err := a.Run(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Run = %v, want ErrRevoked", err)
	}
	if state, _ := LoadState(a.StateDir); state.LastError == "" {
		t.Fatal("the revocation must be visible in the status")
	}
}

func TestRunWaitsTheServerIntervalAndStopsOnCancel(t *testing.T) {
	client := &fakeClient{interval: 600}
	a, _ := newTestAgent(t, client, &[]collect.Package{})
	ctx, cancel := context.WithCancel(context.Background())
	var waits []time.Duration
	a.Wait = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		if len(waits) == 2 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	if err := a.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want nil on cancel", err)
	}
	for _, d := range waits {
		if d < 600*time.Second || d > 660*time.Second {
			t.Fatalf("wait = %v, want the 600s server interval plus at most 10%% jitter", d)
		}
	}
	if client.heartbeats != 2 {
		t.Fatalf("heartbeats = %d, want 2", client.heartbeats)
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
