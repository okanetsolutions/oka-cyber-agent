package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

// FullInventoryEvery is how often the inventory is sent even when it did not change.
const FullInventoryEvery = 24 * time.Hour

var ErrRevoked = errors.New("the server rejected the agent token: this server was revoked in the dashboard or the token is invalid")

type Client interface {
	Heartbeat(ctx context.Context, req api.HeartbeatRequest) (api.HeartbeatResponse, error)
	PutInventory(ctx context.Context, snapshot json.RawMessage) (api.InventoryResponse, error)
}

type Agent struct {
	Config   config.Config
	StateDir string
	Client   Client
	Collect  func(ctx context.Context) (*collect.Inventory, error)
	Logger   *slog.Logger
	Now      func() time.Time
	Wait     func(ctx context.Context, d time.Duration) error

	state  State
	loaded bool
}

// Run reports until the context is cancelled or the server revokes the agent.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.init(); err != nil {
		return err
	}
	for {
		err := a.Cycle(ctx)
		if errors.Is(err, ErrRevoked) {
			return err
		}
		if err != nil {
			a.Logger.Error("report failed, retrying at the next interval", "error", err)
		}
		if err := a.Wait(ctx, a.nextDelay()); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}
}

// Cycle sends a heartbeat, then the inventory when it changed or is due. A failure is kept in the state for
// the status command and returned; ErrRevoked means the server revoked the agent token.
func (a *Agent) Cycle(ctx context.Context) error {
	if err := a.init(); err != nil {
		return err
	}
	err := a.heartbeat(ctx)
	if err == nil {
		err = a.inventory(ctx)
	}
	switch {
	case errors.Is(err, api.ErrUnauthorized):
		a.recordError(ErrRevoked)
		a.save()
		return ErrRevoked
	case err != nil && ctx.Err() != nil:
		return nil
	case err != nil:
		a.recordError(err)
	default:
		a.state.LastError = ""
		a.state.LastErrorAt = time.Time{}
	}
	a.save()
	return err
}

func (a *Agent) init() error {
	if a.Logger == nil {
		a.Logger = slog.Default()
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.Wait == nil {
		a.Wait = sleep
	}
	if !a.loaded {
		s, err := LoadState(a.StateDir, a.Config.ServerID)
		if err != nil {
			return err
		}
		a.state = s
		a.loaded = true
	}
	return nil
}

func (a *Agent) heartbeat(ctx context.Context) error {
	resp, err := a.Client.Heartbeat(ctx, api.HeartbeatRequest{AgentVersion: Version})
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	a.state.LastHeartbeatAt = a.Now().UTC()
	a.setInterval(resp.ReportIntervalSeconds)
	return nil
}

func (a *Agent) inventory(ctx context.Context) error {
	inv, err := a.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect inventory: %w", err)
	}
	snapshot, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(snapshot)
	hash := hex.EncodeToString(sum[:])
	now := a.Now().UTC()
	if hash == a.state.InventoryHash && now.Sub(a.state.LastInventoryAt) < FullInventoryEvery {
		return nil
	}
	resp, err := a.Client.PutInventory(ctx, snapshot)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	a.Logger.Info("inventory sent", "packages", len(inv.Packages), "services", len(inv.Services), "changed", resp.Changed)
	a.state.InventoryHash = hash
	a.state.LastInventoryAt = now
	a.setInterval(resp.ReportIntervalSeconds)
	return nil
}

func (a *Agent) setInterval(seconds int) {
	if seconds > 0 {
		a.state.ReportIntervalSeconds = min(max(seconds, config.MinReportIntervalSeconds), config.MaxReportIntervalSeconds)
	}
}

func (a *Agent) interval() time.Duration {
	seconds := a.state.ReportIntervalSeconds
	if seconds == 0 {
		seconds = a.Config.ReportIntervalSeconds
	}
	if seconds == 0 {
		seconds = config.DefaultReportIntervalSeconds
	}
	return time.Duration(seconds) * time.Second
}

// nextDelay adds up to 10% jitter so servers enrolled together do not report in lockstep.
func (a *Agent) nextDelay() time.Duration {
	interval := a.interval()
	return interval + time.Duration(rand.Int64N(int64(interval/10)+1))
}

func (a *Agent) recordError(err error) {
	a.state.LastError = err.Error()
	a.state.LastErrorAt = a.Now().UTC()
}

func (a *Agent) save() {
	if err := SaveState(a.StateDir, a.state); err != nil {
		a.Logger.Error("save state failed", "error", err)
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
