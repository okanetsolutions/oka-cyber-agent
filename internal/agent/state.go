package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

const stateFileName = "state.json"

type State struct {
	ServerID              string    `json:"server_id,omitempty"`
	LastHeartbeatAt       time.Time `json:"last_heartbeat_at,omitzero"`
	LastInventoryAt       time.Time `json:"last_inventory_at,omitzero"`
	InventoryHash         string    `json:"inventory_hash,omitempty"`
	ReportIntervalSeconds int       `json:"report_interval_seconds,omitempty"`
	LastError             string    `json:"last_error,omitempty"`
	LastErrorAt           time.Time `json:"last_error_at,omitzero"`
}

// LoadState returns the state saved for serverID, or an empty state when the file is missing or belongs to
// another server: after enroll --force the new server must get its first inventory at once and its own
// report interval. The state is only a cache (the worst outcome of losing it is one extra inventory upload),
// so when the file cannot be read or parsed it also returns an empty state, with an error to warn about.
func LoadState(dir, serverID string) (State, error) {
	empty := State{ServerID: serverID}
	path := filepath.Join(dir, stateFileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return empty, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.ServerID != serverID {
		return empty, nil
	}
	return s, nil
}

// SaveState writes the state with mode 0600. When root saves it (sudo run --once), the file is given to the
// owner of the state directory, so the unprivileged service can still read and replace it.
func SaveState(dir string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, stateFileName)
	if err := config.WriteFileAtomic(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if geteuid() != 0 {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	uid, gid, ok := fileOwner(info)
	if !ok || uid == 0 {
		return nil
	}
	if err := chown(path, uid, gid); err != nil {
		return fmt.Errorf("give state to the owner of %s: %w", dir, err)
	}
	return nil
}

var (
	geteuid = os.Geteuid
	chown   = os.Chown
)
