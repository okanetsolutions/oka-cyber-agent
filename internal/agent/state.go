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

// LoadState returns the state saved for serverID. It returns an empty state when the file is missing, is
// unreadable JSON (the worst outcome is one extra inventory upload) or belongs to another server: after
// enroll --force the new server must get its first inventory at once and its own report interval.
func LoadState(dir, serverID string) (State, error) {
	empty := State{ServerID: serverID}
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, fmt.Errorf("read state: %w", err)
	}
	var s State
	if json.Unmarshal(data, &s) != nil || s.ServerID != serverID {
		return empty, nil
	}
	return s, nil
}

func SaveState(dir string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(filepath.Join(dir, stateFileName), append(data, '\n'), 0o600)
}
