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
	LastHeartbeatAt       time.Time `json:"last_heartbeat_at,omitzero"`
	LastInventoryAt       time.Time `json:"last_inventory_at,omitzero"`
	InventoryHash         string    `json:"inventory_hash,omitempty"`
	ReportIntervalSeconds int       `json:"report_interval_seconds,omitempty"`
	LastError             string    `json:"last_error,omitempty"`
	LastErrorAt           time.Time `json:"last_error_at,omitzero"`
}

// LoadState returns an empty state when the file is missing or unreadable JSON: the worst outcome is one
// extra inventory upload.
func LoadState(dir string) (State, error) {
	var s State
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("read state: %w", err)
	}
	if json.Unmarshal(data, &s) != nil {
		return State{}, nil
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
