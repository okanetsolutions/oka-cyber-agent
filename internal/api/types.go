package api

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Secret is a string that never prints: fmt verbs and loggers see [redacted], JSON encoding sees the value.
type Secret string

func (Secret) String() string   { return "[redacted]" }
func (Secret) GoString() string { return "[redacted]" }

type EnrollRequest struct {
	EnrollmentToken Secret `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	OSFamily        string `json:"os_family,omitempty"`
	OSName          string `json:"os_name,omitempty"`
	OSVersion       string `json:"os_version,omitempty"`
	Kernel          string `json:"kernel,omitempty"`
	Architecture    string `json:"architecture,omitempty"`
	AgentVersion    string `json:"agent_version"`
}

type EnrollResponse struct {
	ServerID              ID     `json:"server_id"`
	AgentToken            Secret `json:"agent_token"`
	ReportIntervalSeconds int    `json:"report_interval_seconds"`
}

type HeartbeatRequest struct {
	AgentVersion string `json:"agent_version"`
}

type HeartbeatResponse struct {
	ReportIntervalSeconds int `json:"report_interval_seconds"`
}

type InventoryResponse struct {
	Changed               bool `json:"changed"`
	ReportIntervalSeconds int  `json:"report_interval_seconds"`
}

// ID accepts the server id as a JSON number or string.
type ID string

func (id *ID) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*id = ID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("server_id: %w", err)
	}
	*id = ID(n.String())
	return nil
}
