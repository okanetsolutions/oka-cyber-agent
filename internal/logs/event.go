package logs

import "time"

const (
	SourceAuth = "auth"
	SourceWeb  = "web"
	SourceApp  = "app"
)

// Event kinds and the fields they carry, as defined by the Oka Core log ingestion API
// (okanetsolutions/oka-core#3779).
const (
	KindSSHLoginFailed    = "ssh_login_failed"
	KindSSHLoginSucceeded = "ssh_login_succeeded"
	KindSudoCommand       = "sudo_command"
	KindSudoFailed        = "sudo_failed"
	KindSuSession         = "su_session"
	KindUserCreated       = "user_created"
	KindUserGroupChanged  = "user_group_changed"
	KindPasswordChanged   = "password_changed"
	KindCronModified      = "cron_modified"
	KindHTTPRequest       = "http_request"
	KindHTTPTraffic       = "http_traffic"
	KindAppError          = "app_error"
	KindLogFileRemoved    = "log_file_removed"
)

type Event struct {
	Source   string         `json:"source"`
	Kind     string         `json:"kind"`
	FirstAt  time.Time      `json:"first_at"`
	LastAt   time.Time      `json:"last_at"`
	Count    int            `json:"count"`
	Program  string         `json:"program,omitempty"`
	SrcIP    string         `json:"src_ip,omitempty"`
	Username string         `json:"username,omitempty"`
	Message  string         `json:"message"`
	Fields   map[string]any `json:"fields,omitempty"`
}

func newEvent(source, kind string, at time.Time, message string) Event {
	return Event{Source: source, Kind: kind, FirstAt: at, LastAt: at, Count: 1, Message: message}
}

func (e *Event) set(key string, value any) {
	if e.Fields == nil {
		e.Fields = map[string]any{}
	}
	e.Fields[key] = value
}

// RemovedEvent reports a watched log file that disappeared and was not recreated.
func RemovedEvent(source, path string, at time.Time) Event {
	e := newEvent(source, KindLogFileRemoved, at, "log file removed: "+path)
	e.set("path", path)
	return e
}
