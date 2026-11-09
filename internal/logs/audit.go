package logs

import (
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	auditKey         = "oka_cyber_commands"
	maxAuditPending  = 1024
	maxAuditSessions = 4096
)

// AuditSession is a proven SSH login, keyed by boot ID and kernel audit session ID. No command arguments
// or raw records are retained in a checkpoint, including while a multi-record event is incomplete.
type AuditSession struct {
	AUID string `json:"auid"`
	User string `json:"user"`
}

type auditCommand struct {
	order                uint64
	at                   time.Time
	before               string
	fields               map[string]string
	syscall, execve, cwd bool
}

type auditParser struct {
	order            uint64
	boot             string
	sessions         map[string]AuditSession
	pending          map[string]*auditCommand
	own              map[string]bool
	self, executable string
	cursor           string
}

func newAuditParser(sessions map[string]AuditSession, cursor string) *auditParser {
	exe, _ := os.Executable()
	return &auditParser{sessions: maps.Clone(sessions), pending: map[string]*auditCommand{},
		own: map[string]bool{}, self: strconv.Itoa(os.Getpid()), executable: exe, cursor: cursor}
}

// auditFields extracts only metadata. In particular a0, a1, aN_len, aN[part] and proctitle are never
// decoded or retained, even when EXECVE arguments span multiple records or contain field-like text.
func auditFields(text string) (map[string]string, bool) {
	out := map[string]string{}
	for len(text) > 0 {
		text = strings.TrimLeft(text, " \t")
		if text == "" {
			break
		}
		eq := strings.IndexByte(text, '=')
		blank := strings.IndexAny(text, " \t")
		if eq < 0 || blank >= 0 && blank < eq {
			return nil, false
		}
		key := text[:eq]
		text = text[eq+1:]
		value := ""
		quoted := false
		if len(text) > 0 && (text[0] == '"' || text[0] == '\'') {
			quoted = text[0] == '"'
			end := strings.IndexByte(text[1:], text[0])
			if end < 0 {
				return nil, false
			}
			value, text = text[1:end+1], text[end+2:]
			if text != "" && text[0] != ' ' && text[0] != '\t' {
				return nil, false
			}
		} else {
			end := strings.IndexAny(text, " \t")
			if end < 0 {
				value, text = text, ""
			} else {
				value, text = text[:end], text[end:]
			}
		}
		switch key {
		case "msg":
			nested, ok := auditFields(value)
			if !ok {
				return nil, false
			}
			for k, v := range nested {
				if _, exists := out[k]; exists {
					return nil, false
				}
				out[k] = v
			}
		case "argc", "auid", "ses", "tty", "pid", "ppid", "success", "key", "exe", "cwd", "terminal", "res", "acct":
			if _, exists := out[key]; exists {
				return nil, false
			}
			if !quoted && (key == "exe" || key == "cwd" || key == "acct") {
				decoded, err := hex.DecodeString(value)
				if err != nil {
					return nil, false
				}
				value = string(decoded)
			}
			if len(value) > 4096 {
				return nil, false
			}
			out[key] = value
		}
	}
	return out, true
}

func auditNumber(value string) bool {
	n, err := strconv.ParseUint(value, 10, 32)
	return err == nil && n != 4294967295
}

func auditSessionKey(e JournalEntry, ses string) string { return e.BootID + ":" + ses }

func (p *auditParser) add(e JournalEntry) (Event, bool) {
	p.order++
	previous := p.cursor
	p.cursor = e.Cursor
	for id, pending := range p.pending {
		if e.At.Sub(pending.at) > 5*time.Second {
			delete(p.pending, id)
		}
	}
	if e.Transport != "audit" || e.AuditID == "" || e.BootID == "" {
		return Event{}, false
	}
	if p.boot != e.BootID {
		for key := range p.sessions {
			if !strings.HasPrefix(key, e.BootID+":") {
				delete(p.sessions, key)
			}
		}
		clear(p.pending)
		clear(p.own)
		p.boot = e.BootID
	}
	kind, text, ok := strings.Cut(e.Message, " ")
	if !ok {
		return Event{}, false
	}
	switch kind {
	case "USER_LOGIN", "USER_START", "USER_END", "SYSCALL", "EXECVE", "CWD", "EOE":
	default:
		return Event{}, false
	}
	if kind == "EOE" {
		delete(p.pending, e.BootID+":"+e.AuditID)
		return Event{}, false
	}
	text = strings.TrimPrefix(text, "user ")
	f, ok := auditFields(text)
	if !ok {
		return Event{}, false
	}
	if kind == "USER_LOGIN" || kind == "USER_START" || kind == "USER_END" {
		if !auditNumber(f["ses"]) || !auditNumber(f["auid"]) {
			return Event{}, false
		}
		key := auditSessionKey(e, f["ses"])
		if kind == "USER_END" {
			if TrustedAuthEntry(JournalEntry{Identifier: "sshd", UID: "0", Exe: f["exe"]}) {
				delete(p.sessions, key)
			}
			return Event{}, false
		}
		// Userspace audit records require CAP_AUDIT_WRITE, which some non-root programs have;
		// the kernel-supplied UID must also prove a root SSH logger before trusting its claimed exe.
		if e.UID != "0" {
			return Event{}, false
		}
		exe := JournalEntry{Identifier: "sshd", UID: e.UID, Exe: f["exe"]}
		if f["res"] != "success" || !TrustedAuthEntry(exe) || f["terminal"] == "" || f["terminal"] == "cron" {
			return Event{}, false
		}
		uid, _ := strconv.ParseUint(f["auid"], 10, 32)
		if uid != 0 && uid < 1000 {
			return Event{}, false
		}
		if p.sessions == nil {
			p.sessions = map[string]AuditSession{}
		}
		if len(p.sessions) >= maxAuditSessions {
			return Event{}, false
		}
		user := f["acct"]
		if user == "" {
			user = f["auid"]
			if known, ok := p.sessions[key]; ok && known.AUID == f["auid"] {
				user = known.User
			}
		}
		p.sessions[key] = AuditSession{AUID: f["auid"], User: cut(redactEverywhere(user), maxNameLength)}
		return Event{}, false
	}
	id := e.BootID + ":" + e.AuditID
	pending := p.pending[id]
	if pending == nil {
		if len(p.pending) >= maxAuditPending {
			return Event{}, false
		}
		pending = &auditCommand{order: p.order, at: e.At, before: previous, fields: map[string]string{}}
		p.pending[id] = pending
	}
	switch kind {
	case "SYSCALL":
		if pending.syscall {
			delete(p.pending, id)
			return Event{}, false
		}
		pending.syscall = true
		for _, k := range []string{"auid", "ses", "tty", "pid", "ppid", "success", "key", "exe"} {
			pending.fields[k] = f[k]
		}
	case "EXECVE":
		if argc, exists := f["argc"]; exists {
			if pending.execve && pending.fields["argc"] != argc {
				delete(p.pending, id)
				return Event{}, false
			}
			pending.execve, pending.fields["argc"] = true, argc
		}
	case "CWD":
		if pending.cwd {
			delete(p.pending, id)
			return Event{}, false
		}
		pending.cwd, pending.fields["cwd"] = true, f["cwd"]
	}
	if !pending.syscall || !pending.execve || !pending.cwd {
		return Event{}, false
	}
	delete(p.pending, id)
	f = pending.fields
	if f["pid"] == p.self || f["ppid"] == p.self || p.own[f["ppid"]] || f["exe"] == p.executable ||
		f["exe"] == "/usr/bin/oka-cyber-agent" || f["exe"] == "/usr/local/bin/oka-cyber-agent" {
		if len(p.own) < maxAuditSessions {
			p.own[f["pid"]] = true
		}
		return Event{}, false
	}
	session, exists := p.sessions[auditSessionKey(e, f["ses"])]
	if !exists || session.AUID != f["auid"] || f["success"] != "yes" || f["key"] != auditKey ||
		!interactiveTTY(f["tty"]) || !strings.HasPrefix(f["exe"], "/") || !strings.HasPrefix(f["cwd"], "/") {
		return Event{}, false
	}
	argc, err := strconv.Atoi(f["argc"])
	if err != nil || argc < 1 || argc > 1000000 {
		return Event{}, false
	}
	event := newEvent(SourceCommands, KindCommand, pending.at, fmt.Sprintf("%s [%d args]", f["exe"], argc-1))
	event.Username = session.User
	event.Fields = map[string]any{"ses": f["ses"], "auid": f["auid"], "cwd": f["cwd"], "executable": f["exe"], "arg_count": argc - 1, "tty": f["tty"]}
	return event, true
}

func interactiveTTY(tty string) bool {
	// Audit renders a pseudoterminal as pts0, not pts/0; accepting both also handles distribution variants.
	tty = strings.TrimPrefix(tty, "/dev/")
	if !strings.HasPrefix(tty, "pts") {
		return false
	}
	tty = strings.TrimPrefix(tty, "pts")
	tty = strings.TrimPrefix(tty, "/")
	_, err := strconv.ParseUint(tty, 10, 32)
	return err == nil
}

func (p *auditParser) checkpoint() string {
	// Never acknowledge beyond an incomplete event. Replaying after a crash may duplicate an event,
	// but cannot skip the SYSCALL/EXECVE records needed to reconstruct one.
	cursor := p.cursor
	var earliest uint64
	for _, pending := range p.pending {
		if earliest == 0 || pending.order < earliest {
			earliest, cursor = pending.order, pending.before
		}
	}
	return cursor
}
