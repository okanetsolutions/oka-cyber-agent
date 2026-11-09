package logs

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/auditcontrol"
)

func commandHost(t *testing.T, status string) Options {
	t.Helper()
	o := Options{Root: t.TempDir(), HasJournalctl: func() bool { return true }}
	for _, p := range []string{"/usr/lib/systemd/system/" + auditcontrol.Service, "/usr/lib/systemd/system/" + auditcontrol.PathUnit,
		"/var/log/journal/machine/system.journal", auditcontrol.StatusPath, auditcontrol.FlagPath} {
		if err := os.MkdirAll(filepath.Dir(o.path(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if p == auditcontrol.FlagPath {
			continue
		}
		text := ""
		if p == auditcontrol.StatusPath {
			text = status + "\n"
		}
		if err := os.WriteFile(o.path(p), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func auditJSON(e JournalEntry) string {
	b, _ := json.Marshal(map[string]string{"__CURSOR": e.Cursor, "__REALTIME_TIMESTAMP": strconv.FormatInt(e.At.UnixMicro(), 10),
		"_UID": e.UID, "_TRANSPORT": e.Transport, "_BOOT_ID": e.BootID, "_AUDIT_ID": e.AuditID, "MESSAGE": e.Message})
	return string(b) + "\n"
}

func TestCommandCollectorOptInAndJournalTrust(t *testing.T) {
	o := commandHost(t, "on")
	var args []string
	r, w := io.Pipe()
	start := func(ctx context.Context, name string, a ...string) (io.ReadCloser, func() error, error) {
		if name != "journalctl" {
			t.Errorf("unexpected command %s", name)
		}
		args = append([]string{}, a...)
		go func() { <-ctx.Done(); w.Close() }()
		return r, func() error { return nil }, nil
	}
	c := NewCollector([]string{SourceCommands}, o, Checkpoint{}, start, time.Now)
	t.Cleanup(c.Close)
	c.Poll(context.Background())
	if _, err := os.Stat(o.path(auditcontrol.FlagPath)); err != nil {
		t.Fatal("commands did not request the fixed rule")
	}
	login := auditEntry("1", "USER_LOGIN", `auid=1000 ses=7 msg='acct="alice" exe="/usr/sbin/sshd" terminal=/dev/pts/1 res=success'`)
	records := []JournalEntry{login, auditEntry("2", "SYSCALL", commandSyscall), auditEntry("2", "EXECVE", `argc=2 a0="curl" a1=536563726574`), auditEntry("2", "CWD", `cwd="/home/alice"`)}
	// A fake identifier is not a kernel audit transport and cannot create a login.
	fake := login
	fake.Transport = "syslog"
	fake.Message = strings.ReplaceAll(fake.Message, "ses=7", "ses=8")
	records = append(records, fake)
	for _, e := range records {
		if _, err := io.WriteString(w, auditJSON(e)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for len(c.auditCh) < len(records) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	events := c.Poll(context.Background())
	if len(events) != 1 || events[0].Kind != KindCommand || len(c.audit.sessions) != 1 {
		t.Fatalf("events=%+v sessions=%+v", events, c.audit.sessions)
	}
	if !strings.Contains(strings.Join(args, " "), "_TRANSPORT=audit") || !strings.Contains(strings.Join(args, " "), "--lines=0") {
		t.Fatalf("journal args=%q", args)
	}
	cp := c.Checkpoint()
	if cp.AuditCursor == "" || len(cp.AuditSessions) != 1 {
		t.Fatalf("checkpoint=%+v", cp)
	}
	c.Close()
	if _, err := os.Stat(o.path(auditcontrol.FlagPath)); !os.IsNotExist(err) {
		t.Fatal("rule flag survived disabling commands")
	}
}

func TestCommandsSkippedWhenUnavailableAndOffByDefault(t *testing.T) {
	for _, tc := range []struct {
		name, status, want string
		missing            bool
	}{
		{name: "auditd missing", status: "auditd_missing", want: "auditd_missing"},
		{name: "helper missing", status: "on", missing: true, want: "helper_missing"},
		{name: "immutable rules", status: "rule_apply_failed", want: "rule_apply_failed"},
		{name: "waiting for helper", status: "off", want: "helper_pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := commandHost(t, tc.status)
			if tc.missing {
				_ = os.Remove(o.path("/usr/lib/systemd/system/" + auditcontrol.Service))
			}
			c := NewCollector(nil, o, Checkpoint{}, nil, time.Now)
			c.Poll(context.Background())
			c.Close()
			if _, err := os.Stat(o.path(auditcontrol.FlagPath)); !os.IsNotExist(err) {
				t.Fatal("disabled source wrote flag")
			}
			start := func(ctx context.Context, _ string, _ ...string) (io.ReadCloser, func() error, error) {
				r, w := io.Pipe()
				go func() { <-ctx.Done(); w.Close() }()
				return r, func() error { return nil }, nil
			}
			c = NewCollector([]string{SourceCommands}, o, Checkpoint{}, start, time.Now)
			defer c.Close()
			c.Poll(context.Background())
			skipped := c.Skipped()
			if len(skipped) != 1 || skipped[0].Source != SourceCommands || skipped[0].Reason != tc.want {
				t.Fatalf("skipped=%+v", skipped)
			}

		})
	}
}

func TestCommandAggregationAndPerMinuteBudget(t *testing.T) {
	p := newAuditParser(nil, "")
	loginAudit(p)
	e := commandAudit(p, "2", commandSyscall)[0]
	a := NewAggregator()
	for range 10000 {
		a.Add(e)
	}
	out := a.Flush()
	if len(out) != 1 || out[0].Count != 10000 {
		t.Fatalf("loop emitted %d groups", len(out))
	}
	// The budget survives flushes, bounding distinct commands as well as a repeated loop.
	for i := range 100 {
		v := e
		v.Fields = map[string]any{"ses": "7", "auid": "1000", "executable": "/bin/cmd" + strconv.Itoa(i), "arg_count": 0}
		a.Add(v)
	}
	if a.Pending() != 59 || a.TakeDropped() != 41 {
		t.Fatalf("pending=%d, budget did not survive flush", a.Pending())
	}
	a.Flush()
	e.FirstAt = e.FirstAt.Add(time.Minute)
	e.LastAt = e.FirstAt
	a.Add(e)
	if a.Pending() != 1 {
		t.Fatal("new minute did not reset budget")
	}
}

func TestAuditJournalUsesNativeTransportAndEventTime(t *testing.T) {
	entry, err := ParseJournalEntry([]byte(`{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1794225601000000","_SOURCE_REALTIME_TIMESTAMP":"1794225600123000","_TRANSPORT":"audit","_AUDIT_ID":"32","_BOOT_ID":"boot1","MESSAGE":"CWD cwd=\"/home/alice\""}`))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Transport != "audit" || entry.AuditID != "32" || entry.BootID != "boot1" || entry.At.UnixMicro() != 1794225600123000 {
		t.Fatalf("entry=%+v", entry)
	}
}
