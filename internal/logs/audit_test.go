package logs

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func auditEntry(id, kind, fields string) JournalEntry {
	return JournalEntry{UID: "0", Transport: "audit", BootID: "boot1", AuditID: id, Cursor: "cursor-" + id + "-" + kind,
		At: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC), Message: kind + " " + fields}
}

func loginAudit(p *auditParser) {
	p.add(auditEntry("1", "USER_LOGIN", `pid=300 uid=0 auid=1000 ses=7 msg='op=login acct="alice" exe="/usr/sbin/sshd" terminal=/dev/pts/1 res=success'`))
}

func commandAudit(p *auditParser, id, syscall string, args ...string) []Event {
	records := []JournalEntry{
		auditEntry(id, "SYSCALL", syscall),
		auditEntry(id, "EXECVE", `argc=3 a0="curl" a1="--password" a2=5375706572536563726574`),
		auditEntry(id, "CWD", `cwd="/home/alice"`),
	}
	if len(args) > 0 {
		records[1].Message = "EXECVE " + args[0]
	}
	var out []Event
	for _, e := range records {
		if event, ok := p.add(e); ok {
			out = append(out, event)
		}
	}
	return out
}

const commandSyscall = `arch=c000003e syscall=59 success=yes exit=0 ppid=401 pid=402 auid=1000 ses=7 tty=pts1 exe="/usr/bin/curl" key="oka_cyber_commands"`

func TestAuditCommandDropsAllArgumentFormsBeforeSpool(t *testing.T) {
	for _, args := range []string{
		`argc=3 a0="curl" a1="--password" a2="SuperSecret"`,
		`argc=3 a0="curl" a1="--password" a2=5375706572536563726574`,
		`argc=3 a0="curl" a1_len=10 a1[0]="Super" a1[1]="Secret" a2="--token=AnotherSecret"`,
		`argc=3 a0="curl" a1=" ses=900 auid=0 cwd=/SecretPath " a2="--token=AnotherSecret"`,
	} {
		p := newAuditParser(nil, "")
		loginAudit(p)
		events := commandAudit(p, "2", commandSyscall, args)
		if len(events) != 1 {
			t.Fatalf("events = %+v for %s", events, args)
		}
		e := Redact(events[0])
		want := map[string]any{"ses": "7", "auid": "1000", "cwd": "/home/alice", "executable": "/usr/bin/curl", "arg_count": 2, "tty": "pts1"}
		if e.Source != SourceCommands || e.Kind != KindCommand || e.Username != "alice" || !reflect.DeepEqual(e.Fields, want) {
			t.Fatalf("event = %+v", e)
		}
		spool := Spool{Dir: filepath.Join(t.TempDir(), "spool")}
		if err := spool.Append(Batch{ID: NewBatchID(), Events: []Event{e}, Checkpoint: Checkpoint{AuditSessions: p.sessions}, CreatedAt: e.FirstAt}); err != nil {
			t.Fatal(err)
		}
		b, _, ok, err := spool.Oldest()
		if !ok || err != nil {
			t.Fatalf("spool = %v %v", ok, err)
		}
		encoded, _ := json.Marshal(b)
		for _, secret := range []string{"SuperSecret", "5375706572536563726574", "AnotherSecret", "--password", "--token", "SecretPath", "a1[0]"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("argument text reached event or spool: %s", secret)
			}
		}
	}
}

func TestAuditCommandRequiresSSHInteractiveLogin(t *testing.T) {
	for _, tc := range []struct {
		name, login, syscall string
		own                  bool
	}{
		{name: "no login", syscall: commandSyscall},
		{name: "cron", login: `auid=1000 ses=7 msg='exe="/usr/sbin/crond" terminal=cron res=success'`, syscall: commandSyscall},
		{name: "service", login: `auid=1000 ses=7 msg='exe="/usr/lib/systemd/systemd" terminal=? res=success'`, syscall: commandSyscall},
		{name: "unset auid", login: `auid=4294967295 ses=7 msg='exe="/usr/sbin/sshd" terminal=ssh res=success'`, syscall: strings.Replace(commandSyscall, "auid=1000", "auid=4294967295", 1)},
		{name: "system uid", login: `auid=999 ses=7 msg='exe="/usr/sbin/sshd" terminal=ssh res=success'`, syscall: strings.Replace(commandSyscall, "auid=1000", "auid=999", 1)},
		{name: "no tty", syscall: strings.Replace(commandSyscall, "tty=pts1", "tty=(none)", 1), own: true},
		{name: "wrong session", syscall: strings.Replace(commandSyscall, "ses=7", "ses=8", 1), own: true},
		{name: "failed exec", syscall: strings.Replace(commandSyscall, "success=yes", "success=no", 1), own: true},
		{name: "unrelated rule", syscall: strings.Replace(commandSyscall, auditKey, "other", 1), own: true},
		{name: "agent child", syscall: strings.Replace(commandSyscall, "ppid=401", "ppid="+strconv.Itoa(os.Getpid()), 1), own: true},
		{name: "agent executable", syscall: strings.Replace(commandSyscall, "/usr/bin/curl", "/usr/bin/oka-cyber-agent", 1), own: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newAuditParser(nil, "")
			if tc.own {
				loginAudit(p)
			}
			if tc.login != "" {
				p.add(auditEntry("1", "USER_LOGIN", tc.login))
			}
			if events := commandAudit(p, "2", tc.syscall); len(events) != 0 {
				t.Fatalf("out of scope event = %+v", events)
			}
		})
	}
	p := newAuditParser(nil, "")
	loginAudit(p)
	p.add(auditEntry("3", "USER_END", `auid=1000 ses=7 msg='exe="/usr/sbin/sshd" terminal=ssh res=success'`))
	if len(commandAudit(p, "4", commandSyscall)) != 0 {
		t.Fatal("command after logout")
	}
	p = newAuditParser(nil, "")
	loginAudit(p)
	forged := auditEntry("1", "USER_LOGIN", `auid=0 ses=8 msg='exe="/usr/sbin/sshd" terminal=ssh res=success'`)
	forged.Transport = "syslog"
	p.add(forged)
	if len(p.sessions) != 1 {
		t.Fatal("forged audit transport trusted")
	}
	root := newAuditParser(nil, "")
	root.add(auditEntry("1", "USER_LOGIN", `auid=0 ses=7 msg='exe="/usr/sbin/sshd" terminal=ssh res=success'`))
	if len(commandAudit(root, "2", strings.Replace(commandSyscall, "auid=1000", "auid=0", 1))) != 1 {
		t.Fatal("root SSH login excluded")
	}
}

func TestRealAuditRecords(t *testing.T) {
	b, err := os.ReadFile("testdata/audit/linux-audit-exec.log")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "type=EXECVE ") {
			continue
		}
		_, text, _ := strings.Cut(line, "): ")
		f, ok := auditFields(text)
		if !ok || len(f) != 1 || f["argc"] == "" {
			t.Fatalf("EXECVE metadata = %+v, %v", f, ok)
		}
		seen++
	}
	if seen < 2 {
		t.Fatal("missing multi-record exec fixtures")
	}
	b, err = os.ReadFile("testdata/audit/rhel7-hex.log")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		_, text, _ := strings.Cut(line, "): ")
		f, ok := auditFields(text)
		if !ok || len(f) != 1 || f["argc"] == "" {
			t.Fatalf("hex EXECVE = %+v, %v", f, ok)
		}
	}
	b, err = os.ReadFile("testdata/audit/ubuntu16-login.log")
	if err != nil {
		t.Fatal(err)
	}
	p := newAuditParser(nil, "")
	for i, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !strings.HasPrefix(line, "type=USER_LOGIN ") {
			continue
		}
		_, text, _ := strings.Cut(line, "): ")
		p.add(auditEntry(fmt.Sprint(i), "USER_LOGIN", text))
	}
	if len(p.sessions) != 1 || p.sessions["boot1:36"].AUID != "1001" {
		t.Fatalf("real SSH session = %+v", p.sessions)
	}
	// Hex decoding is reserved for safe metadata, never argument fields.
	f, ok := auditFields(`cwd=` + hex.EncodeToString([]byte("/home/a user")))
	if !ok || f["cwd"] != "/home/a user" {
		t.Fatal("hex cwd not decoded")
	}
}

func TestAuditCheckpointWaitsForCompleteRecord(t *testing.T) {
	p := newAuditParser(nil, "")
	loginAudit(p)
	loginCursor := p.cursor
	p.add(auditEntry("2", "SYSCALL", commandSyscall))
	if p.checkpoint() != loginCursor {
		t.Fatal("checkpoint passed incomplete syscall")
	}
	p.add(auditEntry("2", "CWD", `cwd="/home/alice"`))
	if p.checkpoint() != loginCursor {
		t.Fatal("checkpoint passed incomplete exec")
	}
	e, ok := p.add(auditEntry("2", "EXECVE", `argc=2 a0="curl" a1="Secret"`))
	if !ok || e.Fields["arg_count"] != 1 || p.checkpoint() != p.cursor {
		t.Fatalf("complete event = %+v %v", e, ok)
	}
	resumed := newAuditParser(p.sessions, p.checkpoint())
	if len(commandAudit(resumed, "4", commandSyscall)) != 1 {
		t.Fatal("active SSH session lost on restart")
	}
}

func TestAuditInterleavedAndSplitRecords(t *testing.T) {
	p := newAuditParser(nil, "")
	loginAudit(p)
	before := p.cursor
	p.add(auditEntry("2", "SYSCALL", commandSyscall))
	p.add(auditEntry("3", "SYSCALL", commandSyscall))
	p.add(auditEntry("2", "EXECVE", `argc=2 a0="curl" a1_len=10 a1[0]="Super"`))
	p.add(auditEntry("2", "EXECVE", `a1[1]="Secret"`))
	p.add(auditEntry("3", "EXECVE", `argc=1 a0="curl"`))
	if p.checkpoint() != before {
		t.Fatal("checkpoint did not stay before first incomplete event")
	}
	e, ok := p.add(auditEntry("3", "CWD", `cwd="/"`))
	if !ok || e.Fields["arg_count"] != 0 {
		t.Fatal("interleaved exec lost")
	}
	if p.checkpoint() != before {
		t.Fatal("second event let checkpoint pass first")
	}
	e, ok = p.add(auditEntry("2", "CWD", `cwd="/"`))
	if !ok || e.Fields["arg_count"] != 1 || strings.Contains(e.Message, "Secret") {
		t.Fatal("split arguments retained or count lost")
	}
}

func TestAuditSSHSessionRetainsPAMUsername(t *testing.T) {
	b, err := os.ReadFile("testdata/audit/centos7-session.log")
	if err != nil {
		t.Fatal(err)
	}
	_, text, _ := strings.Cut(strings.TrimSpace(string(b)), "): ")
	p := newAuditParser(nil, "")
	p.add(auditEntry("1", "USER_START", text))
	if p.sessions["boot1:3"].User != "vagrant" {
		t.Fatalf("PAM session=%+v", p.sessions)
	}
	p.add(auditEntry("2", "USER_LOGIN", `auid=1000 ses=3 msg='id=1000 exe="/usr/sbin/sshd" terminal=/dev/pts/1 res=success'`))
	if p.sessions["boot1:3"].User != "vagrant" {
		t.Fatal("USER_LOGIN discarded the PAM user name")
	}
}

func TestAuditLoginRejectsNonRootAuditWriter(t *testing.T) {
	p := newAuditParser(nil, "")
	forged := auditEntry("1", "USER_LOGIN", `auid=1000 ses=7 msg='acct="alice" exe="/usr/sbin/sshd" terminal=ssh res=success'`)
	forged.UID = "1000"
	p.add(forged)
	if len(p.sessions) != 0 || len(commandAudit(p, "2", commandSyscall)) != 0 {
		t.Fatal("non-root audit writer forged an SSH login")
	}
}
