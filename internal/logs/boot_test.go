package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const otherBootID = "0123456789abcdef0123456789abcdef"

func setHostBoot(h hostTree, id string, started time.Time) {
	h.write("/proc/sys/kernel/random/boot_id", id+"\n")
	h.write("/proc/stat", fmt.Sprintf("cpu 1 2 3 4\nbtime %d\nprocesses 12\n", started.Unix()))
}

func TestBootIdentityValidationAndMissingSources(t *testing.T) {
	for _, id := range []string{testBootID, strings.ToUpper(testBootID), "7EE3AB1C-213D-4AA7-B550-DFDCE6E11C4C"} {
		h := newHost(t)
		setHostBoot(h, id, testNow)
		b := h.options(false).bootIdentity()
		if b.id != testBootID || !b.started.Equal(testNow) {
			t.Fatalf("boot = %+v", b)
		}
	}
	for _, id := range []string{"", "null", "boot1", testBootID + "0", "7ee3ab1c213d-4aa7-b550-dfdce6e11c4c", " " + testBootID} {
		e := newEvent(SourceAuth, KindSSHLoginFailed, testNow, "")
		e.setBootID(id)
		if _, present := e.Fields["boot_id"]; present {
			t.Fatalf("invalid identity %q exported: %+v", id, e)
		}
	}
	for _, missing := range []string{"/proc/stat", "/proc/sys/kernel/random/boot_id", "invalid btime", "invalid id"} {
		h := newHost(t)
		setHostBoot(h, testBootID, testNow)
		switch missing {
		case "invalid btime":
			h.write("/proc/stat", "btime invalid\n")
		case "invalid id":
			h.write("/proc/sys/kernel/random/boot_id", "invalid\n")
		default:
			h.write(missing, "")
		}
		if b := h.options(false).bootIdentity(); b.id != "" {
			t.Fatalf("%s: boot = %+v", missing, b)
		}
	}
	if b := newHost(t).options(false).bootIdentity(); b.id != "" {
		t.Fatal("missing proc files invented an ID")
	}
}

var authBootKinds = []string{
	KindSSHLoginFailed, KindSSHLoginSucceeded, KindSSHSessionOpened, KindSSHSessionClosed,
	KindSudoCommand, KindSudoFailed, KindSuSession, KindUserCreated, KindUserGroupChanged,
	KindPasswordChanged, KindCronModified,
}

func assertAuthBootCoverage(t *testing.T, seen map[string]bool) {
	t.Helper()
	for _, kind := range authBootKinds {
		if !seen[kind] {
			t.Errorf("boot ID not tested for %s", kind)
		}
	}
}

func TestSyslogAuthBootIdentityForEveryKind(t *testing.T) {
	now := testNow.AddDate(0, 0, 10)
	seen := map[string]bool{}
	for _, fixture := range []string{"debian-12.auth.log", "debian-12.cron.log", "rocky-9.secure", "rocky-9.cron", "alpine-3.22.sessions.log"} {
		t.Run(fixture, func(t *testing.T) {
			h := newHost(t)
			setHostBoot(h, testBootID, testNow.AddDate(0, 0, -10))
			h.write("/var/log/auth.log", "")
			c := NewCollector([]string{SourceAuth}, h.options(false), Checkpoint{}, nil, func() time.Time { return now })
			defer c.Close()
			c.Poll(context.Background())
			for _, line := range readLines(t, filepath.Join("testdata", "auth", fixture)) {
				h.append("/var/log/auth.log", line+"\n")
			}
			for _, e := range c.Poll(context.Background()) {
				if e.Fields["boot_id"] != testBootID {
					t.Fatalf("missing boot for %+v", e)
				}
				seen[e.Kind] = true
			}
		})
	}
	assertAuthBootCoverage(t, seen)
}

func TestJournalAuthBootIdentityForEveryKind(t *testing.T) {
	seen := map[string]bool{}
	now := testNow
	for _, fixture := range []string{"debian-12.jsonl", "debian-12.sessions.jsonl"} {
		for _, line := range readLines(t, filepath.Join("testdata", "journal", fixture)) {
			entry, err := ParseJournalEntry([]byte(line))
			if err != nil {
				t.Fatal(err)
			}
			c := sessionCollector(&now)
			c.journalPending = []pendingJournalEntry{{entry, now.Add(-logindWait)}}
			for _, e := range c.pollJournal() {
				if want := normalizeBootID(entry.BootID); want == "" || e.Fields["boot_id"] != want {
					t.Fatalf("%s: original boot lost: %+v", fixture, e)
				}
				seen[e.Kind] = true
			}
		}
	}
	assertAuthBootCoverage(t, seen)
}

func TestJournalBootIdentityNeverUsesCurrentBootForBacklog(t *testing.T) {
	var entry JournalEntry
	for _, candidate := range sessionJournalEntries(t) {
		if e, ok := ParseAuth(candidate.Identifier, candidate.Message, candidate.At, candidate.PID); ok && e.Kind == KindSSHSessionClosed {
			entry = candidate
			break
		}
	}
	if entry.Message == "" {
		t.Fatal("fixture lacks a session close")
	}
	now := testNow
	c := sessionCollector(&now)
	c.boot = bootIdentity{otherBootID, now}
	ids := []string{testBootID, otherBootID, testBootID, "", "invalid", strings.ToUpper(testBootID)}
	for i, id := range ids {
		e := entry
		e.BootID, e.Cursor = id, fmt.Sprint(i)
		// Deliberately out of timestamp order, with reused SSH PIDs across boots.
		e.At = now.Add(-time.Duration(i) * time.Minute)
		c.journalCh <- e
	}
	events := c.pollJournal()
	if len(events) != len(ids) || c.Checkpoint().JournalCursor != "5" {
		t.Fatalf("events=%+v checkpoint=%+v", events, c.Checkpoint())
	}
	for i, e := range events {
		want := normalizeBootID(ids[i])
		got, present := e.Fields["boot_id"]
		if want == "" && present || want != "" && got != want {
			t.Fatalf("event %d: boot=%v, present=%v, want %q", i, got, present, want)
		}
	}
}

func TestSyslogBootBoundarySurvivesCheckpointAndReboot(t *testing.T) {
	h := newHost(t)
	setHostBoot(h, testBootID, testNow.Add(-time.Hour))
	h.write("/var/log/auth.log", "")
	newCollector := func(cp Checkpoint) *Collector {
		return NewCollector([]string{SourceAuth}, h.options(false), cp, nil, func() time.Time { return testNow })
	}
	c := newCollector(Checkpoint{})
	c.Poll(context.Background())
	// Save a position before reading a line that will be replayed if the upload fails.
	data, err := json.Marshal(c.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatal(err)
	}
	line := "2026-10-31T20:00:00Z host sshd[4400]: Accepted password for alice from 127.0.0.1 port 22 ssh2\n"
	h.append("/var/log/auth.log", line)
	check := func(c *Collector, want string) {
		t.Helper()
		events := c.Poll(context.Background())
		if len(events) != 1 {
			t.Fatalf("events = %+v", events)
		}
		got, present := events[0].Fields["boot_id"]
		if want == "" && present || want != "" && got != want {
			t.Fatalf("boot=%v, present=%v, want %q", got, present, want)
		}
	}
	check(c, testBootID)
	c.Close()
	c = newCollector(cp)
	check(c, testBootID)
	c.Close()
	// A new boot must not label saved backlog even when its timestamp looks current.
	setHostBoot(h, otherBootID, testNow.Add(-time.Minute))
	c = newCollector(cp)
	check(c, "")
	h.append("/var/log/auth.log", line)
	check(c, otherBootID)
	// A delayed write with a timestamp from before boot is also unknown.
	h.append("/var/log/auth.log", strings.Replace(line, "20:00:00", "19:00:00", 1))
	check(c, "")
	c.Close()
	// Checkpoints from older agents cannot establish provenance.
	pos := cp.Files["/var/log/auth.log"]
	pos.BootID = ""
	cp.Files["/var/log/auth.log"] = pos
	c = newCollector(cp)
	defer c.Close()
	for _, e := range c.Poll(context.Background()) {
		if _, present := e.Fields["boot_id"]; present {
			t.Fatalf("legacy backlog relabelled: %+v", e)
		}
	}
}

func TestAggregationSeparatesBootsAndUnknownIdentity(t *testing.T) {
	p := newAuditParser(nil, "")
	loginAudit(p)
	command := commandAudit(p, "2", commandSyscall)[0]
	for _, e := range []Event{sshFailure("127.0.0.1", "alice", testNow), command} {
		a := NewAggregator()
		for range 2 {
			for _, boot := range []string{testBootID, otherBootID, ""} {
				v := Redact(e)
				delete(v.Fields, "boot_id")
				v.setBootID(boot)
				a.Add(v)
			}
		}
		out := a.Flush()
		if len(out) != 3 || !slices.Equal([]int{out[0].Count, out[1].Count, out[2].Count}, []int{2, 2, 2}) {
			t.Fatalf("%s aggregated across boots: %+v", e.Kind, out)
		}
		if out[0].Fields["boot_id"] != testBootID || out[1].Fields["boot_id"] != otherBootID {
			t.Fatalf("aggregate lost boot identity: %+v", out)
		}
		if _, present := out[2].Fields["boot_id"]; present {
			t.Fatal("unknown aggregate invented an ID")
		}
	}
}

func TestSyslogOmitsUnavailableBootIdentity(t *testing.T) {
	for _, id := range []string{"", "invalid"} {
		h := newHost(t)
		setHostBoot(h, id, testNow.Add(-time.Hour))
		h.write("/var/log/auth.log", "")
		c := NewCollector([]string{SourceAuth}, h.options(false), Checkpoint{}, nil, func() time.Time { return testNow })
		c.Poll(context.Background())
		h.append("/var/log/auth.log", "2026-10-31T20:00:00Z host sshd[42]: Failed password for alice from 127.0.0.1 port 22 ssh2\n")
		events := c.Poll(context.Background())
		c.Close()
		if len(events) != 1 {
			t.Fatalf("events=%+v", events)
		}
		if _, present := events[0].Fields["boot_id"]; present {
			t.Fatalf("unknown boot was exported: %+v", events[0])
		}
	}
}

func TestCommandBudgetSeparatesReusedSessionsAcrossBoots(t *testing.T) {
	p := newAuditParser(nil, "")
	loginAudit(p)
	command := commandAudit(p, "2", commandSyscall)[0]
	a := NewAggregator()
	for _, boot := range []string{testBootID, otherBootID} {
		for i := range 60 {
			e := Redact(command)
			e.setBootID(boot)
			e.set("executable", fmt.Sprintf("/bin/cmd%d", i))
			a.Add(e)
		}
		a.Flush()
	}
	if dropped := a.TakeDropped(); dropped != 0 {
		t.Fatalf("a reused audit session inherited another boot's budget: %d drops", dropped)
	}
}
