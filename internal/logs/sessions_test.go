package logs

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSSHSessionsPerDistribution(t *testing.T) {
	for _, tc := range []struct{ fixture, pid, program string }{
		{"ubuntu-22.04.sessions.log", "3742", "sshd"},
		{"ubuntu-24.04.auth.log", "3942", "sshd"},
		{"debian-12.auth.log", "4400", "sshd"},
		{"rocky-9.secure", "287", "sshd-session"},
		{"alpine-3.22.sessions.log", "21", "sshd-session.pam"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			c := NewCollector(nil, Options{}, Checkpoint{}, nil, nil)
			a := NewAggregator()
			for _, line := range readLines(t, filepath.Join("testdata", "auth", tc.fixture)) {
				if e, ok := c.parseLine(FilePlan{Source: SourceAuth}, line); ok {
					a.Add(Redact(e))
				}
			}
			events := a.Flush()
			for _, kind := range []string{KindSSHLoginSucceeded, KindSSHSessionOpened, KindSSHSessionClosed} {
				e := findEvent(t, events, kind, nil)
				if e.Fields["session"] != tc.pid || e.Program != tc.program || e.Source != SourceAuth || e.Username == "" || e.Count != 1 {
					t.Fatalf("%s: %+v", kind, e)
				}
			}
		})
	}
}

func TestJournalSessionLifecycle(t *testing.T) {
	c := NewCollector(nil, Options{}, Checkpoint{}, nil, func() time.Time { return testNow })
	c.lastPlan = testNow
	c.journalCh = make(chan JournalEntry, 100)
	for _, line := range readLines(t, filepath.Join("testdata", "journal", "debian-12.sessions.jsonl")) {
		entry, err := ParseJournalEntry([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		if entry.PID == "" {
			t.Fatalf("missing trusted PID: %+v", entry)
		}
		c.journalCh <- entry
	}
	a := NewAggregator()
	for _, e := range c.Poll(context.Background()) {
		a.Add(Redact(e))
	}
	events := a.Flush()
	want := []string{KindSSHLoginSucceeded, KindSSHSessionOpened, KindSSHSessionOpened, KindSudoCommand, KindSSHSessionClosed, KindSSHSessionClosed}
	var kinds []string
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	if !slices.Equal(kinds, want) || c.UntrustedEntries() != 0 {
		t.Fatalf("kinds=%v untrusted=%d", kinds, c.UntrustedEntries())
	}
	for _, i := range []int{0, 1, 4} {
		if events[i].Fields["session"] != "824" {
			t.Fatalf("SSH key: %+v", events[i])
		}
	}
	for _, i := range []int{2, 5} {
		if events[i].Fields["logind_session"] != "54" || events[i].Fields["session"] != nil {
			t.Fatalf("logind key: %+v", events[i])
		}
	}
	sudo := events[3]
	if sudo.Username != events[0].Username || sudo.Fields["tty"] != "pts/0" || sudo.Fields["command"] != "/usr/bin/id [0 args]" || sudo.Fields["session"] != nil {
		t.Fatalf("sudo: %+v", sudo)
	}
	if events[5].Username != "" {
		t.Fatalf("invented logout user: %+v", events[5])
	}
}

func TestSessionBoundariesAreNeverAggregated(t *testing.T) {
	a := NewAggregator()
	for range 2 {
		for _, kind := range []string{KindSSHSessionOpened, KindSSHSessionClosed} {
			e := authEvent(kind, "sshd", "", testNow)
			e.set("session", "1234")
			a.Add(Redact(e))
		}
	}
	if events := a.Flush(); len(events) != 4 {
		t.Fatalf("session boundaries aggregated: %+v", events)
	}
}

func TestSSHSessionIgnoresOtherPAMServices(t *testing.T) {
	for _, program := range []string{"sshd", "sshd-session", "sshd.pam", "sshd-session.pam"} {
		for _, service := range []string{"sudo", "su", "login", "cron"} {
			for _, action := range []string{"opened", "closed"} {
				message := "pam_unix(" + service + ":session): session " + action + " for user alice"
				if e, ok := ParseAuth(program, message, testNow, "1234"); ok {
					t.Fatalf("other PAM service: %+v", e)
				}
			}
		}
	}
	for _, message := range []string{"Accepted password for alice from 127.0.0.1 port 1234 ssh2", "pam_unix(sshd:session): session opened for user alice by (uid=0)", "pam_unix(sshd:session): session closed for user alice"} {
		e, ok := ParseAuth("sshd", message, testNow, "")
		if !ok || e.Fields["session"] != nil {
			t.Fatalf("missing PID: %+v %v", e, ok)
		}
	}
}

func TestSudoSessionFields(t *testing.T) {
	for _, fixture := range []string{"debian-12.sudo.log", "ubuntu-24.04.sudo.log", "rocky-9.sudo.secure"} {
		events := authEvents(t, fixture)
		e := events[len(events)-1]
		if e.Fields["tsid"] != "01" && e.Fields["tsid"] != "000001" {
			t.Fatalf("TSID not kept: %+v", e)
		}
	}
	for _, status := range []string{"", "3 incorrect password attempts ; "} {
		for _, tc := range []struct {
			body      string
			tty, tsid any
		}{
			{"TTY=pts/0 ; PWD=/ ; USER=root ; TSID=000001 ; COMMAND=/bin/true privateargument", "pts/0", "000001"},
			{"HOST=web ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/true TTY=fake TSID=fake", "pts/1", nil},
			{"PWD=/ ; USER=root ; COMMAND=/bin/true ; TTY=privateargument ; TSID=privateargument", nil, nil},
			{"TTY=pts/0 ; PWD=/ ; USER=fake ; TSID=999999 ; COMMAND=/fake ; USER=root ; TSID=000001 ; COMMAND=/bin/true", "pts/0", nil},
		} {
			e, ok := ParseAuth("sudo", "alice : "+status+tc.body, testNow, "9999")
			if !ok {
				t.Fatal("no sudo event")
			}
			e = Redact(e)
			if e.Fields["tty"] != tc.tty || e.Fields["tsid"] != tc.tsid || e.Fields["session"] != nil || strings.Contains(e.Message+fmt.Sprint(e.Fields), "privateargument") {
				t.Fatalf("sudo fields or arguments: %+v", e)
			}
		}
	}
}

func TestJournalSessionUsesTrustedPID(t *testing.T) {
	for _, tc := range []struct{ metadata, want string }{
		{`"_PID":"1234","SYSLOG_PID":"5678",`, "1234"},
		{`"SYSLOG_PID":"5678",`, ""},
	} {
		entry, err := ParseJournalEntry([]byte(`{` + tc.metadata + `"MESSAGE":"pam_unix(sshd:session): session closed for user alice","SYSLOG_IDENTIFIER":"sshd"}`))
		if err != nil || entry.PID != tc.want {
			t.Fatalf("entry=%+v err=%v", entry, err)
		}
		e, ok := ParseAuth(entry.Identifier, entry.Message, entry.At, entry.PID)
		if !ok {
			t.Fatal("no session close")
		}
		if got, _ := e.Fields["session"].(string); got != tc.want {
			t.Fatalf("session=%q want %q", got, tc.want)
		}
	}
}

func TestLogindSessionIDsAreOpaque(t *testing.T) {
	for _, message := range []string{"New session c1 of user alice.", "Removed session c1."} {
		e, ok := ParseAuth("systemd-logind", message, testNow, "132")
		if !ok || e.Fields["logind_session"] != "c1" || e.Fields["session"] != nil {
			t.Fatalf("logind: %+v %v", e, ok)
		}
	}
}
