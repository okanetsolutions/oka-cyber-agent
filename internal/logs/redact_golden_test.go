package logs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var laterFixtures = map[string]bool{
	"nginx.auth-user.access.log": true, "apache2.auth-user.access.log": true, "debian-12.sudo-long-cwd.log": true,
	"rocky-9.jsonl": true, "rocky-9-forged.jsonl": true, "rocky-9-exec-race.jsonl": true, "rocky-9.sudo-long-cwd.jsonl": true,
}

// fixtureEvents parses every line of the committed log samples into the event the collector would make of it,
// whatever journald says about its sender.
func fixtureEvents(t *testing.T) map[string][]Event {
	t.Helper()
	events := map[string][]Event{}
	for _, dir := range []string{"app", "web", "auth", "journal"} {
		names, err := filepath.Glob(filepath.Join("testdata", dir, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			// The samples added with a parser fix are covered by its own test.
			if strings.HasSuffix(name, ".md") || laterFixtures[filepath.Base(name)] {
				continue
			}
			for _, line := range readLines(t, name) {
				var e Event
				var ok bool
				switch dir {
				case "app":
					e, ok = ParseMonolog(line, "/var/www/shop/storage/logs/laravel.log", testNow)
				case "web":
					e, ok = ParseAccessLog(line, "")
				case "auth":
					if l, parsed := ParseSyslog(line, testNow); parsed {
						e, ok = ParseAuth(l.Program, l.Message, l.At.UTC(), l.PID)
					}
				case "journal":
					if entry, err := ParseJournalEntry([]byte(line)); err == nil {
						e, ok = ParseAuth(entry.Identifier, entry.Message, entry.At, entry.PID)
					}
				}
				if ok {
					events[filepath.ToSlash(name)] = append(events[filepath.ToSlash(name)], e)
				}
			}
		}
	}
	return events
}

// TestRedactFixturesUnchanged pins what Redact makes of every committed log sample. redacted.golden.json was
// written by the redaction rules as they were before the scans were made linear (UPDATE_GOLDEN=1 rewrites it), so
// a change of a rule shows here as the lines it changes.
func TestRedactFixturesUnchanged(t *testing.T) {
	redacted := map[string][]Event{}
	for name, events := range fixtureEvents(t) {
		for _, e := range events {
			redacted[name] = append(redacted[name], Redact(e))
		}
	}
	got, err := json.MarshalIndent(redacted, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "redacted.golden.json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		gotLines, wantLines := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
		for i := range min(len(gotLines), len(wantLines)) {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("line %d of %s differs\n got %s\nwant %s", i+1, golden, gotLines[i], wantLines[i])
			}
		}
		t.Fatalf("%s: %d lines, want %d", golden, len(gotLines), len(wantLines))
	}
}
