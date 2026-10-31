package logs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type hostTree struct {
	t    *testing.T
	root string
}

func newHost(t *testing.T) hostTree { return hostTree{t, t.TempDir()} }

func (h hostTree) write(path, content string) {
	h.t.Helper()
	full := filepath.Join(h.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h hostTree) append(path, content string) {
	h.t.Helper()
	appendTo(h.t, filepath.Join(h.root, path), content)
}

func (h hostTree) options(journalctl bool, appPaths ...string) Options {
	return Options{Root: h.root, AppPaths: appPaths, HasJournalctl: func() bool { return journalctl }}
}

func filePaths(p Plan) []string {
	var out []string
	for _, f := range p.Files {
		out = append(out, f.Source+":"+f.Path+":"+f.Vhost)
	}
	return out
}

func TestPlanAuthPrefersReadableJournal(t *testing.T) {
	h := newHost(t)
	h.write("/run/log/journal/abc/system.journal", "")
	h.write("/var/log/auth.log", "")
	if p := PlanSources([]string{SourceAuth}, h.options(true)); !p.Journal || len(p.Files) != 0 || len(p.Skipped) != 0 {
		t.Fatalf("plan = %+v, want journald", p)
	}
	if p := PlanSources([]string{SourceAuth}, h.options(false)); p.Journal || !slices.Equal(filePaths(p), []string{"auth:/var/log/auth.log:"}) {
		t.Fatalf("plan without journalctl = %+v, want auth.log", p)
	}
}

func TestPlanAuthFallsBackToFilesWithCronLog(t *testing.T) {
	h := newHost(t)
	h.write("/var/log/secure", "")
	h.write("/var/log/cron", "")
	p := PlanSources([]string{SourceAuth}, h.options(true))
	if p.Journal || !slices.Equal(filePaths(p), []string{"auth:/var/log/secure:", "auth:/var/log/cron:"}) {
		t.Fatalf("plan = %+v", p)
	}
}

func TestPlanAuthReportsWhatItCannotRead(t *testing.T) {
	h := newHost(t)
	p := PlanSources([]string{SourceAuth}, h.options(true))
	if !slices.Equal(p.Skipped, []SkippedSource{{SourceAuth, "/var/log/auth.log", ReasonNotFound}}) {
		t.Fatalf("plan = %+v", p)
	}
	if os.Geteuid() == 0 {
		return
	}
	h.write("/var/log/journal/abc/system.journal", "")
	os.Chmod(filepath.Join(h.root, "/var/log/journal/abc/system.journal"), 0)
	p = PlanSources([]string{SourceAuth}, h.options(true))
	if !slices.Equal(p.Skipped, []SkippedSource{{SourceAuth, "journal", ReasonPermissionDenied}}) {
		t.Fatalf("unreadable journal = %+v", p)
	}
	h.write("/var/log/auth.log", "")
	os.Chmod(filepath.Join(h.root, "/var/log/auth.log"), 0)
	p = PlanSources([]string{SourceAuth}, h.options(true))
	if !slices.Equal(p.Skipped, []SkippedSource{{SourceAuth, "/var/log/auth.log", ReasonPermissionDenied}}) {
		t.Fatalf("unreadable auth.log = %+v", p)
	}
}

func TestPlanWebFindsAccessLogsWithVhosts(t *testing.T) {
	h := newHost(t)
	h.write("/var/log/nginx/access.log", "")
	h.write("/var/log/nginx/shop.example.com.access.log", "")
	h.write("/var/log/nginx/error.log", "")
	h.write("/var/log/httpd/access_log", "")
	p := PlanSources([]string{SourceWeb}, h.options(false))
	want := []string{"web:/var/log/nginx/access.log:", "web:/var/log/nginx/shop.example.com.access.log:shop.example.com", "web:/var/log/httpd/access_log:"}
	if !slices.Equal(filePaths(p), want) || len(p.Skipped) != 0 {
		t.Fatalf("plan = %+v", p)
	}
	if p := PlanSources([]string{SourceWeb}, newHost(t).options(false)); len(p.Files) != 0 || p.Skipped[0].Reason != ReasonNotFound {
		t.Fatalf("no web server = %+v", p)
	}
}

func TestPlanAppUsesOnlyConfiguredPaths(t *testing.T) {
	h := newHost(t)
	h.write("/var/www/shop/storage/logs/laravel-2026-10-30.log", "")
	h.write("/var/www/shop/storage/logs/laravel-2026-10-31.log", "")
	paths := []string{"/var/www/shop/storage/logs/laravel-*.log", "/srv/api/app.log", "relative.log", "/srv/none-*.log"}
	p := PlanSources([]string{SourceApp}, h.options(false, paths...))
	want := []string{"app:/var/www/shop/storage/logs/laravel-2026-10-30.log:", "app:/var/www/shop/storage/logs/laravel-2026-10-31.log:", "app:/srv/api/app.log:"}
	if !slices.Equal(filePaths(p), want) {
		t.Fatalf("files = %v", filePaths(p))
	}
	wantSkipped := []SkippedSource{{SourceApp, "/srv/api/app.log", ReasonNotFound}, {SourceApp, "/srv/none-*.log", ReasonNotFound}}
	if !slices.Equal(p.Skipped, wantSkipped) {
		t.Fatalf("skipped = %v", p.Skipped)
	}
	var many []string
	for i := range 15 {
		many = append(many, filepath.Join("/srv", strings.Repeat("x", i+1)+".log"))
	}
	if p := PlanSources([]string{SourceApp}, h.options(false, many...)); len(p.Files) != MaxAppPaths {
		t.Fatalf("files = %d, want at most %d", len(p.Files), MaxAppPaths)
	}
}

func TestPlanDisabledSourcesReadNothing(t *testing.T) {
	h := newHost(t)
	h.write("/var/log/auth.log", "")
	h.write("/var/log/nginx/access.log", "")
	if p := PlanSources(nil, h.options(true, "/var/log/auth.log")); p.Journal || len(p.Files) != 0 || len(p.Skipped) != 0 {
		t.Fatalf("plan = %+v", p)
	}
}

func fixtureStart(t *testing.T, fixture string, gotArgs *[]string) StartFunc {
	return func(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, error) {
		*gotArgs = append([]string{name}, args...)
		f, err := os.Open(filepath.Join("testdata", "journal", fixture))
		if err != nil {
			return nil, nil, err
		}
		return f, func() error { return nil }, nil
	}
}

func TestJournalRunFollowsAndKeepsCursor(t *testing.T) {
	var args []string
	j := &Journal{Identifiers: []string{"sshd", "sudo"}, Start: fixtureStart(t, "debian-12.jsonl", &args)}
	var entries []JournalEntry
	err := j.Run(context.Background(), func(e JournalEntry) { entries = append(entries, e) })
	if err == nil {
		t.Fatal("Run must report that journalctl exited")
	}
	want := []string{"journalctl", "--follow", "--output=json", "--no-pager", "--quiet", "--identifier=sshd", "--identifier=sudo", "--lines=0"}
	if !slices.Equal(args, want) {
		t.Fatalf("args = %q", args)
	}
	if len(entries) != 73 || j.Cursor != entries[72].Cursor {
		t.Fatalf("entries = %d, cursor = %q", len(entries), j.Cursor)
	}
	j.Run(context.Background(), func(JournalEntry) {})
	if !slices.Contains(args, "--after-cursor="+entries[72].Cursor) {
		t.Fatalf("a restarted journalctl must resume after the cursor: %q", args)
	}
}

func TestCollectorReadsFilesAndResumesFromCheckpoint(t *testing.T) {
	h := newHost(t)
	h.write("/var/log/auth.log", "2026-10-31T18:58:00.000000+00:00 host sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2\n")
	h.write("/var/log/nginx/access.log", "")
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceAuth, SourceWeb}, h.options(false), Checkpoint{}, nil, clock.Now)
	if events := c.Poll(context.Background()); len(events) != 0 {
		t.Fatalf("first enable must not upload history: %+v", events)
	}
	h.append("/var/log/auth.log", "2026-10-31T19:00:00.000000+00:00 host sshd[2]: Accepted publickey for deploy from 198.51.100.4 port 2 ssh2: ED25519 SHA256:x\n")
	h.append("/var/log/auth.log", "2026-10-31T19:00:01.000000+00:00 host CRON[3]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n")
	h.append("/var/log/nginx/access.log", `203.0.113.7 - - [31/Oct/2026:19:00:02 +0000] "GET /.env HTTP/1.1" 404 0 "-" "zgrab"`+"\n")
	events := c.Poll(context.Background())
	if len(events) != 2 || events[0].Kind != KindSSHLoginSucceeded || events[1].Kind != KindHTTPRequest || events[1].Fields["path"] != "/.env" {
		t.Fatalf("events = %+v", events)
	}
	checkpoint := c.Checkpoint()
	c.Close()
	if !slices.Equal(checkpoint.Sources, []string{SourceAuth, SourceWeb}) || len(checkpoint.Files) != 2 {
		t.Fatalf("checkpoint = %+v", checkpoint)
	}

	h.append("/var/log/auth.log", "2026-10-31T19:01:00.000000+00:00 host sudo:    alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n")
	restarted := NewCollector([]string{SourceAuth, SourceWeb}, h.options(false), checkpoint, nil, clock.Now)
	defer restarted.Close()
	events = restarted.Poll(context.Background())
	if len(events) != 1 || events[0].Kind != KindSudoCommand {
		t.Fatalf("after a restart only new lines are read: %+v", events)
	}
}

func TestCollectorReportsRemovedFileAndSkippedSources(t *testing.T) {
	h := newHost(t)
	h.write("/var/www/shop/storage/logs/laravel.log", "")
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceApp, SourceWeb}, h.options(false, "/var/www/shop/storage/logs/laravel.log"), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	c.Poll(context.Background())
	if skipped := c.Skipped(); !slices.Equal(skipped, []SkippedSource{{SourceWeb, "/var/log/nginx", ReasonNotFound}}) {
		t.Fatalf("skipped = %+v", skipped)
	}
	os.Remove(filepath.Join(h.root, "/var/www/shop/storage/logs/laravel.log"))
	c.Poll(context.Background())
	clock.now = clock.now.Add(RemovedAfter)
	events := c.Poll(context.Background())
	if len(events) != 1 || events[0].Kind != KindLogFileRemoved || events[0].Source != SourceApp || events[0].Fields["path"] != "/var/www/shop/storage/logs/laravel.log" {
		t.Fatalf("events = %+v", events)
	}
}

func TestCollectorReadsJournalFromCursor(t *testing.T) {
	h := newHost(t)
	h.write("/run/log/journal/abc/system.journal", "")
	var args []string
	c := NewCollector([]string{SourceAuth}, h.options(true), Checkpoint{Sources: []string{SourceAuth}, JournalCursor: "s=previous"}, fixtureStart(t, "debian-12.jsonl", &args), (&fakeClock{now: testNow}).Now)
	defer c.Close()
	var events []Event
	deadline := time.Now().Add(5 * time.Second)
	for len(events) < 27 && time.Now().Before(deadline) {
		events = append(events, c.Poll(context.Background())...)
		time.Sleep(10 * time.Millisecond)
	}
	if len(events) != 27 {
		t.Fatalf("events = %d, want 27 from the journal fixture", len(events))
	}
	if !slices.Contains(args, "--after-cursor=s=previous") {
		t.Fatalf("args = %q", args)
	}
	if cp := c.Checkpoint(); cp.JournalCursor == "" || cp.JournalCursor == "s=previous" {
		t.Fatalf("checkpoint cursor = %q", cp.JournalCursor)
	}
}
