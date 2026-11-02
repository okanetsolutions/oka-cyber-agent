package logs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func (h hostTree) symlink(target, path string) {
	h.t.Helper()
	full := filepath.Join(h.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		h.t.Fatal(err)
	}
}

func (h hostTree) mkfifo(path string) {
	h.t.Helper()
	full := filepath.Join(h.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := syscall.Mkfifo(full, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// pollWithin fails the test instead of hanging when Poll blocks, as it did on a FIFO.
func pollWithin(t *testing.T, c *Collector) []Event {
	t.Helper()
	done := make(chan []Event, 1)
	go func() { done <- c.Poll(context.Background()) }()
	select {
	case events := <-done:
		return events
	case <-time.After(5 * time.Second):
		t.Fatal("Poll blocked")
		return nil
	}
}

func TestOpenLogFileFollowsOnlyDirectoriesTheAdminWrote(t *testing.T) {
	h := newHost(t)
	h.write("/secret/app.log", "secret\n")
	h.write("/srv/shop/releases/2/storage/logs/laravel.log", "")
	h.symlink(filepath.Join(h.root, "/srv/shop/releases/2"), "/srv/shop/current")
	h.write("/var/www/real/logs/laravel.log", "")
	h.symlink(filepath.Join(h.root, "/secret"), "/var/www/linked")
	h.write("/var/www/linked-file/logs/laravel.log", "")
	h.symlink(filepath.Join(h.root, "/secret/app.log"), "/var/www/real/logs/laravel-link.log")
	h.mkfifo("/var/www/real/logs/laravel-fifo.log")
	h.write("/var/www/real/logs/laravel-dir.log/x", "")
	h.write("/var/www/file", "")

	cases := []struct {
		path, pattern string
		want          error
	}{
		{"/srv/shop/current/storage/logs/laravel.log", "", nil},
		{"/srv/shop/current/storage/logs/laravel.log", "/srv/shop/current/storage/logs/*.log", nil},
		{"/var/www/real/logs/laravel.log", "/var/www/*/logs/laravel.log", nil},
		{"/var/www/real/logs/laravel-link.log", "", errSymlink},
		{"/var/www/real/logs/laravel-link.log", "/var/www/real/logs/laravel-*.log", errSymlink},
		{"/var/www/linked/app.log", "/var/www/*/app.log", errSymlink},
		{"/var/www/real/logs/laravel-fifo.log", "", errNotRegular},
		{"/var/www/real/logs/laravel-dir.log", "", errNotRegular},
		{"/var/www/file/logs/laravel.log", "/var/www/*/logs/laravel.log", errNotRegular},
		{"/var/www/real/logs/none.log", "", os.ErrNotExist},
	}
	for _, c := range cases {
		pattern := ""
		if c.pattern != "" {
			pattern = filepath.Join(h.root, c.pattern)
		}
		f, err := openLogFile(filepath.Join(h.root, c.path), pattern)
		if err == nil {
			f.Close()
		}
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("openLogFile(%s, %q) = %v, want %v", c.path, c.pattern, err, c.want)
		}
	}
}

func TestPlanAuthDoesNotFollowASymlinkedAuthLog(t *testing.T) {
	h := newHost(t)
	h.write("/home/user/fake.log", "")
	h.symlink(filepath.Join(h.root, "/home/user/fake.log"), "/var/log/auth.log")
	p := PlanSources([]string{SourceAuth}, h.options(false))
	if len(p.Files) != 0 || !slices.Equal(p.Skipped, []SkippedSource{{SourceAuth, "/var/log/auth.log", ReasonSymlink}}) {
		t.Fatalf("plan = %+v", p)
	}
}

func TestCollectorSkipsFIFOsWithoutBlocking(t *testing.T) {
	h := newHost(t)
	dir := "/var/www/shop/storage/logs"
	h.write(dir+"/laravel-2026-11-01.log", "")
	h.mkfifo("/srv/api/app.log")
	h.write("/var/log/auth.log", "")
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceAuth, SourceApp}, h.options(false, dir+"/laravel-*.log", "/srv/api/app.log"), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	pollWithin(t, c)
	if !slices.Contains(c.Skipped(), SkippedSource{SourceApp, "/srv/api/app.log", ReasonNotRegularFile}) {
		t.Fatalf("skipped = %+v, want the FIFO named in log_paths", c.Skipped())
	}

	h.mkfifo(dir + "/laravel-x.log")
	h.write(dir+"/laravel-2026-11-02.log", appErrors(1))
	h.append("/var/log/auth.log", "2026-10-31T19:00:00.000000+00:00 host sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n")
	clock.now = clock.now.Add(replanEvery)
	events := pollWithin(t, c)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want the auth line and the new daily log", events)
	}
	if !slices.Contains(c.Skipped(), SkippedSource{SourceApp, dir + "/laravel-x.log", ReasonNotRegularFile}) {
		t.Fatalf("skipped = %+v, want the FIFO matching the glob", c.Skipped())
	}
}

func TestCollectorNeverReadsASymlinkMatchingALogPathGlob(t *testing.T) {
	h := newHost(t)
	dir := "/var/www/shop/storage/logs"
	h.write(dir+"/laravel-2026-11-01.log", "")
	h.write("/var/log/other/secret.log", appErrors(5))
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceApp}, h.options(false, dir+"/laravel-*.log"), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	c.Poll(context.Background())

	h.symlink(filepath.Join(h.root, "/var/log/other/secret.log"), dir+"/laravel-zz.log")
	h.write(dir+"/laravel-2026-11-02.log", appErrors(1))
	clock.now = clock.now.Add(replanEvery)
	events := c.Poll(context.Background())
	if len(events) != 1 || events[0].Fields["file"] != dir+"/laravel-2026-11-02.log" {
		t.Fatalf("events = %+v, want only the regular file", events)
	}
	if !slices.Contains(c.Skipped(), SkippedSource{SourceApp, dir + "/laravel-zz.log", ReasonSymlink}) {
		t.Fatalf("skipped = %+v, want the symlink listed", c.Skipped())
	}
	if _, ok := c.watches[dir+"/laravel-zz.log"]; ok {
		t.Fatal("the symlink is watched")
	}
}

func TestCollectorDoesNotFollowADirectoryAWildcardMatched(t *testing.T) {
	h := newHost(t)
	h.write("/var/www/shop/storage/logs/laravel.log", "")
	h.write("/var/log/other/storage/logs/laravel.log", "")
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceApp}, h.options(false, "/var/www/*/storage/logs/laravel.log"), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	c.Poll(context.Background())

	h.symlink(filepath.Join(h.root, "/var/log/other"), "/var/www/zz")
	h.append("/var/log/other/storage/logs/laravel.log", appErrors(3))
	h.append("/var/www/shop/storage/logs/laravel.log", appErrors(1))
	clock.now = clock.now.Add(replanEvery)
	events := c.Poll(context.Background())
	if len(events) != 1 || events[0].Fields["file"] != "/var/www/shop/storage/logs/laravel.log" {
		t.Fatalf("events = %+v, want only the file in the real directory", events)
	}
	if !slices.Contains(c.Skipped(), SkippedSource{SourceApp, "/var/www/zz/storage/logs/laravel.log", ReasonSymlink}) {
		t.Fatalf("skipped = %+v", c.Skipped())
	}
}

func TestCollectorFollowsDeploySymlinksInTheConfiguredPath(t *testing.T) {
	h := newHost(t)
	h.write("/home/forge/shop/shared/storage/logs/laravel-2026-11-01.log", "")
	h.symlink(filepath.Join(h.root, "/home/forge/shop/shared/storage"), "/home/forge/shop/releases/2/storage")
	h.symlink("releases/2", "/home/forge/shop/current")
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceApp}, h.options(false, "/home/forge/shop/current/storage/logs/laravel-*.log"), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	c.Poll(context.Background())

	h.write("/home/forge/shop/shared/storage/logs/laravel-2026-11-02.log", appErrors(2))
	clock.now = clock.now.Add(replanEvery)
	events := c.Poll(context.Background())
	if len(events) != 2 || events[0].Fields["file"] != "/home/forge/shop/current/storage/logs/laravel-2026-11-02.log" {
		t.Fatalf("events = %+v, want the new daily log read through current/ and storage/", events)
	}
}

func TestTailerStopsAtAFileReplacedBySymlink(t *testing.T) {
	h := newHost(t)
	h.write("/srv/api/app.log", "")
	h.write("/var/log/other/secret.log", "secret\n")
	tail, clock := newTestTailer(filepath.Join(h.root, "/srv/api/app.log"), nil, false)
	tail.Poll()
	h.append("/srv/api/app.log", "last\n")
	os.Remove(filepath.Join(h.root, "/srv/api/app.log"))
	h.symlink(filepath.Join(h.root, "/var/log/other/secret.log"), "/srv/api/app.log")
	if r := tail.Poll(); !slices.Equal(r.Lines, []string{"last"}) || !r.Missing {
		t.Fatalf("poll = %+v, want the old file's last line and no file", r)
	}
	clock.now = clock.now.Add(RemovedAfter)
	if r := tail.Poll(); len(r.Lines) != 0 || !r.Removed {
		t.Fatalf("poll = %+v, want the symlink never read and the log reported removed", r)
	}

	fifo := filepath.Join(h.root, "/srv/api/fifo.log")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan PollResult, 1)
	go func() { done <- NewTailer(fifo, nil, false).Poll() }()
	select {
	case r := <-done:
		if !r.Missing {
			t.Fatalf("poll = %+v, want a FIFO treated as no file", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Poll blocked on a FIFO")
	}
}
