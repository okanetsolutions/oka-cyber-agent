package logs

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func appError(message string) string {
	return "[2026-10-31 19:00:03] production.ERROR: " + message + "\n"
}

func messages(events []Event) []string {
	var out []string
	for _, e := range events {
		if e.Kind == KindHTTPRequest {
			out = append(out, fmt.Sprint(e.Fields["path"]))
			continue
		}
		out = append(out, strings.TrimPrefix(e.Message, "[2026-10-31 19:00:03] production.ERROR: "))
	}
	return out
}

func gzipped(t *testing.T, text string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestCollectorDoesNotRereadARotatedFileTheGlobStillMatches(t *testing.T) {
	h := newHost(t)
	dir := "/var/log/myapp"
	path := func(name string) string { return filepath.Join(h.root, dir, name) }
	h.write(dir+"/app.log", "")
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceApp}, h.options(false, dir+"/*"), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	c.Poll(context.Background())
	h.append(dir+"/app.log", appError("one"))
	if got := messages(c.Poll(context.Background())); !slices.Equal(got, []string{"one"}) {
		t.Fatalf("before rotation: %v", got)
	}

	h.append(dir+"/app.log", appError("two"))
	if err := os.Rename(path("app.log"), path("app.log.1")); err != nil {
		t.Fatal(err)
	}
	h.append(dir+"/app.log.1", appError("three"))
	h.write(dir+"/app.log", appError("four"))
	clock.now = clock.now.Add(replanEvery)
	if got := messages(c.Poll(context.Background())); !slices.Equal(got, []string{"two", "three", "four"}) {
		t.Fatalf("rotation: %v, want the rest of the rotated file once, then the new file", got)
	}
	if _, ok := c.watches[dir+"/app.log.1"]; !ok {
		t.Fatalf("watches = %v, want the rotated file followed under its new name", sortedWatchPaths(c.watches))
	}
	h.append(dir+"/app.log.1", appError("late"))
	clock.now = clock.now.Add(time.Second)
	if got := messages(c.Poll(context.Background())); !slices.Equal(got, []string{"late"}) {
		t.Fatalf("a line written to the rotated file after it was read to its end: %v", got)
	}

	// logrotate with delaycompress: app.log.1 becomes app.log.2.gz, app.log becomes app.log.1.
	if err := os.Rename(path("app.log.1"), path("app.log.2")); err != nil {
		t.Fatal(err)
	}
	h.append(dir+"/app.log", appError("five"))
	if err := os.Rename(path("app.log"), path("app.log.1")); err != nil {
		t.Fatal(err)
	}
	h.write(dir+"/app.log", appError("six"))
	h.write(dir+"/app.log.2.gz", gzipped(t, appError("one")+appError("two")+appError("three")+appError("late")))
	os.Remove(path("app.log.2"))
	h.write(dir+"/app.log.3", gzipped(t, appError("compressed without extension")))
	clock.now = clock.now.Add(replanEvery)
	if got := messages(c.Poll(context.Background())); !slices.Equal(got, []string{"five", "six"}) {
		t.Fatalf("second rotation: %v", got)
	}
	clock.now = clock.now.Add(replanEvery)
	if got := messages(c.Poll(context.Background())); len(got) != 0 {
		t.Fatalf("after the second rotation: %v", got)
	}
	if got := sortedWatchPaths(c.watches); !slices.Equal(got, []string{dir + "/app.log", dir + "/app.log.1"}) {
		t.Fatalf("watches = %v, compressed files must not be followed", got)
	}
	if skipped := c.Skipped(); len(skipped) != 0 {
		t.Fatalf("skipped = %+v, compressed files are left out without a report", skipped)
	}
}

func TestCollectorDoesNotRereadADateextRotatedAccessLog(t *testing.T) {
	h := newHost(t)
	nginx := "/var/log/nginx"
	h.write(nginx+"/access.log", "")
	request := func(path string) string {
		return `203.0.113.7 - - [31/Oct/2026:19:00:02 +0000] "GET ` + path + ` HTTP/1.1" 404 0 "-" "zgrab"` + "\n"
	}
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceWeb}, h.options(false), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	c.Poll(context.Background())

	// A backlog larger than one poll reads, so the rotated file is still being read when the plan finds it
	// as access-20261030.log, which sorts before access.log.
	var want []string
	var b strings.Builder
	for i := 0; b.Len() < maxReadBytes+maxReadBytes/2; i++ {
		want = append(want, fmt.Sprintf("/old/%06d", i))
		b.WriteString(request(want[len(want)-1]))
	}
	h.append(nginx+"/access.log", b.String())
	rotated := nginx + "/access-20261030.log"
	if err := os.Rename(filepath.Join(h.root, nginx, "access.log"), filepath.Join(h.root, rotated)); err != nil {
		t.Fatal(err)
	}
	h.write(nginx+"/access.log", request("/new"))
	h.write(nginx+"/access-20261029.log.gz", gzipped(t, request("/older")))
	clock.now = clock.now.Add(replanEvery)
	got := messages(c.Poll(context.Background()))
	if _, ok := c.watches[rotated]; !ok || len(got) == 0 || slices.Contains(got, "/new") {
		t.Fatalf("first poll read %d lines, watches %v; want only old lines and the rotated name planned", len(got), sortedWatchPaths(c.watches))
	}
	h.append(rotated, request("/written-during-the-drain"))
	want = append(want, "/written-during-the-drain", "/new")
	for range 3 {
		clock.now = clock.now.Add(time.Second)
		got = append(got, messages(c.Poll(context.Background()))...)
	}
	h.append(rotated, request("/late"))
	want = append(want, "/late")
	clock.now = clock.now.Add(replanEvery)
	got = append(got, messages(c.Poll(context.Background()))...)
	if !slices.Equal(got, want) {
		t.Fatalf("read %d lines, want %d: every line once, in order", len(got), len(want))
	}
	if _, ok := c.watches[nginx+"/access-20261029.log.gz"]; ok {
		t.Fatalf("a compressed rotated log is followed")
	}
}

// The end of a rotated file must be remembered until the plan that finds its new name was polled, however
// long the caller waits between polls (an upload can block it for minutes).
func TestCollectorContinuesARotatedFileWhateverTheTimeBetweenPolls(t *testing.T) {
	request := func(path string) string {
		return `203.0.113.7 - - [31/Oct/2026:19:00:02 +0000] "GET ` + path + ` HTTP/1.1" 404 0 "-" "zgrab"` + "\n"
	}
	for _, gap := range []time.Duration{time.Second, 2 * replanEvery, 10 * time.Minute} {
		// held: the poll that plans the rotated name also reads the rotated file to its end, after the
		// tailer of the rotated name, which sorts first, found it held. drained: the rotated file is read to
		// its end in a poll without a plan, and the plan that finds its new name comes later.
		for _, drainFirst := range []bool{false, true} {
			name := fmt.Sprintf("held/%s", gap)
			if drainFirst {
				name = fmt.Sprintf("drained/%s", gap)
			}
			t.Run(name, func(t *testing.T) {
				h := newHost(t)
				nginx := "/var/log/nginx"
				rotated := nginx + "/access-20261030.log"
				h.write(nginx+"/access.log", "")
				clock := &fakeClock{now: testNow}
				c := NewCollector([]string{SourceWeb}, h.options(false), Checkpoint{}, nil, clock.Now)
				defer c.Close()
				c.Poll(context.Background())
				h.append(nginx+"/access.log", request("/one"))
				clock.now = clock.now.Add(time.Second)
				got := messages(c.Poll(context.Background()))

				h.append(nginx+"/access.log", request("/two"))
				if err := os.Rename(filepath.Join(h.root, nginx, "access.log"), filepath.Join(h.root, rotated)); err != nil {
					t.Fatal(err)
				}
				h.write(nginx+"/access.log", request("/new"))
				if drainFirst {
					clock.now = clock.now.Add(time.Second)
					got = append(got, messages(c.Poll(context.Background()))...)
					if _, ok := c.watches[rotated]; ok {
						t.Fatal("the rotated name was planned before the rotated file was read to its end")
					}
					clock.now = clock.now.Add(max(gap, replanEvery))
				} else {
					clock.now = clock.now.Add(max(gap, replanEvery))
					got = append(got, messages(c.Poll(context.Background()))...)
					if _, ok := c.watches[rotated]; !ok {
						t.Fatalf("watches = %v, want the rotated name planned", sortedWatchPaths(c.watches))
					}
				}
				h.append(rotated, request("/late"))
				for range 3 {
					got = append(got, messages(c.Poll(context.Background()))...)
					clock.now = clock.now.Add(gap)
				}
				want := []string{"/one", "/two", "/new", "/late"}
				if !slices.Equal(got, want) {
					t.Fatalf("events = %v, want %v: every line once", got, want)
				}
				if len(c.files.done) != 0 {
					t.Fatalf("%d read ends remembered after the plan that found them was polled", len(c.files.done))
				}
			})
		}
	}
}

func TestCollectorReadsANewDailyFileFromItsStartAfterARotation(t *testing.T) {
	h := newHost(t)
	dir := "/var/www/shop/storage/logs"
	h.write(dir+"/laravel-2026-10-31.log", appErrors(10))
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceApp}, h.options(false, dir+"/laravel-*.log"), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	c.Poll(context.Background())

	old := filepath.Join(h.root, dir, "laravel-2026-10-31.log")
	if err := os.Rename(old, filepath.Join(h.root, dir, "laravel-2026-10-31.log-old")); err != nil {
		t.Fatal(err)
	}
	h.write(dir+"/laravel-2026-10-31.log", "")
	h.write(dir+"/laravel-2026-11-01.log", appError("first error of the day"))
	clock.now = clock.now.Add(replanEvery)
	if got := messages(c.Poll(context.Background())); !slices.Equal(got, []string{"first error of the day"}) {
		t.Fatalf("events = %v, want the new daily file from its start", got)
	}
}

func TestReadFilesContinuesOnlyTheSameRotatedFile(t *testing.T) {
	dir := t.TempDir()
	open := func(name, content string) (*os.File, fileID, int64) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		return f, fileIDOf(info), info.Size()
	}
	rotated, id, size := open("app.log.1", strings.Repeat("old line\n", 20))
	other, _, otherSize := open("other.log", strings.Repeat("new line\n", 30))

	r := newReadFiles()
	r.planned()
	r.finished(rotated, id, size)
	if _, ok := r.resume(other, id, otherSize); ok {
		t.Fatal("a new file that got the inode number back must not be continued")
	}
	r.finished(rotated, id, size)
	r.polled()
	r.planned()
	if offset, ok := r.resume(rotated, id, size); !ok || offset != size {
		t.Fatalf("resume = %d, %v; want the end the other tailer reached, until the next plan was polled", offset, ok)
	}
	if _, ok := r.resume(rotated, id, size); ok {
		t.Fatal("a read end is continued only once")
	}
	r.finished(rotated, id, size)
	r.planned()
	r.polled()
	if _, ok := r.resume(rotated, id, size); ok || len(r.done) != 0 {
		t.Fatal("a read end must be forgotten once the next plan was polled")
	}

	deleted, deletedID, deletedSize := open("deleted.log", "line\n")
	os.Remove(deleted.Name())
	r.finished(deleted, deletedID, deletedSize)
	if _, ok := r.done[deletedID]; ok {
		t.Fatal("a deleted file cannot be found again and must not be remembered")
	}

	holder, waiting := &Tailer{}, &Tailer{}
	if !r.acquire(id, holder) || r.acquire(id, waiting) {
		t.Fatal("a file held by one tailer must not be read by another")
	}
	r.release(id, holder)
	if !r.acquire(id, waiting) {
		t.Fatal("a released file must be readable")
	}
}
