package logs

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func openDescriptors(t *testing.T) int {
	t.Helper()
	names, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(names)
}

// Whoever owns an application's log directory decides how many files a glob pattern matches there. Every
// followed file used to cost an open descriptor, a 64 KB read per second and an entry in every checkpoint,
// without a limit: 20 000 empty files held 20 000 descriptors and allocated 1.2 GB per poll.
func TestCollectorFollowsAtMostMaxGlobFilesPerPattern(t *testing.T) {
	h := newHost(t)
	const pattern = "/srv/app/storage/logs/laravel-*.log"
	const files = MaxGlobFiles + 150
	old := testNow.Add(-48 * time.Hour)
	for i := range files {
		path := fmt.Sprintf("/srv/app/storage/logs/laravel-%04d.log", i)
		h.write(path, "")
		// The files with the highest numbers are the oldest, so the kept ones are not the last of the listing.
		if err := os.Chtimes(filepath.Join(h.root, path), old, testNow.Add(-time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	before := openDescriptors(t)
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceApp}, h.options(false, pattern), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	pollWithin(t, c)

	if len(c.watches) != MaxGlobFiles {
		t.Fatalf("%d files followed, want %d", len(c.watches), MaxGlobFiles)
	}
	for i := range files {
		_, followed := c.watches[fmt.Sprintf("/srv/app/storage/logs/laravel-%04d.log", i)]
		if followed != (i < MaxGlobFiles) {
			t.Fatalf("file %d followed = %v: the most recently modified files are the ones to follow", i, followed)
		}
	}
	if open := openDescriptors(t) - before; open > MaxGlobFiles+8 {
		t.Errorf("%d descriptors open for %d files", open, files)
	}
	want := SkippedSource{SourceApp, pattern, ReasonTooManyFiles}
	if skipped := c.Skipped(); !slices.Equal(skipped, []SkippedSource{want}) {
		t.Errorf("skipped = %+v, want the pattern once", skipped)
	}
	if sendable, ok := want.Sendable(); !ok || sendable != want {
		t.Errorf("the server would not accept %+v", want)
	}

	// The files left out become the newest: they are followed now, and the others are let go.
	for i := MaxGlobFiles; i < files; i++ {
		path := filepath.Join(h.root, fmt.Sprintf("/srv/app/storage/logs/laravel-%04d.log", i))
		if err := os.Chtimes(path, old, testNow.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	clock.now = clock.now.Add(replanEvery)
	pollWithin(t, c)
	_, newest := c.watches[fmt.Sprintf("/srv/app/storage/logs/laravel-%04d.log", files-1)]
	if len(c.watches) != MaxGlobFiles || !newest {
		t.Errorf("after the other files were written to: %d files followed, the newest one %v", len(c.watches), newest)
	}
	if open := openDescriptors(t) - before; open > MaxGlobFiles+8 {
		t.Errorf("%d descriptors open after the second plan", open)
	}
}

// A file a pattern still matches but that is refused now (here it became a symlink) is not followed any longer,
// so refused files cannot add up behind the limit.
func TestCollectorLetsGoOfAGlobFileThatIsRefused(t *testing.T) {
	h := newHost(t)
	h.write("/srv/app/logs/a.log", "")
	h.write("/srv/app/logs/b.log", "")
	clock := &fakeClock{now: testNow}
	c := NewCollector([]string{SourceApp}, h.options(false, "/srv/app/logs/*.log"), Checkpoint{}, nil, clock.Now)
	defer c.Close()
	pollWithin(t, c)
	if len(c.watches) != 2 {
		t.Fatalf("%d files followed, want 2", len(c.watches))
	}
	if err := os.Remove(filepath.Join(h.root, "/srv/app/logs/a.log")); err != nil {
		t.Fatal(err)
	}
	h.symlink("/etc/hostname", "/srv/app/logs/a.log")
	clock.now = clock.now.Add(replanEvery)
	pollWithin(t, c)
	if _, followed := c.watches["/srv/app/logs/a.log"]; followed || len(c.watches) != 1 {
		t.Errorf("watches = %v", sortedWatchPaths(c.watches))
	}
}

// The checkpoint holds a position per followed file and the agent reads at most 4 MB of it back. File names a
// user chose take up to six bytes each in JSON, so the paths of the planned files have a budget of their own.
func TestCheckpointStaysSmallWhateverTheFileNames(t *testing.T) {
	h := newHost(t)
	var patterns []string
	name := strings.Repeat("\x01<", 120)
	for dir := range MaxAppPaths {
		patterns = append(patterns, fmt.Sprintf("/srv/app%d/logs/*.log", dir))
		for i := range 60 {
			h.write(fmt.Sprintf("/srv/app%d/logs/%s%02d.log", dir, name, i), "")
		}
	}
	c := NewCollector([]string{SourceApp}, h.options(false, patterns...), Checkpoint{}, nil, (&fakeClock{now: testNow}).Now)
	defer c.Close()
	pollWithin(t, c)
	data, err := json.Marshal(c.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.watches) == 0 || len(c.watches) == MaxAppPaths*60 || len(data) > 1<<20 {
		t.Errorf("%d of %d files followed, checkpoint of %d bytes", len(c.watches), MaxAppPaths*60, len(data))
	}
	if !slices.ContainsFunc(c.Skipped(), func(s SkippedSource) bool { return s.Reason == ReasonTooManyFiles }) {
		t.Errorf("skipped = %d entries, none says too_many_files", len(c.Skipped()))
	}
}

func TestReadDirNamesGivesUpOnAHugeDirectory(t *testing.T) {
	dir := t.TempDir()
	for i := range maxListedNames {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if names, err := readDirNames(dir); err != nil || len(names) != maxListedNames {
		t.Fatalf("%d names, %v", len(names), err)
	}
	if err := os.WriteFile(filepath.Join(dir, "one-more"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if names, err := readDirNames(dir); !errors.Is(err, errTooManyNames) || names != nil {
		t.Fatalf("%d names, %v", len(names), err)
	}
}

// A poll of a file with nothing new must not take the 64 KB line buffer a read needs.
func TestTailerDoesNotReadAFileWithNothingNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	appendTo(t, path, "one\ntwo\n")
	tailer, _ := newTestTailer(path, nil, false)
	defer tailer.Close()
	if got := lines(tailer.Poll()); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("lines = %q", got)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 200 {
		if r := tailer.Poll(); len(r.Lines) != 0 || r.Err != nil {
			t.Fatalf("poll = %+v", r)
		}
	}
	runtime.ReadMemStats(&after)
	if perPoll := (after.TotalAlloc - before.TotalAlloc) / 200; perPoll > maxLineBytes/8 {
		t.Errorf("an idle poll allocates %d bytes", perPoll)
	}
	appendTo(t, path, "three\npart")
	if got := lines(tailer.Poll()); !slices.Equal(got, []string{"three"}) {
		t.Fatalf("lines = %q", got)
	}
	appendTo(t, path, "ial\n")
	if got := lines(tailer.Poll()); !slices.Equal(got, []string{"partial"}) {
		t.Fatalf("lines = %q", got)
	}
}

var regexpSpoolName = regexp.MustCompile(`^\d{20}-\d+\.json\.gz$`)

func accessLine(path string) string {
	return `203.0.113.9 - - [31/Oct/2026:19:00:00 +0000] "GET ` + path + ` HTTP/1.1" 404 153 "-" "curl/8"` + "\n"
}

// The owner of the web server's log (www-data on Debian) can link it into the log directory of an application.
// The two tailers share the file by device and inode, and when the application's one opened it first, right
// after a rotation, the web source waited for it forever: no web event, and nothing listed as skipped. An
// application log with a second name is refused, so the web source keeps reading.
func TestHardLinkCannotTakeTheWebLogAway(t *testing.T) {
	for name, appPath := range map[string]string{"glob": "/srv/app/storage/logs/*.log", "named in full": "/srv/app/storage/logs/zz.log"} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t)
			h.write("/var/log/nginx/access.log", accessLine("/old"))
			h.write("/srv/app/storage/logs/app.log", "")
			clock := &fakeClock{now: testNow}
			c := NewCollector([]string{SourceApp, SourceWeb}, h.options(false, appPath), Checkpoint{}, nil, clock.Now)
			defer c.Close()
			pollWithin(t, c)

			access := filepath.Join(h.root, "/var/log/nginx/access.log")
			link := filepath.Join(h.root, "/srv/app/storage/logs/zz.log")
			if err := os.Rename(access, access+".1"); err != nil {
				t.Fatal(err)
			}
			h.write("/var/log/nginx/access.log", accessLine("/after-rotation"))
			if err := os.Link(access, link); err != nil {
				t.Skip("no hard links here: ", err)
			}
			clock.now = clock.now.Add(replanEvery)
			events := pollWithin(t, c)
			for i := range 3 {
				h.append("/var/log/nginx/access.log", accessLine(fmt.Sprintf("/attack-%d", i)))
				clock.now = clock.now.Add(replanEvery)
				events = append(events, pollWithin(t, c)...)
			}
			var paths []string
			for _, e := range events {
				if e.Source != SourceWeb || e.Kind != KindHTTPRequest {
					t.Errorf("event %+v", e)
				}
				paths = append(paths, fmt.Sprint(e.Fields["path"]))
			}
			if want := []string{"/after-rotation", "/attack-0", "/attack-1", "/attack-2"}; !slices.Equal(paths, want) {
				t.Errorf("web requests read = %q, want %q", paths, want)
			}
			if want := (SkippedSource{SourceApp, "/srv/app/storage/logs/zz.log", ReasonHardLink}); !slices.Contains(c.Skipped(), want) {
				t.Errorf("skipped = %+v, want %+v", c.Skipped(), want)
			}
			if _, followed := c.watches["/srv/app/storage/logs/zz.log"]; followed && c.watches["/srv/app/storage/logs/zz.log"].tailer.file != nil {
				t.Error("the application tailer holds the linked file")
			}
		})
	}
}

// A file that gets its second name after the plan found it is refused when it is opened.
func TestTailerRefusesAFileWithASecondName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	appendTo(t, path, "one\n")
	if err := os.Link(path, filepath.Join(dir, "other")); err != nil {
		t.Skip("no hard links here: ", err)
	}
	tailer, _ := newTestTailer(path, nil, false)
	tailer.RefuseHardLinks = true
	if r := tailer.Poll(); len(r.Lines) != 0 || !r.Missing || tailer.file != nil {
		t.Fatalf("poll = %+v", r)
	}
	builtin, _ := newTestTailer(path, nil, false)
	defer builtin.Close()
	if got := lines(builtin.Poll()); !slices.Equal(got, []string{"one"}) {
		t.Fatalf("a built in source reads a file whatever its links: %q", got)
	}
}

func webBatch(t *testing.T, events int) Batch {
	t.Helper()
	b := Batch{ID: NewBatchID(), CreatedAt: testNow}
	for range events {
		noise := make([]byte, 600)
		if _, err := rand.Read(noise); err != nil {
			t.Fatal(err)
		}
		e := newEvent(SourceWeb, KindHTTPRequest, testNow, "GET /"+hex.EncodeToString(noise))
		e.set("status", 404)
		b.Events = append(b.Events, e)
	}
	return b
}

func spooledKinds(t *testing.T, s Spool) []string {
	t.Helper()
	dir, err := s.open(false)
	if err != nil || dir == nil {
		t.Fatal(err)
	}
	defer dir.Close()
	entries, err := spoolEntries(dir)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, entry := range entries {
		b, err := readBatch(dir, entry.name)
		if err != nil {
			t.Fatal(err)
		}
		kind := "empty"
		if len(b.Events) > 0 {
			kind = b.Events[0].Source
		}
		kinds = append(kinds, kind)
	}
	return kinds
}

// While uploads are stalled a flood of web requests fills the spool. It used to push out the oldest batches
// whatever they held, so about a thousand requests per megabyte of spool made a login disappear. Web and
// application batches go first now, and the others only when there is nothing else to drop.
func TestSpoolDropsWebAndAppBatchesBeforeLogins(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool"), MaxBytes: 1 << 20}
	login := Batch{ID: NewBatchID(), CreatedAt: testNow, Checkpoint: Checkpoint{JournalCursor: "c1"},
		Events: []Event{newEvent(SourceAuth, KindSSHLoginSucceeded, testNow, "Accepted password for root from 198.51.100.7 port 4242 ssh2")}}
	command := Batch{ID: NewBatchID(), CreatedAt: testNow, Events: []Event{newEvent(SourceCommands, KindCommand, testNow, "/usr/bin/id [0 args]")}}
	for _, b := range []Batch{login, command} {
		if err := s.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	for range 40 {
		if err := s.Append(webBatch(t, 100)); err != nil {
			t.Fatal(err)
		}
	}
	kinds := spooledKinds(t, s)
	if len(kinds) < 3 || kinds[0] != SourceAuth || kinds[1] != SourceCommands || slices.Contains(kinds[2:], SourceAuth) {
		t.Fatalf("spool = %v, want the login and the command first", kinds)
	}
	if got, _, ok, err := s.Oldest(); err != nil || !ok || got.ID != login.ID || got.Checkpoint.JournalCursor != "c1" {
		t.Fatalf("oldest = %+v, %v, %v", got.ID, ok, err)
	}
	if dropped := s.Dropped(); dropped < 2000 || dropped%100 != 0 {
		t.Errorf("dropped = %d, want whole web batches", dropped)
	}

	// With nothing but logins left to drop, the oldest go, as before, and the newest batch stays.
	only := Spool{Dir: filepath.Join(t.TempDir(), "spool"), MaxBytes: 1}
	first, second, third := batchOf(3, "c1"), batchOf(3, "c2"), batchOf(3, "c3")
	for _, b := range []Batch{first, second, third} {
		if err := only.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	if got, _, ok, _ := only.Oldest(); !ok || got.ID != third.ID || only.Dropped() != 6 {
		t.Fatalf("oldest = %+v, dropped = %d", got.ID, only.Dropped())
	}
}

// One flush holds the events of every source, so the web and application events of a batch are spooled as a
// part of their own, which cannot commit the checkpoint: it also covers the events of the part after it.
func TestSpoolWritesWebEventsOfABatchApart(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool"), MaxBytes: 1 << 20}
	mixed := webBatch(t, 50)
	mixed.Checkpoint = Checkpoint{JournalCursor: "c1"}
	login := newEvent(SourceAuth, KindSSHLoginSucceeded, testNow, "Accepted password for root from 198.51.100.7 port 4242 ssh2")
	mixed.Events = slices.Insert(mixed.Events, 25, login)
	mixed.Events = append(mixed.Events, newEvent(SourceApp, KindAppError, testNow, "failed"))
	if err := s.Append(mixed); err != nil {
		t.Fatal(err)
	}
	web, name, ok, err := s.Oldest()
	if err != nil || !ok || len(web.Events) != 51 || !web.Partial || web.ID == mixed.ID || web.Checkpoint.JournalCursor != "c1" || slices.ContainsFunc(web.Events, func(e Event) bool { return !lowPriorityEvent(e) }) {
		t.Fatalf("first part = %d events, partial %v, %v, %v", len(web.Events), web.Partial, ok, err)
	}
	if err := s.Remove(name); err != nil {
		t.Fatal(err)
	}
	rest, _, ok, err := s.Oldest()
	if err != nil || !ok || len(rest.Events) != 1 || rest.Events[0].Kind != KindSSHLoginSucceeded || rest.Partial || rest.ID != mixed.ID || rest.Checkpoint.JournalCursor != "c1" {
		t.Fatalf("second part = %+v, %v, %v", rest, ok, err)
	}
	if kinds := spooledKinds(t, s); !slices.Equal(kinds, []string{SourceAuth}) {
		t.Fatalf("spool = %v", kinds)
	}

	for range 40 {
		if err := s.Append(webBatch(t, 100)); err != nil {
			t.Fatal(err)
		}
	}
	if got, _, ok, _ := s.Oldest(); !ok || got.ID != mixed.ID {
		t.Fatalf("the login of the mixed batch was dropped: oldest = %+v", got.ID)
	}
}

// A spool file of an agent without the priority rule has no mark in its gzip header: it is read as before and
// kept as long as a login, and the files written now are plain gzip JSON such an agent reads.
func TestSpoolFilesReadableAcrossVersions(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool"), MaxBytes: 1 << 20}
	dir, err := s.open(true)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	old := webBatch(t, 10)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(old); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	const oldName = "00000000000000000001-10.json.gz"
	if err := s.writeAtomic(dir, oldName, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if lowPriority(dir, oldName) {
		t.Fatal("a file without the mark may not go first")
	}
	for range 40 {
		if err := s.Append(webBatch(t, 100)); err != nil {
			t.Fatal(err)
		}
	}
	if got, _, ok, err := s.Oldest(); err != nil || !ok || got.ID != old.ID || len(got.Events) != 10 {
		t.Fatalf("oldest = %+v, %v, %v", got.ID, ok, err)
	}

	newest, err := s.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer newest.Close()
	entries, err := spoolEntries(newest)
	if err != nil || len(entries) < 2 {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if !lowPriority(newest, last.name) || !regexpSpoolName.MatchString(last.name) {
		t.Fatalf("%s: a web batch carries the mark under a name of the same form", last.name)
	}
	data, err := readRegular(newest, last.name, maxSpoolRead)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var b Batch
	if err := json.NewDecoder(zr).Decode(&b); err != nil || len(b.Events) != 100 {
		t.Fatalf("%d events, %v", len(b.Events), err)
	}
}

// On a host without the files, the limits above add no skipped source of their own.
func TestLimitsAddNoSkippedSourceOnAnEmptyHost(t *testing.T) {
	c := NewCollector([]string{SourceApp, SourceWeb}, newHost(t).options(false, "/srv/none-*.log"), Checkpoint{}, nil, (&fakeClock{now: testNow}).Now)
	defer c.Close()
	c.Poll(context.Background())
	for _, s := range c.Skipped() {
		if s.Reason != ReasonNotFound {
			t.Errorf("skipped = %+v", s)
		}
	}
}
