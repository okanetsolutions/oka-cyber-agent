package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func newTestTailer(path string, resume *Position, startAtEnd bool) (*Tailer, *fakeClock) {
	clock := &fakeClock{now: testNow}
	t := NewTailer(path, resume, startAtEnd)
	t.Now = clock.Now
	return t, clock
}

func lines(r PollResult) []string { return r.Lines }

func TestTailerReadsCompleteLinesOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "one\ntwo\npart")
	tail, _ := newTestTailer(path, nil, false)
	if got := lines(tail.Poll()); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("lines = %q", got)
	}
	appendTo(t, path, "ial\r\nthree\n")
	if got := lines(tail.Poll()); !slices.Equal(got, []string{"partial", "three"}) {
		t.Fatalf("lines = %q, want the partial line completed", got)
	}
	if got := lines(tail.Poll()); len(got) != 0 {
		t.Fatalf("lines = %q, want nothing new", got)
	}
}

func TestTailerStartAtEndSkipsHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "old\n")
	tail, _ := newTestTailer(path, nil, true)
	if got := lines(tail.Poll()); len(got) != 0 {
		t.Fatalf("lines = %q, want no history", got)
	}
	appendTo(t, path, "new\n")
	if got := lines(tail.Poll()); !slices.Equal(got, []string{"new"}) {
		t.Fatalf("lines = %q", got)
	}
}

func TestTailerResumesSameFileAndRestartsRotatedOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "a\nb\n")
	first, _ := newTestTailer(path, nil, false)
	first.Poll()
	pos := first.Position()
	first.Close()
	appendTo(t, path, "c\n")
	resumed, _ := newTestTailer(path, &pos, true)
	if got := lines(resumed.Poll()); !slices.Equal(got, []string{"c"}) {
		t.Fatalf("resumed lines = %q", got)
	}
	resumed.Close()

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, "fresh\n")
	other, _ := newTestTailer(path, &pos, true)
	if got := lines(other.Poll()); !slices.Equal(got, []string{"fresh"}) {
		t.Fatalf("a saved position of another inode must not apply: %q", got)
	}
}

func TestTailerFollowsRenameRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	appendTo(t, path, "1\n")
	tail, _ := newTestTailer(path, nil, false)
	tail.Poll()
	appendTo(t, path, "2\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path+".1", "3\n")
	appendTo(t, path, "4\n")
	if got := lines(tail.Poll()); !slices.Equal(got, []string{"2", "3", "4"}) {
		t.Fatalf("lines = %q, want the rest of the old file, then the new one", got)
	}
}

func TestTailerFollowsCopyTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	appendTo(t, path, "1\n2\n")
	tail, _ := newTestTailer(path, nil, false)
	tail.Poll()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, "3\n")
	if got := lines(tail.Poll()); !slices.Equal(got, []string{"3"}) {
		t.Fatalf("lines = %q", got)
	}
}

func TestTailerLateCreationAndRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "laravel.log")
	tail, clock := newTestTailer(path, nil, true)
	if r := tail.Poll(); len(r.Lines) != 0 || r.Removed || r.Err != nil {
		t.Fatalf("missing file = %+v", r)
	}
	appendTo(t, path, "created later\n")
	if got := lines(tail.Poll()); !slices.Equal(got, []string{"created later"}) {
		t.Fatalf("a file created after start must be read from its beginning: %q", got)
	}

	appendTo(t, path, "last words\n")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if r := tail.Poll(); !slices.Equal(r.Lines, []string{"last words"}) || r.Removed {
		t.Fatalf("first poll after removal = %+v", r)
	}
	clock.now = clock.now.Add(RemovedAfter - time.Second)
	if r := tail.Poll(); r.Removed {
		t.Fatal("removal reported too early")
	}
	clock.now = clock.now.Add(time.Second)
	if r := tail.Poll(); !r.Removed {
		t.Fatal("removal not reported after 5 minutes")
	}
	clock.now = clock.now.Add(time.Hour)
	if r := tail.Poll(); r.Removed {
		t.Fatal("removal reported twice")
	}
}

func TestTailerRecreatedFileIsNotRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "x\n")
	tail, clock := newTestTailer(path, nil, false)
	tail.Poll()
	os.Remove(path)
	tail.Poll()
	clock.now = clock.now.Add(time.Minute)
	appendTo(t, path, "y\n")
	if got := lines(tail.Poll()); !slices.Equal(got, []string{"y"}) {
		t.Fatalf("lines = %q", got)
	}
	clock.now = clock.now.Add(time.Hour)
	if r := tail.Poll(); r.Removed {
		t.Fatal("a recreated file must not be reported as removed")
	}
}

func TestTailerCutsVeryLongLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	long := strings.Repeat("a", maxLineBytes*2+10)
	appendTo(t, path, long+"\nnext\n")
	tail, _ := newTestTailer(path, nil, false)
	got := lines(tail.Poll())
	if len(got) != 2 || len(got[0]) != maxLineBytes || got[1] != "next" {
		t.Fatalf("lines = %d, first %d bytes", len(got), len(got[0]))
	}
	if pos := tail.Position(); pos.Offset != int64(len(long)+len("\nnext\n")) {
		t.Fatalf("offset = %d", pos.Offset)
	}
}

func TestTailerReportsUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of mode")
	}
	path := filepath.Join(t.TempDir(), "secure")
	appendTo(t, path, "x\n")
	os.Chmod(path, 0)
	tail, _ := newTestTailer(path, nil, false)
	if r := tail.Poll(); r.Err == nil {
		t.Fatal("want a permission error")
	}
}

func TestTailerRecreatedFileWithReusedInodeIsReadFromStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "old line\n")
	tail, _ := newTestTailer(path, nil, false)
	tail.Poll()
	os.Remove(path)
	tail.Poll()
	appendTo(t, path, "new line\n")
	if got := lines(tail.Poll()); !slices.Equal(got, []string{"new line"}) {
		t.Fatalf("lines = %q", got)
	}
}

func inodeOfPath(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return inodeOf(info)
}

// A rename keeps the inode number, so moving a prepared file into place recreates the watched file with the
// inode of the saved position, as a filesystem that hands a freed inode number back does.
func TestTailerForgetsSavedPositionOfAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	staged := path + ".new"
	appendTo(t, staged, "first line\n"+strings.Repeat("x", 9000)+"\nlast line\n")
	tail, _ := newTestTailer(path, &Position{Inode: inodeOfPath(t, staged), Offset: 9000}, false)
	if r := tail.Poll(); !r.Missing {
		t.Fatalf("poll = %+v, want missing", r)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
	if got := lines(tail.Poll()); len(got) != 3 || got[0] != "first line" {
		t.Fatalf("lines = %.40q, want the recreated file from its start", got)
	}
}

// backlog appends numbered lines past maxReadBytes, so reading them takes three polls.
func backlog(t *testing.T, path string) []string {
	t.Helper()
	var want []string
	var b strings.Builder
	for i := 0; b.Len() < 2*maxReadBytes+maxReadBytes/2; i++ {
		line := fmt.Sprintf("old %06d %s", i, strings.Repeat("x", 80))
		want = append(want, line)
		b.WriteString(line + "\n")
	}
	appendTo(t, path, b.String())
	return want
}

func TestTailerReadsAllOfARotatedFileBeforeTheNewOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	appendTo(t, path, "first\n")
	tail, _ := newTestTailer(path, nil, false)
	tail.Poll()
	want := backlog(t, path)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, "new 1\n")
	want = append(want, "new 1")

	var got []string
	polls := 0
	for ; polls < 10; polls++ {
		r := tail.Poll()
		if len(r.Lines) == 0 {
			break
		}
		if r.Missing || r.Err != nil {
			t.Fatalf("poll %d = missing %v, err %v", polls, r.Missing, r.Err)
		}
		got = append(got, r.Lines...)
	}
	if polls != 3 {
		t.Fatalf("read in %d polls, want 3 bounded ones", polls)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("read %d lines, want %d: every old line in order, then the new file", len(got), len(want))
	}
}

func TestTailerReadsAllOfADeletedFileBeforeReportingItMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "laravel-2026-11-01.log")
	appendTo(t, path, "first\n")
	tail, _ := newTestTailer(path, nil, false)
	tail.Poll()
	want := backlog(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var got []string
	for range 10 {
		r := tail.Poll()
		got = append(got, r.Lines...)
		if r.Missing {
			break
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("read %d lines before missing, want %d", len(got), len(want))
	}
}

func TestTailerRestartWhileReadingARotatedFileReadsTheNewOneFromItsStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	appendTo(t, path, "first\n")
	tail, _ := newTestTailer(path, nil, false)
	tail.Poll()
	backlog(t, path)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, "new 1\n")
	if got := lines(tail.Poll()); len(got) == 0 || slices.Contains(got, "new 1") {
		t.Fatalf("first poll read %d lines, want only old ones", len(got))
	}
	pos := tail.Position()
	if pos.Inode != inodeOfPath(t, path+".1") {
		t.Fatalf("position %+v is not in the rotated file", pos)
	}
	tail.Close()

	restarted, _ := newTestTailer(path, &pos, false)
	if got := lines(restarted.Poll()); !slices.Equal(got, []string{"new 1"}) {
		t.Fatalf("lines after restart = %.60q, want the new file from its start", got)
	}
}
