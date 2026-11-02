package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func batchOf(n int, cursor string) Batch {
	b := Batch{ID: NewBatchID(), Checkpoint: Checkpoint{Sources: []string{SourceAuth}, JournalCursor: cursor}, CreatedAt: testNow}
	for range n {
		b.Events = append(b.Events, newEvent(SourceAuth, KindSudoCommand, testNow, strings.Repeat("x", 100)))
	}
	return b
}

func TestSpoolIsFirstInFirstOut(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool")}
	if _, _, ok, err := s.Oldest(); ok || err != nil || !s.Empty() {
		t.Fatal("a new spool is empty")
	}
	first, second := batchOf(2, "c1"), batchOf(0, "c2")
	for _, b := range []Batch{first, second} {
		if err := s.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	got, path, ok, err := s.Oldest()
	if err != nil || !ok || got.ID != first.ID || len(got.Events) != 2 {
		t.Fatalf("oldest = %+v, %v, %v", got.ID, ok, err)
	}
	if newest, ok := s.Newest(); !ok || newest.Checkpoint.JournalCursor != "c2" {
		t.Fatalf("newest = %+v", newest)
	}
	if err := s.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, _, _, _ := s.Oldest(); got.ID != second.ID {
		t.Fatalf("oldest after remove = %s", got.ID)
	}
	info, err := os.Stat(s.Dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("spool dir mode = %v, %v", info.Mode().Perm(), err)
	}
}

func TestSpoolDropsOldestWhenFull(t *testing.T) {
	s := Spool{Dir: t.TempDir(), MaxBytes: 1}
	for i := range 3 {
		if err := s.Append(batchOf(5+i, "")); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := s.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	entries, _ := spoolEntries(dir)
	if len(entries) != 1 || entries[0].events != 7 {
		t.Fatalf("entries = %+v, want only the newest batch", entries)
	}
	if s.Dropped() != 11 {
		t.Fatalf("dropped = %d, want 5 + 6", s.Dropped())
	}
	s.AddDropped(-11)
	if s.Dropped() != 0 {
		t.Fatalf("dropped = %d", s.Dropped())
	}
}

func TestSpoolDropsUnreadableBatches(t *testing.T) {
	s := Spool{Dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(s.Dir, "00000000000000000001-4.json.gz"), []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := batchOf(1, "")
	s.Append(good)
	if got, _, ok, _ := s.Oldest(); !ok || got.ID != good.ID || s.Dropped() != 4 {
		t.Fatalf("oldest = %s, dropped = %d", got.ID, s.Dropped())
	}
}

func TestSpoolClear(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool")}
	s.Append(batchOf(1, ""))
	s.AddDropped(3)
	if err := s.Clear(); err != nil || !s.Empty() || s.Dropped() != 0 {
		t.Fatalf("clear = %v", err)
	}
}

func TestNewBatchIDIsUUIDv4(t *testing.T) {
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 100 {
		id := NewBatchID()
		if !uuid.MatchString(id) || seen[id] {
			t.Fatalf("batch id %q", id)
		}
		seen[id] = true
	}
}

func TestSpoolReplaceKeepsTheOrder(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool")}
	first, second := batchOf(4, "c1"), batchOf(1, "c2")
	for _, b := range []Batch{first, second} {
		if err := s.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	_, name, _, _ := s.Oldest()
	left, right := batchOf(2, "c1"), batchOf(2, "c1")
	left.Partial = true
	if err := s.Replace(name, []Batch{left, right}); err != nil {
		t.Fatal(err)
	}
	// A part replaced in turn gets its parts in its own place, before the next part.
	_, leftName, _, _ := s.Oldest()
	if err := s.Replace(leftName, []Batch{batchOf(1, "c1"), batchOf(1, "c1")}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		b, name, ok, err := s.Oldest()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		got = append(got, fmt.Sprintf("%s:%d:%v", name, len(b.Events), b.Partial))
		if err := s.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"00000000000000000001.0.0-1.json.gz:1:false",
		"00000000000000000001.0.1-1.json.gz:1:false",
		"00000000000000000001.1-2.json.gz:2:false",
		"00000000000000000002-1.json.gz:1:false",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v\nwant %v", got, want)
	}

	if err := s.Append(batchOf(0, "c3")); err != nil {
		t.Fatal(err)
	}
	if _, name, _, _ := s.Oldest(); name != "00000000000000000001-0.json.gz" {
		t.Fatalf("name after the spool emptied = %s", name)
	}
}

// TestSpoolReplaceSurvivesAStop leaves the replaced batch next to its parts, as a stop between writing the parts
// and removing it would: the batch is still the oldest, so it is sent and replaced again first.
func TestSpoolReplaceSurvivesAStop(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool")}
	if err := s.Append(batchOf(2, "c1")); err != nil {
		t.Fatal(err)
	}
	original, name, _, _ := s.Oldest()
	data, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	parts := []Batch{batchOf(1, "c1"), batchOf(1, "c1")}
	if err := s.Replace(name, parts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, again, _, _ := s.Oldest(); again != name || b.ID != original.ID {
		t.Fatalf("oldest = %s, want the replaced batch %s first", again, name)
	}
	if err := s.Replace(name, parts); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("spool = %v, %v, want the two parts only", entries, err)
	}
}
