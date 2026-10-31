package logs

import (
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
	entries, _ := s.entries()
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
