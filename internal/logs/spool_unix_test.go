//go:build unix

package logs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

func TestSpoolModesDoNotDependOnTheUmask(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool")}
	previous := syscall.Umask(0o377)
	t.Cleanup(func() { syscall.Umask(previous) })
	if err := s.Append(batchOf(1, "")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDropped(2); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(s.Dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("spool dir mode = %v, %v", info.Mode().Perm(), err)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	for _, e := range entries {
		if info, err := e.Info(); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, %v", e.Name(), info.Mode().Perm(), err)
		}
	}
}

func TestSpoolRefusesASymlinkedDirectory(t *testing.T) {
	stateDir, elsewhere := t.TempDir(), t.TempDir()
	dir := filepath.Join(stateDir, "spool")
	if err := os.Symlink(elsewhere, dir); err != nil {
		t.Fatal(err)
	}
	s := Spool{Dir: dir}
	if err := s.Append(batchOf(1, "")); err == nil {
		t.Fatal("Append wrote through a symlinked spool directory")
	}
	if err := s.AddDropped(1); err == nil {
		t.Fatal("AddDropped wrote through a symlinked spool directory")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("files written outside the state directory: %v", entries)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the symlink is still there: %v", err)
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Fatalf("Clear followed the symlink: %v", err)
	}
}

func TestSpoolDoesNotBlockOnAFIFO(t *testing.T) {
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool")}
	good := batchOf(1, "")
	if err := s.Append(good); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(s.Dir, "00000000000000000000-9.json.gz"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.Dir, droppedFileName)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(s.Dir, droppedFileName), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan Batch, 1)
	go func() {
		b, _, _, _ := s.Oldest()
		_ = s.Dropped()
		done <- b
	}()
	select {
	case b := <-done:
		if b.ID != good.ID {
			t.Fatalf("oldest = %s, want the regular batch", b.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the spool blocked on a FIFO")
	}
}

func TestRootSpoolGivesItsFilesToTheOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files to another user")
	}
	const serviceUID, serviceGID = 65534, 65534
	s := Spool{Dir: filepath.Join(t.TempDir(), "spool"), Owner: &config.Owner{UID: serviceUID, GID: serviceGID}}
	if err := s.Append(batchOf(1, "")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDropped(1); err != nil {
		t.Fatal(err)
	}
	paths := []string{s.Dir}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		paths = append(paths, filepath.Join(s.Dir, e.Name()))
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		if st.Uid != serviceUID || st.Gid != serviceGID {
			t.Fatalf("%s is owned by %d:%d, want %d:%d", path, st.Uid, st.Gid, serviceUID, serviceGID)
		}
	}
}
