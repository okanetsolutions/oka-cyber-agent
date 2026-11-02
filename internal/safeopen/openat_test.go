package safeopen

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenAtRefusesSymlinksAndDoesNotBlockOnFIFOs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "file"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	if _, err := OpenAt(dir, "link", os.O_RDONLY); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("OpenAt(link) = %v, want ELOOP", err)
	}
	f, err := FollowAt(dir, "link", os.O_RDONLY)
	if err != nil {
		t.Fatalf("FollowAt(link) = %v", err)
	}
	f.Close()
	f, err = OpenAt(dir, "file", os.O_RDONLY)
	if err != nil || f.Name() != filepath.Join(root, "file") {
		t.Fatalf("OpenAt(file) = %v, %v", f, err)
	}
	f.Close()

	done := make(chan error, 1)
	go func() {
		f, err := OpenAt(dir, "fifo", os.O_RDONLY)
		if err == nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("OpenAt(fifo) = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OpenAt blocked on a FIFO")
	}
}
