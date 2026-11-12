package safeopen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

func TestReadlinkAtReadsTheLinkInTheOpenDirectory(t *testing.T) {
	root := t.TempDir()
	long := "/" + strings.Repeat("a/", 300) + "target"
	for name, target := range map[string]string{"short": "releases/3", "long": long} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	for name, want := range map[string]string{"short": "releases/3", "long": long} {
		if got, err := ReadlinkAt(dir, name); err != nil || got != want {
			t.Fatalf("ReadlinkAt(%s) = %q, %v, want %q", name, got, err, want)
		}
	}
	if _, err := ReadlinkAt(dir, "file"); err == nil {
		t.Fatal("ReadlinkAt(file) gave no error")
	}
	if _, err := ReadlinkAt(dir, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadlinkAt(missing) = %v, want not exist", err)
	}
}
