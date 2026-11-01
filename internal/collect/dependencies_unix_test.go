//go:build unix

package collect

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestDependencyScanDoesNotBlockOnAFIFO(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/rust/Cargo.lock")
	tr.write("/home/mallory/app/placeholder", "")
	if err := syscall.Mkfifo(filepath.Join(tr.root, "home", "mallory", "app", "package-lock.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr.symlink("package-lock.json", "/home/mallory/app/yarn.lock")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv, err := Run(ctx, DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/home", "/srv"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := manifests(inv); !mapsEqual(got, map[string]int{"/srv/rust/Cargo.lock": 9}) {
		t.Fatalf("manifests = %v, want only the Cargo.lock", got)
	}
	for _, f := range []string{"/home/mallory/app/package-lock.json", "/home/mallory/app/yarn.lock"} {
		if !slices.Contains(inv.SkippedFiles, SkippedFile{Path: f, Reason: ReasonParseError}) {
			t.Fatalf("skipped = %v, want %s skipped", inv.SkippedFiles, f)
		}
	}
}

type listedEntry struct{ info fs.FileInfo }

func (e listedEntry) Name() string               { return e.info.Name() }
func (e listedEntry) IsDir() bool                { return false }
func (e listedEntry) Type() fs.FileMode          { return e.info.Mode().Type() }
func (e listedEntry) Info() (fs.FileInfo, error) { return e.info, nil }

// The walk lists a regular executable, then a local user replaces it before goBinary opens it: a FIFO must not
// block the open, and a symlink to another binary must not be read in its place.
func TestGoBinaryIsNotReadWhenSwappedAfterTheWalk(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tr := tree{t, t.TempDir()}
	tr.copy(self, "/opt/tool/real")
	tr.write("/opt/tool/listed", "\x7fELF placeholder")
	for _, name := range []string{"real", "listed"} {
		if err := os.Chmod(filepath.Join(tr.root, "opt", "tool", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(tr.root, "opt", "tool", "fifo"), 0o755); err != nil {
		t.Fatal(err)
	}
	tr.symlink("real", "/opt/tool/link")
	root, err := os.OpenRoot(filepath.Join(tr.root, "opt"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info := func(name string) listedEntry {
		fi, err := os.Lstat(filepath.Join(tr.root, "opt", "tool", name))
		if err != nil {
			t.Fatal(err)
		}
		return listedEntry{fi}
	}
	read := func(rel string, entry listedEntry) int {
		s := &scan{hostRoot: "/opt", root: root, inv: &Inventory{}, seen: map[string]bool{}}
		done := make(chan struct{})
		go func() {
			s.goBinary(rel, "/opt/"+rel, entry)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("goBinary(%s) blocked", rel)
		}
		return len(s.inv.Packages)
	}

	if read("tool/real", info("real")) == 0 {
		t.Fatal("the listed binary itself must be read")
	}
	if n := read("tool/fifo", info("listed")); n != 0 {
		t.Fatalf("a FIFO swapped in gave %d packages", n)
	}
	if n := read("tool/link", info("listed")); n != 0 {
		t.Fatalf("a symlink swapped in gave %d packages from its target", n)
	}
}
