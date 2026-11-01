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

	"github.com/okanetsolutions/oka-cyber-agent/internal/collect/lockfile"
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
	want := []SkippedFile{{"/home/mallory/app/package-lock.json", ReasonParseError}, {"/home/mallory/app/yarn.lock", ReasonSymlink}}
	if !slices.Equal(inv.SkippedFiles, want) {
		t.Fatalf("skipped = %v, want %v", inv.SkippedFiles, want)
	}
}

type listedEntry struct {
	name string
	info fs.FileInfo
}

func (e listedEntry) Name() string               { return e.name }
func (e listedEntry) IsDir() bool                { return e.info.IsDir() }
func (e listedEntry) Type() fs.FileMode          { return e.info.Mode().Type() }
func (e listedEntry) Info() (fs.FileInfo, error) { return e.info, nil }

func openDirectory(t *testing.T, path string) *os.File {
	t.Helper()
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	return dir
}

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
	dir := openDirectory(t, filepath.Join(tr.root, "opt", "tool"))
	listedAs := func(name, listed string) listedEntry {
		fi, err := os.Lstat(filepath.Join(tr.root, "opt", "tool", listed))
		if err != nil {
			t.Fatal(err)
		}
		return listedEntry{name, fi}
	}
	read := func(entry listedEntry) int {
		s := &scan{hostRoot: "/opt", inv: &Inventory{}, seen: map[string]bool{}}
		done := make(chan struct{})
		go func() {
			s.goBinary(dir, "/opt/tool/"+entry.name, entry)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("goBinary(%s) blocked", entry.name)
		}
		return len(s.inv.Packages)
	}

	if read(listedAs("real", "real")) == 0 {
		t.Fatal("the listed binary itself must be read")
	}
	if n := read(listedAs("fifo", "listed")); n != 0 {
		t.Fatalf("a FIFO swapped in gave %d packages", n)
	}
	if n := read(listedAs("link", "listed")); n != 0 {
		t.Fatalf("a symlink swapped in gave %d packages from its target", n)
	}
}

// The walk lists a regular lock file and a real directory, then a local user replaces each with a symlink into
// an excluded directory before they are opened. Neither symlink is followed.
func TestEntriesSwappedForSymlinksAfterTheWalkAreNotFollowed(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/secret/Cargo.lock")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/app/Cargo.lock")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/web/Cargo.lock")
	srv := filepath.Join(tr.root, "srv")
	listed := func(name string) listedEntry {
		fi, err := os.Lstat(filepath.Join(srv, name))
		if err != nil {
			t.Fatal(err)
		}
		return listedEntry{name, fi}
	}
	appDir := openDirectory(t, filepath.Join(srv, "app"))
	lock, web := listed("app/Cargo.lock"), listed("web")
	lock.name = "Cargo.lock"
	if err := os.Remove(filepath.Join(srv, "app", "Cargo.lock")); err != nil {
		t.Fatal(err)
	}
	tr.symlink("../secret/Cargo.lock", "/srv/app/Cargo.lock")
	if err := os.RemoveAll(filepath.Join(srv, "web")); err != nil {
		t.Fatal(err)
	}
	tr.symlink("secret", "/srv/web")

	s := &scan{hostRoot: "/srv", options: DependencyOptions{MaxDepth: 6, MaxFileSize: DefaultMaxFileSize, ExcludePaths: []string{"/srv/secret"}}, inv: &Inventory{}, seen: map[string]bool{}, dirs: map[string][]string{}}
	cargo, _ := lockfile.ForFile("Cargo.lock")
	s.lockFile(appDir, "/srv/app/Cargo.lock", cargo, lock)
	if err := s.directory(context.Background(), openDirectory(t, srv), "web", "/srv/web", web); err != nil {
		t.Fatal(err)
	}
	if len(s.inv.Packages) != 0 {
		t.Fatalf("packages = %+v, want none from the excluded directory", s.inv.Packages)
	}
	if want := []SkippedFile{{"/srv/app/Cargo.lock", ReasonSymlink}}; !slices.Equal(s.inv.SkippedFiles, want) {
		t.Fatalf("skipped = %v, want %v", s.inv.SkippedFiles, want)
	}
}
