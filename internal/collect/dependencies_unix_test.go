//go:build unix

package collect

import (
	"context"
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
