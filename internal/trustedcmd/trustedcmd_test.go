package trustedcmd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestLookSkipsNonExecutablesAndRejectsPaths(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	previous := Dirs
	Dirs = []string{first, second}
	t.Cleanup(func() { Dirs = previous })
	if err := os.WriteFile(filepath.Join(first, "rpm"), []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(first, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "rpm"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if path, err := Look("rpm"); err != nil || path != filepath.Join(second, "rpm") {
		t.Fatalf("Look(rpm) = %q, %v; want the executable in the second directory", path, err)
	}
	for _, name := range []string{"", "dir", "missing", "./rpm", filepath.Join(second, "rpm"), "../rpm"} {
		if path, err := Look(name); !errors.Is(err, exec.ErrNotFound) {
			t.Errorf("Look(%q) = %q, %v; want exec.ErrNotFound", name, path, err)
		}
	}
}

func TestLookIgnoresTheAgentPath(t *testing.T) {
	untrusted := t.TempDir()
	if err := os.WriteFile(filepath.Join(untrusted, "journalctl"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	previous := Dirs
	Dirs = []string{t.TempDir()}
	t.Cleanup(func() { Dirs = previous })
	t.Setenv("PATH", untrusted)
	if path, err := Look("journalctl"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("Look(journalctl) = %q, %v; want exec.ErrNotFound", path, err)
	}
}

func TestEnvHasOnlyTheTrustedPath(t *testing.T) {
	previous := Dirs
	Dirs = []string{"/a", "/b"}
	t.Cleanup(func() { Dirs = previous })
	t.Setenv("PATH", "/untrusted")
	want := []string{"LC_ALL=C", "PATH=/a:/b", "SYSTEMD_COLORS=0"}
	if got := Env("SYSTEMD_COLORS=0"); !slices.Equal(got, want) {
		t.Fatalf("Env = %q, want %q", got, want)
	}
}
