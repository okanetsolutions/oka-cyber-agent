package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/okanetsolutions/oka-cyber-agent/internal/trustedcmd"
)

// uninstall, enroll and status run as root, so a command planted in a directory of root's PATH must not run.
func TestRootCommandsIgnoreThePath(t *testing.T) {
	planted, system := t.TempDir(), t.TempDir()
	marker := filepath.Join(planted, "ran")
	for _, name := range []string{"systemctl", "userdel", "deluser"} {
		if err := os.WriteFile(filepath.Join(planted, name), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", planted)
	previous := trustedcmd.Dirs
	trustedcmd.Dirs = []string{system}
	t.Cleanup(func() { trustedcmd.Dirs = previous })

	if _, err := trustedCommand(context.Background(), "systemctl", "--version"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("trustedCommand found systemctl outside the system directories: %v", err)
	}
	if run := systemctl(); run != nil {
		t.Fatal("systemctl() returned a runner for a systemctl that is only in PATH")
	}
	if err := deleteUser(context.Background(), "nobody-here"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("deleteUser = %v, want exec.ErrNotFound", err)
	}
	if got := systemdVersion(context.Background()); got != 0 {
		t.Fatalf("systemdVersion = %d, want 0 without a system systemctl", got)
	}
	if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a command planted in PATH was run")
	}

	if err := os.WriteFile(filepath.Join(system, "systemctl"), []byte("#!/bin/sh\necho \"systemd 239 (239-82.el8)\"\necho \"PATH=$PATH\" >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := systemdVersion(context.Background()); got != 239 {
		t.Fatalf("systemdVersion = %d, want 239 from the system systemctl", got)
	}
}
