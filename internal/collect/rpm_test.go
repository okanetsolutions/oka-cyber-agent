package collect

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/okanetsolutions/oka-cyber-agent/internal/trustedcmd"
)

// plantCommand writes an executable shell script that creates marker when run and prints output.
func plantCommand(t *testing.T, dir, name, marker, output string) {
	t.Helper()
	script := "#!/bin/sh\n: > '" + marker + "'\necho " + output + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func withTrustedCommandDirs(t *testing.T, dirs ...string) {
	t.Helper()
	previous := trustedcmd.Dirs
	trustedcmd.Dirs = dirs
	t.Cleanup(func() { trustedcmd.Dirs = previous })
}

func TestRunCommandIgnoresTheAgentPath(t *testing.T) {
	scratch := t.TempDir()
	untrusted, trusted := filepath.Join(scratch, "untrusted"), filepath.Join(scratch, "trusted")
	for _, dir := range []string{untrusted, trusted} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	planted := filepath.Join(scratch, "planted-ran")
	plantCommand(t, untrusted, "rpm", planted, "planted")
	t.Setenv("PATH", untrusted+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Run("missing from the trusted directories", func(t *testing.T) {
		withTrustedCommandDirs(t, trusted)
		if _, err := runCommand(context.Background(), "rpm", "--version"); !errors.Is(err, exec.ErrNotFound) {
			t.Fatalf("runCommand error = %v, want exec.ErrNotFound", err)
		}
		if _, err := os.Stat(planted); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the rpm planted first in PATH was executed")
		}
	})

	t.Run("present in a trusted directory", func(t *testing.T) {
		withTrustedCommandDirs(t, trusted)
		plantCommand(t, trusted, "rpm", filepath.Join(scratch, "trusted-ran"), "trusted")
		output, err := runCommand(context.Background(), "rpm", "--version")
		if err != nil {
			t.Fatalf("runCommand: %v", err)
		}
		if string(output) != "trusted\n" {
			t.Fatalf("output = %q, want the trusted rpm", output)
		}
		if _, err := os.Stat(planted); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the rpm planted first in PATH was executed")
		}
	})
}
