//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

// A hardened host runs sudo with a umask of 027 or 077; enroll must still leave the config dir and config.yaml
// readable by the service user, and the token never readable by other users.
func TestEnrollUnderARestrictiveUmask(t *testing.T) {
	useFixtureHost(t)
	_, srv := newFakeTenant(t)
	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })
	configDir := filepath.Join(t.TempDir(), "oka-cyber-agent")

	r := runCLI(t, "", "enroll", "--url", srv.URL, "--token", "enroll-secret", "--insecure-dev", "--config-dir", configDir)
	if r.code != exitOK {
		t.Fatalf("enroll = %+v", r)
	}
	for path, want := range map[string]os.FileMode{configDir: config.DirMode, filepath.Join(configDir, config.FileName): 0o644} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %#o, want %#o", path, got, want)
		}
	}
	info, err := os.Stat(filepath.Join(configDir, config.TokenFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 && got != 0o640 {
		t.Fatalf("token mode = %#o, want 0600 or 0640", got)
	}
}
