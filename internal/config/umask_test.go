//go:build unix

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// withUmask sets the process umask for the rest of the test, so tests that call it must not run in parallel.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	previous := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(previous) })
}

func requireMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %#o, want %#o", path, got, want)
	}
}

func TestEnrollmentFilesKeepTheirModesUnderARestrictiveUmask(t *testing.T) {
	withUmask(t, 0o077)
	parent := filepath.Join(t.TempDir(), "etc")
	dir := filepath.Join(parent, "oka-cyber-agent")
	if err := CheckWritable(dir); err != nil {
		t.Fatal(err)
	}
	requireMode(t, parent, DirMode)
	requireMode(t, dir, DirMode)

	if err := Save(dir, validConfig()); err != nil {
		t.Fatal(err)
	}
	requireMode(t, filepath.Join(dir, FileName), 0o644)

	if err := SaveToken(dir, "agent-secret", TokenAccessFor(os.Geteuid(), 0, -1)); err != nil {
		t.Fatal(err)
	}
	requireMode(t, filepath.Join(dir, TokenFileName), 0o600)
	if err := SaveToken(dir, "agent-secret", TokenAccess{Owner: &Owner{UID: os.Getuid(), GID: os.Getgid()}, Mode: 0o640}); err != nil {
		t.Fatal(err)
	}
	requireMode(t, filepath.Join(dir, TokenFileName), 0o640)
}

func TestSaveCreatesAMissingConfigDirUnderARestrictiveUmask(t *testing.T) {
	withUmask(t, 0o027)
	dir := filepath.Join(t.TempDir(), "oka-cyber-agent")
	if err := SaveToken(dir, "agent-secret", TokenAccessFor(os.Geteuid(), 0, -1)); err != nil {
		t.Fatal(err)
	}
	requireMode(t, dir, DirMode)
	requireMode(t, filepath.Join(dir, TokenFileName), 0o600)
}

func TestAnExistingConfigDirKeepsItsMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "oka-cyber-agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := CheckWritable(dir); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, validConfig()); err != nil {
		t.Fatal(err)
	}
	requireMode(t, dir, 0o750)
}

func TestMakeDirRefusesAFileInPlaceOfTheDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oka-cyber-agent")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckWritable(path); err == nil {
		t.Fatal("want an error when the config dir is a file")
	}
	if err := CheckWritable(filepath.Join(path, "sub")); err == nil {
		t.Fatal("want an error when a parent of the config dir is a file")
	}
}

func TestOpenDirDoesNotFollowASymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if d, err := openDir(link); err == nil {
		d.Close()
		t.Fatal("openDir followed a symlink")
	}
	d, err := openDir(target)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
}
