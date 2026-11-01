package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWatcherSeesAReenrollAndIgnoresABrokenEdit(t *testing.T) {
	dir := t.TempDir()
	if err := SaveToken(dir, "agent-secret"); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, validConfig()); err != nil {
		t.Fatal(err)
	}
	w := NewWatcher(dir)
	changed := func() (bool, error) {
		t.Helper()
		return w.Changed()
	}
	if ok, err := changed(); ok || err != nil {
		t.Fatalf("Changed = %v, %v before any change", ok, err)
	}

	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("url: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := changed(); ok || err == nil {
		t.Fatalf("Changed = %v, %v after a broken edit, want false and an error", ok, err)
	}
	if ok, err := changed(); ok || err != nil {
		t.Fatalf("Changed = %v, %v, want the broken edit reported once", ok, err)
	}

	reenrolled := validConfig()
	reenrolled.ServerID = "43"
	if err := SaveToken(dir, "new-agent-secret"); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, reenrolled); err != nil {
		t.Fatal(err)
	}
	if ok, err := changed(); !ok || err != nil {
		t.Fatalf("Changed = %v, %v after enroll --force, want true", ok, err)
	}
	if ok, err := changed(); ok || err != nil {
		t.Fatalf("Changed = %v, %v, want no change after it was seen", ok, err)
	}

	if err := SaveToken(dir, "rotated"); err != nil {
		t.Fatal(err)
	}
	if ok, err := changed(); !ok || err != nil {
		t.Fatalf("Changed = %v, %v after the token alone was replaced, want true", ok, err)
	}

	if err := os.Remove(filepath.Join(dir, TokenFileName)); err != nil {
		t.Fatal(err)
	}
	if ok, err := changed(); ok || err == nil {
		t.Fatalf("Changed = %v, %v without a token, want false and an error", ok, err)
	}
}

func TestWatcherWithoutFilesNeverReportsAChange(t *testing.T) {
	w := NewWatcher(t.TempDir())
	if ok, err := w.Changed(); ok || err != nil {
		t.Fatalf("Changed = %v, %v", ok, err)
	}
}
