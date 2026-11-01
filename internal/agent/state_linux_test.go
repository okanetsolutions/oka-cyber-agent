package agent

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadStateDoesNotBlockOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, stateFileName), 0o600); err != nil {
		t.Fatal(err)
	}
	type loaded struct {
		state State
		err   error
	}
	done := make(chan loaded, 1)
	go func() {
		state, err := LoadState(dir, "42")
		done <- loaded{state, err}
	}()
	select {
	case got := <-done:
		if got.err == nil || got.state != (State{ServerID: "42"}) {
			t.Fatalf("LoadState = %+v, %v; want an empty state and an error to warn about", got.state, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadState blocked on a FIFO")
	}
	if err := SaveState(dir, State{ServerID: "42"}); err != nil {
		t.Fatalf("SaveState = %v, want the FIFO replaced", err)
	}
}

func TestRootSaveStateDoesNotFollowAPlantedSymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the state directory to another user")
	}
	const serviceUID, serviceGID = 65534, 65534
	dir := t.TempDir()
	if err := os.Chown(dir, serviceUID, serviceGID); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(target, []byte("root:x:0:0\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, stateFileName)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(dir, State{ServerID: "42"}); err != nil {
		t.Fatal(err)
	}
	assertUntouched(t, target, "root:x:0:0\n", 0o640)
	assertOwnedBy(t, target, 0, 0)
	assertOwnedBy(t, path, serviceUID, serviceGID)
}
