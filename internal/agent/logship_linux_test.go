package agent

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestShipperDoesNotBlockOnAFIFOCheckpoint(t *testing.T) {
	h := newShipperHost(t)
	if err := syscall.Mkfifo(filepath.Join(h.stateDir, checkpointFileName), 0o600); err != nil {
		t.Fatal(err)
	}
	s := h.shipper()
	done := make(chan bool, 1)
	go func() {
		cp := s.committed()
		done <- len(cp.Files) == 0 && cp.JournalCursor == ""
	}()
	select {
	case empty := <-done:
		if !empty {
			t.Fatal("a FIFO must read as no position")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading the log positions blocked on a FIFO")
	}
}
