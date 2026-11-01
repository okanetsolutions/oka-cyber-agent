//go:build !linux

package collect

import (
	"os"
	"path/filepath"
	"syscall"
)

// openAt refuses a symlink in the last path component only, because the standard library has no openat on
// every Unix. Releases are Linux builds (see openat_linux.go); this keeps go test working on macOS.
func openAt(dir *os.File, name string, flag int) (*os.File, error) {
	return os.OpenFile(filepath.Join(dir.Name(), name), flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
