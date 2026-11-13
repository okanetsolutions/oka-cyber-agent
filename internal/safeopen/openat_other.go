//go:build !linux

package safeopen

import (
	"os"
	"path/filepath"
	"syscall"
)

// OpenAt refuses a symlink in the last path component only, because the standard library has no openat on
// every Unix. Releases are Linux builds (see openat_linux.go); this keeps go test working on macOS.
func OpenAt(dir *os.File, name string, flag int) (*os.File, error) {
	return os.OpenFile(filepath.Join(dir.Name(), name), flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func FollowAt(dir *os.File, name string, flag int) (*os.File, error) {
	return os.OpenFile(filepath.Join(dir.Name(), name), flag|syscall.O_NONBLOCK, 0)
}

func ReadlinkAt(dir *os.File, name string) (string, error) {
	return os.Readlink(filepath.Join(dir.Name(), name))
}
