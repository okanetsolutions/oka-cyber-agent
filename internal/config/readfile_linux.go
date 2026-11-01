package config

import (
	"os"
	"syscall"
)

// openRegular opens path without following a symlink in its last component and without blocking on a FIFO,
// so a file planted by another user in a directory it can write to is neither followed nor waited on.
func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
