package collect

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// openAt opens name, a single path component, in the directory dir. O_NOFOLLOW makes the kernel refuse a symlink
// with ELOOP instead of following it, and since the walk opens every directory the same way, relative to its
// parent, no symlink is followed anywhere below a scan path, even one swapped in after the walk listed the
// entry. O_NONBLOCK keeps a FIFO from blocking the open.
func openAt(dir *os.File, name string, flag int) (*os.File, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var openErr error
	err = conn.Control(func(dirfd uintptr) {
		for {
			fd, openErr = syscall.Openat(int(dirfd), name, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
			if openErr != syscall.EINTR {
				return
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, &fs.PathError{Op: "openat", Path: name, Err: openErr}
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), nil
}
