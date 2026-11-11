package safeopen

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// OpenAt opens name, a single path component, in the directory dir. O_NOFOLLOW makes the kernel refuse a symlink
// with ELOOP instead of following it, and when a walk opens every directory the same way, relative to its
// parent, no symlink is followed anywhere below where it started, even one swapped in after the walk listed the
// entry. O_NONBLOCK keeps a FIFO from blocking the open.
func OpenAt(dir *os.File, name string, flag int) (*os.File, error) {
	return openat(dir, name, flag|syscall.O_NOFOLLOW)
}

// FollowAt opens name in dir like OpenAt but follows it when it is a symlink. Use it only for a name the
// administrator chose, never for one found by listing a directory.
func FollowAt(dir *os.File, name string, flag int) (*os.File, error) {
	return openat(dir, name, flag)
}

// ReadlinkAt reads the target of the symlink name, a single path component, in the directory dir. Like OpenAt it
// looks name up relative to dir itself, so a symlink swapped into a parent path after dir was opened is not
// followed.
func ReadlinkAt(dir *os.File, name string) (string, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return "", err
	}
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return "", err
	}
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		var n uintptr
		var errno syscall.Errno
		err = conn.Control(func(dirfd uintptr) {
			n, _, errno = syscall.Syscall6(syscall.SYS_READLINKAT, dirfd, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(size), 0, 0)
		})
		if err != nil {
			return "", err
		}
		if errno != 0 {
			return "", &fs.PathError{Op: "readlinkat", Path: name, Err: errno}
		}
		if int(n) < size {
			return string(buf[:n]), nil
		}
	}
}

func openat(dir *os.File, name string, flag int) (*os.File, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var openErr error
	err = conn.Control(func(dirfd uintptr) {
		for {
			fd, openErr = syscall.Openat(int(dirfd), name, flag|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
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
