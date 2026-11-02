package collect

import (
	"bytes"
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

// inotify reports every open of a file in a watched directory, and of the directory itself, so this proves the
// excluded files are not even opened, not only that their packages are left out.
func TestDependencyDiscoveryNeverOpensExcludedFiles(t *testing.T) {
	tr, options := symlinkedIntoExcluded(t)
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	for _, dir := range []string{"/srv/secret", "/srv/secret/app", "/srv/secret/bin", "/srv/releases/5/storage"} {
		if _, err := syscall.InotifyAddWatch(fd, filepath.Join(tr.root, dir), syscall.IN_OPEN); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: options}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64<<10)
	n, err := syscall.Read(fd, buf)
	if err == syscall.EAGAIN {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var opened []string
	for i := 0; i+syscall.SizeofInotifyEvent <= n; {
		event := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[i]))
		name := buf[i+syscall.SizeofInotifyEvent : i+syscall.SizeofInotifyEvent+int(event.Len)]
		opened = append(opened, string(bytes.TrimRight(name, "\x00")))
		i += syscall.SizeofInotifyEvent + int(event.Len)
	}
	t.Fatalf("opened under an excluded path: %q (an empty name is the directory itself)", opened)
}
