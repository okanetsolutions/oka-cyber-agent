package logs

import (
	"bytes"
	"io/fs"
	"os"
	"syscall"
)

// readEndCheckBytes is how many bytes before the remembered offset must still be the same for a file to be
// taken as the rotated one and not a new file that got its inode number back.
const readEndCheckBytes = 64

type fileID struct{ dev, ino uint64 }

type readEnd struct {
	offset int64
	before []byte
	// plan is the number of plans the Collector had made when the file was read to its end.
	plan int
}

// readFiles is what the tailers of one Collector share about the files they read, by device and inode. A
// rotated file can still match a glob pattern under its new name (app.log.1 for /var/log/app/*, or
// access-20261030.log for *access*.log with logrotate's dateext and extension .log). The tailer of the old
// name reads it to its end, so the tailer of the new name must neither read it at the same time nor start it
// again from its beginning: it waits while another tailer holds the file open, then continues where that
// tailer stopped.
//
// The end of a rotated file is remembered until the first plan made after it was recorded has been polled,
// whatever the time between polls: that plan lists every glob match there is, and its tailers ask for the end
// when they open the file, also a tailer that found the file still held in the poll that recorded it. So the
// map holds at most the files rotated during the last two plans.
type readFiles struct {
	open  map[fileID]*Tailer
	done  map[fileID]readEnd
	plans int
}

func newReadFiles() *readFiles {
	return &readFiles{open: map[fileID]*Tailer{}, done: map[fileID]readEnd{}}
}

// acquire reports whether t may read the file, which it may unless another tailer holds it open.
func (r *readFiles) acquire(id fileID, t *Tailer) bool {
	if r == nil {
		return true
	}
	if holder, ok := r.open[id]; ok && holder != t {
		return false
	}
	r.open[id] = t
	return true
}

func (r *readFiles) release(id fileID, t *Tailer) {
	if r != nil && r.open[id] == t {
		delete(r.open, id)
	}
}

// planned counts a plan of the Collector.
func (r *readFiles) planned() { r.plans++ }

// polled forgets the ends recorded before the latest plan, once the tailers of that plan were all polled.
func (r *readFiles) polled() {
	for id, e := range r.done {
		if e.plan < r.plans {
			delete(r.done, id)
		}
	}
}

// finished remembers how far f, which a tailer read to its end after it was rotated, was read. A file that no
// longer has a name cannot be found again and is not remembered.
func (r *readFiles) finished(f *os.File, id fileID, offset int64) {
	if r == nil {
		return
	}
	info, err := f.Stat()
	if err != nil || nlinkOf(info) == 0 {
		return
	}
	r.done[id] = readEnd{offset: offset, before: bytesBefore(f, offset), plan: r.plans}
}

// resume returns where to continue f when another tailer recently finished reading it. The bytes before that
// offset must be the ones that tailer read: a deleted file's inode number can be given to a new file.
func (r *readFiles) resume(f *os.File, id fileID, size int64) (int64, bool) {
	if r == nil {
		return 0, false
	}
	e, ok := r.done[id]
	if !ok {
		return 0, false
	}
	delete(r.done, id)
	if size < e.offset || !bytes.Equal(bytesBefore(f, e.offset), e.before) {
		return 0, false
	}
	return e.offset, true
}

func bytesBefore(f *os.File, offset int64) []byte {
	start := max(offset-readEndCheckBytes, 0)
	buf := make([]byte, offset-start)
	n, _ := f.ReadAt(buf, start)
	return buf[:n]
}

func fileIDOf(info fs.FileInfo) fileID {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}
	}
	return fileID{}
}

func nlinkOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}
