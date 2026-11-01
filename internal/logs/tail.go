package logs

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	// RemovedAfter is how long a watched file may be missing before log_file_removed is reported.
	RemovedAfter = 5 * time.Minute

	maxLineBytes = 64 << 10
	maxReadBytes = 4 << 20
)

// Position is how far a file has been read: the byte offset after the last complete line of the file with
// that inode.
type Position struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// Tailer follows one file by path and inode. It is polled: every Poll returns the complete lines written
// since the previous one. It handles rename rotation (the old file is read to its end before switching),
// copytruncate (the offset is reset when the file shrinks) and files created after it started.
type Tailer struct {
	Path string
	Now  func() time.Time

	file         *os.File
	inode        uint64
	offset       int64
	skipping     bool
	resume       *Position
	startAtEnd   bool
	missingSince time.Time
	removed      bool
	seen         bool
}

// NewTailer starts at resume when it still points at the same file, at the end of the current file when
// startAtEnd is set (first enable: no history is uploaded), and otherwise at the beginning.
func NewTailer(path string, resume *Position, startAtEnd bool) *Tailer {
	return &Tailer{Path: path, resume: resume, startAtEnd: startAtEnd, Now: time.Now}
}

type PollResult struct {
	Lines []string
	// Removed is set once when the file has been missing for RemovedAfter.
	Removed bool
	// Missing is set while the file does not exist, after what the old file still held was read.
	Missing bool
	// Err is a read error other than the file being absent, such as permission denied.
	Err error
}

func (t *Tailer) Position() Position {
	return Position{Inode: t.inode, Offset: t.offset}
}

func (t *Tailer) Close() {
	if t.file != nil {
		t.file.Close()
		t.file = nil
	}
}

func (t *Tailer) Poll() PollResult {
	var r PollResult
	info, err := os.Stat(t.Path)
	if errors.Is(err, fs.ErrNotExist) {
		r.Missing = true
		if t.file != nil {
			r.Lines = t.drain()
			t.Close()
		}
		// A recreated file may get the deleted file's inode number back, so the position is forgotten.
		t.inode, t.offset, t.skipping = 0, 0, false
		if t.missingSince.IsZero() {
			t.missingSince = t.Now()
		}
		if !t.removed && t.seen && t.Now().Sub(t.missingSince) >= RemovedAfter {
			t.removed = true
			r.Removed = true
		}
		t.startAtEnd = false
		return r
	}
	if err != nil {
		r.Err = err
		return r
	}
	t.missingSince = time.Time{}
	t.removed = false

	inode := inodeOf(info)
	if t.file != nil && inode != t.inode {
		r.Lines = t.drain()
		t.Close()
		t.offset = 0
		t.startAtEnd = false
	}
	if t.file == nil {
		if err := t.open(inode, info.Size()); err != nil {
			r.Err = err
			return r
		}
	}
	if info.Size() < t.offset {
		t.offset = 0
		t.skipping = false
	}
	r.Lines = append(r.Lines, t.read()...)
	return r
}

func (t *Tailer) open(inode uint64, size int64) error {
	f, err := os.Open(t.Path)
	if err != nil {
		return err
	}
	t.file = f
	switch {
	case t.resume != nil && t.resume.Inode == inode && t.resume.Offset <= size:
		t.offset = t.resume.Offset
	case t.resume != nil:
		t.offset = 0
	case t.startAtEnd:
		t.offset = size
	case t.inode == inode:
	default:
		t.offset = 0
	}
	t.resume = nil
	t.startAtEnd = false
	t.inode = inode
	t.seen = true
	t.skipping = false
	return nil
}

// drain reads what was written to the old file after the last poll and before it was renamed or deleted.
func (t *Tailer) drain() []string {
	return t.read()
}

// read returns the complete lines after the offset and moves the offset past them, so a line that is still
// being written is read again in full on the next poll. Lines longer than maxLineBytes are cut, and the rest
// of such a line is skipped.
func (t *Tailer) read() []string {
	if t.file == nil {
		return nil
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(t.file, t.offset, maxReadBytes), maxLineBytes)
	var lines []string
	var consumed int64
	for {
		chunk, err := reader.ReadSlice('\n')
		switch {
		case err == nil:
			consumed += int64(len(chunk))
			if !t.skipping {
				lines = append(lines, strings.TrimRight(string(chunk), "\r\n"))
			}
			t.skipping = false
		case errors.Is(err, bufio.ErrBufferFull):
			consumed += int64(len(chunk))
			if !t.skipping {
				lines = append(lines, string(chunk))
			}
			t.skipping = true
		default:
			if t.skipping {
				consumed += int64(len(chunk))
			}
			t.offset += consumed
			return lines
		}
	}
}

func inodeOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
