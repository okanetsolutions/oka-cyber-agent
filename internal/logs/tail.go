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
// since the previous one. It handles rename rotation (the old file is read to its end before switching, over
// several polls when it holds more than maxReadBytes), copytruncate (the offset is reset when the file
// shrinks) and files created after it started. A symlink or anything but a regular file at Path counts as no
// file (see openLogFile).
//
// While a rotated file is still being read, Position is the position in that old file. The old file is known
// only by the open descriptor, not by a path, so after a restart at that point the new file is read from its
// start and the rest of the old one is not read.
type Tailer struct {
	Path string
	// Pattern is the glob pattern Path was found by, "" for a path named in full.
	Pattern string
	Now     func() time.Time

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
// startAtEnd is set (a file that existed before it was watched: no history is uploaded), and otherwise at the
// beginning. A file that is missing when first polled is read from its beginning once created.
func NewTailer(path string, resume *Position, startAtEnd bool) *Tailer {
	return &Tailer{Path: path, resume: resume, startAtEnd: startAtEnd, Now: time.Now}
}

type PollResult struct {
	Lines []string
	// Removed is set once when the file has been missing for RemovedAfter.
	Removed bool
	// Missing is set while there is no regular file at Path, after what the old file still held was read.
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
	// Lstat is enough to notice a new file without opening the path on every poll; open checks the whole path.
	info, err := os.Lstat(t.Path)
	missing := errors.Is(err, fs.ErrNotExist) || err == nil && !info.Mode().IsRegular()
	if err != nil && !missing {
		r.Err = err
		return r
	}
	if t.file != nil && (missing || inodeOf(info) != t.inode) {
		// The file was rotated or deleted. The old file is read to its end before the new one, still at most
		// maxReadBytes per poll, so a backlog of several polls is read in order and nothing is skipped.
		var more bool
		r.Lines, more = t.read()
		if more {
			return r
		}
		t.Close()
		t.offset = 0
		t.startAtEnd = false
	}
	if missing {
		return t.missing(r)
	}
	t.missingSince = time.Time{}
	t.removed = false
	if t.file == nil {
		info, err = t.open()
		switch {
		case errors.Is(err, fs.ErrNotExist) || errors.Is(err, errSymlink) || errors.Is(err, errNotRegular):
			return t.missing(r)
		case err != nil:
			r.Err = err
			return r
		}
	}
	if info.Size() < t.offset {
		t.offset = 0
		t.skipping = false
	}
	lines, _ := t.read()
	r.Lines = append(r.Lines, lines...)
	return r
}

func (t *Tailer) missing(r PollResult) PollResult {
	r.Missing = true
	// A recreated file may get the deleted file's inode number back, so the position is forgotten, also the
	// saved one when the file is missing before it was ever opened.
	t.inode, t.offset, t.skipping = 0, 0, false
	t.resume = nil
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

// open opens the file at Path and returns what the open descriptor refers to, which can differ from what the
// latest Lstat saw.
func (t *Tailer) open() (fs.FileInfo, error) {
	f, err := openLogFile(t.Path, t.Pattern)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	inode, size := inodeOf(info), info.Size()
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
	return info, nil
}

// read returns the complete lines after the offset, at most maxReadBytes of them, and moves the offset past
// them, so a line that is still being written is read again in full on the next poll. more is set when the
// limit stopped it before the end of the file. Lines longer than maxLineBytes are cut, and the rest of such a
// line is skipped.
func (t *Tailer) read() (lines []string, more bool) {
	if t.file == nil {
		return nil, false
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(t.file, t.offset, maxReadBytes), maxLineBytes)
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
			more = errors.Is(err, io.EOF) && consumed+int64(len(chunk)) == maxReadBytes
			if t.skipping {
				consumed += int64(len(chunk))
			}
			t.offset += consumed
			return lines, more
		}
	}
}

func inodeOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
