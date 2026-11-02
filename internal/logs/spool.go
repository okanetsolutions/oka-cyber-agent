package logs

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

const (
	DefaultSpoolBytes = 100 << 20
	droppedFileName   = "dropped"
	spoolFileMode     = 0o600
	spoolDirMode      = 0o700
	// maxSpoolRead bounds what one spool file may decompress to: a batch is at most a few MB of JSON.
	maxSpoolRead = 64 << 20
)

// Batch is one upload: at most MaxBatchEvents events with the batch_id the server deduplicates retries by,
// and the checkpoint to save once the server acknowledged it.
type Batch struct {
	ID         string     `json:"batch_id"`
	Events     []Event    `json:"events"`
	Checkpoint Checkpoint `json:"checkpoint"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Spool keeps batches on disk until the server acknowledges them, so nothing is lost when the server is
// unreachable or the agent restarts. Each batch is one gzip file named "<sequence>-<events>.json.gz". When
// the spool grows over MaxBytes the oldest batches are dropped and their events counted in Dropped.
//
// Dir is a directory inside the agent's state directory, which the service user can write to. Every file is
// reached through an os.Root on the state directory, so a symlink planted there never leads outside it, and a
// FIFO or other special file is skipped rather than waited on. The directory gets mode 0700 and the files
// 0600 through their open descriptors, whatever the umask, and when Owner is set (root running the agent) they
// are given to it, so the service can still use them.
type Spool struct {
	Dir      string
	MaxBytes int64
	Owner    *config.Owner
}

func (s Spool) Append(b Batch) error {
	dir, err := s.open(true)
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := spoolEntries(dir)
	if err != nil {
		return err
	}
	sequence := int64(1)
	if len(entries) > 0 {
		sequence = entries[len(entries)-1].sequence + 1
	}
	name := fmt.Sprintf("%020d-%d.json.gz", sequence, len(b.Events))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := s.writeAtomic(dir, name, buf.Bytes()); err != nil {
		return err
	}
	return s.enforceLimit(dir)
}

// Oldest returns the next batch to send and its name for Remove. A batch that cannot be read is dropped and
// counted.
func (s Spool) Oldest() (Batch, string, bool, error) {
	dir, err := s.open(false)
	if err != nil || dir == nil {
		return Batch{}, "", false, err
	}
	defer dir.Close()
	for {
		entries, err := spoolEntries(dir)
		if err != nil || len(entries) == 0 {
			return Batch{}, "", false, err
		}
		b, err := readBatch(dir, entries[0].name)
		if err == nil {
			return b, entries[0].name, true, nil
		}
		if err := s.drop(dir, entries[0]); err != nil {
			return Batch{}, "", false, err
		}
	}
}

// Newest is the latest batch, whose checkpoint is where collection resumes after a restart.
func (s Spool) Newest() (Batch, bool) {
	dir, err := s.open(false)
	if err != nil || dir == nil {
		return Batch{}, false
	}
	defer dir.Close()
	entries, err := spoolEntries(dir)
	if err != nil {
		return Batch{}, false
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if b, err := readBatch(dir, entries[i].name); err == nil {
			return b, true
		}
	}
	return Batch{}, false
}

// Remove deletes the batch Oldest returned under name.
func (s Spool) Remove(name string) error {
	dir, err := s.open(false)
	if err != nil || dir == nil {
		return err
	}
	defer dir.Close()
	return removeEntry(dir, name)
}

// Dropped is the number of events dropped and not yet reported to the server.
func (s Spool) Dropped() int {
	dir, err := s.open(false)
	if err != nil || dir == nil {
		return 0
	}
	defer dir.Close()
	return dropped(dir)
}

func (s Spool) AddDropped(n int) error {
	if n == 0 {
		return nil
	}
	dir, err := s.open(true)
	if err != nil {
		return err
	}
	defer dir.Close()
	return s.addDropped(dir, n)
}

// Clear deletes the spool directory and everything in it. A symlink in its place is removed, not followed.
func (s Spool) Clear() error {
	parent, err := os.OpenRoot(filepath.Dir(s.Dir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.RemoveAll(filepath.Base(s.Dir))
}

func (s Spool) Empty() bool {
	dir, err := s.open(false)
	if err != nil || dir == nil {
		return true
	}
	defer dir.Close()
	entries, err := spoolEntries(dir)
	return err != nil || len(entries) == 0
}

// open returns the spool directory, creating it when create is set. Without create, a missing directory is
// (nil, nil).
func (s Spool) open(create bool) (*os.Root, error) {
	parent, err := os.OpenRoot(filepath.Dir(s.Dir))
	if err != nil {
		if !create && errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("log spool: %w", err)
	}
	defer parent.Close()
	name := filepath.Base(s.Dir)
	info, err := parent.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !create:
		return nil, nil
	case errors.Is(err, fs.ErrNotExist):
		if err := s.makeDir(parent, name); err != nil {
			return nil, fmt.Errorf("log spool: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("log spool: %w", err)
	case !info.IsDir():
		return nil, fmt.Errorf("log spool %s: %w", s.Dir, syscall.ENOTDIR)
	}
	dir, err := parent.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("log spool: %w", err)
	}
	return dir, nil
}

func (s Spool) makeDir(parent *os.Root, name string) error {
	if err := parent.Mkdir(name, spoolDirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	d, err := parent.Open(name)
	if err != nil {
		return err
	}
	defer d.Close()
	if s.Owner != nil {
		if err := d.Chown(s.Owner.UID, s.Owner.GID); err != nil {
			return err
		}
	}
	return d.Chmod(spoolDirMode)
}

type spoolEntry struct {
	name     string
	sequence int64
	events   int
	size     int64
}

func spoolEntries(dir *os.Root) ([]spoolEntry, error) {
	d, err := dir.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	dirEntries, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var entries []spoolEntry
	for _, d := range dirEntries {
		base, ok := strings.CutSuffix(d.Name(), ".json.gz")
		if !ok || !d.Type().IsRegular() {
			continue
		}
		sequenceText, eventsText, ok := strings.Cut(base, "-")
		sequence, err1 := strconv.ParseInt(sequenceText, 10, 64)
		events, err2 := strconv.Atoi(eventsText)
		info, err3 := d.Info()
		if !ok || err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		entries = append(entries, spoolEntry{d.Name(), sequence, events, info.Size()})
	}
	slices.SortFunc(entries, func(a, b spoolEntry) int { return cmp.Compare(a.sequence, b.sequence) })
	return entries, nil
}

func (s Spool) enforceLimit(dir *os.Root) error {
	limit := s.MaxBytes
	if limit <= 0 {
		limit = DefaultSpoolBytes
	}
	entries, err := spoolEntries(dir)
	if err != nil {
		return err
	}
	var total int64
	for _, e := range entries {
		total += e.size
	}
	for len(entries) > 1 && total > limit {
		if err := s.drop(dir, entries[0]); err != nil {
			return err
		}
		total -= entries[0].size
		entries = entries[1:]
	}
	return nil
}

func (s Spool) drop(dir *os.Root, e spoolEntry) error {
	if err := removeEntry(dir, e.name); err != nil {
		return err
	}
	return s.addDropped(dir, e.events)
}

func (s Spool) addDropped(dir *os.Root, n int) error {
	return s.writeAtomic(dir, droppedFileName, []byte(strconv.Itoa(max(dropped(dir)+n, 0))))
}

func dropped(dir *os.Root) int {
	data, err := readRegular(dir, droppedFileName, 32)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return max(n, 0)
}

func removeEntry(dir *os.Root, name string) error {
	err := dir.Remove(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// writeAtomic replaces name with data. Mode and owner are set through the open temporary file, never by name.
func (s Spool) writeAtomic(dir *os.Root, name string, data []byte) error {
	tmp := "." + name + "." + randomHex(8)
	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, spoolFileMode)
	if err != nil {
		return err
	}
	defer dir.Remove(tmp)
	if s.Owner != nil {
		if err := f.Chown(s.Owner.UID, s.Owner.GID); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Chmod(spoolFileMode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return dir.Rename(tmp, name)
}

// readRegular reads at most limit bytes of name when it is a regular file, without blocking on a FIFO.
func readRegular(dir *os.Root, name string, limit int64) ([]byte, error) {
	f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", name, config.ErrNotRegularFile)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

func readBatch(dir *os.Root, name string) (Batch, error) {
	data, err := readRegular(dir, name, maxSpoolRead)
	if err != nil {
		return Batch{}, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Batch{}, err
	}
	var b Batch
	if err := json.NewDecoder(io.LimitReader(zr, maxSpoolRead)).Decode(&b); err != nil {
		return Batch{}, err
	}
	return b, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewBatchID returns a random (version 4) UUID.
func NewBatchID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
