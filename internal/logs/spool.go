package logs

import (
	"bytes"
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
// and the checkpoint to save once the server acknowledged it. A batch split in parts (see Spool.Replace) keeps
// its checkpoint on every part, but only the last one may commit it: the others are Partial, since the
// checkpoint also covers the events of the parts after them.
type Batch struct {
	ID         string     `json:"batch_id"`
	Events     []Event    `json:"events"`
	Checkpoint Checkpoint `json:"checkpoint"`
	Partial    bool       `json:"partial,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Stream is the upload queue a batch waits in. Oka Core accepts batches of command events alone even when the
// daily allowance of the other events is used up, and answers 429 until midnight to any other batch, so command
// batches are uploaded with their own retry state and never wait behind another batch.
type Stream int

const (
	StreamLogs Stream = iota
	StreamCommands
)

func batchStream(b Batch) Stream {
	if len(b.Events) == 0 {
		return StreamLogs
	}
	for _, e := range b.Events {
		if e.Source != SourceCommands {
			return StreamLogs
		}
	}
	return StreamCommands
}

// The tag after the event count in a spool file name: none for StreamLogs, the stream of a command batch, or
// an acknowledged batch kept only for its checkpoint (see MarkAcked).
const (
	tagCommands = "commands"
	tagAcked    = "acked"
)

func streamTag(b Batch) string {
	if batchStream(b) == StreamCommands {
		return tagCommands
	}
	return ""
}

// Spool keeps batches on disk until the server acknowledges them, so nothing is lost when the server is
// unreachable or the agent restarts. Each batch is one gzip file named "<sequence>-<events>.json.gz", where the
// parts that replace a batch add ".<part>" to its sequence, and a command batch or an acknowledged one adds
// "-commands" or "-acked" to the event count. When the spool grows over MaxBytes batches are dropped and
// their events counted in Dropped: the oldest of those that hold only web requests and application errors
// first, and the oldest of the others (logins, sudo, commands) only when none of those is left. Anyone on the
// internet decides how many web events there are, so while uploads are stalled a flood of requests must not
// push the logins out of the spool.
//
// Which batches may go first is written in the gzip header of the file (see lowPriorityMark), where an agent
// without this rule does not look: both read the files of the other, and a file without the mark is kept as
// long as one with logins. Append writes the web and application events of a batch apart from its other
// events, as a part of their own, so that the mark can apply.
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
		sequence = entries[len(entries)-1].sequence[0] + 1
	}
	if low, rest := byPriority(b.Events); len(low) > 0 && len(rest) > 0 {
		// The checkpoint also covers the events of the second part, so only that one may commit it.
		part := Batch{ID: NewBatchID(), Events: low, Checkpoint: b.Checkpoint, Partial: true, CreatedAt: b.CreatedAt}
		if err := s.writeBatch(dir, fmt.Sprintf("%020d", sequence), part, streamTag(part)); err != nil {
			return err
		}
		sequence++
		b.Events = rest
	}
	if err := s.writeBatch(dir, fmt.Sprintf("%020d", sequence), b, streamTag(b)); err != nil {
		return err
	}
	return s.enforceLimit(dir)
}

// lowPriorityMark is the gzip header comment of a batch that holds nothing but web and application events.
const lowPriorityMark = "oka-cyber-agent: web and app events only"

func lowPriorityEvent(e Event) bool {
	return e.Source == SourceWeb || e.Source == SourceApp
}

// byPriority splits events, in order, into the web and application events and the others.
func byPriority(events []Event) (low, rest []Event) {
	for _, e := range events {
		if lowPriorityEvent(e) {
			low = append(low, e)
		} else {
			rest = append(rest, e)
		}
	}
	return low, rest
}

// lowPriority reads the gzip header of the spooled batch name and tells whether it carries lowPriorityMark.
func lowPriority(dir *os.Root, name string) bool {
	f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return false
	}
	zr, err := gzip.NewReader(f)
	return err == nil && zr.Comment == lowPriorityMark
}

// Replace puts parts in place of the batch Oldest returned under name, in the same order: a batch split in
// smaller ones, or one without an event the server rejected. The parts are written before the batch is
// removed, and their names sort after it, so a stop in between sends the batch again first, which replaces it
// with the same parts again.
func (s Spool) Replace(name string, parts []Batch) error {
	dir, err := s.open(true)
	if err != nil {
		return err
	}
	defer dir.Close()
	sequence, _, ok := strings.Cut(name, "-")
	if !ok {
		return fmt.Errorf("log spool: not a batch name: %q", name)
	}
	for i, part := range parts {
		if err := s.writeBatch(dir, fmt.Sprintf("%s.%d", sequence, i), part, streamTag(part)); err != nil {
			return err
		}
	}
	return removeEntry(dir, name)
}

// MarkAcked puts an empty batch with the checkpoint of b in place of the batch Oldest returned under name,
// once the server acknowledged it while an older batch of another stream still waits. Positions are committed
// in spool order only (see AckedHead), so a checkpoint never moves back and never skips a batch not yet sent.
func (s Spool) MarkAcked(name string, b Batch) error {
	dir, err := s.open(true)
	if err != nil {
		return err
	}
	defer dir.Close()
	sequence, _, ok := strings.Cut(name, "-")
	if !ok {
		return fmt.Errorf("log spool: not a batch name: %q", name)
	}
	b.Events = []Event{}
	if err := s.writeBatch(dir, sequence+".0", b, tagAcked); err != nil {
		return err
	}
	return removeEntry(dir, name)
}

// AckedHead returns the first batch of the spool when it is an acknowledged one, whose checkpoint is due.
func (s Spool) AckedHead() (Batch, string, bool) {
	dir, err := s.open(false)
	if err != nil || dir == nil {
		return Batch{}, "", false
	}
	defer dir.Close()
	for {
		entries, err := spoolEntries(dir)
		if err != nil || len(entries) == 0 || entries[0].tag != tagAcked {
			return Batch{}, "", false
		}
		if b, err := readBatch(dir, entries[0].name); err == nil {
			return b, entries[0].name, true
		}
		if err := removeEntry(dir, entries[0].name); err != nil {
			return Batch{}, "", false
		}
	}
}

// IsOldest tells whether name is the first batch of the spool.
func (s Spool) IsOldest(name string) bool {
	dir, err := s.open(false)
	if err != nil || dir == nil {
		return false
	}
	defer dir.Close()
	entries, err := spoolEntries(dir)
	return err == nil && len(entries) > 0 && entries[0].name == name
}

func (s Spool) writeBatch(dir *os.Root, sequence string, b Batch, tag string) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if low, rest := byPriority(b.Events); len(low) > 0 && len(rest) == 0 {
		zw.Comment = lowPriorityMark
	}
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if tag != "" {
		tag = "-" + tag
	}
	return s.writeAtomic(dir, fmt.Sprintf("%s-%d%s.json.gz", sequence, len(b.Events), tag), buf.Bytes())
}

// Oldest returns the next batch to send and its name for Remove. A batch that cannot be read is dropped and
// counted.
func (s Spool) Oldest() (Batch, string, bool, error) {
	return s.OldestIn(nil)
}

// OldestIn is Oldest for the streams skip does not leave out.
func (s Spool) OldestIn(skip func(Stream) bool) (Batch, string, bool, error) {
	dir, err := s.open(false)
	if err != nil || dir == nil {
		return Batch{}, "", false, err
	}
	defer dir.Close()
	for {
		entries, err := spoolEntries(dir)
		if err != nil {
			return Batch{}, "", false, err
		}
		i := slices.IndexFunc(entries, func(e spoolEntry) bool { return e.tag != tagAcked && (skip == nil || !skip(e.stream())) })
		if i < 0 {
			return Batch{}, "", false, nil
		}
		b, err := readBatch(dir, entries[i].name)
		if err == nil {
			return b, entries[i].name, true, nil
		}
		if err := s.drop(dir, entries[i]); err != nil {
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
	name string
	// sequence orders the batches: a part of a replaced batch comes after it and before the next batch.
	sequence []int64
	events   int
	tag      string
	size     int64
}

func (e spoolEntry) stream() Stream {
	return StreamOf(e.name)
}

// StreamOf is the stream of the spooled batch name.
func StreamOf(name string) Stream {
	if strings.HasSuffix(name, "-"+tagCommands+".json.gz") {
		return StreamCommands
	}
	return StreamLogs
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
		eventsText, tag, _ := strings.Cut(eventsText, "-")
		sequence, err1 := parseSequence(sequenceText)
		events, err2 := strconv.Atoi(eventsText)
		info, err3 := d.Info()
		if !ok || err1 != nil || err2 != nil || err3 != nil || tag != "" && tag != tagCommands && tag != tagAcked {
			continue
		}
		entries = append(entries, spoolEntry{d.Name(), sequence, events, tag, info.Size()})
	}
	slices.SortFunc(entries, func(a, b spoolEntry) int { return slices.Compare(a.sequence, b.sequence) })
	return entries, nil
}

func parseSequence(text string) ([]int64, error) {
	var sequence []int64
	for part := range strings.SplitSeq(text, ".") {
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("log spool: bad sequence %q", text)
		}
		sequence = append(sequence, n)
	}
	return sequence, nil
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
	// The newest batch always stays, and the header of a file is read once, only while the spool is over its
	// limit and only until a batch that may go first is found.
	protected := 0
	for len(entries) > 1 && total > limit {
		for protected < len(entries)-1 && !lowPriority(dir, entries[protected].name) {
			protected++
		}
		victim := 0
		if protected < len(entries)-1 {
			victim = protected
		} else {
			protected--
		}
		if err := s.drop(dir, entries[victim]); err != nil {
			return err
		}
		total -= entries[victim].size
		entries = slices.Delete(entries, victim, victim+1)
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
