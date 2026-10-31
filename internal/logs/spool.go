package logs

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultSpoolBytes = 100 << 20
	droppedFileName   = "dropped"
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
type Spool struct {
	Dir      string
	MaxBytes int64
}

func (s Spool) Append(b Batch) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	entries, err := s.entries()
	if err != nil {
		return err
	}
	sequence := int64(1)
	if len(entries) > 0 {
		sequence = entries[len(entries)-1].sequence + 1
	}
	name := fmt.Sprintf("%020d-%d.json.gz", sequence, len(b.Events))
	if err := writeGzipJSON(filepath.Join(s.Dir, name), b); err != nil {
		return err
	}
	return s.enforceLimit()
}

// Oldest returns the next batch to send. A batch that cannot be read is dropped and counted.
func (s Spool) Oldest() (Batch, string, bool, error) {
	for {
		entries, err := s.entries()
		if err != nil || len(entries) == 0 {
			return Batch{}, "", false, err
		}
		path := filepath.Join(s.Dir, entries[0].name)
		b, err := readGzipJSON(path)
		if err == nil {
			return b, path, true, nil
		}
		if err := s.drop(entries[0]); err != nil {
			return Batch{}, "", false, err
		}
	}
}

// Newest is the latest batch, whose checkpoint is where collection resumes after a restart.
func (s Spool) Newest() (Batch, bool) {
	entries, err := s.entries()
	if err != nil {
		return Batch{}, false
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if b, err := readGzipJSON(filepath.Join(s.Dir, entries[i].name)); err == nil {
			return b, true
		}
	}
	return Batch{}, false
}

func (s Spool) Remove(path string) error {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Dropped is the number of events dropped and not yet reported to the server.
func (s Spool) Dropped() int {
	data, err := os.ReadFile(filepath.Join(s.Dir, droppedFileName))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return max(n, 0)
}

func (s Spool) AddDropped(n int) error {
	if n == 0 {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.Dir, droppedFileName), []byte(strconv.Itoa(max(s.Dropped()+n, 0))), 0o600)
}

func (s Spool) Clear() error {
	return os.RemoveAll(s.Dir)
}

func (s Spool) Empty() bool {
	entries, err := s.entries()
	return err != nil || len(entries) == 0
}

type spoolEntry struct {
	name     string
	sequence int64
	events   int
	size     int64
}

func (s Spool) entries() ([]spoolEntry, error) {
	dirEntries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []spoolEntry
	for _, d := range dirEntries {
		base, ok := strings.CutSuffix(d.Name(), ".json.gz")
		if !ok {
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
	slices.SortFunc(entries, func(a, b spoolEntry) int { return int(a.sequence - b.sequence) })
	return entries, nil
}

func (s Spool) enforceLimit() error {
	limit := s.MaxBytes
	if limit <= 0 {
		limit = DefaultSpoolBytes
	}
	entries, err := s.entries()
	if err != nil {
		return err
	}
	var total int64
	for _, e := range entries {
		total += e.size
	}
	for len(entries) > 1 && total > limit {
		if err := s.drop(entries[0]); err != nil {
			return err
		}
		total -= entries[0].size
		entries = entries[1:]
	}
	return nil
}

func (s Spool) drop(e spoolEntry) error {
	if err := s.Remove(filepath.Join(s.Dir, e.name)); err != nil {
		return err
	}
	return s.AddDropped(e.events)
}

func writeGzipJSON(path string, v any) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".batch-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	zw := gzip.NewWriter(tmp)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		tmp.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readGzipJSON(path string) (Batch, error) {
	f, err := os.Open(path)
	if err != nil {
		return Batch{}, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return Batch{}, err
	}
	var b Batch
	if err := json.NewDecoder(zr).Decode(&b); err != nil {
		return Batch{}, err
	}
	return b, nil
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
