package logs

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/trustedcmd"
)

const (
	replanEvery    = time.Minute
	journalBackoff = 10 * time.Second
	journalBuffer  = 10000
	logindWait     = 5 * time.Second
)

// Checkpoint is how far every reader got: file positions by path and the journal cursor. The agent saves it
// only after the server acknowledged the events read up to it (at least once delivery).
type Checkpoint struct {
	Sources       []string                `json:"sources"`
	Files         map[string]Position     `json:"files"`
	JournalCursor string                  `json:"journal_cursor,omitempty"`
	AuditCursor   string                  `json:"audit_cursor,omitempty"`
	AuditSessions map[string]AuditSession `json:"audit_sessions,omitempty"`
}

type pendingJournalEntry struct {
	entry    JournalEntry
	received time.Time
}

type watch struct {
	plan   FilePlan
	tailer *Tailer
	// planned is whether the latest plan still lists the file.
	planned bool
}

// Collector reads the enabled sources and parses their lines into events. Poll is called from one
// goroutine; journald entries arrive from a background journalctl process.
type Collector struct {
	sources []string
	options Options
	now     func() time.Time
	start   StartFunc

	firstEnable map[string]bool
	resume      Checkpoint
	watches     map[string]*watch
	files       *readFiles
	skipped     []SkippedSource
	lastPlan    time.Time
	// listed holds the file names in the directories of the watched files, read just before the latest plan.
	listed map[string]map[string]bool

	commandFlag bool
	auditCancel context.CancelFunc
	auditDone   chan struct{}
	auditCh     chan JournalEntry
	audit       *auditParser

	journalCancel  context.CancelFunc
	journalDone    chan struct{}
	journalCh      chan JournalEntry
	journalCursor  string
	journalPending []pendingJournalEntry
	// untrustedEntries counts journal entries dropped because they claimed an auth identifier without
	// coming from that program (see TrustedAuthEntry).
	untrustedEntries int
}

// NewCollector starts at resume for the sources that were already enabled when it was saved. A newly enabled
// source starts at the current end of the journal, and every file without a saved position starts at its
// current end: no history is uploaded (see plan).
func NewCollector(sources []string, o Options, resume Checkpoint, start StartFunc, now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	resume.Files = maps.Clone(resume.Files)
	if o.HasJournalctl == nil {
		o.HasJournalctl = func() bool { _, err := trustedcmd.Look("journalctl"); return err == nil }
	}
	c := &Collector{
		sources:     slices.Clone(sources),
		options:     o,
		now:         now,
		start:       start,
		firstEnable: map[string]bool{},
		resume:      resume,
		watches:     map[string]*watch{},
		files:       newReadFiles(),
	}
	for _, s := range sources {
		c.firstEnable[s] = !slices.Contains(resume.Sources, s)
	}
	return c
}

func (c *Collector) Sources() []string { return slices.Clone(c.sources) }

func (c *Collector) Skipped() []SkippedSource { return slices.Clone(c.skipped) }

func (c *Collector) UntrustedEntries() int { return c.untrustedEntries }

// Poll returns the events read since the previous call.
func (c *Collector) Poll(ctx context.Context) []Event {
	planned := c.lastPlan.IsZero() || c.now().Sub(c.lastPlan) >= replanEvery
	if planned {
		c.plan(ctx)
	}
	var events []Event
	for _, path := range sortedWatchPaths(c.watches) {
		w := c.watches[path]
		result := w.tailer.Poll()
		for _, line := range result.Lines {
			if e, ok := c.parseLine(w.plan, line); ok {
				events = append(events, e)
			}
		}
		if w.plan.Pattern != "" && result.Missing && !w.planned {
			c.dropWatch(path)
			continue
		}
		if result.Removed && w.plan.Pattern == "" {
			events = append(events, RemovedEvent(w.plan.Source, w.plan.Path, c.now().UTC()))
		}
	}
	if planned {
		c.files.polled()
	}
	events = append(events, c.pollJournal()...)
	return append(events, c.pollCommands()...)
}

// Hold an unmatched SSH open briefly so logind can enrich it across polls. The cursor
// stays before held entries, so a checkpoint cannot skip an event awaiting enrichment.
func (c *Collector) pollJournal() []Event {
	now := c.now()
read:
	for len(c.journalPending) < journalBuffer {
		select {
		case entry := <-c.journalCh:
			c.journalPending = append(c.journalPending, pendingJournalEntry{entry, now})
		default:
			break read
		}
	}
	type leaderKey struct{ boot, pid string }
	starts := map[leaderKey][]JournalEntry{}
	for _, pending := range c.journalPending {
		e := pending.entry
		if e.Identifier == "systemd-logind" && e.MessageID == logindSessionStart &&
			e.SessionID != "" && e.Leader != "" && TrustedAuthEntry(e) {
			key := leaderKey{e.BootID, e.Leader}
			starts[key] = append(starts[key], e)
		}
	}
	var events []Event
	consumed := 0
	for _, pending := range c.journalPending {
		entry := pending.entry
		if !TrustedAuthEntry(entry) {
			c.untrustedEntries++
		} else if e, ok := ParseAuth(entry.Identifier, entry.Message, entry.At, entry.PID); ok {
			if e.Kind == KindSSHSessionOpened && entry.PID != "" {
				key := leaderKey{entry.BootID, entry.PID}
				candidates := starts[key]
				for len(candidates) > 0 && candidates[0].At.Before(entry.At) {
					candidates = candidates[1:]
				}
				if len(candidates) > 0 && candidates[0].At.Sub(entry.At) <= logindWait {
					e.set("logind_session", candidates[0].SessionID)
					starts[key] = candidates[1:]
				} else if now.Sub(pending.received) < logindWait && len(c.journalPending) < journalBuffer {
					break
				}
			}
			events = append(events, e)
		}
		c.journalCursor = entry.Cursor
		consumed++
	}
	c.journalPending = slices.Delete(c.journalPending, 0, consumed)
	return events
}

func (c *Collector) parseLine(plan FilePlan, line string) (Event, bool) {
	now := c.now()
	switch plan.Source {
	case SourceAuth:
		l, ok := ParseSyslog(line, now)
		if !ok || !slices.Contains(AuthIdentifiers, l.Program) {
			return Event{}, false
		}
		return ParseAuth(l.Program, l.Message, l.At.UTC(), l.PID)
	case SourceWeb:
		e, ok := ParseAccessLog(line, plan.Vhost)
		e.FirstAt, e.LastAt = e.FirstAt.UTC(), e.LastAt.UTC()
		return e, ok
	case SourceApp:
		e, ok := ParseMonolog(line, plan.Path, now)
		e.FirstAt, e.LastAt = e.FirstAt.UTC(), e.LastAt.UTC()
		return e, ok
	}
	return Event{}, false
}

// plan resolves the sources again, so log files created later (a new vhost, a new daily log) are picked
// up. A file named in full keeps its tailer when it disappears, which reports log_file_removed after
// RemovedAfter. A file found by a glob pattern that is gone and no longer matches is dropped silently
// after its last lines were read. A file rotated by rename keeps matching once it is created again under
// the same name, so its tailer follows the new file.
//
// A file that enters the plan without a saved position starts at its current end, since it may hold years
// of history: a file found at startup, a file added to log_paths, a new vhost's existing log. Only a file
// created while the agent was watching is read from its start (a new daily laravel-YYYY-MM-DD.log, a new
// vhost log in /var/log/nginx): one whose directory was listed before the previous plan without it. A file
// that is new only by name, because a rotation renamed it to a name a glob pattern matches (app.log.1), is
// the same file another tailer is reading or just read to its end: its tailer waits for that one and goes on
// from where it stopped (see readFiles), so no line is read twice.
func (c *Collector) plan(ctx context.Context) {
	startup := c.lastPlan.IsZero()
	previous := c.listed
	c.listed = map[string]map[string]bool{}
	c.listWatchedDirs()
	c.lastPlan = c.now()
	c.files.planned()
	p := PlanSources(c.sources, c.options)
	c.planCommands(ctx, &p)
	c.skipped = p.Skipped
	planned := map[string]FilePlan{}
	for _, f := range p.Files {
		if prev, ok := planned[f.Path]; !ok || prev.Pattern != "" {
			planned[f.Path] = f
		}
	}
	for path, w := range c.watches {
		f, ok := planned[path]
		if w.planned = ok; ok {
			w.plan = f
			w.tailer.Pattern = c.options.patternPath(f.Pattern)
		}
	}
	for path, f := range planned {
		if _, ok := c.watches[path]; ok {
			continue
		}
		var resume *Position
		if !c.firstEnable[f.Source] {
			resume = c.savedPosition(path, startup)
		}
		startAtEnd := resume == nil && !createdSince(previous, path)
		t := NewTailer(c.options.path(path), resume, startAtEnd)
		t.Pattern = c.options.patternPath(f.Pattern)
		t.Now = c.now
		t.files = c.files
		c.watches[path] = &watch{plan: f, tailer: t, planned: true}
	}
	// The saved position of a file that is gone is forgotten, since a file created later under its name may
	// get the old inode number back. A file that exists but is not planned (unreadable) keeps it.
	for path := range c.resume.Files {
		if _, ok := c.watches[path]; ok {
			continue
		}
		if _, err := os.Lstat(c.options.path(path)); errors.Is(err, fs.ErrNotExist) {
			delete(c.resume.Files, path)
		}
	}
	// A directory watched for the first time is listed now, so that a file created in it before the next
	// plan is recognized as new.
	c.listWatchedDirs()
	if p.Journal && c.journalCh == nil {
		cursor := ""
		if !c.firstEnable[SourceAuth] {
			cursor = c.resume.JournalCursor
		}
		c.startJournal(ctx, cursor)
	}
}

// savedPosition is the position saved for path. At startup the file at path may also be one that was saved
// under another name: a rotation while the agent was stopped renamed it to a name a glob pattern matches
// (app.log saved, now app.log.1 for /var/log/myapp/*). It is recognized by device and inode when the position
// saved for path is for another file and the file is no longer at the name it was saved under. Later plans do
// not look, since saved positions are not updated while the agent runs and readFiles follows the renames.
// The Tailer checks the inode, size and checksum again when it opens the file.
func (c *Collector) savedPosition(path string, startup bool) *Position {
	pos, saved := c.resume.Files[path]
	if startup {
		if id, ok := c.fileIDAt(path); ok && (!saved || pos.Dev != id.dev || pos.Inode != id.ino) {
			for _, other := range slices.Sorted(maps.Keys(c.resume.Files)) {
				moved := c.resume.Files[other]
				if other == path || moved.Dev != id.dev || moved.Inode != id.ino {
					continue
				}
				if at, ok := c.fileIDAt(other); !ok || at != id {
					return &moved
				}
			}
		}
	}
	if !saved {
		return nil
	}
	return &pos
}

func (c *Collector) fileIDAt(path string) (fileID, bool) {
	info, err := os.Lstat(c.options.path(path))
	if err != nil || !info.Mode().IsRegular() {
		return fileID{}, false
	}
	return fileIDOf(info), true
}

// listWatchedDirs records the names in each directory of a watched file that is not listed yet. A directory
// that cannot be listed is not recorded, so a file found in it later is treated as one that existed before.
func (c *Collector) listWatchedDirs() {
	for path := range c.watches {
		dir := filepath.Dir(path)
		if _, ok := c.listed[dir]; ok {
			continue
		}
		if names, err := readDirNames(c.options.path(dir)); err == nil {
			c.listed[dir] = names
		}
	}
}

// readDirNames opens dir with O_DIRECTORY and O_NONBLOCK, so a FIFO put in its place cannot block the open.
func readDirNames(dir string) (map[string]bool, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set, nil
}

// createdSince reports whether path was missing from its directory when the directory was listed.
func createdSince(listed map[string]map[string]bool, path string) bool {
	names, ok := listed[filepath.Dir(path)]
	return ok && !names[filepath.Base(path)]
}

// dropWatch forgets a file, also its saved position, so a file created later under the same name is read
// from its start even if it gets the old inode number back.
func (c *Collector) dropWatch(path string) {
	c.watches[path].tailer.Close()
	delete(c.watches, path)
	delete(c.resume.Files, path)
}

func (c *Collector) startJournal(ctx context.Context, cursor string) {
	c.journalCursor = cursor
	c.journalCh = make(chan JournalEntry, journalBuffer)
	ctx, c.journalCancel = context.WithCancel(ctx)
	c.journalDone = make(chan struct{})
	j := &Journal{Identifiers: AuthIdentifiers, Cursor: cursor, Start: c.start}
	go func() {
		defer close(c.journalDone)
		for ctx.Err() == nil {
			_ = j.Run(ctx, func(e JournalEntry) {
				select {
				case c.journalCh <- e:
				case <-ctx.Done():
				}
			})
			select {
			case <-ctx.Done():
				return
			case <-time.After(journalBackoff):
			}
		}
	}()
}

// Checkpoint is the position after the last event Poll returned.
func (c *Collector) Checkpoint() Checkpoint {
	cp := Checkpoint{Sources: slices.Clone(c.sources), Files: map[string]Position{}}
	for path, w := range c.watches {
		if pos := w.tailer.Position(); pos.Inode != 0 {
			cp.Files[path] = pos
		}
	}
	c.commandCheckpoint(&cp)
	cp.JournalCursor = c.journalCursor
	return cp
}

func (c *Collector) Close() {
	c.closeCommands()
	if c.journalCancel != nil {
		c.journalCancel()
		<-c.journalDone
	}
	for _, w := range c.watches {
		w.tailer.Close()
	}
}

func sortedWatchPaths(m map[string]*watch) []string {
	paths := make([]string, 0, len(m))
	for p := range m {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	return paths
}
