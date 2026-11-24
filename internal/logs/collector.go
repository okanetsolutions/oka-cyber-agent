package logs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
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
	replanEvery       = time.Minute
	journalBackoff    = 10 * time.Second
	journalBuffer     = 10000
	logindWait        = 5 * time.Second
	unsetAuditSession = "4294967295"
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

// logindLeader identifies the sshd process a logind session start names as its leader.
type logindLeader struct{ boot, pid string }

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
	// letGo holds where the files a glob pattern found but that were let go while still there stopped (see
	// letGoWatch), by path.
	letGo    map[string]letGoPosition
	letGoSeq uint64
	skipped  []SkippedSource
	lastPlan time.Time
	boot     bootIdentity
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
	// logindStarts holds trusted logind session starts by leader, kept after their own cursor is consumed
	// because on Red Hat systems logind logs the start before pam_unix logs the SSH open.
	logindStarts map[logindLeader][]JournalEntry
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
		for i, line := range result.Lines {
			if e, ok := c.parseLine(w.plan, line); ok {
				// Existing bytes may belong to an earlier boot, even if a yearless syslog
				// timestamp looks recent. Only newly appended lines can use the host ID.
				if w.plan.Source == SourceAuth && result.live[i] &&
					e.FirstAt.After(c.boot.started) && !e.FirstAt.After(c.now()) {
					e.setBootID(c.boot.id)
				}
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
// logind may log the session start on either side of the open: after it on Debian, before it on Red Hat,
// where pam_systemd comes before pam_unix in the session stack.
func (c *Collector) pollJournal() []Event {
	now := c.now()
	if c.logindStarts == nil {
		c.logindStarts = map[logindLeader][]JournalEntry{}
	}
read:
	for len(c.journalPending) < journalBuffer {
		select {
		case e := <-c.journalCh:
			c.journalPending = append(c.journalPending, pendingJournalEntry{e, now})
			if e.Identifier == "systemd-logind" && e.MessageID == logindSessionStart &&
				e.SessionID != "" && e.Leader != "" && TrustedAuthEntry(e) {
				key := logindLeader{e.BootID, e.Leader}
				c.logindStarts[key] = append(c.logindStarts[key], e)
			}
		default:
			break read
		}
	}
	var events []Event
	var consumedAt time.Time
	consumed := 0
	for _, pending := range c.journalPending {
		entry := pending.entry
		if !TrustedAuthEntry(entry) {
			c.untrustedEntries++
		} else if e, ok := ParseAuth(entry.Identifier, entry.Message, entry.At, entry.PID); ok {
			e.setBootID(entry.BootID)
			if e.Kind == KindSSHSessionOpened && entry.PID != "" {
				key := logindLeader{entry.BootID, entry.PID}
				candidates := c.logindStarts[key]
				for len(candidates) > 0 && entry.At.Sub(candidates[0].At) > logindWait {
					candidates = candidates[1:]
				}
				if len(candidates) > 0 && candidates[0].At.Sub(entry.At) <= logindWait {
					e.set("logind_session", candidates[0].SessionID)
					c.logindStarts[key] = candidates[1:]
				} else if now.Sub(pending.received) < logindWait && len(c.journalPending) < journalBuffer {
					break
				}
			}
			if e.Fields["logind_session"] == nil {
				if entry.SystemdSession != "" {
					e.set("logind_session", entry.SystemdSession)
				} else if entry.AuditSession != "" && entry.AuditSession != unsetAuditSession {
					e.set("logind_session", entry.AuditSession)
				}
			}
			events = append(events, e)
		}
		c.journalCursor = entry.Cursor
		consumedAt = entry.At
		consumed++
	}
	c.journalPending = slices.Delete(c.journalPending, 0, consumed)
	// A start more than logindWait older than the journal already consumed can no longer match an open.
	for key, starts := range c.logindStarts {
		starts = slices.DeleteFunc(starts, func(e JournalEntry) bool { return consumedAt.Sub(e.At) > logindWait })
		if len(starts) == 0 {
			delete(c.logindStarts, key)
		} else {
			c.logindStarts[key] = starts
		}
	}
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
// from where it stopped (see readFiles), so no line is read twice. A file that was let go while still there
// (one more than MaxGlobFiles) goes on from where it was let go (see letGoWatch).
func (c *Collector) plan(ctx context.Context) {
	startup := c.lastPlan.IsZero()
	if startup && slices.Contains(c.sources, SourceAuth) {
		c.boot = c.options.bootIdentity()
	}
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
			continue
		}
		// A file a glob pattern found that is still there but no longer planned (refused, or one more than
		// MaxGlobFiles) is let go at once, or the files once followed would add up without a limit. One that is
		// gone was rotated away: its tailer reads what it still holds and is dropped by Poll.
		if _, err := os.Lstat(c.options.path(path)); err == nil && w.plan.Pattern != "" {
			c.letGoWatch(path)
		}
	}
	var added []string
	for path := range planned {
		if _, ok := c.watches[path]; !ok {
			added = append(added, path)
		}
	}
	slices.Sort(added)
	letGo := c.takeLetGo(added)
	for _, path := range added {
		f := planned[path]
		resume, wasLetGo := letGo[path]
		if !wasLetGo && !c.firstEnable[f.Source] {
			resume = c.savedPosition(path, startup)
		}
		startAtEnd := resume == nil && !createdSince(previous, path)
		t := NewTailer(c.options.path(path), resume, startAtEnd)
		if f.Source == SourceAuth {
			t.bootID = c.boot.id
		}
		t.Pattern = c.options.patternPath(f.Pattern)
		t.RefuseHardLinks = f.Source == SourceApp
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
	for path := range c.letGo {
		if _, err := os.Lstat(c.options.path(path)); errors.Is(err, fs.ErrNotExist) {
			delete(c.letGo, path)
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

// maxListedNames is how many names of a watched directory are remembered. A directory with more counts as one
// that cannot be listed, so the list a user can grow at will is never kept in memory.
const maxListedNames = 20000

var errTooManyNames = errors.New("too many names")

// readDirNames opens dir with O_DIRECTORY and O_NONBLOCK, so a FIFO put in its place cannot block the open.
func readDirNames(dir string) (map[string]bool, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := map[string]bool{}
	for {
		names, err := f.Readdirnames(1024)
		for _, name := range names {
			set[name] = true
		}
		switch {
		case len(set) > maxListedNames:
			return nil, fmt.Errorf("%s: %w", dir, errTooManyNames)
		case errors.Is(err, io.EOF):
			return set, nil
		case err != nil:
			return nil, err
		}
	}
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
	delete(c.letGo, path)
}

const (
	// maxLetGoFiles and maxLetGoPathBytes bound the positions kept for files let go while still there. Whoever
	// can write to a log directory decides how many files a pattern matches, so the oldest are forgotten first.
	maxLetGoFiles     = 5000
	maxLetGoPathBytes = 1 << 20
)

type letGoPosition struct {
	pos Position
	seq uint64
}

// letGoWatch stops following a file a glob pattern found that is still there but no longer planned: one more
// than MaxGlobFiles, or refused. Where its tailer stopped is kept, so that when the file is planned again
// (a quiet vhost's log that becomes the newest because it is attacked) it goes on from there and what was
// written meanwhile is read. The Tailer takes the position only for the same device, inode and bytes before
// the offset; another file at that name is read from its start (see takeLetGo). The positions are kept in
// memory only: the checkpoint, which every spooled batch carries, holds the followed files alone, so after a
// restart a file that was let go starts at its end when it is planned again, like any file without a saved
// position.
func (c *Collector) letGoWatch(path string) {
	pos, ok := c.watches[path].tailer.handOver()
	c.dropWatch(path)
	if !ok {
		return
	}
	if c.letGo == nil {
		c.letGo = map[string]letGoPosition{}
	}
	c.letGoSeq++
	c.letGo[path] = letGoPosition{pos, c.letGoSeq}
	c.boundLetGo()
}

// boundLetGo forgets the oldest let go positions beyond maxLetGoFiles or maxLetGoPathBytes, a tenth more than
// needed at once so that a stream of let go files does not sort the map on every one.
func (c *Collector) boundLetGo() {
	size := 0
	for path := range c.letGo {
		size += len(path)
	}
	if len(c.letGo) <= maxLetGoFiles && size <= maxLetGoPathBytes {
		return
	}
	paths := slices.SortedFunc(maps.Keys(c.letGo), func(a, b string) int {
		return cmp.Compare(c.letGo[a].seq, c.letGo[b].seq)
	})
	for _, path := range paths {
		if len(c.letGo) <= maxLetGoFiles*9/10 && size <= maxLetGoPathBytes*9/10 {
			return
		}
		size -= len(path)
		delete(c.letGo, path)
	}
}

// takeLetGo returns where the files at paths, about to be followed, start when they were let go before, and
// forgets those positions. A position goes to the path that holds its device and inode now, so a file that
// was rotated to another name a pattern matches goes on where it was let go. A path whose let go file was
// replaced by another (a rotation while it was not followed) starts at the beginning of the new file, an
// empty Position, which is what following it would have read; the name a file was renamed away from keeps
// that empty Position for when it is planned later.
func (c *Collector) takeLetGo(paths []string) map[string]*Position {
	starts := map[string]*Position{}
	if len(c.letGo) == 0 {
		return starts
	}
	byID := map[fileID]string{}
	for _, path := range slices.Sorted(maps.Keys(c.letGo)) {
		pos := c.letGo[path].pos
		id := fileID{pos.Dev, pos.Inode}
		if _, ok := byID[id]; !ok && pos.Inode != 0 {
			byID[id] = path
		}
	}
	moved := map[string]bool{}
	for _, path := range paths {
		id, ok := c.fileIDAt(path)
		if !ok {
			continue
		}
		if from, ok := byID[id]; ok {
			pos := c.letGo[from].pos
			starts[path] = &pos
			delete(byID, id)
			moved[from] = from != path
		}
	}
	for _, path := range paths {
		if _, ok := c.letGo[path]; ok && starts[path] == nil {
			starts[path] = &Position{}
		}
	}
	for _, path := range paths {
		delete(c.letGo, path)
	}
	for from, renamed := range moved {
		if e, ok := c.letGo[from]; ok && renamed {
			c.letGo[from] = letGoPosition{seq: e.seq}
		}
	}
	return starts
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
