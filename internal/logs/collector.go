package logs

import (
	"context"
	"os/exec"
	"slices"
	"time"
)

const (
	replanEvery    = time.Minute
	journalBackoff = 10 * time.Second
	journalBuffer  = 10000
)

// Checkpoint is how far every reader got: file positions by path and the journal cursor. The agent saves it
// only after the server acknowledged the events read up to it (at least once delivery).
type Checkpoint struct {
	Sources       []string            `json:"sources"`
	Files         map[string]Position `json:"files"`
	JournalCursor string              `json:"journal_cursor,omitempty"`
}

type watch struct {
	plan   FilePlan
	tailer *Tailer
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
	skipped     []SkippedSource
	lastPlan    time.Time

	journalCancel context.CancelFunc
	journalDone   chan struct{}
	journalCh     chan JournalEntry
	journalCursor string
}

// NewCollector starts at resume for the sources that were already enabled when it was saved. A source that
// is newly enabled starts at the current end of its files and of the journal: no history is uploaded.
func NewCollector(sources []string, o Options, resume Checkpoint, start StartFunc, now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	if o.HasJournalctl == nil {
		o.HasJournalctl = func() bool { _, err := exec.LookPath("journalctl"); return err == nil }
	}
	c := &Collector{
		sources:     slices.Clone(sources),
		options:     o,
		now:         now,
		start:       start,
		firstEnable: map[string]bool{},
		resume:      resume,
		watches:     map[string]*watch{},
	}
	for _, s := range sources {
		c.firstEnable[s] = !slices.Contains(resume.Sources, s)
	}
	return c
}

func (c *Collector) Sources() []string { return slices.Clone(c.sources) }

func (c *Collector) Skipped() []SkippedSource { return slices.Clone(c.skipped) }

// Poll returns the events read since the previous call.
func (c *Collector) Poll(ctx context.Context) []Event {
	if c.lastPlan.IsZero() || c.now().Sub(c.lastPlan) >= replanEvery {
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
		if result.Removed {
			events = append(events, RemovedEvent(w.plan.Source, w.plan.Path, c.now().UTC()))
		}
	}
	for {
		select {
		case entry := <-c.journalCh:
			if e, ok := ParseAuth(entry.Identifier, entry.Message, entry.At); ok {
				events = append(events, e)
			}
			c.journalCursor = entry.Cursor
			continue
		default:
		}
		break
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
		return ParseAuth(l.Program, l.Message, l.At.UTC())
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
// up. Files that disappear keep their tailer, which reports log_file_removed after RemovedAfter.
func (c *Collector) plan(ctx context.Context) {
	c.lastPlan = c.now()
	p := PlanSources(c.sources, c.options)
	c.skipped = p.Skipped
	firstPlan := len(c.watches) == 0 && c.journalCh == nil
	for _, f := range p.Files {
		if _, ok := c.watches[f.Path]; ok {
			continue
		}
		var resume *Position
		if pos, ok := c.resume.Files[f.Path]; ok && !c.firstEnable[f.Source] {
			resume = &pos
		}
		startAtEnd := firstPlan && c.firstEnable[f.Source]
		t := NewTailer(c.options.path(f.Path), resume, startAtEnd)
		t.Now = c.now
		c.watches[f.Path] = &watch{plan: f, tailer: t}
	}
	if p.Journal && c.journalCh == nil {
		cursor := ""
		if !c.firstEnable[SourceAuth] {
			cursor = c.resume.JournalCursor
		}
		c.startJournal(ctx, cursor)
	}
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
	cp.JournalCursor = c.journalCursor
	return cp
}

func (c *Collector) Close() {
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
