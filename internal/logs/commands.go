package logs

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/auditcontrol"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

func (c *Collector) planCommands(ctx context.Context, p *Plan) {
	if !slices.Contains(c.sources, SourceCommands) {
		return
	}
	skip := func(reason string) {
		p.Skipped = append(p.Skipped, SkippedSource{SourceCommands, auditcontrol.RulePath, reason})
	}
	for _, unit := range []string{auditcontrol.Service, auditcontrol.PathUnit} {
		found := false
		for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
			if info, err := os.Stat(c.options.path(filepath.Join(dir, unit))); err == nil && info.Mode().IsRegular() {
				found = true
				break
			}
		}
		if !found {
			skip("helper_missing")
			return
		}
	}
	reason, _ := c.options.journalAccess()
	if reason != "" {
		skip("journal_" + reason)
		return
	}
	if err := config.WriteFileAtomic(c.options.path(auditcontrol.FlagPath), nil, 0o600, nil); err != nil {
		skip("flag_write_failed")
		return
	}
	c.commandFlag = true
	if c.auditCh == nil {
		c.auditCh = make(chan JournalEntry, journalBuffer)
		cursor := ""
		sessions := map[string]AuditSession{}
		if !c.firstEnable[SourceCommands] {
			cursor, sessions = c.resume.AuditCursor, c.resume.AuditSessions
		}
		c.audit = newAuditParser(sessions, cursor)
		ctx, c.auditCancel = context.WithCancel(ctx)
		c.auditDone = make(chan struct{})
		j := &Journal{Audit: true, Cursor: cursor, Start: c.start}
		go func() {
			defer close(c.auditDone)
			for ctx.Err() == nil {
				_ = j.Run(ctx, func(e JournalEntry) {
					select {
					case c.auditCh <- e:
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
}

func (c *Collector) commandStatus() string {
	status, err := os.ReadFile(c.options.path(auditcontrol.StatusPath))
	if err != nil {
		return "helper_pending"
	}
	switch status := strings.TrimSpace(string(status)); status {
	case "on":
		return ""
	case "auditd_missing", "audit_disabled", "audit_control_unavailable", "rule_write_failed", "rule_remove_failed", "rule_apply_failed":
		return status
	default:
		return "helper_pending"
	}
}

func (c *Collector) pollCommands() []Event {
	if c.auditCh == nil {
		return nil
	}
	reason := c.commandStatus()
	c.skipped = slices.DeleteFunc(c.skipped, func(s SkippedSource) bool { return s.Source == SourceCommands })
	if reason != "" {
		c.skipped = append(c.skipped, SkippedSource{SourceCommands, auditcontrol.RulePath, reason})
	}
	var events []Event
	for {
		select {
		case entry := <-c.auditCh:
			// Track SSH logins immediately after opt-in, even while the helper is applying the rule.
			if e, ok := c.audit.add(entry); ok && reason == "" {
				events = append(events, e)
			}
		default:
			return events
		}
	}
}

func (c *Collector) closeCommands() {
	if c.auditCancel != nil {
		c.auditCancel()
		<-c.auditDone
	}
	if c.commandFlag {
		_ = os.Remove(c.options.path(auditcontrol.FlagPath))
	}
}

func (c *Collector) commandCheckpoint(cp *Checkpoint) {
	if c.audit != nil {
		cp.AuditCursor, cp.AuditSessions = c.audit.checkpoint(), maps.Clone(c.audit.sessions)
	}
}

// DisableCommands removes the on/off flag even after a previous process crashed. The path unit applies
// the fixed removal rule; no privileged command is run by the agent.
func DisableCommands(o Options) error {
	err := os.Remove(o.path(auditcontrol.FlagPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
