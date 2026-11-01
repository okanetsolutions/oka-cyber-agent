package logs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	ReasonPermissionDenied = "permission_denied"
	ReasonNotFound         = "not_found"

	MaxAppPaths = 10
)

var (
	authFiles   = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"}
	cronFiles   = []string{"/var/log/cron.log", "/var/log/cron"}
	webPatterns = []string{"/var/log/nginx/*access*.log", "/var/log/apache2/*access*.log", "/var/log/httpd/*access_log"}
	journalDirs = []string{"/var/log/journal", "/run/log/journal"}
)

type SkippedSource struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type FilePlan struct {
	Source string
	Path   string
	Vhost  string
	// Glob is set for a file found by a glob pattern rather than named in full. Such files come and go with
	// normal retention (a daily laravel-YYYY-MM-DD.log, a removed vhost), so their removal is not reported.
	Glob bool
}

// Plan is what the enabled sources resolve to on this host. Paths are host paths; Options.Root only
// prefixes them for tests.
type Plan struct {
	Journal bool
	Files   []FilePlan
	Skipped []SkippedSource
}

type Options struct {
	Root string
	// AppPaths come only from the local configuration file; the server can never add one.
	AppPaths []string
	// HasJournalctl reports whether journalctl can be run.
	HasJournalctl func() bool
}

func (o Options) path(p string) string {
	return filepath.Join(o.Root, p)
}

// PlanSources resolves the enabled built in sources: auth reads journald when journalctl exists and the
// system journal is readable, and the first auth log file (plus the cron log) only when there is no
// journal; web reads the nginx and Apache access logs; app reads the configured log_paths.
func PlanSources(enabled []string, o Options) Plan {
	var p Plan
	if slices.Contains(enabled, SourceAuth) {
		o.planAuth(&p)
	}
	if slices.Contains(enabled, SourceWeb) {
		o.planWeb(&p)
	}
	if slices.Contains(enabled, SourceApp) {
		o.planApp(&p)
	}
	return p
}

// planAuth never reads the auth log files when the system journal exists, even when it is unreadable: any
// local user can write a line with any program name to them (logger -p auth.info -t sshd), while journald
// records who really sent each entry (see TrustedAuthEntry).
func (o Options) planAuth(p *Plan) {
	switch o.journalAccess() {
	case "":
		p.Journal = true
		return
	case ReasonPermissionDenied:
		p.Skipped = append(p.Skipped, SkippedSource{SourceAuth, "journal", ReasonPermissionDenied})
		return
	}
	for _, path := range authFiles {
		switch reason := o.readable(path); reason {
		case "":
			p.Files = append(p.Files, FilePlan{Source: SourceAuth, Path: path})
			for _, cron := range cronFiles {
				if o.readable(cron) == "" {
					p.Files = append(p.Files, FilePlan{Source: SourceAuth, Path: cron})
				}
			}
			return
		case ReasonPermissionDenied:
			p.Skipped = append(p.Skipped, SkippedSource{SourceAuth, path, ReasonPermissionDenied})
			return
		}
	}
	p.Skipped = append(p.Skipped, SkippedSource{SourceAuth, authFiles[0], ReasonNotFound})
}

// journalAccess returns "" when the system journal can be read, permission_denied when its files exist
// but are not readable (the agent's user is not in the systemd-journal or adm group), and not_found
// when there is no journal or no journalctl.
func (o Options) journalAccess() string {
	if o.HasJournalctl == nil || !o.HasJournalctl() {
		return ReasonNotFound
	}
	found := false
	for _, dir := range journalDirs {
		files, _ := filepath.Glob(o.path(filepath.Join(dir, "*", "system*.journal")))
		for _, file := range files {
			found = true
			if f, err := os.Open(file); err == nil {
				f.Close()
				return ""
			}
		}
	}
	if found {
		return ReasonPermissionDenied
	}
	return ReasonNotFound
}

func (o Options) planWeb(p *Plan) {
	var found bool
	for _, pattern := range webPatterns {
		matches, _ := filepath.Glob(o.path(pattern))
		for _, match := range matches {
			hostPath := o.hostPath(match)
			found = true
			if reason := o.readable(hostPath); reason != "" {
				p.Skipped = append(p.Skipped, SkippedSource{SourceWeb, hostPath, reason})
				continue
			}
			p.Files = append(p.Files, FilePlan{Source: SourceWeb, Path: hostPath, Vhost: VhostFromPath(hostPath), Glob: true})
		}
	}
	if !found {
		p.Skipped = append(p.Skipped, SkippedSource{SourceWeb, "/var/log/nginx", ReasonNotFound})
	}
}

// planApp follows every configured path, also the ones that do not exist yet (they are read from the start
// once created). Glob patterns, such as Laravel's daily laravel-*.log files, are expanded.
func (o Options) planApp(p *Plan) {
	paths := o.AppPaths
	if len(paths) > MaxAppPaths {
		paths = paths[:MaxAppPaths]
	}
	for _, configured := range paths {
		if !filepath.IsAbs(configured) {
			continue
		}
		if !strings.ContainsAny(configured, "*?[") {
			if reason := o.readable(configured); reason != "" {
				p.Skipped = append(p.Skipped, SkippedSource{SourceApp, configured, reason})
				if reason == ReasonPermissionDenied {
					continue
				}
			}
			p.Files = append(p.Files, FilePlan{Source: SourceApp, Path: configured})
			continue
		}
		matches, _ := filepath.Glob(o.path(configured))
		if len(matches) == 0 {
			p.Skipped = append(p.Skipped, SkippedSource{SourceApp, configured, ReasonNotFound})
		}
		for _, match := range matches {
			hostPath := o.hostPath(match)
			if reason := o.readable(hostPath); reason != "" {
				p.Skipped = append(p.Skipped, SkippedSource{SourceApp, hostPath, reason})
				continue
			}
			p.Files = append(p.Files, FilePlan{Source: SourceApp, Path: hostPath, Glob: true})
		}
	}
}

func (o Options) readable(hostPath string) string {
	f, err := os.Open(o.path(hostPath))
	switch {
	case err == nil:
		f.Close()
		return ""
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermissionDenied
	default:
		return ReasonNotFound
	}
}

func (o Options) hostPath(full string) string {
	if o.Root == "" || o.Root == "/" {
		return full
	}
	rel, err := filepath.Rel(o.Root, full)
	if err != nil {
		return full
	}
	return "/" + rel
}
