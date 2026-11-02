package logs

import (
	"path/filepath"
	"slices"
)

const (
	ReasonPermissionDenied = "permission_denied"
	ReasonNotFound         = "not_found"
	ReasonSymlink          = "symlink"
	ReasonNotRegularFile   = "not_regular_file"

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
	// Pattern is the glob pattern the file was found by, "" for a file named in full. Such files come and go
	// with normal retention (a daily laravel-YYYY-MM-DD.log, a removed vhost), so their removal is not
	// reported. A name the pattern's wildcards matched is never followed through a symlink (see openLogFile).
	Pattern string
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
		switch reason := o.readable(path, ""); reason {
		case "":
			p.Files = append(p.Files, FilePlan{Source: SourceAuth, Path: path})
			for _, cron := range cronFiles {
				if o.readable(cron, "") == "" {
					p.Files = append(p.Files, FilePlan{Source: SourceAuth, Path: cron})
				}
			}
			return
		case ReasonNotFound:
		default:
			p.Skipped = append(p.Skipped, SkippedSource{SourceAuth, path, reason})
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
		pattern := o.path(filepath.Join(dir, "*", "system*.journal"))
		files, _ := filepath.Glob(pattern)
		for _, file := range files {
			found = true
			if f, err := openLogFile(file, pattern); err == nil {
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
			if reason := o.readable(hostPath, pattern); reason != "" {
				p.Skipped = append(p.Skipped, SkippedSource{SourceWeb, hostPath, reason})
				continue
			}
			p.Files = append(p.Files, FilePlan{Source: SourceWeb, Path: hostPath, Vhost: VhostFromPath(hostPath), Pattern: pattern})
		}
	}
	if !found {
		p.Skipped = append(p.Skipped, SkippedSource{SourceWeb, "/var/log/nginx", ReasonNotFound})
	}
}

// planApp follows every configured path, also the ones that do not exist yet (they are read from the start
// once created). Glob patterns, such as Laravel's daily laravel-*.log files, are expanded. A file that is a
// symlink is never read, nor one found through a directory a wildcard matched that is a symlink: the
// directories of log files are often writable by the application's user (see openLogFile).
func (o Options) planApp(p *Plan) {
	paths := o.AppPaths
	if len(paths) > MaxAppPaths {
		paths = paths[:MaxAppPaths]
	}
	for _, configured := range paths {
		if !filepath.IsAbs(configured) {
			continue
		}
		if !hasGlobMeta(configured) {
			if reason := o.readable(configured, ""); reason != "" {
				p.Skipped = append(p.Skipped, SkippedSource{SourceApp, configured, reason})
				if reason == ReasonPermissionDenied {
					continue
				}
			}
			p.Files = append(p.Files, FilePlan{Source: SourceApp, Path: configured})
			continue
		}
		pattern := filepath.Clean(configured)
		matches, _ := filepath.Glob(o.path(pattern))
		if len(matches) == 0 {
			p.Skipped = append(p.Skipped, SkippedSource{SourceApp, configured, ReasonNotFound})
		}
		for _, match := range matches {
			hostPath := o.hostPath(match)
			if reason := o.readable(hostPath, pattern); reason != "" {
				p.Skipped = append(p.Skipped, SkippedSource{SourceApp, hostPath, reason})
				continue
			}
			p.Files = append(p.Files, FilePlan{Source: SourceApp, Path: hostPath, Pattern: pattern})
		}
	}
}

// readable reports why the log file at hostPath, found by the glob pattern (a host path, "" for a file named
// in full), cannot be read, or "" when it can.
func (o Options) readable(hostPath, pattern string) string {
	f, err := openLogFile(o.path(hostPath), o.patternPath(pattern))
	if err == nil {
		f.Close()
	}
	return skipReason(err)
}

func (o Options) patternPath(pattern string) string {
	if pattern == "" {
		return ""
	}
	return o.path(pattern)
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
