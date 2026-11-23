package logs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	ReasonPermissionDenied = "permission_denied"
	ReasonNotFound         = "not_found"
	ReasonSymlink          = "symlink"
	ReasonNotRegularFile   = "not_regular_file"
	// ReasonHardLink is an application log with another name somewhere (see errHardLink).
	ReasonHardLink = "hard_link"
	// ReasonTooManyFiles is listed once for a glob pattern, with the pattern as its path, when it matches more
	// files than are followed.
	ReasonTooManyFiles = "too_many_files"

	// reasonCompressed marks a glob match that is a compressed rotated log. It is left out of the plan
	// without being reported, since every rotation makes one.
	reasonCompressed = "compressed"

	MaxAppPaths = 10
	// MaxGlobFiles is how many files of one glob pattern are followed: the most recently modified ones. Every
	// followed file costs an open descriptor, a poll per second and an entry in every checkpoint, and whoever
	// can write to a log directory decides how many files a pattern matches there.
	MaxGlobFiles = 200
	// maxPlannedPathBytes bounds the paths of all the files found by glob patterns in one plan, as JSON writes
	// them (a byte of a file name takes up to six), so that the checkpoint, which holds a position per followed
	// file, stays far below what the agent reads back (4 MB).
	maxPlannedPathBytes = 512 << 10
)

var (
	authFiles   = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"}
	cronFiles   = []string{"/var/log/cron.log", "/var/log/cron"}
	webPatterns = []string{"/var/log/nginx/*access*.log", "/var/log/apache2/*access*.log", "/var/log/httpd/*access_log"}
	journalDirs = []string{"/var/log/journal", "/run/log/journal"}

	compressedExtensions = []string{".gz", ".xz", ".bz2", ".zst", ".zip"}
	compressedMagic      = [][]byte{{0x1f, 0x8b}, {0xfd, '7', 'z', 'X', 'Z', 0x00}, []byte("BZh"), {0x28, 0xb5, 0x2f, 0xfd}, []byte("PK\x03\x04")}
)

type SkippedSource struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// MaxSkippedPathLength is the longest path the server accepts in a skipped source.
const MaxSkippedPathLength = 1024

// Sendable returns the skipped source as the server accepts it, ok false when it cannot be: the server
// requires an absolute path of at most MaxSkippedPathLength characters without NUL, CR or LF, and rejects the
// whole request otherwise. A path a glob matched may hold any byte, so those are replaced and a long path cut.
func (s SkippedSource) Sendable() (SkippedSource, bool) {
	if !strings.HasPrefix(s.Path, "/") || s.Source == "" || s.Reason == "" {
		return s, false
	}
	s.Path = cut(strings.NewReplacer("\x00", "\uFFFD", "\r", "\uFFFD", "\n", "\uFFFD").Replace(s.Path), MaxSkippedPathLength)
	s.Reason = cut(s.Reason, maxNameLength)
	return s, true
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

	// globPathBytes is how much of maxPlannedPathBytes the files found by glob patterns have used.
	globPathBytes int
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
	switch reason, dir := o.journalAccess(); reason {
	case "":
		p.Journal = true
		return
	case ReasonPermissionDenied:
		p.Skipped = append(p.Skipped, SkippedSource{SourceAuth, dir, ReasonPermissionDenied})
		return
	}
	for _, path := range authFiles {
		switch reason := o.readable(SourceAuth, path, ""); reason {
		case "":
			p.Files = append(p.Files, FilePlan{Source: SourceAuth, Path: path})
			for _, cron := range cronFiles {
				if o.readable(SourceAuth, cron, "") == "" {
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

// journalAccess returns "" when the system journal can be read, permission_denied and the first journal
// directory that has files when they are not readable (the agent's user is not in the systemd-journal or adm
// group), and not_found when there is no journal or no journalctl.
func (o Options) journalAccess() (reason, dir string) {
	if o.HasJournalctl == nil || !o.HasJournalctl() {
		return ReasonNotFound, ""
	}
	for _, journalDir := range journalDirs {
		pattern := o.path(filepath.Join(journalDir, "*", "system*.journal"))
		files, _ := filepath.Glob(pattern)
		for _, file := range files {
			if dir == "" {
				dir = journalDir
			}
			if f, err := openLogFile(file, pattern); err == nil {
				f.Close()
				return "", ""
			}
		}
	}
	if dir != "" {
		return ReasonPermissionDenied, dir
	}
	return ReasonNotFound, ""
}

func (o Options) planWeb(p *Plan) {
	var found bool
	for _, pattern := range webPatterns {
		found = o.planGlob(p, SourceWeb, pattern) || found
	}
	if !found {
		p.Skipped = append(p.Skipped, SkippedSource{SourceWeb, "/var/log/nginx", ReasonNotFound})
	}
}

// planApp follows every configured path, also the ones that do not exist yet (they are read from the start
// once created). Glob patterns, such as Laravel's daily laravel-*.log files, are expanded. A file that is a
// symlink is never read, nor one found through a directory a wildcard matched that is a symlink: the
// directories of log files are often writable by the application's user (see openLogFile). For the same reason
// a file with a second hard link is not read either (see errHardLink).
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
			if reason := o.readable(SourceApp, configured, ""); reason != "" {
				p.Skipped = append(p.Skipped, SkippedSource{SourceApp, configured, reason})
				if reason == ReasonPermissionDenied || reason == ReasonHardLink {
					continue
				}
			}
			p.Files = append(p.Files, FilePlan{Source: SourceApp, Path: configured})
			continue
		}
		if !o.planGlob(p, SourceApp, filepath.Clean(configured)) {
			p.Skipped = append(p.Skipped, SkippedSource{SourceApp, configured, ReasonNotFound})
		}
	}
}

// planGlob plans the files the glob pattern (a host path) matches and tells whether it matches any. Compressed
// rotated logs are left out, a file that cannot be read is listed as skipped, and of more than MaxGlobFiles
// matches only the most recently modified ones are looked at: the pattern is then listed once as
// ReasonTooManyFiles, as it is when the paths of the planned files use up maxPlannedPathBytes.
func (o Options) planGlob(p *Plan, source, pattern string) (found bool) {
	matches, _ := filepath.Glob(o.path(pattern))
	found = len(matches) > 0
	matches = slices.DeleteFunc(matches, func(match string) bool {
		return slices.Contains(compressedExtensions, strings.ToLower(filepath.Ext(match)))
	})
	tooMany := len(matches) > MaxGlobFiles
	if tooMany {
		matches = latestModified(matches, MaxGlobFiles)
	}
	for _, match := range matches {
		hostPath := o.hostPath(match)
		reason := o.readable(source, hostPath, pattern)
		if reason == reasonCompressed {
			continue
		}
		if reason != "" {
			p.Skipped = append(p.Skipped, SkippedSource{source, hostPath, reason})
			continue
		}
		encoded, _ := json.Marshal(hostPath)
		if p.globPathBytes+len(encoded) > maxPlannedPathBytes {
			tooMany = true
			break
		}
		p.globPathBytes += len(encoded)
		file := FilePlan{Source: source, Path: hostPath, Pattern: pattern}
		if source == SourceWeb {
			file.Vhost = VhostFromPath(hostPath)
		}
		p.Files = append(p.Files, file)
	}
	if tooMany {
		p.Skipped = append(p.Skipped, SkippedSource{source, pattern, ReasonTooManyFiles})
	}
	return found
}

// latestModified returns the n most recently modified of paths, in the order they came in. A path that is gone
// counts as the oldest.
func latestModified(paths []string, n int) []string {
	modified := make(map[string]time.Time, len(paths))
	for _, path := range paths {
		if info, err := os.Lstat(path); err == nil {
			modified[path] = info.ModTime()
		}
	}
	latest := slices.Clone(paths)
	slices.SortStableFunc(latest, func(a, b string) int { return modified[b].Compare(modified[a]) })
	keep := make(map[string]bool, n)
	for _, path := range latest[:n] {
		keep[path] = true
	}
	return slices.DeleteFunc(slices.Clone(paths), func(path string) bool { return !keep[path] })
}

// readable reports why the log file at hostPath, found by the glob pattern (a host path, "" for a file named
// in full), cannot be read, or "" when it can. A glob match that is a compressed rotated log (by its
// extension or its first bytes, logrotate's compress option) is reasonCompressed: it is never parsed as text.
func (o Options) readable(source, hostPath, pattern string) string {
	if pattern != "" && slices.Contains(compressedExtensions, strings.ToLower(filepath.Ext(hostPath))) {
		return reasonCompressed
	}
	f, err := openLogFile(o.path(hostPath), o.patternPath(pattern))
	if err == nil && source == SourceApp {
		err = refuseHardLink(f)
	}
	if err != nil {
		return skipReason(err)
	}
	defer f.Close()
	if pattern != "" && compressed(f) {
		return reasonCompressed
	}
	return ""
}

func compressed(f *os.File) bool {
	head := make([]byte, 6)
	n, _ := f.ReadAt(head, 0)
	for _, magic := range compressedMagic {
		if bytes.HasPrefix(head[:n], magic) {
			return true
		}
	}
	return false
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
