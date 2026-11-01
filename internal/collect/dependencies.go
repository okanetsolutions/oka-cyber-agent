package collect

import (
	"context"
	"debug/buildinfo"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"

	"github.com/okanetsolutions/oka-cyber-agent/internal/collect/lockfile"
)

const (
	ReasonTooLarge           = "too_large"
	ReasonParseError         = "parse_error"
	ReasonUnresolvedVersions = "unresolved_versions"
	ReasonNoLockFile         = "no_lock_file"
	ReasonSymlink            = "symlink"
	ReasonNotFound           = "not_found"
)

var (
	DefaultScanPaths   = []string{"/var/www", "/srv", "/opt", "/home"}
	DefaultMaxDepth    = 6
	DefaultMaxFileSize = int64(20 << 20)

	skippedDirectories = []string{"node_modules", "vendor", "bower_components", "site-packages", "dist-packages", "__pycache__"}
	pseudoFilesystems  = []string{"/proc", "/sys", "/dev"}
)

type DependencyOptions struct {
	ScanPaths    []string
	ExcludePaths []string
	MaxDepth     int
	MaxFileSize  int64
	GoBinaries   bool
}

// DependencyCollector finds dependency lock files under the scan paths. It opens only the file names in
// lockfile.Formats (plus executables when GoBinaries is on) and never follows a symlink below a scan path: every
// directory and file is opened relative to its parent directory without following one (see openAt), so the path
// it checks against exclude_paths is the path of what it opens.
type DependencyCollector struct {
	Root    string
	Options DependencyOptions
}

func (DependencyCollector) Name() string { return "dependencies" }

func (c DependencyCollector) Collect(ctx context.Context, inv *Inventory) error {
	o := c.Options
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = DefaultMaxFileSize
	}
	excluded := excludedFiles(c.Root, o.ExcludePaths)
	seen := map[string]bool{}
	for _, scanPath := range o.ScanPaths {
		if err := ctx.Err(); err != nil {
			return err
		}
		scanPath = filepath.Clean(scanPath)
		if !filepath.IsAbs(scanPath) || isExcluded(scanPath, o.ExcludePaths) {
			continue
		}
		s := &scan{collector: c, options: o, hostRoot: scanPath, excluded: excluded, inv: inv, seen: seen, dirs: map[string][]string{}}
		if err := s.run(ctx); err != nil {
			return err
		}
	}
	return nil
}

// excludedFiles lists the files and directories that exclude_paths name, so that one reached under another
// path is excluded too: an exclude path that goes through a symlink (/var/www/current/storage with current a
// symlink to a release directory), a scan path that is a symlink into an excluded directory, or a bind mount.
func excludedFiles(root string, excludePaths []string) []fs.FileInfo {
	var infos []fs.FileInfo
	for _, p := range excludePaths {
		if info, err := os.Stat(filepath.Join(root, p)); err == nil {
			infos = append(infos, info)
		}
	}
	return infos
}

type scan struct {
	collector DependencyCollector
	options   DependencyOptions
	hostRoot  string
	excluded  []fs.FileInfo
	inv       *Inventory
	seen      map[string]bool
	dirs      map[string][]string
}

func (s *scan) run(ctx context.Context) error {
	full := filepath.Join(s.collector.Root, s.hostRoot)
	resolved, ok := s.resolveScanPath(full)
	if !ok {
		return nil
	}
	dir, err := os.OpenFile(full, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer dir.Close()
	if !s.isFileAt(dir, resolved) {
		return nil
	}
	if err := s.walk(ctx, dir, "."); err != nil {
		return err
	}
	s.reportManifestsWithoutLockFiles()
	return nil
}

// resolveScanPath resolves the symlinks of a scan path and refuses it when it is an excluded directory or lies
// inside one. It only looks up file metadata, so nothing under an excluded directory is opened.
func (s *scan) resolveScanPath(full string) (string, bool) {
	if len(s.excluded) == 0 {
		return full, true
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", false
	}
	for p := resolved; ; p = filepath.Dir(p) {
		if info, err := os.Stat(p); err == nil && s.isExcludedFile(info) {
			return "", false
		}
		if p == filepath.Dir(p) {
			return resolved, true
		}
	}
}

// isFileAt makes sure the scan path did not change between resolveScanPath and the open.
func (s *scan) isFileAt(dir *os.File, resolved string) bool {
	if len(s.excluded) == 0 {
		return true
	}
	opened, err := dir.Stat()
	if err != nil {
		return false
	}
	current, err := os.Stat(resolved)
	return err == nil && os.SameFile(opened, current)
}

func (s *scan) isExcludedFile(info fs.FileInfo) bool {
	return slices.ContainsFunc(s.excluded, func(e fs.FileInfo) bool { return os.SameFile(e, info) })
}

// isExcludedEntry looks the entry up without opening it (the type of a listed entry is that of the entry
// itself, never of a symlink target) and tells whether it is one of the excluded files or directories.
func (s *scan) isExcludedEntry(d fs.DirEntry) bool {
	if len(s.excluded) == 0 {
		return false
	}
	info, err := d.Info()
	return err != nil || s.isExcludedFile(info)
}

// walk lists dir, reached at rel, in name order. A symlinked directory is listed as a symlink, not a directory,
// so the walk never descends into one; and because a subdirectory is opened relative to dir without following
// a symlink, one swapped in after the listing is refused rather than followed.
func (s *scan) walk(ctx context.Context, dir *os.File, rel string) error {
	entries, _ := dir.ReadDir(-1)
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	for _, d := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		entryRel := path.Join(rel, d.Name())
		hostPath := path.Join(s.hostRoot, entryRel)
		if d.IsDir() {
			if err := s.directory(ctx, dir, entryRel, hostPath, d); err != nil {
				return err
			}
			continue
		}
		s.file(dir, entryRel, hostPath, d)
	}
	return nil
}

func (s *scan) directory(ctx context.Context, parent *os.File, rel, hostPath string, d fs.DirEntry) error {
	if skippedDirectory(rel, d.Name()) || strings.Count(rel, "/")+1 >= s.options.MaxDepth || isExcluded(hostPath, s.options.ExcludePaths) || isExcluded(hostPath, pseudoFilesystems) || s.isExcludedEntry(d) {
		return nil
	}
	dir, err := openAt(parent, d.Name(), os.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil {
		return nil
	}
	defer dir.Close()
	if info, err := dir.Stat(); err != nil || s.isExcludedFile(info) {
		return nil
	}
	return s.walk(ctx, dir, rel)
}

func (s *scan) file(dir *os.File, rel, hostPath string, d fs.DirEntry) {
	format, isLockFile := lockfile.ForFile(d.Name())
	_, isManifest := lockfile.Manifests[d.Name()]
	excluded := isExcluded(hostPath, s.options.ExcludePaths)
	// An excluded lock file is never opened, but it still resolves the manifests next to it.
	if isLockFile || isManifest && !excluded {
		s.dirs[path.Dir(rel)] = append(s.dirs[path.Dir(rel)], d.Name())
	}
	if excluded {
		return
	}
	if isLockFile {
		s.lockFile(dir, hostPath, format, d)
	} else if s.options.GoBinaries && d.Type().IsRegular() {
		s.goBinary(dir, hostPath, d)
	}
}

// skippedDirectory leaves out installed dependency trees (their own lock files describe libraries, not the
// deployed application), hidden directories (.git and package manager caches such as .npm, .cargo, .m2) and
// the Go module cache.
func skippedDirectory(rel, name string) bool {
	return slices.Contains(skippedDirectories, name) || strings.HasPrefix(name, ".") || rel == "pkg/mod" || strings.HasSuffix(rel, "/pkg/mod")
}

// lockFile reports a symlinked lock file without opening it: its target may be outside the scan path or under
// an excluded path. A target inside a scan path is reported under its own path.
func (s *scan) lockFile(dir *os.File, hostPath string, format lockfile.Format, d fs.DirEntry) {
	if s.seen[hostPath] || s.isExcludedEntry(d) {
		return
	}
	s.seen[hostPath] = true
	if d.Type()&fs.ModeSymlink != 0 {
		s.inv.Skip(hostPath, ReasonSymlink)
		return
	}
	data, reason := s.read(dir, d.Name())
	if reason == ReasonNotFound {
		return
	}
	if reason != "" {
		s.inv.Skip(hostPath, reason)
		return
	}
	result, err := format.Parse(data)
	if err != nil {
		s.inv.Skip(hostPath, ReasonParseError)
		return
	}
	if result.Unresolved > 0 {
		// Normalize drops this record when some packages of the file are sent (see Inventory.Normalize).
		s.inv.Skip(hostPath, ReasonUnresolvedVersions)
	}
	for _, d := range result.Dependencies {
		s.inv.Packages = append(s.inv.Packages, Package{
			Ecosystem:    format.Ecosystem,
			Name:         d.Name,
			Version:      d.Version,
			ManifestPath: hostPath,
			Direct:       d.Direct,
		})
	}
}

// read opens a lock file the walk listed as a regular file. A symlink swapped in since is refused (ELOOP), a
// file removed since is ignored, and openAt's O_NONBLOCK keeps a FIFO given a lock file name by any local user
// from blocking the open, and with it the whole inventory.
func (s *scan) read(dir *os.File, name string) ([]byte, string) {
	f, err := openAt(dir, name, os.O_RDONLY)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ReasonNotFound
	case errors.Is(err, syscall.ELOOP):
		return nil, ReasonSymlink
	case errors.Is(err, fs.ErrPermission):
		return nil, ReasonPermissionDenied
	case err != nil:
		return nil, ReasonParseError
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ReasonParseError
	}
	if info.Size() > s.options.MaxFileSize {
		return nil, ReasonTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, s.options.MaxFileSize+1))
	if err != nil {
		return nil, ReasonParseError
	}
	if int64(len(data)) > s.options.MaxFileSize {
		return nil, ReasonTooLarge
	}
	return data, ""
}

// goBinary reads the module list Go embeds in executables (only when collect_go_binaries is on). The lock file
// size limit does not apply: buildinfo.Read reads the headers and searches the data segment in small chunks
// through io.ReaderAt, so a large binary (terraform, kubectl) costs no more memory than a small one. Like a lock
// file it is opened with openAt, and once open it must still be the regular file the walk listed, so a FIFO
// or a symlink swapped in after the walk cannot block the inventory or be read in its place.
func (s *scan) goBinary(dir *os.File, hostPath string, d fs.DirEntry) {
	listed, err := d.Info()
	if err != nil || listed.Mode().Perm()&0o111 == 0 || listed.Size() < 4 || s.seen[hostPath] || s.isExcludedFile(listed) {
		return
	}
	f, err := openAt(dir, d.Name(), os.O_RDONLY)
	if err != nil {
		return
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(listed, opened) {
		return
	}
	build, err := buildinfo.Read(f)
	if err != nil {
		return
	}
	s.seen[hostPath] = true
	s.inv.Packages = append(s.inv.Packages, GoBuildPackages(build, hostPath)...)
}

// GoBuildPackages lists the binary's own module and the modules compiled into it, plus the standard library as
// "stdlib", the name OSV.dev uses for Go toolchain vulnerabilities. The main module comes first so that it wins
// if a dependency ever carries the same path.
func GoBuildPackages(build *buildinfo.BuildInfo, manifestPath string) []Package {
	var packages []Package
	if version, ok := strings.CutPrefix(build.GoVersion, "go"); ok {
		version, _, _ = strings.Cut(version, " ")
		packages = append(packages, Package{Ecosystem: lockfile.Go, Name: "stdlib", Version: version, ManifestPath: manifestPath})
	}
	for _, m := range append([]*debug.Module{&build.Main}, build.Deps...) {
		if p, ok := goModulePackage(m, manifestPath); ok {
			packages = append(packages, p)
		}
	}
	return packages
}

// goModulePackage reports a module under its replacement when go.mod replaced it, and only when the version
// names published code. Go stamps the main module with the release it was installed at (go install m@v1.2.0)
// or, since Go 1.24, with the version control state of the build: a tag (v1.2.0), a pseudo-version for an
// untagged commit, "+dirty" when the working tree had uncommitted changes, and "(devel)" or nothing when it
// cannot tell. A pseudo-version (v1.2.1-0.20261101203445-395da2043f88) is kept, as it is for dependencies: it
// names one commit and sorts as a pre-release of the next version, which is how the Go vulnerability database
// and OSV.dev compare it. A dirty build is left out because its code is no published version, and a directory
// replacement has no version at all.
func goModulePackage(m *debug.Module, manifestPath string) (Package, bool) {
	if m.Replace != nil {
		m = m.Replace
	}
	version := strings.TrimPrefix(m.Version, "v")
	if m.Path == "" || version == "" || version == "(devel)" || strings.HasSuffix(version, "+dirty") {
		return Package{}, false
	}
	return Package{Ecosystem: lockfile.Go, Name: m.Path, Version: version, ManifestPath: manifestPath}, true
}

// reportManifestsWithoutLockFiles records manifests such as package.json that have no lock file next to
// them or in a parent directory (workspaces keep one lock file at their root).
func (s *scan) reportManifestsWithoutLockFiles() {
	for _, dir := range sortedKeys(s.dirs) {
		for _, name := range s.dirs[dir] {
			locks, ok := lockfile.Manifests[name]
			if !ok || s.hasLockFile(dir, locks) {
				continue
			}
			s.inv.Skip(path.Join(s.hostRoot, dir, name), ReasonNoLockFile)
		}
	}
}

func (s *scan) hasLockFile(dir string, locks []string) bool {
	for {
		for _, name := range s.dirs[dir] {
			if slices.Contains(locks, name) {
				return true
			}
		}
		if dir == "." {
			return false
		}
		dir = path.Dir(dir)
	}
}

func isExcluded(hostPath string, excluded []string) bool {
	for _, e := range excluded {
		e = filepath.Clean(e)
		if hostPath == e || strings.HasPrefix(hostPath, strings.TrimSuffix(e, "/")+"/") {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
