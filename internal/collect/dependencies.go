package collect

import (
	"context"
	"debug/buildinfo"
	"errors"
	"io"
	"io/fs"
	"iter"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"

	"github.com/okanetsolutions/oka-cyber-agent/internal/collect/lockfile"
	"github.com/okanetsolutions/oka-cyber-agent/internal/safeopen"
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

// What one walk keeps and reads, whatever any local user planted under a scan path. A host within these limits is
// reported as it was before them.
const (
	// maxWalkPackages is how many dependency packages the walk holds for Normalize to choose MaxPackages from. The
	// lock files and Go binaries found after that are recorded as package_limit, as Normalize records those it cuts.
	maxWalkPackages = 4 * MaxPackages

	// maxGoBinaryBytes is how much of one executable is read to find its Go build info. A real Go binary needs its
	// headers and build info section, well under a megabyte.
	maxGoBinaryBytes = 8 << 20

	directoryBatch = 1024
)

// Variables so that tests can reach them with small trees.
var (
	// maxWalkBytes is how much of lock files and application detail files one walk reads: 51 files of the default
	// size limit. Past it a lock file is recorded as package_limit without being read.
	maxWalkBytes int64 = 1 << 30

	// maxDirectoryEntries is how many subdirectories and dependency files of one directory are walked. A directory
	// with more is recorded as too_large and walked in part.
	maxDirectoryEntries = 100_000
)

var errGoBinaryBudget = errors.New("more to read than a Go binary needs")

type DependencyOptions struct {
	ScanPaths    []string
	ExcludePaths []string
	MaxDepth     int
	MaxFileSize  int64
	GoBinaries   bool
	// ApplicationDetails also reads, in a directory with a parsed lock file, the name and runtime requirements of
	// composer.json and package.json and the origin remote, branch and commit of .git (see scan.application).
	ApplicationDetails bool
}

// DependencyCollector finds dependency lock files under the scan paths. It opens only the file names in
// lockfile.Formats (plus executables when GoBinaries is on, and the files scan.application names when
// ApplicationDetails is on) and never follows a symlink below a scan path: every
// directory and file is opened relative to its parent directory without following one (see safeopen.OpenAt), so
// the path it checks against exclude_paths is the path of what it opens.
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
	budget := &walkBudget{}
	for _, scanPath := range o.ScanPaths {
		if err := ctx.Err(); err != nil {
			return err
		}
		scanPath = filepath.Clean(scanPath)
		if !filepath.IsAbs(scanPath) || isExcluded(scanPath, o.ExcludePaths) {
			continue
		}
		s := &scan{collector: c, options: o, hostRoot: scanPath, excluded: excluded, inv: inv, seen: seen, budget: budget, dirs: map[string][]string{}}
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
	budget    *walkBudget
	dirs      map[string][]string
}

// walkBudget counts what the scans of one Collect hold and read (see maxWalkPackages and maxWalkBytes).
type walkBudget struct {
	packages int
	bytes    int64
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
	entries, complete := s.list(ctx, dir)
	if !complete {
		s.inv.Skip(path.Join(s.hostRoot, rel), ReasonTooLarge)
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	releases, release := s.liveRelease(ctx, dir, rel, entries)
	if releases != nil {
		defer releases.Close()
	}
	parsedLockFile := false
	for _, d := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		entryRel := path.Join(rel, d.Name())
		hostPath := path.Join(s.hostRoot, entryRel)
		if releases != nil {
			switch d.Name() {
			case "releases":
				continue
			case "current":
				if err := s.directory(ctx, releases, entryRel, hostPath, release); err != nil {
					return err
				}
				continue
			}
		}
		if d.IsDir() {
			if err := s.directory(ctx, dir, entryRel, hostPath, d); err != nil {
				return err
			}
			continue
		}
		if s.file(ctx, dir, entryRel, hostPath, d) {
			parsedLockFile = true
		}
	}
	if parsedLockFile && s.options.ApplicationDetails {
		s.application(dir, path.Join(s.hostRoot, rel))
	}
	return nil
}

// list reads dir in batches and keeps only the entries the walk acts on, so a directory of millions of other files
// (uploads, caches, mail) costs no memory, and at most maxDirectoryEntries of those it keeps. complete is false
// when it left entries out.
func (s *scan) list(ctx context.Context, dir *os.File) (entries []fs.DirEntry, complete bool) {
	for ctx.Err() == nil {
		batch, err := dir.ReadDir(directoryBatch)
		for _, d := range batch {
			if !s.walked(d) {
				continue
			}
			if len(entries) == maxDirectoryEntries {
				return entries, false
			}
			entries = append(entries, d)
		}
		if err != nil || len(batch) == 0 {
			break
		}
	}
	return entries, true
}

// walked tells whether the walk does anything with the entry d: a directory it may descend into, a lock file or a
// manifest by name, the current link of a deployment folder, or an executable when Go binaries are read.
func (s *scan) walked(d fs.DirEntry) bool {
	name := d.Name()
	if d.IsDir() {
		return !skippedDirectoryName(name)
	}
	if _, isLockFile := lockfile.ForFile(name); isLockFile {
		return true
	}
	if _, isManifest := lockfile.Manifests[name]; isManifest {
		return true
	}
	if d.Type()&fs.ModeSymlink != 0 {
		return name == "current"
	}
	if !s.options.GoBinaries || !d.Type().IsRegular() {
		return false
	}
	info, err := d.Info()
	return err == nil && executable(info)
}

func executable(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o111 != 0 && info.Size() >= 4
}

func (s *scan) directory(ctx context.Context, parent *os.File, rel, hostPath string, d fs.DirEntry) error {
	dir := s.openDirectory(parent, rel, hostPath, d)
	if dir == nil {
		return nil
	}
	defer dir.Close()
	return s.walk(ctx, dir, rel)
}

// openDirectory opens the directory entry d of parent, reached at rel, unless the walk leaves it out. It returns
// nil for a directory that is skipped, too deep, excluded or cannot be opened.
func (s *scan) openDirectory(parent *os.File, rel, hostPath string, d fs.DirEntry) *os.File {
	if skippedDirectory(rel, d.Name()) || strings.Count(rel, "/")+1 >= s.options.MaxDepth || isExcluded(hostPath, s.options.ExcludePaths) || isExcluded(hostPath, pseudoFilesystems) || s.isExcludedEntry(d) {
		return nil
	}
	dir, err := safeopen.OpenAt(parent, d.Name(), os.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil {
		return nil
	}
	if info, err := dir.Stat(); err != nil || s.isExcludedFile(info) {
		dir.Close()
		return nil
	}
	return dir
}

// liveRelease recognises the deployment layout of Forge, Envoyer, Deployer and Capistrano: a releases directory
// with one directory per deploy, next to a current symlink to the live one. When current names a direct
// subdirectory of that releases directory, it returns the open releases directory and the entry of the live
// release, which the walk then walks under the stable current path instead of every kept release. current is
// accepted written as releases/<name>, or as an absolute path whose parent is this releases directory itself
// (the same file, so a layout reached through a symlinked or bind mounted scan path is recognised too).
//
// current itself is never opened: its text, read relative to dir, only chooses which entry of the releases
// directory to walk, and both are opened relative to their parent without following a symlink, with the checks
// of any other directory. For any other current it returns nil, and the directory is walked as any other: every
// release under its own path, current skipped as a symlink.
func (s *scan) liveRelease(ctx context.Context, dir *os.File, rel string, entries []fs.DirEntry) (*os.File, fs.DirEntry) {
	releasesEntry, hasReleases := entryNamed(entries, "releases")
	current, hasCurrent := entryNamed(entries, "current")
	if !hasReleases || !releasesEntry.IsDir() || !hasCurrent || current.Type()&fs.ModeSymlink == 0 || ctx.Err() != nil {
		return nil, nil
	}
	target, err := safeopen.ReadlinkAt(dir, "current")
	if err != nil {
		return nil, nil
	}
	parent, name := path.Split(strings.TrimSuffix(target, "/"))
	parent = strings.TrimSuffix(parent, "/")
	if name == "" || name == "." || name == ".." || !path.IsAbs(parent) && parent != "releases" && parent != "./releases" {
		return nil, nil
	}
	releasesRel := path.Join(rel, "releases")
	releases := s.openDirectory(dir, releasesRel, path.Join(s.hostRoot, releasesRel), releasesEntry)
	if releases == nil {
		return nil, nil
	}
	if path.IsAbs(parent) && !s.isSameFile(releases, parent) {
		releases.Close()
		return nil, nil
	}
	// The release is looked up by name instead of listing releases, which can hold any number of entries. Like a
	// listed entry, it only says what to open: openDirectory opens it relative to releases without following a
	// symlink.
	if release, err := os.Lstat(filepath.Join(releases.Name(), name)); err == nil && release.IsDir() {
		return releases, fs.FileInfoToDirEntry(release)
	}
	releases.Close()
	return nil, nil
}

// isSameFile tells whether the host path p names the open directory dir. It only looks up file metadata.
func (s *scan) isSameFile(dir *os.File, p string) bool {
	opened, err := dir.Stat()
	if err != nil {
		return false
	}
	named, err := os.Stat(filepath.Join(s.collector.Root, p))
	return err == nil && os.SameFile(opened, named)
}

// entryNamed finds an entry in a directory listing sorted by name.
func entryNamed(entries []fs.DirEntry, name string) (fs.DirEntry, bool) {
	i, found := slices.BinarySearchFunc(entries, name, func(d fs.DirEntry, name string) int { return strings.Compare(d.Name(), name) })
	if !found {
		return nil, false
	}
	return entries[i], true
}

// file tells whether d is a lock file it parsed.
func (s *scan) file(ctx context.Context, dir *os.File, rel, hostPath string, d fs.DirEntry) bool {
	format, isLockFile := lockfile.ForFile(d.Name())
	_, isManifest := lockfile.Manifests[d.Name()]
	// An exclude path may name the file under another path, such as releases/<name>/package.json for a file the
	// walk reaches as current/package.json.
	excluded := isExcluded(hostPath, s.options.ExcludePaths) || (isLockFile || isManifest) && s.isExcludedEntry(d)
	// An excluded lock file is never opened, but it still resolves the manifests next to it.
	if isLockFile || isManifest && !excluded {
		s.dirs[path.Dir(rel)] = append(s.dirs[path.Dir(rel)], d.Name())
	}
	if excluded {
		return false
	}
	if isLockFile {
		return s.lockFile(dir, hostPath, format, d)
	}
	if s.options.GoBinaries && d.Type().IsRegular() {
		s.goBinary(ctx, dir, hostPath, d)
	}
	return false
}

// skippedDirectory leaves out installed dependency trees (their own lock files describe libraries, not the
// deployed application), hidden directories (.git and package manager caches such as .npm, .cargo, .m2) and
// the Go module cache.
func skippedDirectory(rel, name string) bool {
	return skippedDirectoryName(name) || rel == "pkg/mod" || strings.HasSuffix(rel, "/pkg/mod")
}

func skippedDirectoryName(name string) bool {
	return slices.Contains(skippedDirectories, name) || strings.HasPrefix(name, ".")
}

// lockFile reports a symlinked lock file without opening it: its target may be outside the scan path or under
// an excluded path. A target inside a scan path is reported under its own path. It tells whether the directory
// holds a lock file whose packages are sent or kept on the server: one it parsed, or one it left out as
// package_limit because the walk already holds or read as much as it may.
func (s *scan) lockFile(dir *os.File, hostPath string, format lockfile.Format, d fs.DirEntry) bool {
	if s.seen[hostPath] || s.isExcludedEntry(d) {
		return false
	}
	s.seen[hostPath] = true
	if d.Type()&fs.ModeSymlink != 0 {
		s.inv.Skip(hostPath, ReasonSymlink)
		return false
	}
	if s.budget.packages >= maxWalkPackages {
		s.inv.Skip(hostPath, ReasonPackageLimit)
		return true
	}
	data, reason := s.read(dir, d.Name())
	if reason == ReasonNotFound {
		return false
	}
	if reason != "" {
		s.inv.Skip(hostPath, reason)
		return reason == ReasonPackageLimit
	}
	result, err := format.Parse(data)
	if errors.Is(err, lockfile.ErrTooLarge) {
		s.inv.Skip(hostPath, ReasonTooLarge)
		return false
	}
	if err != nil {
		s.inv.Skip(hostPath, ReasonParseError)
		return false
	}
	if result.Unresolved > 0 {
		// Normalize drops this record when some packages of the file are sent (see Inventory.Normalize).
		s.inv.Skip(hostPath, ReasonUnresolvedVersions)
	}
	s.keep(hostPath, func(yield func(Package) bool) {
		for _, d := range result.Dependencies {
			if !yield(Package{Ecosystem: format.Ecosystem, Name: d.Name, Version: d.Version, ManifestPath: hostPath, Direct: d.Direct}) {
				return
			}
		}
	})
	return true
}

// keep adds the packages of the manifest at hostPath to the inventory. It applies the rules of Inventory.Normalize
// while the walk runs, so that what the walk holds is bounded whatever the files hold: an entry the server would
// reject is recorded as invalid_entries instead of kept (its name can be as long as the file), names and versions
// are copied out of the file they were parsed from, and a manifest is recorded as package_limit with none of its
// packages kept when it has more than MaxPackages of them, which can never be sent, or when the walk would hold
// more than maxWalkPackages with it.
func (s *scan) keep(hostPath string, packages iter.Seq[Package]) {
	start := len(s.inv.Packages)
	invalid := false
	for p := range packages {
		if !p.valid() {
			invalid = true
			continue
		}
		if kept := len(s.inv.Packages) - start; kept == MaxPackages || s.budget.packages+kept == maxWalkPackages {
			s.inv.Packages = s.inv.Packages[:start]
			s.inv.Skip(hostPath, ReasonPackageLimit)
			return
		}
		p.Name, p.Version = strings.Clone(p.Name), strings.Clone(p.Version)
		s.inv.Packages = append(s.inv.Packages, p)
	}
	if invalid {
		s.inv.Skip(hostPath, ReasonInvalidEntries)
	}
	s.budget.packages += len(s.inv.Packages) - start
}

// read opens a lock file the walk listed as a regular file. A symlink swapped in since is refused (ELOOP), a
// file removed since is ignored, and safeopen.OpenAt's O_NONBLOCK keeps a FIFO given a lock file name by any
// local user from blocking the open, and with it the whole inventory. The reason is package_limit when the walk
// already read maxWalkBytes: any number of large files, or of links to one, would otherwise keep one report
// reading for hours.
func (s *scan) read(dir *os.File, name string) ([]byte, string) {
	f, err := safeopen.OpenAt(dir, name, os.O_RDONLY)
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
	if s.budget.bytes+info.Size() > maxWalkBytes {
		return nil, ReasonPackageLimit
	}
	data, err := io.ReadAll(io.LimitReader(f, s.options.MaxFileSize+1))
	s.budget.bytes += int64(len(data))
	if err != nil {
		return nil, ReasonParseError
	}
	if int64(len(data)) > s.options.MaxFileSize {
		return nil, ReasonTooLarge
	}
	return data, ""
}

// goBinary reads the module list Go embeds in executables (only when collect_go_binaries is on). The lock file
// size limit does not apply: a real binary (terraform, kubectl) is far larger, and buildinfo.Read only needs its
// headers and its build info section. It gets a reader that stops at maxGoBinaryBytes, because what it reads and
// allocates otherwise follows sizes written in the file, which any local user can set to terabytes in a sparse
// file. Like a lock file the binary is opened with safeopen.OpenAt, and once open it must still be the regular
// file the walk listed, so a FIFO or a symlink swapped in after the walk cannot block the inventory or be read in
// its place.
func (s *scan) goBinary(ctx context.Context, dir *os.File, hostPath string, d fs.DirEntry) {
	listed, err := d.Info()
	if err != nil || !executable(listed) || s.seen[hostPath] || s.isExcludedFile(listed) {
		return
	}
	f, err := safeopen.OpenAt(dir, d.Name(), os.O_RDONLY)
	if err != nil {
		return
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(listed, opened) {
		return
	}
	build, err := buildinfo.Read(&budgetReader{ctx: ctx, file: f, left: maxGoBinaryBytes})
	if err != nil {
		return
	}
	s.seen[hostPath] = true
	s.keep(hostPath, slices.Values(GoBuildPackages(build, hostPath)))
}

// budgetReader reads a file until it has been asked for more than left bytes in all, or ctx is done.
type budgetReader struct {
	ctx  context.Context
	file io.ReaderAt
	left int64
}

func (b *budgetReader) ReadAt(p []byte, off int64) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if b.left -= int64(len(p)); b.left < 0 {
		return 0, errGoBinaryBudget
	}
	return b.file.ReadAt(p, off)
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
