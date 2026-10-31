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
	"slices"
	"strings"

	"github.com/okanetsolutions/oka-cyber-agent/internal/collect/lockfile"
)

const (
	ReasonTooLarge           = "too_large"
	ReasonParseError         = "parse_error"
	ReasonUnresolvedVersions = "unresolved_versions"
	ReasonNoLockFile         = "no_lock_file"
	ReasonOutsideScanRoot    = "symlink_outside_scan_root"
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
// lockfile.Formats (plus executables when GoBinaries is on), does not descend into symlinked directories,
// and reads files through os.Root, so a symlink cannot lead it outside the scan root it was found in.
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
	seen := map[string]bool{}
	for _, scanPath := range o.ScanPaths {
		if err := ctx.Err(); err != nil {
			return err
		}
		scanPath = filepath.Clean(scanPath)
		if !filepath.IsAbs(scanPath) || isExcluded(scanPath, o.ExcludePaths) {
			continue
		}
		s := &scan{collector: c, options: o, hostRoot: scanPath, inv: inv, seen: seen, dirs: map[string][]string{}}
		if err := s.run(ctx); err != nil {
			return err
		}
	}
	return nil
}

type scan struct {
	collector DependencyCollector
	options   DependencyOptions
	hostRoot  string
	root      *os.Root
	inv       *Inventory
	seen      map[string]bool
	dirs      map[string][]string
}

func (s *scan) run(ctx context.Context) error {
	root, err := os.OpenRoot(filepath.Join(s.collector.Root, s.hostRoot))
	if err != nil {
		return nil
	}
	defer root.Close()
	s.root = root
	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		hostPath := path.Join(s.hostRoot, rel)
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			return s.directory(rel, hostPath, d)
		}
		format, isLockFile := lockfile.ForFile(d.Name())
		if _, isManifest := lockfile.Manifests[d.Name()]; isLockFile || isManifest {
			s.dirs[path.Dir(rel)] = append(s.dirs[path.Dir(rel)], d.Name())
		}
		if isLockFile {
			s.lockFile(rel, hostPath, format, d.Type()&fs.ModeSymlink != 0)
		} else if s.options.GoBinaries && d.Type().IsRegular() {
			s.goBinary(rel, hostPath, d)
		}
		return nil
	})
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	s.reportManifestsWithoutLockFiles()
	return nil
}

func (s *scan) directory(rel, hostPath string, d fs.DirEntry) error {
	if rel == "." {
		return nil
	}
	if skippedDirectory(rel, d.Name()) || strings.Count(rel, "/")+1 >= s.options.MaxDepth || isExcluded(hostPath, s.options.ExcludePaths) || isExcluded(hostPath, pseudoFilesystems) {
		return fs.SkipDir
	}
	return nil
}

// skippedDirectory leaves out installed dependency trees (their own lock files describe libraries, not the
// deployed application), hidden directories (.git and package manager caches such as .npm, .cargo, .m2) and
// the Go module cache.
func skippedDirectory(rel, name string) bool {
	return slices.Contains(skippedDirectories, name) || strings.HasPrefix(name, ".") || rel == "pkg/mod" || strings.HasSuffix(rel, "/pkg/mod")
}

func (s *scan) lockFile(rel, hostPath string, format lockfile.Format, symlink bool) {
	if s.seen[hostPath] {
		return
	}
	s.seen[hostPath] = true
	data, reason := s.read(rel, symlink)
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

// read opens a lock file through the scan root. A symlink that resolves outside the root cannot be opened
// (os.Root refuses it) and is reported; a dangling one is ignored.
func (s *scan) read(rel string, symlink bool) ([]byte, string) {
	f, err := s.root.Open(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ReasonNotFound
	case errors.Is(err, fs.ErrPermission):
		return nil, ReasonPermissionDenied
	case err != nil && symlink:
		return nil, ReasonOutsideScanRoot
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

// goBinary reads the module list Go embeds in executables (only when collect_go_binaries is on).
func (s *scan) goBinary(rel, hostPath string, d fs.DirEntry) {
	info, err := d.Info()
	if err != nil || info.Mode().Perm()&0o111 == 0 || info.Size() > s.options.MaxFileSize || info.Size() < 4 || s.seen[hostPath] {
		return
	}
	f, err := s.root.Open(rel)
	if err != nil {
		return
	}
	defer f.Close()
	build, err := buildinfo.Read(f)
	if err != nil {
		return
	}
	s.seen[hostPath] = true
	s.inv.Packages = append(s.inv.Packages, GoBuildPackages(build, hostPath)...)
}

// GoBuildPackages lists the modules compiled into a Go binary, plus the standard library as "stdlib", the
// name OSV.dev uses for Go toolchain vulnerabilities.
func GoBuildPackages(build *buildinfo.BuildInfo, manifestPath string) []Package {
	var packages []Package
	if version, ok := strings.CutPrefix(build.GoVersion, "go"); ok {
		version, _, _ = strings.Cut(version, " ")
		packages = append(packages, Package{Ecosystem: lockfile.Go, Name: "stdlib", Version: version, ManifestPath: manifestPath})
	}
	for _, dep := range build.Deps {
		module := dep
		if dep.Replace != nil {
			module = dep.Replace
		}
		version := strings.TrimPrefix(module.Version, "v")
		if module.Path == "" || version == "" || version == "(devel)" {
			continue
		}
		packages = append(packages, Package{Ecosystem: lockfile.Go, Name: module.Path, Version: version, ManifestPath: manifestPath})
	}
	return packages
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
