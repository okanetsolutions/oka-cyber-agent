package collect

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

func lockFixture(name string) string {
	return filepath.Join("lockfile", "testdata", name)
}

type tree struct {
	t    *testing.T
	root string
}

func (tr tree) copy(fixture, hostPath string) {
	tr.t.Helper()
	copyFile(tr.t, fixture, filepath.Join(tr.root, hostPath))
}

func (tr tree) write(hostPath, content string) {
	tr.t.Helper()
	full := filepath.Join(tr.root, hostPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr tree) symlink(target, hostPath string) {
	tr.t.Helper()
	full := filepath.Join(tr.root, hostPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		tr.t.Fatal(err)
	}
}

func manifests(inv *Inventory) map[string]int {
	counts := map[string]int{}
	for _, p := range inv.Packages {
		counts[p.ManifestPath]++
	}
	return counts
}

func TestDependencyDiscovery(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("composer/composer.lock"), "/var/www/shop/composer.lock")
	tr.write("/var/www/shop/composer.json", "{}")
	tr.copy(lockFixture("composer/composer.lock"), "/var/www/shop/vendor/acme/lib/composer.lock")
	tr.write("/var/www/legacy/package.json", "{}")
	tr.copy(lockFixture("pnpm-v9/pnpm-lock.yaml"), "/var/www/mono/pnpm-lock.yaml")
	tr.write("/var/www/mono/packages/web/package.json", "{}")
	tr.copy(lockFixture("bundler/Gemfile.lock"), "/var/www/deep/a/b/c/d/Gemfile.lock")
	tr.copy(lockFixture("npm-v3/package-lock.json"), "/var/www/deep/a/b/c/d/e/package-lock.json")
	tr.copy(lockFixture("requirements-mixed/requirements.txt"), "/srv/api/requirements.txt")
	tr.write("/srv/unpinned/requirements.txt", "django>=4.2\nrequests\n")
	tr.copy(lockFixture("npm-v3/package-lock.json"), "/srv/api/node_modules/x/package-lock.json")
	tr.copy(lockFixture("npm-v3/package-lock.json"), "/srv/api/.git/package-lock.json")
	tr.write("/home/forge/.bun/install/cache/accepts@1.3.8@@@1/package.json", "{}")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/home/forge/.cargo/registry/src/serde/Cargo.lock")
	tr.copy(lockFixture("gomod/go.mod"), "/home/forge/go/pkg/mod/github.com/gin-gonic/gin@v1.9.1/go.mod")
	tr.write("/srv/big/yarn.lock", strings.Repeat("# padding\n", 30000))
	tr.write("/srv/broken/Pipfile.lock", "{not json")
	tr.copy(lockFixture("gomod/go.mod"), "/outside/go.mod")
	tr.symlink("../../outside/go.mod", "/srv/escape/go.mod")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/rust/Cargo.lock")
	tr.symlink("../rust/Cargo.lock", "/srv/inside/Cargo.lock")
	tr.symlink("../var/www/shop", "/srv/linkdir")
	tr.symlink("missing.lock", "/srv/dangling/uv.lock")
	tr.copy(lockFixture("composer/composer.lock"), "/opt/excluded/composer.lock")
	tr.copy(lockFixture("nuget/packages.lock.json"), "/opt/dotnet/packages.lock.json")
	tr.copy(lockFixture("gradle/gradle.lockfile"), "/proc/1/root/gradle.lockfile")

	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{
		ScanPaths:    []string{"/var/www", "/srv", "/srv/api", "/opt", "/home", "/nope", "relative"},
		ExcludePaths: []string{"/opt/excluded"},
		MaxDepth:     6,
		MaxFileSize:  200_000,
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantManifests := map[string]int{
		"/var/www/shop/composer.lock":        7,
		"/var/www/mono/pnpm-lock.yaml":       73,
		"/var/www/deep/a/b/c/d/Gemfile.lock": 9,
		"/srv/api/requirements.txt":          5,
		"/srv/rust/Cargo.lock":               9,
		"/srv/inside/Cargo.lock":             9,
		"/opt/dotnet/packages.lock.json":     8,
	}
	if got := manifests(inv); !mapsEqual(got, wantManifests) {
		t.Fatalf("manifests = %v\nwant %v", got, wantManifests)
	}
	// /srv/api/requirements.txt has unpinned lines too, but it is sent with its 5 pinned packages and not listed,
	// so the server deletes a package removed from it instead of keeping everything stored for a skipped path.
	wantSkipped := []SkippedFile{
		{"/srv/big/yarn.lock", ReasonTooLarge},
		{"/srv/broken/Pipfile.lock", ReasonParseError},
		{"/srv/escape/go.mod", ReasonOutsideScanRoot},
		{"/srv/unpinned/requirements.txt", ReasonUnresolvedVersions},
		{"/var/www/legacy/package.json", ReasonNoLockFile},
	}
	if !slices.Equal(inv.SkippedFiles, wantSkipped) {
		t.Fatalf("skipped = %v\nwant %v", inv.SkippedFiles, wantSkipped)
	}
	for _, p := range inv.Packages {
		if p.ManifestPath == "/srv/api/requirements.txt" && p.Ecosystem != "PyPI" {
			t.Fatalf("package %+v has the wrong ecosystem", p)
		}
	}
}

// exclude_paths applies to files as it does to directories: an excluded lock file or executable is never
// opened, and an excluded lock file still counts as the lock file of the manifest next to it.
func TestDependencyDiscoveryExcludesFiles(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("bundler/Gemfile.lock"), "/srv/app/Gemfile.lock")
	tr.write("/srv/app/Gemfile", "")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/app/Cargo.lock")
	tr.write("/srv/other/package.json", "{}")
	tr.copy(self, "/srv/bin/tool")
	if err := os.Chmod(filepath.Join(tr.root, "/srv/bin/tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(tr.root, "/srv/app/Gemfile.lock"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(tr.root, "/srv/app/Gemfile.lock"), 0o644) })
	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{
		ScanPaths:    []string{"/srv"},
		ExcludePaths: []string{"/srv/app/Gemfile.lock", "/srv/bin/tool/", "/srv/other/package.json"},
		GoBinaries:   true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"/srv/app/Cargo.lock": 9}; !mapsEqual(manifests(inv), want) {
		t.Fatalf("manifests = %v, want %v", manifests(inv), want)
	}
	// Opening an unreadable excluded file would have listed it as permission_denied (when not root).
	if len(inv.SkippedFiles) != 0 {
		t.Fatalf("skipped = %v, want none", inv.SkippedFiles)
	}
}

// One version per name reaches the snapshot, and it is the direct one the lock file names, not the first by key.
func TestDependencyDiscoveryKeepsTheDirectVersion(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("pnpm-v9-duplicates/pnpm-lock.yaml"), "/srv/web/pnpm-lock.yaml")
	tr.copy(lockFixture("cargo-duplicates/Cargo.lock"), "/srv/rust/Cargo.lock")
	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/srv"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"/srv/web/pnpm-lock.yaml emoji-regex": "9.2.2", "/srv/web/pnpm-lock.yaml ansi-regex": "5.0.1", "/srv/rust/Cargo.lock syn": "2.0.119"}
	for _, p := range inv.Packages {
		version, ok := want[p.ManifestPath+" "+p.Name]
		if !ok {
			continue
		}
		if isDirect := p.Direct != nil && *p.Direct; p.Version != version || !isDirect {
			t.Fatalf("%s %s = %s direct %v, want %s direct", p.ManifestPath, p.Name, p.Version, isDirect, version)
		}
		delete(want, p.ManifestPath+" "+p.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing %v", want)
	}
}

// max_depth counts path components below the scan path, like find -maxdepth: /srv/a/b/Cargo.lock is at depth 3.
func TestDependencyDiscoveryHonoursMaxDepth(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/a/Cargo.lock")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/a/b/Cargo.lock")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/a/b/c/Cargo.lock")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/a/b/c/d/Cargo.lock")
	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/srv"}, MaxDepth: 3}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"/srv/a/Cargo.lock": 9, "/srv/a/b/Cargo.lock": 9}
	if got := manifests(inv); !mapsEqual(got, want) {
		t.Fatalf("manifests = %v, want %v", got, want)
	}
}

func TestDependencyDiscoverySkipsWhatItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of mode")
	}
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("bundler/Gemfile.lock"), "/home/alice/app/Gemfile.lock")
	tr.copy(lockFixture("poetry-1/poetry.lock"), "/home/bob/poetry.lock")
	for _, p := range []string{"/home/alice", "/home/bob/poetry.lock"} {
		if err := os.Chmod(filepath.Join(tr.root, p), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(filepath.Join(tr.root, p), 0o755) })
	}
	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/home"}}})
	if err != nil {
		t.Fatalf("an unreadable directory must not fail the inventory: %v", err)
	}
	want := []SkippedFile{{"/home/bob/poetry.lock", ReasonPermissionDenied}}
	if len(inv.Packages) != 0 || !slices.Equal(inv.SkippedFiles, want) {
		t.Fatalf("inventory = %+v", inv)
	}
}

func TestGoBinariesOnlyWhenEnabled(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tr := tree{t, t.TempDir()}
	tr.copy(self, "/opt/tool/bin/tool")
	if err := os.Chmod(filepath.Join(tr.root, "/opt/tool/bin/tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	tr.write("/opt/tool/bin/script.sh", "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(tr.root, "/opt/tool/bin/script.sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	// max_file_size is for lock files: a Go binary far larger than it (terraform, kubectl) is still read.
	off, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/opt"}, MaxFileSize: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Packages) != 0 {
		t.Fatalf("Go binaries must not be read unless enabled: %+v", off.Packages)
	}

	on, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/opt"}, MaxFileSize: 1024, GoBinaries: true}})
	if err != nil {
		t.Fatal(err)
	}
	selfInfo, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("the test binary has no build information")
	}
	want := map[string]bool{"stdlib": true}
	for _, dep := range selfInfo.Deps {
		want[dep.Path] = true
	}
	got := map[string]bool{}
	for _, p := range on.Packages {
		if p.ManifestPath != "/opt/tool/bin/tool" || p.Ecosystem != "Go" {
			t.Fatalf("unexpected package %+v", p)
		}
		if p.Name == "stdlib" && "go"+p.Version != strings.Fields(runtime.Version())[0] {
			t.Fatalf("stdlib = %s, want %s", p.Version, runtime.Version())
		}
		got[p.Name] = true
	}
	if !mapsEqualBool(got, want) {
		t.Fatalf("modules = %v, want %v", got, want)
	}
}

func mapsEqualBool(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func TestDefaultsIncludeDependenciesOnlyWhenConfigured(t *testing.T) {
	has := func(o Options) bool {
		cs, err := Defaults(o)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(cs, func(c Collector) bool { return c.Name() == "dependencies" })
	}
	if has(Options{}) || !has(Options{Dependencies: &DependencyOptions{}}) {
		t.Fatal("the dependency collector must follow Options.Dependencies")
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
