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
		{"/srv/dangling/uv.lock", ReasonSymlink},
		{"/srv/escape/go.mod", ReasonSymlink},
		{"/srv/inside/Cargo.lock", ReasonSymlink},
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

// symlinkedIntoExcluded builds a tree where /srv/secret is excluded and every way of reaching a file under it
// goes through a symlink: file symlinks with relative and absolute targets, directory symlinks with relative and
// absolute targets, a file symlink through a directory symlink, a symlinked executable and a scan path that is a
// symlink into the excluded directory. /srv/current/storage is excluded too, though the walk only meets it as
// /srv/releases/5/storage because /srv/current is a symlink.
func symlinkedIntoExcluded(t *testing.T) (tree, DependencyOptions) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tr := tree{t, t.TempDir()}
	abs := func(hostPath string) string { return filepath.Join(tr.root, hostPath) }
	tr.copy(lockFixture("composer/composer.lock"), "/srv/secret/composer.lock")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/secret/Cargo.lock")
	tr.copy(lockFixture("npm-v3/package-lock.json"), "/srv/secret/app/package-lock.json")
	tr.copy(self, "/srv/secret/bin/tool")
	if err := os.Chmod(abs("/srv/secret/bin/tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	tr.symlink("../secret/composer.lock", "/srv/app/composer.lock")
	tr.symlink(abs("/srv/secret/Cargo.lock"), "/srv/abs/Cargo.lock")
	tr.symlink("secret/app", "/srv/web")
	tr.symlink(abs("/srv/secret/app"), "/srv/webabs")
	tr.symlink("secret/app", "/srv/link")
	tr.symlink("../link/package-lock.json", "/srv/through/package-lock.json")
	tr.symlink("../secret/bin/tool", "/srv/bin/tool")
	tr.symlink("srv/secret/app", "/data")
	tr.copy(lockFixture("composer/composer.lock"), "/srv/releases/5/storage/composer.lock")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/releases/5/Cargo.lock")
	tr.symlink("releases/5", "/srv/current")
	return tr, DependencyOptions{
		ScanPaths:    []string{"/srv", "/data"},
		ExcludePaths: []string{"/srv/secret", "/srv/current/storage"},
		GoBinaries:   true,
	}
}

// A file under an excluded path is never read or reported, whatever symlink leads to it. A symlinked lock file
// is listed without being opened, and a symlinked directory or executable is not entered or read.
func TestDependencyDiscoveryNeverFollowsSymlinksIntoExcludedPaths(t *testing.T) {
	tr, options := symlinkedIntoExcluded(t)
	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"/srv/releases/5/Cargo.lock": 9}; !mapsEqual(manifests(inv), want) {
		t.Fatalf("manifests = %v, want %v", manifests(inv), want)
	}
	wantSkipped := []SkippedFile{
		{"/srv/abs/Cargo.lock", ReasonSymlink},
		{"/srv/app/composer.lock", ReasonSymlink},
		{"/srv/through/package-lock.json", ReasonSymlink},
	}
	if !slices.Equal(inv.SkippedFiles, wantSkipped) {
		t.Fatalf("skipped = %v\nwant %v", inv.SkippedFiles, wantSkipped)
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
	if p, ok := goModulePackage(&selfInfo.Main, ""); ok {
		want[p.Name] = true
	}
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

// The build information of real binaries, as debug/buildinfo reads it: staticcheck installed with go install at
// v0.8.2, and a module built by Go 1.26 from git at the tag v1.2.0 (tagged), at that tag with an uncommitted
// change (dirty) and one commit after it (pseudo).
func TestGoBuildPackagesReportTheMainModule(t *testing.T) {
	tests := []struct {
		fixture, main, version string
	}{
		{"staticcheck.txt", "honnef.co/go/tools", "0.8.2"},
		{"tagged.txt", "example.com/acme/tool", "1.2.0"},
		{"pseudo.txt", "example.com/acme/tool", "1.2.1-0.20261101203445-395da2043f88"},
		{"dirty.txt", "example.com/acme/tool", ""},
	}
	for _, tt := range tests {
		data, err := os.ReadFile(filepath.Join("testdata", "gobuildinfo", tt.fixture))
		if err != nil {
			t.Fatal(err)
		}
		build, err := debug.ParseBuildInfo(string(data))
		if err != nil {
			t.Fatal(err)
		}
		packages := GoBuildPackages(build, "/opt/bin/tool")
		versions := map[string]string{}
		for _, p := range packages {
			if p.Ecosystem != "Go" || p.ManifestPath != "/opt/bin/tool" {
				t.Fatalf("%s: unexpected package %+v", tt.fixture, p)
			}
			versions[p.Name] = p.Version
		}
		if versions[tt.main] != tt.version {
			t.Errorf("%s: main module %s = %q, want %q", tt.fixture, tt.main, versions[tt.main], tt.version)
		}
		// ParseBuildInfo leaves GoVersion empty, so there is no stdlib here.
		if want := 1 + len(build.Deps); tt.version != "" && len(packages) != want {
			t.Errorf("%s: %d packages, want the main module and %d dependencies", tt.fixture, len(packages), len(build.Deps))
		}
	}
}

func TestGoBuildPackagesSkipUnpublishedVersions(t *testing.T) {
	build := &debug.BuildInfo{
		GoVersion: "go1.26.0",
		Main:      debug.Module{Path: "example.com/app", Version: "v2.0.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v2.0.1"}},
		Deps: []*debug.Module{
			{Path: "example.com/devel", Version: "(devel)"},
			{Path: "example.com/empty"},
			{Path: "example.com/local", Version: "v1.0.0", Replace: &debug.Module{Path: "../local"}},
			{Path: "example.com/forked", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/fork2", Version: "v1.0.1"}},
		},
	}
	var got []string
	for _, p := range GoBuildPackages(build, "/opt/bin/app") {
		got = append(got, p.Name+"@"+p.Version)
	}
	want := []string{"stdlib@1.26.0", "example.com/fork@2.0.1", "example.com/fork2@1.0.1"}
	if !slices.Equal(got, want) {
		t.Fatalf("packages = %v, want %v", got, want)
	}
	build.Main = debug.Module{Path: "example.com/app", Version: "(devel)"}
	for _, p := range GoBuildPackages(build, "/opt/bin/app") {
		if p.Name == "example.com/app" {
			t.Fatalf("a (devel) main module has no published version: %+v", p)
		}
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
