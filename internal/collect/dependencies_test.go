package collect

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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
	wantSkipped := []SkippedFile{
		{"/srv/api/requirements.txt", ReasonUnresolvedVersions},
		{"/srv/big/yarn.lock", ReasonTooLarge},
		{"/srv/broken/Pipfile.lock", ReasonParseError},
		{"/srv/escape/go.mod", ReasonOutsideScanRoot},
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

	off, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/opt"}, MaxFileSize: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Packages) != 0 {
		t.Fatalf("Go binaries must not be read unless enabled: %+v", off.Packages)
	}

	on, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/opt"}, MaxFileSize: 1 << 30, GoBinaries: true}})
	if err != nil {
		t.Fatal(err)
	}
	stdlib, yaml := false, false
	for _, p := range on.Packages {
		if p.ManifestPath != "/opt/tool/bin/tool" || p.Ecosystem != "Go" {
			t.Fatalf("unexpected package %+v", p)
		}
		stdlib = stdlib || (p.Name == "stdlib" && "go"+p.Version == strings.Fields(runtime.Version())[0])
		yaml = yaml || p.Name == "go.yaml.in/yaml/v3"
	}
	if !stdlib || !yaml {
		t.Fatalf("packages = %+v, want stdlib %s and go.yaml.in/yaml/v3", on.Packages, runtime.Version())
	}
}

func TestDefaultsIncludeDependenciesOnlyWhenConfigured(t *testing.T) {
	has := func(cs []Collector) bool {
		return slices.ContainsFunc(cs, func(c Collector) bool { return c.Name() == "dependencies" })
	}
	if has(Defaults(Options{})) || !has(Defaults(Options{Dependencies: &DependencyOptions{}})) {
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
