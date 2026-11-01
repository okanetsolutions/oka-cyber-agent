package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fixedUname() (Uname, error) {
	return Uname{Nodename: "web-1", Release: "6.1.0-26-amd64", Machine: "x86_64"}, nil
}

func hostRoot(name string) string {
	return filepath.Join("testdata", "hosts", name)
}

func collectHost(t *testing.T, host string, rpmOutput string) *Inventory {
	t.Helper()
	root := hostRoot(host)
	collectors := []Collector{
		OSCollector{Root: root, Uname: fixedUname},
		DpkgCollector{Root: root},
		RPMCollector{Root: root, Run: func(context.Context, string, ...string) ([]byte, error) {
			return os.ReadFile(rpmOutput)
		}},
		APKCollector{Root: root},
	}
	inv, err := Run(context.Background(), collectors...)
	if err != nil {
		t.Fatalf("Run(%s): %v", host, err)
	}
	return inv
}

func findPackage(t *testing.T, inv *Inventory, name string) Package {
	t.Helper()
	for _, p := range inv.Packages {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("package %q not in inventory", name)
	return Package{}
}

type failingCollector struct{}

func (failingCollector) Name() string                              { return "failing" }
func (failingCollector) Collect(context.Context, *Inventory) error { return errors.New("boom") }

func TestRunFailsWholeWhenOneCollectorFails(t *testing.T) {
	inv, err := Run(context.Background(), OSCollector{Root: hostRoot("debian-12"), Uname: fixedUname}, failingCollector{})
	if err == nil || inv != nil {
		t.Fatalf("Run = %v, %v; want nil inventory and an error", inv, err)
	}
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, OSCollector{Root: hostRoot("debian-12"), Uname: fixedUname}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestDefaultsRunOSFirstAndHonourCollectServices(t *testing.T) {
	names := func(o Options) []string {
		cs, err := Defaults(o)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cs {
			out = append(out, c.Name())
		}
		return out
	}
	with := names(Options{CollectServices: true})
	if with[0] != "os" || !slices.Contains(with, "services") {
		t.Fatalf("collectors = %v, want os first and services included", with)
	}
	if without := names(Options{}); slices.Contains(without, "services") {
		t.Fatalf("collectors = %v, want no services collector", without)
	}
}

// defaultsWithFakes builds the default collectors for root with a fixed uname and the given rpm runner.
func defaultsWithFakes(t *testing.T, root string, rpm CommandRunner) []Collector {
	t.Helper()
	collectors, err := Defaults(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range collectors {
		switch c := c.(type) {
		case OSCollector:
			c.Uname = fixedUname
			collectors[i] = c
		case RPMCollector:
			c.Run = rpm
			collectors[i] = c
		}
	}
	return collectors
}

func TestDefaultsPassAnAbsoluteRootToRPM(t *testing.T) {
	relative := "./" + hostRoot("rocky-9") + "/"
	want, err := filepath.Abs(hostRoot("rocky-9"))
	if err != nil {
		t.Fatal(err)
	}
	var gotRoot string
	collectors := defaultsWithFakes(t, relative, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		gotRoot = args[slices.Index(args, "--root")+1]
		return os.ReadFile(filepath.Join("testdata", "rpm", "rocky-9.txt"))
	})
	inv, err := Run(context.Background(), collectors...)
	if err != nil {
		t.Fatal(err)
	}
	if gotRoot != want {
		t.Fatalf("rpm --root = %q, want %q", gotRoot, want)
	}
	if len(inv.Packages) != 146 {
		t.Fatalf("packages = %d, want 146", len(inv.Packages))
	}
}

func TestDefaultsReadDpkgAndAPKFromARelativeRoot(t *testing.T) {
	noRPM := func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("rpm must not run on this host")
	}
	for host, want := range map[string]int{"debian-12": 88, "alpine-3.20": 14} {
		inv, err := Run(context.Background(), defaultsWithFakes(t, hostRoot(host), noRPM)...)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if len(inv.Packages) != want {
			t.Fatalf("%s: packages = %d, want %d", host, len(inv.Packages), want)
		}
	}
}

func TestDefaultsFailWhenTheRootCannotBeMadeAbsolute(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := filepath.Abs("rootfs"); err == nil {
		t.Skip("the working directory still resolves after removal on this platform")
	}
	if collectors, err := Defaults(Options{Root: "rootfs"}); err == nil || collectors != nil {
		t.Fatalf("Defaults = %v, %v; want an error", collectors, err)
	}
}

func TestInventoryJSONMatchesServerContract(t *testing.T) {
	inv, err := Run(context.Background(), OSCollector{Root: hostRoot("arch"), Uname: fixedUname})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if packages, ok := decoded["packages"].([]any); !ok || len(packages) != 0 {
		t.Fatalf("packages = %#v, want an empty JSON array", decoded["packages"])
	}
	os := decoded["os"].(map[string]any)
	for key := range os {
		if !slices.Contains([]string{"family", "name", "version", "kernel", "architecture", "osv_ecosystem"}, key) {
			t.Fatalf("os has key %q the server does not accept", key)
		}
	}
	if strings.Contains(string(raw), "web-1") {
		t.Fatal("hostname must only be sent at enrollment")
	}
}

func TestNormalizeDedupesSortsAndCapsPackages(t *testing.T) {
	inv := &Inventory{}
	inv.Packages = append(inv.Packages,
		Package{Ecosystem: "npm", Name: "b", Version: "1", ManifestPath: "/srv/app/package-lock.json"},
		Package{Ecosystem: "Debian:12", Name: "z", Version: "1", Architecture: "amd64"},
		Package{Ecosystem: "Debian:12", Name: "a", Version: "1", Architecture: "amd64"},
		Package{Ecosystem: "Debian:12", Name: "a", Version: "2", Architecture: "amd64"},
	)
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, p := range inv.Packages {
		got = append(got, p.Ecosystem+"/"+p.Name+"@"+p.Version)
	}
	want := []string{"Debian:12/a@1", "Debian:12/z@1", "npm/b@1"}
	if !slices.Equal(got, want) {
		t.Fatalf("packages = %v, want %v", got, want)
	}
}

func osPackages(n int) []Package {
	packages := make([]Package, 0, n)
	for i := range n {
		packages = append(packages, Package{Ecosystem: "Debian:12", Name: fmt.Sprintf("os-%05d", i), Version: "1", Architecture: "amd64"})
	}
	return packages
}

func dependencyPackages(manifest string, n int) []Package {
	packages := make([]Package, 0, n)
	for i := range n {
		packages = append(packages, Package{Ecosystem: "npm", Name: fmt.Sprintf("dep-%05d", i), Version: "1", ManifestPath: manifest})
	}
	return packages
}

func TestNormalizeCutsDependenciesByManifestAboveTheLimit(t *testing.T) {
	packages := slices.Concat(
		dependencyPackages("/srv/b/package-lock.json", 10),
		osPackages(MaxPackages-15),
		dependencyPackages("/srv/c/package-lock.json", 10),
		dependencyPackages("/srv/a/package-lock.json", 10),
	)
	forward := &Inventory{Packages: slices.Clone(packages)}
	reversed := &Inventory{Packages: slices.Clone(packages)}
	slices.Reverse(reversed.Packages)
	for _, inv := range []*Inventory{forward, reversed} {
		if err := inv.Normalize(); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(forward.Packages, reversed.Packages) || !slices.Equal(forward.SkippedFiles, reversed.SkippedFiles) {
		t.Fatal("the packages kept depend on collector order")
	}
	if len(forward.Packages) != MaxPackages-5 {
		t.Fatalf("len = %d, want %d", len(forward.Packages), MaxPackages-5)
	}
	manifests := map[string]int{}
	for _, p := range forward.Packages {
		manifests[p.ManifestPath]++
	}
	if manifests[""] != MaxPackages-15 || manifests["/srv/a/package-lock.json"] != 10 || manifests["/srv/b/package-lock.json"] != 0 || manifests["/srv/c/package-lock.json"] != 0 {
		t.Fatalf("packages per manifest = %v, want every OS package, all of a and none of b or c: a manifest sent in part would also be skipped", manifests)
	}
	want := []SkippedFile{
		{Path: "/srv/b/package-lock.json", Reason: ReasonPackageLimit},
		{Path: "/srv/c/package-lock.json", Reason: ReasonPackageLimit},
	}
	if !slices.Equal(forward.SkippedFiles, want) {
		t.Fatalf("skipped files = %v, want %v", forward.SkippedFiles, want)
	}
}

// InventoryIngestionService::syncPackages keeps every stored package whose manifest path is skipped, so a manifest
// both sent and skipped would keep packages removed from it forever.
func TestNormalizeNeverSendsAndSkipsTheSameManifest(t *testing.T) {
	inv := &Inventory{
		Packages: []Package{
			{Ecosystem: "PyPI", Name: "django", Version: "3.2", ManifestPath: "/srv/api/requirements.txt"},
			{Ecosystem: "Go", Name: "example.com/tools", Version: "1.0.0", ManifestPath: "/srv/tool/go.mod"},
		},
		SkippedFiles: []SkippedFile{
			{Path: "/srv/api/requirements.txt", Reason: ReasonUnresolvedVersions},
			{Path: "/srv/tool/go.mod", Reason: ReasonUnresolvedVersions},
			{Path: "/srv/tool/go.mod", Reason: ReasonInvalidEntries},
			{Path: "/srv/web/requirements.txt", Reason: ReasonUnresolvedVersions},
		},
	}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	want := []SkippedFile{{Path: "/srv/web/requirements.txt", Reason: ReasonUnresolvedVersions}}
	if len(inv.Packages) != 2 || !slices.Equal(inv.SkippedFiles, want) {
		t.Fatalf("inventory = %+v, want both packages sent and only the manifest without packages skipped", inv)
	}
}

func TestNormalizeFailsWhenOSPackagesExceedTheLimit(t *testing.T) {
	inv := &Inventory{Packages: slices.Concat(osPackages(MaxPackages+1), dependencyPackages("/srv/a/package-lock.json", 1))}
	if err := inv.Normalize(); !errors.Is(err, ErrTooManyOSPackages) {
		t.Fatalf("err = %v, want ErrTooManyOSPackages", err)
	}
}

func skippedFiles(n int, reason string) []SkippedFile {
	files := make([]SkippedFile, 0, n)
	for i := range n {
		files = append(files, SkippedFile{Path: fmt.Sprintf("/srv/m/%05d/package-lock.json", i), Reason: reason})
	}
	return files
}

func TestNormalizeKeepsCutManifestsWhenCappingSkippedFiles(t *testing.T) {
	inv := &Inventory{
		Packages: slices.Concat(
			osPackages(MaxPackages-1),
			dependencyPackages("/a/package-lock.json", 1),
			dependencyPackages("/srv/b/package-lock.json", 1),
			dependencyPackages("/z/package-lock.json", 1),
		),
		SkippedFiles: skippedFiles(MaxSkippedFiles, ReasonPermissionDenied),
	}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(inv.SkippedFiles) != MaxSkippedFiles {
		t.Fatalf("skipped files = %d, want %d", len(inv.SkippedFiles), MaxSkippedFiles)
	}
	if !slices.IsSortedFunc(inv.SkippedFiles, compareSkippedFiles) {
		t.Fatal("skipped files are not sorted")
	}
	sent := map[string]bool{}
	for _, p := range inv.Packages {
		sent[p.ManifestPath] = true
	}
	skipped := map[string]string{}
	for _, f := range inv.SkippedFiles {
		skipped[f.Path] = f.Reason
	}
	want := map[string]string{"/srv/b/package-lock.json": ReasonPackageLimit, "/z/package-lock.json": ReasonPackageLimit}
	for manifest, reason := range want {
		if sent[manifest] || skipped[manifest] != reason {
			t.Errorf("%s: sent %v, skipped as %q; want it skipped as %q so the server keeps what it stored for it", manifest, sent[manifest], skipped[manifest], reason)
		}
	}
	if !sent["/a/package-lock.json"] {
		t.Error("/a/package-lock.json fits under the package limit and must be sent")
	}
}

func TestNormalizeFailsWhenCutManifestsExceedTheSkippedFilesLimit(t *testing.T) {
	packages := osPackages(MaxPackages)
	for i := range MaxSkippedFiles + 1 {
		packages = append(packages, dependencyPackages(fmt.Sprintf("/srv/m/%05d/package-lock.json", i), 1)...)
	}
	inv, err := Run(context.Background(), packagesCollector(packages))
	if !errors.Is(err, ErrTooManyCutManifests) || inv != nil {
		t.Fatalf("Run returned an inventory: %v, err = %v; want none and ErrTooManyCutManifests", inv != nil, err)
	}
}

type packagesCollector []Package

func (packagesCollector) Name() string { return "packages" }
func (c packagesCollector) Collect(_ context.Context, inv *Inventory) error {
	inv.Packages = append(inv.Packages, c...)
	return nil
}

func TestRunFailsWhenOSPackagesExceedTheLimit(t *testing.T) {
	inv, err := Run(context.Background(), packagesCollector(osPackages(MaxPackages+1)))
	if !errors.Is(err, ErrTooManyOSPackages) || inv != nil {
		t.Fatalf("Run = %v, %v; want nil inventory and ErrTooManyOSPackages", inv, err)
	}
}

func TestNormalizeDedupesServicesAndSkippedFiles(t *testing.T) {
	inv := &Inventory{
		Services: []Service{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 80, Process: "nginx"},
			{Protocol: "tcp", Address: "0.0.0.0", Port: 80, Process: "nginx"},
			{Protocol: "tcp", Address: "0.0.0.0", Port: 22},
		},
		SkippedFiles: []SkippedFile{{"/b", "x"}, {"/a", "x"}, {"/b", "x"}},
	}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	wantServices := []Service{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 22},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 80, Process: "nginx"},
	}
	if !slices.Equal(inv.Services, wantServices) {
		t.Fatalf("services = %v, want %v", inv.Services, wantServices)
	}
	if !slices.Equal(inv.SkippedFiles, []SkippedFile{{"/a", "x"}, {"/b", "x"}}) {
		t.Fatalf("skipped = %v", inv.SkippedFiles)
	}
}

func TestNormalizeDropsEntriesTheServerWouldReject(t *testing.T) {
	inv := &Inventory{Packages: []Package{
		{Ecosystem: "Rocky Linux:9", Name: "bash", Version: "5.1.8-9.el9"},
		{Ecosystem: "npm", Name: "has space", Version: "1.0.0", ManifestPath: "/srv/app/package-lock.json"},
		{Ecosystem: "npm", Name: "ok", Version: "1.0.0\n", ManifestPath: "/srv/app/package-lock.json"},
		{Ecosystem: "npm", Name: strings.Repeat("a", 256), Version: "1.0.0"},
		{Ecosystem: "npm", Name: "fine", Version: "1.0.0", ManifestPath: "/srv/app/package-lock.json"},
		{Ecosystem: "npm", Name: "bad name", Version: "1.0.0", ManifestPath: "/srv/odd/package-lock.json"},
	}, SkippedFiles: []SkippedFile{{Path: "relative/path", Reason: "x"}}}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(inv.Packages) != 2 {
		t.Fatalf("packages = %+v, want bash and fine", inv.Packages)
	}
	// /srv/app is sent with its valid package and not listed, so the server still deletes what was removed from it.
	want := []SkippedFile{{Path: "/srv/odd/package-lock.json", Reason: ReasonInvalidEntries}}
	if !slices.Equal(inv.SkippedFiles, want) {
		t.Fatalf("skipped = %v, want %v", inv.SkippedFiles, want)
	}
}

func TestMarshalLeavesOutLargestDependencyFilesToFitTheLimit(t *testing.T) {
	inv := &Inventory{Packages: []Package{}, SkippedFiles: []SkippedFile{}, Services: []Service{}}
	for i := range 50 {
		inv.Packages = append(inv.Packages, Package{Ecosystem: "Debian:12", Name: fmt.Sprintf("deb%d", i), Version: "1"})
	}
	for i := range 300 {
		inv.Packages = append(inv.Packages, Package{Ecosystem: "npm", Name: fmt.Sprintf("big%d", i), Version: "1", ManifestPath: "/srv/big/package-lock.json"})
	}
	for i := range 100 {
		inv.Packages = append(inv.Packages, Package{Ecosystem: "npm", Name: fmt.Sprintf("small%d", i), Version: "1", ManifestPath: "/srv/small/package-lock.json"})
	}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	full, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := inv.Marshal(len(full) - 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) >= len(full) || len(inv.Packages) != 150 {
		t.Fatalf("packages = %d, want the 300 package manifest left out", len(inv.Packages))
	}
	if !slices.Contains(inv.SkippedFiles, SkippedFile{Path: "/srv/big/package-lock.json", Reason: ReasonPackageLimit}) {
		t.Fatalf("skipped = %v", inv.SkippedFiles)
	}

	if _, err := inv.Marshal(10); err == nil {
		t.Fatal("OS packages alone over the limit must be an error")
	}
}
