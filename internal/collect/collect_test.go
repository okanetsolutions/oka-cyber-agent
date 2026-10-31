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
	names := func(cs []Collector) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Name())
		}
		return out
	}
	with := names(Defaults(Options{CollectServices: true}))
	if with[0] != "os" || !slices.Contains(with, "services") {
		t.Fatalf("collectors = %v, want os first and services included", with)
	}
	if without := names(Defaults(Options{})); slices.Contains(without, "services") {
		t.Fatalf("collectors = %v, want no services collector", without)
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
	if len(forward.Packages) != MaxPackages {
		t.Fatalf("len = %d, want %d", len(forward.Packages), MaxPackages)
	}
	manifests := map[string]int{}
	for _, p := range forward.Packages {
		manifests[p.ManifestPath]++
	}
	if manifests[""] != MaxPackages-15 || manifests["/srv/a/package-lock.json"] != 10 || manifests["/srv/b/package-lock.json"] != 5 || manifests["/srv/c/package-lock.json"] != 0 {
		t.Fatalf("packages per manifest = %v, want every OS package, all of a, half of b and none of c", manifests)
	}
	want := []SkippedFile{
		{Path: "/srv/b/package-lock.json", Reason: ReasonPackageLimit},
		{Path: "/srv/c/package-lock.json", Reason: ReasonPackageLimit},
	}
	if !slices.Equal(forward.SkippedFiles, want) {
		t.Fatalf("skipped files = %v, want %v", forward.SkippedFiles, want)
	}
}

func TestNormalizeFailsWhenOSPackagesExceedTheLimit(t *testing.T) {
	inv := &Inventory{Packages: slices.Concat(osPackages(MaxPackages+1), dependencyPackages("/srv/a/package-lock.json", 1))}
	if err := inv.Normalize(); !errors.Is(err, ErrTooManyOSPackages) {
		t.Fatalf("err = %v, want ErrTooManyOSPackages", err)
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
