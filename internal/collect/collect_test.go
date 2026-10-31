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
	inv.Normalize()
	got := []string{}
	for _, p := range inv.Packages {
		got = append(got, p.Ecosystem+"/"+p.Name+"@"+p.Version)
	}
	want := []string{"Debian:12/a@1", "Debian:12/z@1", "npm/b@1"}
	if !slices.Equal(got, want) {
		t.Fatalf("packages = %v, want %v", got, want)
	}

	big := &Inventory{}
	for i := range MaxPackages + 5 {
		big.Packages = append(big.Packages, Package{Ecosystem: "npm", Name: fmt.Sprintf("p%d", i), Version: "1", ManifestPath: "/srv/app/package-lock.json"})
	}
	big.Normalize()
	if len(big.Packages) != MaxPackages {
		t.Fatalf("len = %d, want %d", len(big.Packages), MaxPackages)
	}
	if !slices.Contains(big.SkippedFiles, SkippedFile{Path: "/srv/app/package-lock.json", Reason: ReasonPackageLimit}) {
		t.Fatalf("skipped files = %v, want the truncated manifest", big.SkippedFiles)
	}
}

func TestNormalizeDedupesServicesAndSkippedFiles(t *testing.T) {
	inv := &Inventory{
		Services: []Service{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 80, PID: 20, Process: "nginx"},
			{Protocol: "tcp", Address: "0.0.0.0", Port: 80, PID: 10, Process: "nginx"},
			{Protocol: "tcp", Address: "0.0.0.0", Port: 22},
		},
		SkippedFiles: []SkippedFile{{"/b", "x"}, {"/a", "x"}, {"/b", "x"}},
	}
	inv.Normalize()
	wantServices := []Service{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 22},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 80, PID: 10, Process: "nginx"},
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
	}, SkippedFiles: []SkippedFile{{Path: "relative/path", Reason: "x"}}}
	inv.Normalize()
	if len(inv.Packages) != 2 {
		t.Fatalf("packages = %+v, want bash and fine", inv.Packages)
	}
	want := []SkippedFile{{Path: "/srv/app/package-lock.json", Reason: ReasonInvalidEntries}}
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
	inv.Normalize()
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
