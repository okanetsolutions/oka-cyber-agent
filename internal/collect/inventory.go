// Package collect reads facts from the host: OS release, installed packages, dependency lock files and listening services.
package collect

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// Server side limits from InventorySnapshotValidator in Oka Core: a snapshot above them is rejected whole.
const (
	MaxPackages     = 20000
	MaxSkippedFiles = 1000
	MaxServices     = 4096
)

// ErrTooManyOSPackages means the OS packages alone exceed MaxPackages. They have no manifest path to record as
// skipped, and the server deletes every stored package missing from a snapshot, so the inventory fails instead.
var ErrTooManyOSPackages = errors.New("more OS packages than the server accepts")

// ErrTooManyCutManifests means more manifests were cut by MaxPackages than MaxSkippedFiles can list. A cut manifest
// left out of skipped_files would have everything the server stored for it deleted, so the inventory fails instead.
var ErrTooManyCutManifests = errors.New("more manifests cut by the package limit than the server accepts as skipped")

const (
	ReasonUnsupportedDistribution = "unsupported_distribution"
	ReasonPermissionDenied        = "permission_denied"
	ReasonPackageLimit            = "package_limit"
	ReasonInvalidEntries          = "invalid_entries"
)

type Inventory struct {
	OS           OS            `json:"os"`
	Packages     []Package     `json:"packages"`
	SkippedFiles []SkippedFile `json:"skipped_files"`
	Services     []Service     `json:"services"`
}

type OS struct {
	Hostname     string `json:"-"`
	Family       string `json:"family,omitempty"`
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	OSVEcosystem string `json:"osv_ecosystem,omitempty"`
}

type Package struct {
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture,omitempty"`
	SourcePackage string `json:"source_package,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
	ManifestPath  string `json:"manifest_path,omitempty"`
	Direct        *bool  `json:"direct,omitempty"`
}

type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type Service struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
}

type Collector interface {
	Name() string
	Collect(ctx context.Context, inv *Inventory) error
}

type Options struct {
	Root            string
	CollectServices bool
	// Dependencies enables the dependency file collector when not nil.
	Dependencies *DependencyOptions
}

// Defaults returns the collectors in the order they must run: package collectors read the OS facts the first one fills in.
// The root is made absolute because rpm rejects a relative --root.
func Defaults(o Options) ([]Collector, error) {
	root, err := filepath.Abs(cmp.Or(o.Root, "/"))
	if err != nil {
		return nil, fmt.Errorf("root %q: %w", o.Root, err)
	}
	collectors := []Collector{
		OSCollector{Root: root},
		DpkgCollector{Root: root},
		RPMCollector{Root: root},
		APKCollector{Root: root},
	}
	if o.Dependencies != nil {
		collectors = append(collectors, DependencyCollector{Root: root, Options: *o.Dependencies})
	}
	if o.CollectServices {
		collectors = append(collectors, ServicesCollector{Root: root})
	}
	return collectors, nil
}

// Run fails as a whole when one collector fails, so a partial package list is never reported as the full inventory.
func Run(ctx context.Context, collectors ...Collector) (*Inventory, error) {
	inv := &Inventory{Packages: []Package{}, SkippedFiles: []SkippedFile{}, Services: []Service{}}
	for _, c := range collectors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := c.Collect(ctx, inv); err != nil {
			return nil, fmt.Errorf("%s collector: %w", c.Name(), err)
		}
	}
	if err := inv.Normalize(); err != nil {
		return nil, err
	}
	return inv, nil
}

func (inv *Inventory) Skip(path, reason string) {
	inv.SkippedFiles = append(inv.SkippedFiles, SkippedFile{Path: path, Reason: reason})
}

// Normalize dedupes and sorts the inventory and applies the server limits, so an unchanged host always produces the same snapshot.
// Above MaxPackages it keeps every OS package and cuts dependency packages by manifest path, recording each manifest
// it cuts as skipped so the server keeps what it stored for it. Those records are never dropped by MaxSkippedFiles:
// the other skipped files are capped first.
func (inv *Inventory) Normalize() error {
	seen := make(map[packageIdentity]bool, len(inv.Packages))
	packages := make([]Package, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		if !p.valid() {
			if validPath(p.ManifestPath) {
				inv.Skip(p.ManifestPath, ReasonInvalidEntries)
			}
			continue
		}
		id := p.identity()
		if seen[id] {
			continue
		}
		seen[id] = true
		packages = append(packages, p)
	}
	if len(packages) > MaxPackages {
		slices.SortFunc(packages, func(a, b Package) int {
			return cmp.Or(cmp.Compare(a.ManifestPath, b.ManifestPath), a.identity().compare(b.identity()))
		})
		if packages[MaxPackages].ManifestPath == "" {
			return fmt.Errorf("%w: limit %d", ErrTooManyOSPackages, MaxPackages)
		}
		for i, p := range packages[MaxPackages:] {
			if i == 0 || p.ManifestPath != packages[MaxPackages+i-1].ManifestPath {
				inv.Skip(p.ManifestPath, ReasonPackageLimit)
			}
		}
		packages = packages[:MaxPackages]
	}
	slices.SortFunc(packages, func(a, b Package) int { return a.identity().compare(b.identity()) })
	inv.Packages = packages

	inv.SkippedFiles = slices.DeleteFunc(inv.SkippedFiles, func(f SkippedFile) bool { return !validPath(f.Path) || f.Reason == "" })
	slices.SortFunc(inv.SkippedFiles, compareSkippedFiles)
	inv.SkippedFiles = slices.Compact(inv.SkippedFiles)
	if len(inv.SkippedFiles) > MaxSkippedFiles {
		cut := slices.DeleteFunc(slices.Clone(inv.SkippedFiles), func(f SkippedFile) bool { return f.Reason != ReasonPackageLimit })
		if len(cut) > MaxSkippedFiles {
			return fmt.Errorf("%w: %d manifests, limit %d", ErrTooManyCutManifests, len(cut), MaxSkippedFiles)
		}
		others := slices.DeleteFunc(inv.SkippedFiles, func(f SkippedFile) bool { return f.Reason == ReasonPackageLimit })
		inv.SkippedFiles = slices.Concat(others[:MaxSkippedFiles-len(cut)], cut)
		slices.SortFunc(inv.SkippedFiles, compareSkippedFiles)
	}

	slices.SortFunc(inv.Services, compareServices)
	inv.Services = slices.CompactFunc(inv.Services, func(a, b Service) bool {
		return a.Protocol == b.Protocol && a.Address == b.Address && a.Port == b.Port
	})
	if len(inv.Services) > MaxServices {
		inv.Services = inv.Services[:MaxServices]
	}
	return nil
}

func compareSkippedFiles(a, b SkippedFile) int {
	return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Reason, b.Reason))
}

func compareServices(a, b Service) int {
	return cmp.Or(
		cmp.Compare(a.Protocol, b.Protocol),
		cmp.Compare(a.Address, b.Address),
		cmp.Compare(a.Port, b.Port),
		cmp.Compare(a.Process, b.Process),
	)
}

// valid applies the server's per package rules, so one odd entry in a lock file cannot get the whole
// snapshot rejected.
func (p Package) valid() bool {
	return p.Ecosystem != "" && len(p.Ecosystem) <= 255 && validToken(p.Name) == nil && validToken(p.Version) == nil &&
		len(p.Architecture) <= 255 && len(p.SourcePackage) <= 255 && len(p.SourceVersion) <= 255 &&
		(p.ManifestPath == "" || validPath(p.ManifestPath))
}

var errInvalidToken = errors.New("invalid")

func validToken(s string) error {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) {
		return errInvalidToken
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return errInvalidToken
		}
	}
	return nil
}

func validPath(p string) bool {
	return strings.HasPrefix(p, "/") && len(p) <= 1024 && utf8.ValidString(p) && !strings.ContainsAny(p, "\x00\r\n")
}

type packageIdentity struct {
	ecosystem, name, architecture, manifestPath string
}

// identity mirrors InventorySnapshotValidator::identity: the server rejects a snapshot with two packages sharing it.
func (p Package) identity() packageIdentity {
	return packageIdentity{p.Ecosystem, p.Name, p.Architecture, p.ManifestPath}
}

func (a packageIdentity) compare(b packageIdentity) int {
	return cmp.Or(
		cmp.Compare(a.ecosystem, b.ecosystem),
		cmp.Compare(a.name, b.name),
		cmp.Compare(a.architecture, b.architecture),
		cmp.Compare(a.manifestPath, b.manifestPath),
	)
}

// Marshal encodes the inventory for upload. When it is larger than limit bytes, the dependency files with
// the most packages are left out one at a time and recorded as skipped (package_limit) until it fits.
func (inv *Inventory) Marshal(limit int) ([]byte, error) {
	for {
		data, err := json.Marshal(inv)
		if err != nil || len(data) <= limit {
			return data, err
		}
		largest := largestManifest(inv.Packages)
		if largest == "" {
			return nil, fmt.Errorf("inventory is %d bytes, over the %d byte limit, without dependency files to leave out", len(data), limit)
		}
		inv.Packages = slices.DeleteFunc(inv.Packages, func(p Package) bool { return p.ManifestPath == largest })
		inv.Skip(largest, ReasonPackageLimit)
		if err := inv.Normalize(); err != nil {
			return nil, err
		}
	}
}

func largestManifest(packages []Package) string {
	counts := map[string]int{}
	var largest string
	for _, p := range packages {
		if p.ManifestPath == "" {
			continue
		}
		counts[p.ManifestPath]++
		if c := counts[p.ManifestPath]; c > counts[largest] || (c == counts[largest] && p.ManifestPath < largest) {
			largest = p.ManifestPath
		}
	}
	return largest
}
