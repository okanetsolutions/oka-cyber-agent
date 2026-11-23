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

	MaxApplications           = 1000
	MaxApplicationRuntimes    = 20
	MaxApplicationFieldLength = 255
	MaxRepositoryLength       = 1024
)

// ErrTooManyOSPackages means the OS packages alone exceed MaxPackages. They have no manifest path to record as
// skipped, and the server deletes every stored package missing from a snapshot, so the inventory fails instead.
var ErrTooManyOSPackages = errors.New("more OS packages than the server accepts")

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
	// Applications is left out of the snapshot when empty: an agent with collect_application_details off sends
	// what an agent older than the key does.
	Applications []Application `json:"applications,omitempty"`
	// DroppedManifests lists the manifests with packages stored on the server whose skip record Marshal had to leave
	// out of skipped_files: the server deletes what it stored for them.
	DroppedManifests []string `json:"-"`
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
	Origin        string `json:"origin,omitempty"`
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

// Application describes the directory the agent parsed at least one lock file in. Path is that directory as the
// manifest paths of its packages name it; every other field is left out when the directory does not say.
type Application struct {
	Path       string    `json:"path"`
	Name       string    `json:"name,omitempty"`
	Repository string    `json:"repository,omitempty"`
	Branch     string    `json:"branch,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	Runtimes   []Runtime `json:"runtimes,omitempty"`
}

// Runtime is a language runtime requirement the application declares, such as php ^8.3.
type Runtime struct {
	Name       string `json:"name"`
	Constraint string `json:"constraint"`
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
//
// A manifest path is sent either through its packages or in skipped_files, never both. The server keeps every stored
// package whose manifest path is skipped and replaces the others with what the snapshot sends, so a manifest the agent can
// read only in part (entries without a pinned version, entries the server would reject) is sent with the packages it
// resolves and is not listed: a package removed from it is then deleted and its findings close. Such a manifest is
// listed only when none of its packages can be sent, and the server then keeps what it last stored for it.
//
// Above MaxPackages it keeps every OS package and cuts whole dependency manifests, recording each one it cuts as skipped
// so the server keeps what it stored for it. MaxSkippedFiles is applied by Marshal, which knows what the server stored.
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
		boundary := packages[MaxPackages].ManifestPath
		if boundary == "" {
			return fmt.Errorf("%w: limit %d", ErrTooManyOSPackages, MaxPackages)
		}
		cut := MaxPackages
		for cut > 0 && packages[cut-1].ManifestPath == boundary {
			cut--
		}
		for i, p := range packages[cut:] {
			if i == 0 || p.ManifestPath != packages[cut+i-1].ManifestPath {
				inv.Skip(p.ManifestPath, ReasonPackageLimit)
			}
		}
		packages = packages[:cut]
	}
	slices.SortFunc(packages, func(a, b Package) int { return a.identity().compare(b.identity()) })
	inv.Packages = packages

	sent := map[string]bool{}
	for _, p := range packages {
		sent[p.ManifestPath] = true
	}
	inv.SkippedFiles = slices.DeleteFunc(inv.SkippedFiles, func(f SkippedFile) bool {
		return !validPath(f.Path) || f.Reason == "" || sent[f.Path]
	})
	slices.SortFunc(inv.SkippedFiles, compareSkippedFiles)
	inv.SkippedFiles = slices.Compact(inv.SkippedFiles)

	slices.SortFunc(inv.Services, compareServices)
	inv.Services = slices.CompactFunc(inv.Services, func(a, b Service) bool {
		return a.Protocol == b.Protocol && a.Address == b.Address && a.Port == b.Port
	})
	if len(inv.Services) > MaxServices {
		inv.Services = inv.Services[:MaxServices]
	}

	inv.Applications = slices.DeleteFunc(inv.Applications, func(a Application) bool { return !validPath(a.Path) })
	slices.SortStableFunc(inv.Applications, func(a, b Application) int { return cmp.Compare(a.Path, b.Path) })
	inv.Applications = slices.CompactFunc(inv.Applications, func(a, b Application) bool { return a.Path == b.Path })
	if len(inv.Applications) > MaxApplications {
		inv.Applications = inv.Applications[:MaxApplications]
	}
	for i, a := range inv.Applications {
		if len(a.Runtimes) > MaxApplicationRuntimes {
			inv.Applications[i].Runtimes = a.Runtimes[:MaxApplicationRuntimes]
		}
	}
	return nil
}

// fitSkippedFiles applies the count limit to all records and the byte limit to optional records. A negative
// remaining budget means Marshal must free package space for the records that preserve stored packages.
func (inv *Inventory) fitSkippedFiles(budget int, stored func(path string) bool, cut map[string]bool) (remaining int, trimmedForSize bool, err error) {
	const (
		storedPath = iota
		cutManifest
		retainingReason
		otherReason
	)
	type ranked struct {
		file SkippedFile
		rank int
	}
	records := make([]ranked, 0, len(inv.SkippedFiles))
	for _, f := range inv.SkippedFiles {
		rank := otherReason
		switch {
		case stored != nil && stored(f.Path):
			rank = storedPath
		case cut[f.Path]:
			rank = cutManifest
		case retainsStoredPackages(f.Reason):
			// Prefer records that could retain packages if local state was lost.
			rank = retainingReason
		}
		records = append(records, ranked{f, rank})
	}
	slices.SortFunc(records, func(a, b ranked) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), compareSkippedFiles(a.file, b.file))
	})
	kept := inv.SkippedFiles[:0]
	keptPaths := make(map[string]bool)
	for _, r := range records {
		if len(kept) == MaxSkippedFiles {
			if r.rank == storedPath {
				inv.DroppedManifests = append(inv.DroppedManifests, r.file.Path)
			}
			continue
		}
		size, err := jsonRowSize(r.file, len(kept))
		if err != nil {
			return 0, false, err
		}
		if size > budget && r.rank > cutManifest {
			trimmedForSize = true
			continue
		}
		budget -= size
		kept = append(kept, r.file)
		if r.rank == storedPath {
			keptPaths[r.file.Path] = true
		}
	}
	inv.DroppedManifests = slices.DeleteFunc(inv.DroppedManifests, func(path string) bool { return keptPaths[path] })
	slices.Sort(inv.DroppedManifests)
	inv.DroppedManifests = slices.Compact(inv.DroppedManifests)
	inv.SkippedFiles = kept
	slices.SortFunc(inv.SkippedFiles, compareSkippedFiles)
	return budget, trimmedForSize, nil
}

// retainsStoredPackages tells whether a skip record would keep packages stored for that path. A no_lock_file record
// names a package.json (or similar) that never has packages of its own, and an unsupported_distribution record a
// package database whose packages have no manifest path, so they keep nothing.
func retainsStoredPackages(reason string) bool {
	return reason != ReasonNoLockFile && reason != ReasonUnsupportedDistribution
}

// StoredManifests returns the manifest paths the server has packages stored for once it accepts this snapshot: those
// sent with packages, and those it had packages for (stored, the same function Marshal got) that are listed in
// skipped_files, because the server keeps the stored packages of every listed path.
func (inv *Inventory) StoredManifests(stored func(path string) bool) []string {
	var paths []string
	for _, p := range inv.Packages {
		if p.ManifestPath != "" {
			paths = append(paths, p.ManifestPath)
		}
	}
	for _, f := range inv.SkippedFiles {
		if stored != nil && stored(f.Path) {
			paths = append(paths, f.Path)
		}
	}
	slices.Sort(paths)
	return slices.Compact(paths)
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

// Marshal encodes a normalized inventory within the server limits. To fit the body, it trims application details
// first, then optional skip records, then the largest dependency manifests. Skip records for stored paths and
// manifests cut here share the byte budget with packages and are subject to the skipped_files count limit.
func (inv *Inventory) Marshal(limit int, stored func(path string) bool) ([]byte, error) {
	if len(inv.SkippedFiles) <= MaxSkippedFiles {
		data, err := json.Marshal(inv)
		if err != nil || len(data) <= limit {
			return data, err
		}
	}

	cut := make(map[string]bool)
	var budget int
	for {
		base := *inv
		base.Applications = nil
		base.SkippedFiles = inv.SkippedFiles[:0]
		data, err := json.Marshal(&base)
		if err != nil {
			return nil, err
		}
		var trimmedForSize bool
		budget, trimmedForSize, err = inv.fitSkippedFiles(limit-len(data), stored, cut)
		if err != nil {
			return nil, err
		}
		if trimmedForSize || budget < 0 {
			inv.Applications = nil
		}
		if budget >= 0 {
			break
		}
		largest := largestManifest(inv.Packages)
		if largest == "" {
			return nil, fmt.Errorf("inventory is %d bytes, over the %d byte limit, without dependency files to leave out", limit-budget, limit)
		}
		inv.Packages = slices.DeleteFunc(inv.Packages, func(p Package) bool { return p.ManifestPath == largest })
		cut[largest] = true
		inv.Skip(largest, ReasonPackageLimit)
	}
	budget -= len(`,"applications":[]`)
	for i, app := range inv.Applications {
		size, err := jsonRowSize(app, i)
		if err != nil {
			return nil, err
		}
		if size > budget {
			inv.Applications = inv.Applications[:i]
			break
		}
		budget -= size
	}
	return json.Marshal(inv)
}

// jsonRowSize uses the same escaping as the final snapshot and includes the comma before a row when needed.
func jsonRowSize(row any, index int) (int, error) {
	data, err := json.Marshal(row)
	size := len(data)
	if index > 0 {
		size++
	}
	return size, err
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
