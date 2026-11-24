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
// Above MaxPackages it keeps every OS package and cuts whole dependency manifests, those with the most packages first,
// recording each one it cuts as skipped so the server keeps what it stored for it. MaxSkippedFiles is applied by
// Marshal, which knows what the server stored.
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
		rows := map[string]int{}
		for _, p := range packages {
			rows[p.ManifestPath]++
		}
		if rows[""] > MaxPackages {
			return fmt.Errorf("%w: limit %d", ErrTooManyOSPackages, MaxPackages)
		}
		delete(rows, "")
		// The manifest with the most packages goes first, so that the fewest are cut and a file made to hold
		// thousands of packages goes before the applications next to it, wherever its path sorts. Among equals the
		// last by path goes first.
		manifests := sortedKeys(rows)
		slices.SortFunc(manifests, func(a, b string) int { return cmp.Or(cmp.Compare(rows[b], rows[a]), cmp.Compare(b, a)) })
		cut := map[string]bool{}
		for i, total := 0, len(packages); total > MaxPackages; i++ {
			cut[manifests[i]] = true
			total -= rows[manifests[i]]
			inv.Skip(manifests[i], ReasonPackageLimit)
		}
		packages = slices.DeleteFunc(packages, func(p Package) bool { return cut[p.ManifestPath] })
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

	inv.Applications = firstApplications(inv.Applications)
	for i, a := range inv.Applications {
		if len(a.Runtimes) > MaxApplicationRuntimes {
			inv.Applications[i].Runtimes = a.Runtimes[:MaxApplicationRuntimes]
		}
	}
	return nil
}

// firstApplications returns the applications a snapshot sends: one for each path the server accepts, the first
// collected, and the MaxApplications first by path. The walk also calls it now and then on those it holds, which
// changes nothing of what is sent and keeps their number bounded.
func firstApplications(applications []Application) []Application {
	applications = slices.DeleteFunc(applications, func(a Application) bool { return !validPath(a.Path) })
	slices.SortStableFunc(applications, func(a, b Application) int { return cmp.Compare(a.Path, b.Path) })
	applications = slices.CompactFunc(applications, func(a, b Application) bool { return a.Path == b.Path })
	if len(applications) > MaxApplications {
		applications = applications[:MaxApplications]
	}
	return applications
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

// Marshal encodes a normalized inventory within the server limits: MaxSkippedFiles records and limit bytes. To fit
// the body it leaves out, in this order, the application details, the skip records that keep nothing stored on the
// server, and then the dependency manifests with the most packages, recording each as package_limit.
//
// A record that keeps packages stored on the server is the last thing left out: stored tells which paths have
// some, and without it every manifest cut here may. Such a record is only left out when the snapshot cannot hold it
// even with every dependency manifest cut (the largest records go first), or holds MaxSkippedFiles of them already
// (the last by path go first); its path is then listed in DroppedManifests, because the server deletes what it
// stored for it. The record of a cut manifest the server has
// nothing stored for is sent when it fits.
//
// Every size is that of the encoded JSON, where one byte of a path can take six, and is counted once, so what any
// local user planted under a scan path costs time in proportion to the inventory and never fails the snapshot: the
// only error left is OS packages that do not fit by themselves.
func (inv *Inventory) Marshal(limit int, stored func(path string) bool) ([]byte, error) {
	if len(inv.SkippedFiles) <= MaxSkippedFiles {
		data, err := json.Marshal(inv)
		if err != nil || len(data) <= limit {
			return data, err
		}
	}
	if err := inv.fit(limit, stored); err != nil {
		return nil, err
	}
	return json.Marshal(inv)
}

// jsonRows is the size of the elements of a JSON array: their encodings and the commas between them.
type jsonRows struct {
	count, bytes int
}

func (r *jsonRows) add(count, bytes int) {
	r.count += count
	r.bytes += bytes
}

func (r jsonRows) size() int {
	return r.bytes + max(r.count-1, 0)
}

// with is the size of the array with one more element of size bytes.
func (r jsonRows) with(bytes int) int {
	r.add(1, bytes)
	return r.size()
}

type sizedSkip struct {
	file SkippedFile
	size int
}

func compareSizedSkips(a, b sizedSkip) int { return compareSkippedFiles(a.file, b.file) }

func (inv *Inventory) fit(limit int, stored func(path string) bool) error {
	isStored := func(path string) bool { return stored != nil && stored(path) }

	if inv.Packages == nil {
		inv.Packages = []Package{}
	}
	empty := *inv
	empty.Packages, empty.SkippedFiles, empty.Applications = []Package{}, []SkippedFile{}, nil
	data, err := json.Marshal(&empty)
	if err != nil {
		return err
	}
	fixed := len(data)

	type manifest struct {
		path string
		rows jsonRows
	}
	var packages jsonRows
	var osPackages jsonRows
	manifests := map[string]*manifest{}
	for _, p := range inv.Packages {
		size, err := jsonSize(p)
		if err != nil {
			return err
		}
		packages.add(1, size)
		if p.ManifestPath == "" {
			osPackages.add(1, size)
			continue
		}
		m := manifests[p.ManifestPath]
		if m == nil {
			m = &manifest{path: p.ManifestPath}
			manifests[p.ManifestPath] = m
		}
		m.rows.add(1, size)
	}
	if size := fixed + osPackages.size(); size > limit {
		return fmt.Errorf("inventory is %d bytes, over the %d byte limit, without dependency files to leave out", size, limit)
	}
	largest := make([]*manifest, 0, len(manifests))
	for _, m := range manifests {
		largest = append(largest, m)
	}
	slices.SortFunc(largest, func(a, b *manifest) int {
		return cmp.Or(cmp.Compare(b.rows.count, a.rows.count), cmp.Compare(a.path, b.path))
	})

	// required holds, in the order of the snapshot, the records that keep stored packages. dropped lists the paths
	// of those left out.
	var required, optional []sizedSkip
	var requiredRows jsonRows
	var dropped []string
	drop := func(i int) {
		r := required[i]
		required = slices.Delete(required, i, i+1)
		requiredRows.add(-1, -r.size)
		if isStored(r.file.Path) {
			dropped = append(dropped, r.file.Path)
		}
	}
	require := func(r sizedSkip) {
		at, _ := slices.BinarySearchFunc(required, r, compareSizedSkips)
		required = slices.Insert(required, at, r)
		requiredRows.add(1, r.size)
		if len(required) > MaxSkippedFiles {
			drop(len(required) - 1)
		}
	}
	for _, f := range inv.SkippedFiles {
		size, err := jsonSize(f)
		if err != nil {
			return err
		}
		if isStored(f.Path) {
			require(sizedSkip{f, size})
		} else {
			optional = append(optional, sizedSkip{f, size})
		}
	}

	over := func() bool { return fixed+packages.size()+requiredRows.size() > limit }
	cut := map[string]bool{}
	var cutUnstored []sizedSkip
	for _, m := range largest {
		if !over() {
			break
		}
		cut[m.path] = true
		packages.add(-m.rows.count, -m.rows.bytes)
		record := SkippedFile{Path: m.path, Reason: ReasonPackageLimit}
		size, err := jsonSize(record)
		if err != nil {
			return err
		}
		if stored == nil || stored(m.path) {
			require(sizedSkip{record, size})
		} else {
			cutUnstored = append(cutUnstored, sizedSkip{record, size})
		}
	}
	// Records that still do not fit go by size, the largest first and among equals the last: a local user who
	// makes records too large for the body (a path can take six kilobytes) loses those, not the short records of
	// the applications next to them.
	droppedForSize := false
	for over() && len(required) > 0 {
		largest := 0
		for i, r := range required {
			if r.size >= required[largest].size {
				largest = i
			}
		}
		drop(largest)
		droppedForSize = true
	}

	// The other records are added while they fit, those whose reason could keep packages if the state was lost
	// first. With a manifest cut, the records that keep nothing were given up before it: the records of the
	// manifests cut come first, then those that could keep packages.
	trimmed := len(cut) > 0 || droppedForSize
	slices.SortStableFunc(optional, func(a, b sizedSkip) int {
		return cmp.Or(cmp.Compare(retainingRank(a.file.Reason), retainingRank(b.file.Reason)), compareSizedSkips(a, b))
	})
	if trimmed {
		slices.SortFunc(cutUnstored, compareSizedSkips)
		retaining := slices.DeleteFunc(optional, func(r sizedSkip) bool { return !retainsStoredPackages(r.file.Reason) })
		optional = append(cutUnstored, retaining...)
	}
	records := requiredRows
	kept := make([]SkippedFile, 0, min(len(required)+len(optional), MaxSkippedFiles))
	for _, r := range required {
		kept = append(kept, r.file)
	}
	for _, r := range optional {
		if len(kept) == MaxSkippedFiles {
			break
		}
		if fixed+packages.size()+records.with(r.size) > limit {
			trimmed = true
			continue
		}
		records.add(1, r.size)
		kept = append(kept, r.file)
	}
	slices.SortFunc(kept, compareSkippedFiles)

	inv.Packages = slices.DeleteFunc(inv.Packages, func(p Package) bool { return cut[p.ManifestPath] })
	inv.SkippedFiles = kept
	keptPaths := map[string]bool{}
	for _, f := range kept {
		keptPaths[f.Path] = true
	}
	inv.DroppedManifests = append(inv.DroppedManifests, dropped...)
	inv.DroppedManifests = slices.DeleteFunc(inv.DroppedManifests, func(path string) bool { return keptPaths[path] })
	slices.Sort(inv.DroppedManifests)
	inv.DroppedManifests = slices.Compact(inv.DroppedManifests)

	if trimmed {
		inv.Applications = nil
		return nil
	}
	budget := limit - fixed - packages.size() - records.size() - len(`,"applications":[]`)
	var applications jsonRows
	for i, app := range inv.Applications {
		size, err := jsonSize(app)
		if err != nil {
			return err
		}
		if applications.with(size) > budget {
			inv.Applications = inv.Applications[:i]
			break
		}
		applications.add(1, size)
	}
	return nil
}

func retainingRank(reason string) int {
	if retainsStoredPackages(reason) {
		return 0
	}
	return 1
}

// jsonSize is the size of v in the snapshot, with the escaping the snapshot is encoded with.
func jsonSize(v any) (int, error) {
	data, err := json.Marshal(v)
	return len(data), err
}
