package collect

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const megabyte = 1 << 20

// bodyLimit is api.MaxBodyBytes, which this package cannot import.
const bodyLimit = 5 * megabyte

// spent runs f and returns how long it took and how many bytes it allocated in all, which is more than it ever
// held at once.
func spent(f func()) (time.Duration, uint64) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	f()
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	return elapsed, after.TotalAlloc - before.TotalAlloc
}

// notStored is what the agent gives Marshal for a host the server has no dependency packages of.
func notStored(string) bool { return false }

func pins(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "pkg%05d==1.0\n", i)
	}
	return b.String()
}

func copyInventory(inv *Inventory) *Inventory {
	c := *inv
	c.Packages, c.SkippedFiles, c.Services, c.Applications = slices.Clone(inv.Packages), slices.Clone(inv.SkippedFiles), slices.Clone(inv.Services), slices.Clone(inv.Applications)
	c.DroppedManifests = nil
	return &c
}

// costlyPath is a path of the 1024 bytes the server accepts whose every "<" takes six bytes in JSON.
func costlyPath(i int, file string) string {
	long := strings.Repeat("<", 255)
	return fmt.Sprintf("/srv/%s/%s/%s/%s%04d/%s", long, long, long, strings.Repeat("<", 1024-len("/srv////")-3*255-4-1-len(file)), i, file)
}

func checkSnapshot(t *testing.T, data []byte, osPackages int) Inventory {
	t.Helper()
	if len(data) > bodyLimit {
		t.Fatalf("snapshot is %d bytes, over the %d the server accepts", len(data), bodyLimit)
	}
	var sent Inventory
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatal(err)
	}
	if got := manifests(&sent)[""]; got != osPackages {
		t.Fatalf("%d OS packages sent, want all %d", got, osPackages)
	}
	if len(sent.SkippedFiles) > MaxSkippedFiles {
		t.Fatalf("%d skipped files sent", len(sent.SkippedFiles))
	}
	return sent
}

// A local user plants a thousand one line lock files under paths that take six times their length in JSON. The
// snapshot used to fail on every report, after 39 seconds: each manifest cut to fit the body left a record as large
// as the package it removed, and the whole inventory was encoded again for each.
func TestPlantedPathsCannotFailOrSlowTheSnapshot(t *testing.T) {
	tr := tree{t, t.TempDir()}
	var planted []string
	for i := range 1000 {
		planted = append(planted, costlyPath(i, "requirements.txt"))
		tr.write(planted[i], "a==1\n")
	}
	if len(planted[0]) != 1024 {
		t.Fatalf("the planted paths are %d bytes, want the 1024 the server accepts", len(planted[0]))
	}
	const shop = "/srv/app/requirements.txt"
	tr.write(shop, pins(2000))
	collected, err := Run(context.Background(), packagesCollector(osPackages(1500)), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/srv"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := manifests(collected); len(got) != 1002 || got[shop] != 2000 {
		t.Fatalf("collected %d manifests with %d packages of the shop, want all 1002 and 2000", len(got), got[shop])
	}
	for name, stored := range map[string]func(string) bool{
		"nothing stored":        notStored,
		"no record of what is":  nil,
		"the shop stored":       storedSet(shop),
		"every manifest stored": storedSet(append(planted, shop)...),
	} {
		t.Run(name, func(t *testing.T) {
			inv := copyInventory(collected)
			var data []byte
			var err error
			elapsed, _ := spent(func() { data, err = inv.Marshal(bodyLimit, stored) })
			if err != nil {
				t.Fatalf("the planted files failed the snapshot: %v", err)
			}
			if elapsed > 5*time.Second {
				t.Errorf("the snapshot took %v", elapsed)
			}
			t.Logf("a snapshot of %d bytes in %v", len(data), elapsed)
			sent := checkSnapshot(t, data, 1500)
			skipped := skippedReasons(&sent)
			for manifest, packages := range manifests(collected) {
				switch {
				case manifest == "" || manifests(&sent)[manifest] == packages:
				case manifests(&sent)[manifest] != 0:
					t.Fatalf("%s is sent in part", manifest)
				case skipped[manifest] == ReasonPackageLimit || slices.Contains(inv.DroppedManifests, manifest):
				case stored != nil && stored(manifest):
					t.Fatalf("%s is stored and is neither sent, skipped nor reported as dropped", manifest)
				}
			}
		})
	}
}

// The skip records of 880 stored manifests under costly paths are larger than the body by themselves. Records of
// one size are left out from the end and reported, where Marshal used to fail for as long as the files stayed.
func TestStoredRecordsCannotFailTheSnapshot(t *testing.T) {
	inv := &Inventory{Packages: osPackages(1500)}
	var stored []string
	for i := range 880 {
		stored = append(stored, costlyPath(i, "requirements.txt"))
		inv.Skip(stored[i], ReasonUnresolvedVersions)
	}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	if full, err := json.Marshal(inv); err != nil || len(full) <= bodyLimit {
		t.Fatalf("the records are %d bytes, %v; want more than the body", len(full), err)
	}
	data, err := inv.Marshal(bodyLimit, storedSet(stored...))
	if err != nil {
		t.Fatalf("stored skip records failed the snapshot: %v", err)
	}
	sent := checkSnapshot(t, data, 1500)
	skipped := skippedReasons(&sent)
	if len(inv.DroppedManifests) == 0 || len(sent.SkippedFiles) < 700 {
		t.Fatalf("%d records sent and %d manifests dropped, want most records sent and the rest reported", len(sent.SkippedFiles), len(inv.DroppedManifests))
	}
	for i, manifest := range stored {
		if kept, dropped := skipped[manifest] != "", slices.Contains(inv.DroppedManifests, manifest); kept == dropped {
			t.Fatalf("%s: kept %v, dropped %v; want one of them", manifest, kept, dropped)
		}
		if i > 0 && skipped[manifest] != "" && skipped[stored[i-1]] == "" {
			t.Fatalf("%s is kept and the one before it is not: records of one size must be left out from the end", manifest)
		}
	}
}

// Records that must go to fit the body go by size, so records made too large for it cannot take the place of the
// short record that keeps an application's stored packages, wherever its path sorts.
func TestOversizedStoredRecordsAreDroppedBeforeSmallOnes(t *testing.T) {
	const victim = "/var/www/shop/composer.lock"
	inv := &Inventory{Packages: osPackages(1500)}
	stored := []string{victim}
	inv.Skip(victim, ReasonParseError)
	for i := range 900 {
		planted := costlyPath(i, "requirements.txt")
		stored = append(stored, planted)
		inv.Skip(planted, ReasonUnresolvedVersions)
	}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	if full, err := json.Marshal(inv); err != nil || len(full) <= bodyLimit {
		t.Fatalf("the records are %d bytes, %v; want more than the body", len(full), err)
	}
	data, err := inv.Marshal(bodyLimit, storedSet(stored...))
	if err != nil {
		t.Fatal(err)
	}
	sent := checkSnapshot(t, data, 1500)
	if skippedReasons(&sent)[victim] != ReasonParseError || slices.Contains(inv.DroppedManifests, victim) {
		t.Fatalf("the short record of %s was left out to make room for oversized ones (dropped: %d manifests)", victim, len(inv.DroppedManifests))
	}
	if len(inv.DroppedManifests) == 0 || len(sent.Applications) != 0 {
		t.Fatalf("%d manifests dropped and %d applications sent, want oversized records dropped and reported, and no application details", len(inv.DroppedManifests), len(sent.Applications))
	}
}

// 4000 manifests of one package with rows as large as the server accepts took Marshal 2 minutes 48 seconds.
func TestMarshalTimeGrowsWithTheInventoryNotItsSquare(t *testing.T) {
	inv := &Inventory{}
	for i := range 4000 {
		inv.Packages = append(inv.Packages, Package{Ecosystem: "Packagist", Name: strings.Repeat("<", 255), Version: "1" + strings.Repeat("<", 254), ManifestPath: costlyPath(i, "composer.lock")})
	}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	var data []byte
	var err error
	elapsed, _ := spent(func() { data, err = inv.Marshal(bodyLimit, notStored) })
	if err != nil {
		t.Fatal(err)
	}
	sent := checkSnapshot(t, data, 0)
	if len(sent.Packages) < 400 || elapsed > 20*time.Second {
		t.Fatalf("%d packages sent in %v, want what fits the body, in seconds", len(sent.Packages), elapsed)
	}
}

// The record of a manifest cut to fit the body is sent when it fits. When the server has nothing stored for the
// manifest the record keeps nothing, so no other manifest is cut to make room for it.
func TestMarshalLeavesOutTheRecordOfAnUnstoredCutManifestThatDoesNotFit(t *testing.T) {
	const largest = "/srv/large/package-lock.json"
	const smaller = "/srv/small/package-lock.json"
	os := osPackages(1)
	want := &Inventory{Packages: slices.Concat(os, dependencyPackages(smaller, 2)), SkippedFiles: []SkippedFile{}, Services: []Service{}}
	inv := &Inventory{Packages: slices.Concat(want.Packages, dependencyPackages(largest, 3)), SkippedFiles: []SkippedFile{}, Services: []Service{}}
	checkMarshaledInventory(t, inv, want, want, notStored)

	record := &Inventory{Packages: want.Packages, SkippedFiles: []SkippedFile{{Path: largest, Reason: ReasonPackageLimit}}, Services: []Service{}}
	inv = &Inventory{Packages: slices.Concat(want.Packages, dependencyPackages(largest, 3)), SkippedFiles: []SkippedFile{}, Services: []Service{}}
	checkMarshaledInventory(t, inv, record, record, notStored)
}

// After a manifest is cut, the records whose reason keeps stored packages are still sent while they fit, also when
// the local state does not know their path (state.json lost): the server would otherwise delete what it stored for
// a lock file that only failed to parse. Records that keep nothing are given up for the cut.
func TestMarshalKeepsRetainingRecordsThatFitAfterACut(t *testing.T) {
	const big, small = "/srv/big/package-lock.json", "/srv/small/package-lock.json"
	broken := SkippedFile{Path: "/srv/broken/composer.lock", Reason: ReasonParseError}
	noLock := SkippedFile{Path: "/srv/site/package.json", Reason: ReasonNoLockFile}
	cutRecord := SkippedFile{Path: big, Reason: ReasonPackageLimit}
	newInventory := func(skipped ...SkippedFile) *Inventory {
		return &Inventory{Packages: slices.Concat(dependencyPackages(big, 200), dependencyPackages(small, 1)), SkippedFiles: skipped, Services: []Service{}}
	}
	want := &Inventory{Packages: dependencyPackages(small, 1), SkippedFiles: []SkippedFile{cutRecord, broken}, Services: []Service{}}

	checkMarshaledInventory(t, newInventory(broken), want, copyInventory(want), notStored)
	checkMarshaledInventory(t, newInventory(broken, noLock), want, copyInventory(want), notStored)

	// With more room than the cut leaves, the record is kept and the snapshot stays under the limit.
	for _, limit := range []int{8000, 12000} {
		inv := newInventory(broken)
		if err := inv.Normalize(); err != nil {
			t.Fatal(err)
		}
		data, err := inv.Marshal(limit, notStored)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > limit || len(inv.Packages) != 1 || !slices.Equal(inv.SkippedFiles, want.SkippedFiles) {
			t.Fatalf("limit %d: %d bytes, %d packages, skipped %v, want the big manifest cut and %v", limit, len(data), len(inv.Packages), inv.SkippedFiles, want.SkippedFiles)
		}
	}
}

// Above MaxPackages the manifests with the most packages are cut first. They used to be cut from the last path, so
// one file of 20 000 packages under /home took the place of every application under /srv and /var/www.
func TestNormalizeCutsTheManifestsWithTheMostPackagesFirst(t *testing.T) {
	const planted, shop, blog = "/home/mallory/requirements.txt", "/var/www/shop/composer.lock", "/var/www/blog/composer.lock"
	inv := &Inventory{Packages: slices.Concat(
		osPackages(100),
		dependencyPackages(planted, MaxPackages),
		dependencyPackages(shop, 300),
		dependencyPackages(blog, 40),
	)}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	if got := manifests(inv); got[""] != 100 || got[planted] != 0 || got[shop] != 300 || got[blog] != 40 {
		t.Fatalf("packages per manifest = %v, want the planted file cut and both applications sent", got)
	}
	if want := []SkippedFile{{Path: planted, Reason: ReasonPackageLimit}}; !slices.Equal(inv.SkippedFiles, want) {
		t.Fatalf("skipped = %v, want %v", inv.SkippedFiles, want)
	}
}

// The walk holds maxWalkPackages packages at most, and none of a file with more than the server accepts in all:
// what comes after is recorded as package_limit without being read. Hard links make any number of large lock
// files out of one.
func TestWalkHoldsABoundedNumberOfPackages(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.write("/srv/0-more-than-the-server-accepts/requirements.txt", pins(MaxPackages+1))
	tr.write("/srv/1/requirements.txt", pins(MaxPackages))
	for i := 2; i <= 7; i++ {
		link := filepath.Join(tr.root, fmt.Sprintf("srv/%d/requirements.txt", i))
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(tr.root, "srv/1/requirements.txt"), link); err != nil {
			t.Skipf("no hard links here: %v", err)
		}
	}
	collector := DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/srv"}, ApplicationDetails: true}}
	held := &Inventory{}
	if err := collector.Collect(context.Background(), held); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{}
	for i := 1; i <= 4; i++ {
		want[fmt.Sprintf("/srv/%d/requirements.txt", i)] = MaxPackages
	}
	if got := manifests(held); len(held.Packages) != maxWalkPackages || !mapsEqualInt(got, want) {
		t.Fatalf("the walk holds %d packages of %v, want %d of the first four files", len(held.Packages), got, maxWalkPackages)
	}
	limited := skippedReasons(held)
	for _, manifest := range []string{"/srv/0-more-than-the-server-accepts/requirements.txt", "/srv/5/requirements.txt", "/srv/6/requirements.txt", "/srv/7/requirements.txt"} {
		if limited[manifest] != ReasonPackageLimit {
			t.Errorf("%s skipped as %q, want package_limit so the server keeps what it stored for it", manifest, limited[manifest])
		}
	}
	// A lock file left out is still the lock file of an application, whose details the server would otherwise forget.
	if len(held.Applications) != 8 {
		t.Errorf("%d applications, want the 8 directories with a lock file", len(held.Applications))
	}

	inv, err := Run(context.Background(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if got := manifests(inv); len(inv.Packages) != MaxPackages || got["/srv/1/requirements.txt"] != MaxPackages {
		t.Fatalf("sent %v, want the first file alone", got)
	}
	if got := skippedReasons(inv); len(got) != 7 || got["/srv/2/requirements.txt"] != ReasonPackageLimit || got["/srv/7/requirements.txt"] != ReasonPackageLimit {
		t.Fatalf("skipped = %v, want the seven other lock files as package_limit", got)
	}
}

func mapsEqualInt(a, b map[string]int) bool {
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

// An entry the server would refuse is not held by the walk, whose memory its name would otherwise take: a name can
// be as long as the file. The file is still sent with its other packages, and listed when it has none.
func TestWalkHoldsNothingTheServerRefuses(t *testing.T) {
	entry := func(name string) string {
		return `{"name": "` + name + `", "version": "1.0.0", "notification-url": "https://packagist.org/downloads/"}`
	}
	long := strings.Repeat("a", megabyte)
	tr := tree{t, t.TempDir()}
	tr.write("/srv/mixed/composer.lock", `{"packages": [`+entry(long)+`, `+entry("acme/ok")+`, `+entry("has space")+`]}`)
	tr.write("/srv/refused/composer.lock", `{"packages": [`+entry(long)+`]}`)
	collector := DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/srv"}}}
	held := &Inventory{}
	if err := collector.Collect(context.Background(), held); err != nil {
		t.Fatal(err)
	}
	if len(held.Packages) != 1 || held.Packages[0].Name != "acme/ok" {
		t.Fatalf("the walk holds %d packages, want acme/ok alone", len(held.Packages))
	}
	inv, err := Run(context.Background(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if want := []SkippedFile{{Path: "/srv/refused/composer.lock", Reason: ReasonInvalidEntries}}; len(inv.Packages) != 1 || !slices.Equal(inv.SkippedFiles, want) {
		t.Fatalf("packages = %+v, skipped = %v; want acme/ok and %v", inv.Packages, inv.SkippedFiles, want)
	}
}

// One walk reads maxWalkBytes of lock files and detail files, then records lock files as package_limit unread:
// any number of files of the size limit, or of links to one, would otherwise keep a report reading for hours.
func TestWalkReadsABoundedNumberOfBytes(t *testing.T) {
	defer func(limit int64) { maxWalkBytes = limit }(maxWalkBytes)
	maxWalkBytes = 64 << 10
	lock := "django==4.2.11\n" + strings.Repeat("# padding\n", 1000)
	tr := tree{t, t.TempDir()}
	for i := range 10 {
		tr.write(fmt.Sprintf("/srv/%d/requirements.txt", i), lock)
	}
	tr.write("/srv/9/composer.json", `{"name": "acme/nine"}`+strings.Repeat(" ", 8<<10))
	inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/srv"}})
	read := maxWalkBytes / int64(len(lock))
	if read < 2 || read > 8 {
		t.Fatalf("%d lock files fit the limit, want a few of the ten", read)
	}
	skipped := skippedReasons(inv)
	for i := range 10 {
		manifest := fmt.Sprintf("/srv/%d/requirements.txt", i)
		if sent, wantSent := manifests(inv)[manifest] == 1, int64(i) < read; sent != wantSent || !sent && skipped[manifest] != ReasonPackageLimit {
			t.Errorf("%s: sent %v, skipped as %q; want the first %d sent and the others package_limit", manifest, sent, skipped[manifest], read)
		}
	}
	if len(inv.Applications) != 10 || inv.Applications[9].Path != "/srv/9" || inv.Applications[9].Name != "" {
		t.Errorf("applications = %+v, want all ten and no detail file read past the limit", inv.Applications)
	}
}

// A directory is read in batches and only what the walk acts on is kept, maxDirectoryEntries at most: files of no
// interest do not count, and a directory with more subdirectories than that is walked in part and recorded.
func TestWalkListsABoundedNumberOfEntries(t *testing.T) {
	defer func(limit int) { maxDirectoryEntries = limit }(maxDirectoryEntries)
	maxDirectoryEntries = 5
	tr := tree{t, t.TempDir()}
	for i := range 8 {
		tr.write(fmt.Sprintf("/srv/many/%d/requirements.txt", i), "django==4.2.11\n")
	}
	for i := range 4 {
		tr.write(fmt.Sprintf("/srv/few/%d/requirements.txt", i), "django==4.2.11\n")
	}
	for i := range 3 * directoryBatch {
		tr.write(fmt.Sprintf("/srv/few/upload-%04d.jpg", i), "")
		tr.write(fmt.Sprintf("/srv/few/.cache-%04d/requirements.txt", i), "django==4.2.11\n")
	}
	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/srv"}}})
	if err != nil {
		t.Fatal(err)
	}
	few, many := 0, 0
	for manifest := range manifests(inv) {
		switch {
		case strings.HasPrefix(manifest, "/srv/few/"):
			few++
		case strings.HasPrefix(manifest, "/srv/many/"):
			many++
		}
	}
	if few != 4 || many != 5 {
		t.Errorf("%d lock files found under /srv/few and %d under /srv/many, want 4 and %d", few, many, maxDirectoryEntries)
	}
	if want := []SkippedFile{{Path: "/srv/many", Reason: ReasonTooLarge}}; !slices.Equal(inv.SkippedFiles, want) {
		t.Errorf("skipped = %v, want %v", inv.SkippedFiles, want)
	}
}

// The walk holds fewer than twice MaxApplications applications at any time, and sends the same ones as if it held
// them all: the first by path.
func TestWalkHoldsABoundedNumberOfApplications(t *testing.T) {
	const directories = 2*MaxApplications + 100
	tr := tree{t, t.TempDir()}
	var want []string
	for i := range directories {
		// Walked in the order of the names, which is not the order of the paths: "/srv/9" comes before "/srv/9-0".
		directory := fmt.Sprintf("/srv/%d/%d-0", i%7, directories-i)
		want = append(want, directory)
		tr.write(directory+"/requirements.txt", "django==4.2.11\n")
	}
	slices.Sort(want)
	collector := DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/srv"}, ApplicationDetails: true}}
	held := &Inventory{}
	if err := collector.Collect(context.Background(), held); err != nil {
		t.Fatal(err)
	}
	if len(held.Applications) >= 2*MaxApplications || len(held.Packages) != directories {
		t.Fatalf("the walk holds %d applications for %d lock files, want fewer than %d", len(held.Applications), len(held.Packages), 2*MaxApplications)
	}
	if err := held.Normalize(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range held.Applications {
		got = append(got, a.Path)
	}
	if !slices.Equal(got, want[:MaxApplications]) {
		t.Fatalf("applications sent: %d from %s to %s, want the first %d by path", len(got), got[0], got[len(got)-1], MaxApplications)
	}
}

// The files of TestHostileLockFilesAreRefusedAtOnce in the lockfile package, under a scan path: each used to end the
// process or take gigabytes or minutes. They are skipped and the lock files next to them are reported.
func TestHostileLockFilesAreSkippedByTheWalk(t *testing.T) {
	equal := func(head, line string) string { return head + strings.Repeat(line, 20000) }
	hostile := map[string]struct{ content, reason string }{
		"/home/mallory/1/Cargo.lock":     {"a = " + strings.Repeat("[", 2*megabyte), ReasonParseError},
		"/home/mallory/2/uv.lock":        {strings.Repeat("a.", 30000) + "a = 1\n", ReasonParseError},
		"/home/mallory/3/poetry.lock":    {"a = " + strings.Repeat("{a=", 20000), ReasonParseError},
		"/home/mallory/4/pnpm-lock.yaml": {equal("lockfileVersion: '9.0'\npackages:\n", "  a: {}\n"), ReasonParseError},
		"/home/mallory/5/yarn.lock":      {equal("__metadata:\n  version: 8\n", "a: {}\n"), ReasonParseError},
		"/home/mallory/6/pnpm-lock.yaml": {"lockfileVersion: '9.0'\nx: {" + strings.Repeat("a,", 10*megabyte) + "a}\n", ReasonTooLarge},
		"/home/mallory/7/uv.lock":        {"a = [" + strings.Repeat("1,", 10*megabyte) + "1]\n", ReasonTooLarge},
		"/home/mallory/8/composer.lock":  {`{"packages": [` + strings.Repeat("{},", 6*megabyte) + `{}]}`, ReasonTooLarge},
	}
	tr := tree{t, t.TempDir()}
	for path, file := range hostile {
		tr.write(path, file.content)
	}
	tr.copy(lockFixture("composer/composer.lock"), "/srv/shop/composer.lock")
	tr.copy(lockFixture("uv/uv.lock"), "/srv/api/uv.lock")
	tr.copy(lockFixture("pnpm-v9/pnpm-lock.yaml"), "/srv/web/pnpm-lock.yaml")
	// A manifest is decoded for the application details: one that is all entries gives none.
	tr.write("/srv/shop/composer.json", `{"name": "acme/shop", "require": {"php": "^8.3"}, "extra": [`+strings.Repeat("{},", 6*megabyte)+`{}]}`)
	var inv *Inventory
	var err error
	elapsed, allocated := spent(func() {
		inv, err = Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: DefaultScanPaths, ApplicationDetails: true}})
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > 30*time.Second || allocated > 512*megabyte {
		t.Errorf("the walk took %v and allocated %d MB, want seconds and little more than the files it read", elapsed, allocated/megabyte)
	}
	want := map[string]int{"/srv/shop/composer.lock": 7, "/srv/api/uv.lock": 18, "/srv/web/pnpm-lock.yaml": 73}
	if got := manifests(inv); !mapsEqualInt(got, want) {
		t.Errorf("packages per manifest = %v, want %v", got, want)
	}
	if want := []Application{{Path: "/srv/api"}, {Path: "/srv/shop"}, {Path: "/srv/web"}}; !reflect.DeepEqual(inv.Applications, want) {
		t.Errorf("applications = %+v, want %+v", inv.Applications, want)
	}
	skipped := skippedReasons(inv)
	if len(skipped) != len(hostile) {
		t.Errorf("skipped = %v, want the %d planted files", skipped, len(hostile))
	}
	for path, file := range hostile {
		if skipped[path] != file.reason {
			t.Errorf("%s skipped as %q, want %q", path, skipped[path], file.reason)
		}
	}
}

// sparseELF writes an executable of dataSize bytes that takes no disk space: an ELF file whose .go.buildinfo
// section covers all of it. The section starts with the build info of Go 1.26.0 and a module list that claims
// moduleBytes bytes, or holds no build info for the search to find when moduleBytes is negative.
func sparseELF(t *testing.T, path string, dataSize uint64, moduleBytes int64) {
	t.Helper()
	const dataOffset = 0x1000
	names := "\x00.go.buildinfo\x00.shstrtab\x00"
	var header bytes.Buffer
	write := func(v any) {
		if err := binary.Write(&header, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	write(elf.Header64{
		Ident: [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:  uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Phoff: 64, Shoff: 64 + 56, Ehsize: 64, Phentsize: 56, Phnum: 1, Shentsize: 64, Shnum: 3, Shstrndx: 2,
	})
	write(elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_W), Off: dataOffset, Vaddr: dataOffset, Paddr: dataOffset, Filesz: dataSize, Memsz: dataSize, Align: 0x1000})
	write(elf.Section64{})
	write(elf.Section64{Name: 1, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE), Addr: dataOffset, Off: dataOffset, Size: dataSize, Addralign: 16})
	write(elf.Section64{Name: 15, Type: uint32(elf.SHT_STRTAB), Off: 64 + 56 + 3*64, Size: uint64(len(names)), Addralign: 1})
	header.WriteString(names)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(header.Bytes()); err != nil {
		t.Fatal(err)
	}
	if moduleBytes >= 0 {
		info := append([]byte("\xff Go buildinf:"), 8, 2)
		info = append(info, make([]byte, 16)...)
		info = append(info, byte(len("go1.26.0")))
		info = append(info, "go1.26.0"...)
		info = binary.AppendUvarint(info, uint64(moduleBytes))
		if _, err := f.WriteAt(info, dataOffset); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Truncate(int64(dataOffset + dataSize)); err != nil {
		t.Skipf("no sparse files of %d bytes here: %v", dataSize, err)
	}
}

// An executable is read for at most maxGoBinaryBytes, whatever sizes it claims. A sparse one whose module list
// claims a gigabyte made buildinfo.Read allocate 6 gigabytes, and one of 256 gigabytes without build info kept it
// reading for 15 seconds, with no bound but the largest file the file system holds.
func TestGoBinaryReadIsBounded(t *testing.T) {
	// The same file with a module list it does hold is read as the Go binary it is.
	tr := tree{t, t.TempDir()}
	tr.write("/opt/tool/placeholder", "")
	sparseELF(t, filepath.Join(tr.root, "opt/tool/tool"), 4096, 0)
	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/opt"}, GoBinaries: true}})
	if want := []Package{{Ecosystem: "Go", Name: "stdlib", Version: "1.26.0", ManifestPath: "/opt/tool/tool"}}; err != nil || !slices.Equal(inv.Packages, want) {
		t.Fatalf("packages = %+v, %v; want %+v", inv.Packages, err, want)
	}
	for name, write := range map[string]func(t *testing.T, path string){
		"a module list of a gigabyte":          func(t *testing.T, path string) { sparseELF(t, path, 1<<30+4096, 1<<30) },
		"256 gigabytes without build info":     func(t *testing.T, path string) { sparseELF(t, path, 256<<30, -1) },
		"a section larger than the file holds": func(t *testing.T, path string) { sparseELF(t, path, 1<<20, 1<<40) },
	} {
		t.Run(name, func(t *testing.T) {
			tr := tree{t, t.TempDir()}
			tr.write("/opt/tool/placeholder", "")
			write(t, filepath.Join(tr.root, "opt/tool/tool"))
			var inv *Inventory
			var err error
			elapsed, allocated := spent(func() {
				inv, err = Run(context.Background(), DependencyCollector{Root: tr.root, Options: DependencyOptions{ScanPaths: []string{"/opt"}, GoBinaries: true}})
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Packages) != 0 || len(inv.SkippedFiles) != 0 {
				t.Errorf("inventory = %+v, want nothing from a file that is no Go binary", inv)
			}
			if elapsed > 10*time.Second || allocated > 64*megabyte {
				t.Errorf("the executable took %v and %d MB, want at most the %d MB read", elapsed, allocated/megabyte, maxGoBinaryBytes/megabyte)
			}
		})
	}
}

// A real Go binary, here the test binary, which is tens of megabytes, is read with a fraction of the budget, and a
// report that is stopped does not wait for the binary it is reading.
func TestGoBinaryReadBudgetLeavesRealBinariesAlone(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader := &budgetReader{ctx: context.Background(), file: f, left: maxGoBinaryBytes}
	if _, err := buildinfo.Read(reader); err != nil {
		t.Fatalf("the test binary is not read within %d bytes: %v", maxGoBinaryBytes, err)
	}
	if used := maxGoBinaryBytes - reader.left; used > maxGoBinaryBytes/4 {
		t.Errorf("the test binary took %d bytes of the %d allowed, want a small part", used, maxGoBinaryBytes)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := buildinfo.Read(&budgetReader{ctx: ctx, file: f, left: maxGoBinaryBytes}); err == nil {
		t.Error("a stopped report still read the binary")
	}
	if _, err := (&budgetReader{ctx: context.Background(), file: f, left: 15}).ReadAt(make([]byte, 16), 0); !errors.Is(err, errGoBinaryBudget) {
		t.Errorf("a read past the budget: err = %v, want errGoBinaryBudget", err)
	}
}
