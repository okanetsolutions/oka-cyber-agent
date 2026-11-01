// Package lockfile parses dependency lock files into resolved package versions. It never guesses: entries
// without a resolved version are counted as unresolved instead of reported.
package lockfile

import (
	"cmp"
	"regexp"
	"strings"
)

const (
	Packagist = "Packagist"
	NPM       = "npm"
	PyPI      = "PyPI"
	RubyGems  = "RubyGems"
	Go        = "Go"
	CratesIO  = "crates.io"
	Maven     = "Maven"
	NuGet     = "NuGet"
)

type Dependency struct {
	Name    string
	Version string
	// Direct is true when the file says the project depends on it directly, false when it says the
	// dependency is transitive, and nil when the file does not say.
	Direct *bool
}

type Result struct {
	Dependencies []Dependency
	Unresolved   int
}

type Format struct {
	FileName  string
	Ecosystem string
	parse     func(data []byte) (Result, error)
}

// Parse reads a lock file and keeps one version per name (see onePerName).
func (f Format) Parse(data []byte) (Result, error) {
	r, err := f.parse(data)
	if err != nil {
		return r, err
	}
	candidates := make([]candidate, len(r.Dependencies))
	for i, d := range r.Dependencies {
		rank := 1
		switch {
		case d.Direct == nil:
		case *d.Direct:
			rank = 0
		default:
			rank = 2
		}
		candidates[i] = candidate{d, rank}
	}
	r.Dependencies = onePerName(candidates)
	return r, nil
}

var Formats = []Format{
	{"composer.lock", Packagist, ParseComposerLock},
	{"package-lock.json", NPM, ParseNPMLock},
	{"npm-shrinkwrap.json", NPM, ParseNPMLock},
	{"yarn.lock", NPM, ParseYarnLock},
	{"pnpm-lock.yaml", NPM, ParsePNPMLock},
	{"requirements.txt", PyPI, ParseRequirements},
	{"poetry.lock", PyPI, ParsePoetryLock},
	{"Pipfile.lock", PyPI, ParsePipfileLock},
	{"uv.lock", PyPI, ParseUVLock},
	{"Gemfile.lock", RubyGems, ParseGemfileLock},
	{"go.mod", Go, ParseGoMod},
	{"Cargo.lock", CratesIO, ParseCargoLock},
	{"gradle.lockfile", Maven, ParseGradleLockfile},
	{"pom.xml", Maven, ParsePOM},
	{"packages.lock.json", NuGet, ParseNuGetLock},
}

func ForFile(name string) (Format, bool) {
	for _, f := range Formats {
		if f.FileName == name {
			return f, true
		}
	}
	return Format{}, false
}

// Manifests maps manifest files that declare dependencies without resolving them to the lock files that
// would resolve them, so a manifest found without any of its lock files is reported as skipped.
var Manifests = map[string][]string{
	"package.json":  {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"},
	"composer.json": {"composer.lock"},
	"Gemfile":       {"Gemfile.lock"},
	"Pipfile":       {"Pipfile.lock"},
	"Cargo.toml":    {"Cargo.lock"},
}

func direct(b bool) *bool { return &b }

// candidate is a dependency with the rank its lock file gives it among the versions of its name: lower is
// closer to the project (a direct dependency, a top level install).
type candidate struct {
	Dependency
	rank int
}

// onePerName keeps one version of each name, because Oka Core accepts one package per name in a manifest. It
// keeps the lowest rank: parsers that know which copy is top level rank it first (npm, yarn), and Format.Parse
// then ranks direct dependencies before unknown ones before transitive ones. Among equal ranks it keeps the
// highest version: the lock file cannot tell which copy the project imports, and the highest is the one a range
// written in the project's own manifest usually resolves to (package managers dedupe toward the newest version
// that satisfies every range), while the older copies are pinned by dependencies that lag behind.
func onePerName(candidates []candidate) []Dependency {
	best := map[string]int{}
	var kept []Dependency
	var ranks []int
	for _, c := range candidates {
		i, seen := best[c.Name]
		if !seen {
			best[c.Name] = len(kept)
			kept = append(kept, c.Dependency)
			ranks = append(ranks, c.rank)
			continue
		}
		if cmp.Or(cmp.Compare(c.rank, ranks[i]), compareVersions(kept[i].Version, c.Version)) < 0 {
			kept[i], ranks[i] = c.Dependency, c.rank
		}
	}
	return kept
}

// compareVersions orders versions by their dot separated numeric release (1.10.0 above 1.9.3) and puts a
// release above its pre-releases (1.0.0 above 1.0.0-rc.1); anything else is compared as text, so the order is
// the same on every host.
func compareVersions(a, b string) int {
	releaseA, restA := splitRelease(a)
	releaseB, restB := splitRelease(b)
	for i := range max(len(releaseA), len(releaseB)) {
		if c := compareNumbers(field(releaseA, i), field(releaseB, i)); c != 0 {
			return c
		}
	}
	preA, preB := strings.HasPrefix(restA, "-"), strings.HasPrefix(restB, "-")
	switch {
	case restA == "" && preB:
		return 1
	case preA && restB == "":
		return -1
	}
	return cmp.Compare(a, b)
}

func splitRelease(v string) ([]string, string) {
	end := 0
	for end < len(v) && (v[end] == '.' || v[end] >= '0' && v[end] <= '9') {
		end++
	}
	return strings.FieldsFunc(v[:end], func(r rune) bool { return r == '.' }), v[end:]
}

func field(fields []string, i int) string {
	if i < len(fields) {
		return fields[i]
	}
	return "0"
}

// compareNumbers compares digit strings of any length without converting them, so a huge field cannot overflow.
func compareNumbers(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	return cmp.Or(cmp.Compare(len(a), len(b)), cmp.Compare(a, b))
}

var pep503Separators = regexp.MustCompile(`[-_.]+`)

// NormalizePyPIName applies PEP 503, the form PyPI and OSV.dev compare names in.
func NormalizePyPIName(name string) string {
	return pep503Separators.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// looksLikeVersion rejects references that are not registry versions (git URLs, file paths, links).
func looksLikeVersion(v string) bool {
	return v != "" && v[0] >= '0' && v[0] <= '9' && !strings.ContainsAny(v, " :/\\")
}
