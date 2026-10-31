// Package lockfile parses dependency lock files into resolved package versions. It never guesses: entries
// without a resolved version are counted as unresolved instead of reported.
package lockfile

import (
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
	Parse     func(data []byte) (Result, error)
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

var pep503Separators = regexp.MustCompile(`[-_.]+`)

// NormalizePyPIName applies PEP 503, the form PyPI and OSV.dev compare names in.
func NormalizePyPIName(name string) string {
	return pep503Separators.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// looksLikeVersion rejects references that are not registry versions (git URLs, file paths, links).
func looksLikeVersion(v string) bool {
	return v != "" && v[0] >= '0' && v[0] <= '9' && !strings.ContainsAny(v, " :/\\")
}
