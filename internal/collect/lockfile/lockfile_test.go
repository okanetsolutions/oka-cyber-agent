package lockfile

import (
	"bytes"
	"cmp"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type spot struct {
	name, version string
	direct        *bool
}

var (
	yes     = direct(true)
	no      = direct(false)
	unknown *bool
)

// When a name is locked in several versions, the direct one is kept where the file says which it is, the one
// the project's own range asks for in yarn, and otherwise the highest.
var (
	pnpmDuplicates = []spot{{"ansi-regex", "5.0.1", yes}, {"strip-ansi", "7.2.0", yes}, {"wrap-ansi", "8.1.0", yes}, {"string-width", "5.1.2", no}, {"emoji-regex", "9.2.2", yes}, {"ansi-styles", "6.2.3", no}}
	yarnDuplicates = []spot{{"ansi-regex", "5.0.1", unknown}, {"strip-ansi", "7.2.0", unknown}, {"wrap-ansi", "8.1.0", unknown}, {"string-width", "5.1.2", unknown}, {"emoji-regex", "9.2.2", unknown}, {"ansi-styles", "6.2.3", unknown}}
)

func TestParsersAgainstRealLockFiles(t *testing.T) {
	tests := []struct {
		fixture    string
		count      int
		unresolved int
		spots      []spot
	}{
		{"composer/composer.lock", 7, 0, []spot{{"monolog/monolog", "3.12.1", unknown}, {"symfony/deprecation-contracts", "3.7.1", unknown}, {"phpunit/php-timer", "", unknown}}},
		// Composer 2.11 with a path repository (acme/http 2.1.0), a VCS repository (acme/vcs-lib v1.4.0) and an inline
		// package repository (acme/inline 3.0.0) next to psr/log from Packagist.
		{"composer-sources/composer.lock", 1, 3, []spot{{"psr/log", "3.0.2", unknown}}},
		{"npm-v3/package-lock.json", 73, 0, []spot{{"express", "4.19.2", yes}, {"@sentry/node", "7.100.0", yes}, {"lodash", "4.17.20", yes}, {"accepts", "1.3.8", no}}},
		{"npm-shrinkwrap/npm-shrinkwrap.json", 73, 0, []spot{{"express", "4.19.2", yes}}},
		{"npm-v1/package-lock.json", -1, 0, []spot{{"express", "4.17.1", unknown}, {"mocha", "8.0.1", unknown}}},
		// npm 6 with --legacy-bundling: debug 2.6.9 pulls ms 2.0.0 and send 0.18.0 pulls ms 2.1.3, both one level
		// deep; tar 6 pulls mkdirp 1.0.4 and write 1.0.3 pulls mkdirp 0.5.6, whose minimist sits nowhere else.
		{"npm-v1-nested/package-lock.json", 27, 0, []spot{{"debug", "2.6.9", unknown}, {"ms", "2.1.3", unknown}, {"mkdirp", "1.0.4", unknown}, {"minimist", "1.2.8", unknown}}},
		{"yarn-v1/yarn.lock", 79, 0, []spot{{"express", "4.19.2", unknown}, {"@babel/code-frame", "7.24.2", unknown}}},
		{"yarn-v1-sources/yarn.lock", 8, 0, []spot{{"string-width", "5.1.2", unknown}, {"@types/node", "20.19.43", unknown}, {"undici-types", "6.21.0", unknown}}},
		{"yarn-berry/yarn.lock", 86, 0, []spot{{"express", "4.19.2", unknown}, {"resolve", "1.22.8", unknown}}},
		// Yarn 4.5.3 against a registry that serves lodash from a nonstandard tarball URL writes its resolution as
		// lodash@npm:4.17.21::__archiveUrl=<url encoded tarball URL>.
		{"yarn-berry-archive-url/yarn.lock", 2, 0, []spot{{"lodash", "4.17.21", unknown}, {"left-pad", "1.3.0", unknown}}},
		{"pnpm-v5/pnpm-lock.yaml", 72, 0, []spot{{"express", "4.18.2", yes}, {"react-dom", "18.2.0", yes}, {"accepts", "1.3.8", no}}},
		{"pnpm-v6/pnpm-lock.yaml", 73, 0, []spot{{"express", "4.19.2", yes}, {"react-dom", "18.3.1", yes}, {"typescript", "5.4.5", yes}, {"accepts", "1.3.8", no}}},
		{"pnpm-v9/pnpm-lock.yaml", 73, 0, []spot{{"express", "4.19.2", yes}, {"react-dom", "18.3.1", yes}, {"typescript", "5.4.5", yes}, {"accepts", "1.3.8", no}}},
		// One project locked by npm 10, pnpm 7, 8 and 9, yarn 1.22 and yarn 4: it depends on ansi-regex ^5 while
		// strip-ansi 7 pulls ansi-regex 6, on emoji-regex ^9 while cliui pulls emoji-regex 8, and cliui pulls older
		// string-width and ansi-styles than wrap-ansi 8 does. It also installs is-positive from git, left-pad from a tarball URL and tarlib from a
		// file: tarball, which are not registry releases.
		{"npm-duplicates/package-lock.json", 11, 3, []spot{{"ansi-regex", "5.0.1", yes}, {"strip-ansi", "7.2.0", yes}, {"wrap-ansi", "8.1.0", yes}, {"string-width", "4.2.3", no}, {"emoji-regex", "9.2.2", yes}, {"ansi-styles", "6.2.3", no}}},
		{"pnpm-v5-duplicates/pnpm-lock.yaml", 11, 4, pnpmDuplicates},
		{"pnpm-v6-duplicates/pnpm-lock.yaml", 11, 4, pnpmDuplicates},
		{"pnpm-v9-duplicates/pnpm-lock.yaml", 11, 4, pnpmDuplicates},
		{"yarn-v1-duplicates/yarn.lock", 11, 0, yarnDuplicates},
		{"yarn-berry-duplicates/yarn.lock", 11, 0, yarnDuplicates},
		{"poetry-1/poetry.lock", 14, 0, []spot{{"django", "4.2.11", unknown}, {"requests", "2.31.0", unknown}, {"pytest", "8.1.1", unknown}}},
		{"poetry-2/poetry.lock", 14, 0, []spot{{"django", "4.2.11", unknown}, {"requests", "2.31.0", unknown}}},
		{"poetry-sources/poetry.lock", 4, 0, []spot{{"idna", "3.7", unknown}, {"urllib3", "2.8.0", unknown}}},
		{"pipenv/Pipfile.lock", 16, 0, []spot{{"requests", "2.31.0", unknown}, {"flask", "3.0.3", unknown}, {"pytest", "8.1.1", unknown}}},
		{"uv/uv.lock", 18, 0, []spot{{"fastapi", "0.110.1", yes}, {"requests", "2.31.0", yes}, {"pytest", "8.1.1", yes}, {"starlette", "", no}}},
		{"uv-sources/uv.lock", 4, 0, []spot{{"idna", "3.7", yes}, {"urllib3", "2.8.0", no}}},
		{"requirements-hashes/requirements.txt", 12, 0, []spot{{"requests", "2.31.0", unknown}, {"charset-normalizer", "3.5.2", unknown}}},
		{"requirements-freeze/requirements.txt", 12, 0, []spot{{"pyproject-hooks", "1.3.3", unknown}}},
		{"requirements-mixed/requirements.txt", 5, 4, []spot{{"django", "4.2.11", unknown}, {"django-environ", "0.11.2", unknown}, {"psycopg2-binary", "2.9.9", unknown}, {"requests", "2.31.0", unknown}, {"pillow", "10.3.0", unknown}}},
		// Bundler 2.5 with a git gem (gitgem 0.4.0) and a path gem (localgem 1.2.0) next to rack from rubygems.org.
		{"bundler-sources/Gemfile.lock", 1, 2, []spot{{"rack", "3.0.10", yes}}},
		{"bundler/Gemfile.lock", 9, 0, []spot{{"sinatra", "4.0.0", yes}, {"nokogiri", "1.16.4", yes}, {"rack", "3.0.10", yes}, {"tilt", "2.9.0", no}}},
		{"gomod/go.mod", 25, 0, []spot{{"github.com/gin-gonic/gin", "1.9.1", yes}, {"golang.org/x/text", "0.14.0", yes}, {"golang.org/x/net", "0.10.0", no}, {"github.com/ugorji/go/codec", "1.2.12", no}}},
		{"cargo/Cargo.lock", 9, 0, []spot{{"serde", "1.0.229", yes}, {"tokio", "1.54.1", yes}, {"proc-macro2", "", no}}},
		// Cargo 1.x: the project depends on syn 2 while thiserror-impl pulls syn 1 and clap_derive syn 3, and on
		// heck 0.4 while clap_derive pulls heck 0.5.
		{"cargo-duplicates/Cargo.lock", -1, 0, []spot{{"syn", "2.0.119", yes}, {"heck", "0.4.1", yes}, {"thiserror-impl", "1.0.30", no}}},
		{"gradle/gradle.lockfile", 11, 0, []spot{{"org.apache.logging.log4j:log4j-core", "2.14.1", unknown}, {"com.google.guava:guava", "32.1.3-jre", unknown}}},
		{"maven/pom.xml", 3, 3, []spot{{"org.apache.logging.log4j:log4j-core", "2.14.1", yes}, {"org.postgresql:postgresql", "42.7.3", yes}, {"junit:junit", "4.13.2", yes}}},
		// The same project with the encodings older Maven projects declare, and accented or typographic characters in
		// its description.
		{"maven-iso-8859-1/pom.xml", 3, 3, []spot{{"org.apache.logging.log4j:log4j-core", "2.14.1", yes}, {"junit:junit", "4.13.2", yes}}},
		{"maven-windows-1252/pom.xml", 3, 3, []spot{{"org.apache.logging.log4j:log4j-core", "2.14.1", yes}, {"junit:junit", "4.13.2", yes}}},
		{"maven-us-ascii/pom.xml", 3, 3, []spot{{"org.apache.logging.log4j:log4j-core", "2.14.1", yes}, {"junit:junit", "4.13.2", yes}}},
		{"nuget/packages.lock.json", 8, 0, []spot{{"Newtonsoft.Json", "13.0.3", yes}, {"Serilog", "3.1.1", yes}, {"Microsoft.Extensions.Primitives", "8.0.0", no}}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			format, ok := ForFile(filepath.Base(tt.fixture))
			if !ok {
				t.Fatalf("no format for %s", tt.fixture)
			}
			data, err := os.ReadFile(filepath.Join("testdata", tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			r, err := format.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if tt.count >= 0 && len(r.Dependencies) != tt.count {
				t.Errorf("dependencies = %d, want %d", len(r.Dependencies), tt.count)
			}
			if r.Unresolved != tt.unresolved {
				t.Errorf("unresolved = %d, want %d", r.Unresolved, tt.unresolved)
			}
			names := map[string]bool{}
			for _, d := range r.Dependencies {
				if names[d.Name] {
					t.Errorf("%s is reported more than once", d.Name)
				}
				names[d.Name] = true
				if d.Name == "" || strings.ContainsAny(d.Name+d.Version, " \t\n") || !looksLikeVersion(d.Version) {
					t.Errorf("invalid dependency %+v", d)
				}
			}
			for _, s := range tt.spots {
				d, found := first(r.Dependencies, s.name)
				if !found {
					t.Errorf("%s not found", s.name)
					continue
				}
				if s.version != "" && d.Version != s.version {
					t.Errorf("%s version = %s, want %s", s.name, d.Version, s.version)
				}
				if (d.Direct == nil) != (s.direct == nil) || (d.Direct != nil && *d.Direct != *s.direct) {
					t.Errorf("%s direct = %v, want %v", s.name, show(d.Direct), show(s.direct))
				}
			}
		})
	}
}

func TestNPMLockPrefersHoistedVersion(t *testing.T) {
	data := []byte(`{"lockfileVersion":3,"packages":{
		"":{"dependencies":{"a":"^1.0.0"}},
		"node_modules/a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
		"node_modules/a/node_modules/b":{"version":"2.0.0","resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz"},
		"node_modules/b":{"version":"1.5.0","resolved":"https://registry.npmjs.org/b/-/b-1.5.0.tgz"},
		"node_modules/c":{"version":"file:../c"},
		"node_modules/local":{"resolved":"packages/local","link":true},
		"packages/local":{"version":"0.0.1"}
	}}`)
	r, err := ParseNPMLock(data)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := first(r.Dependencies, "b"); b.Version != "1.5.0" || *b.Direct {
		t.Fatalf("b = %+v, want the hoisted 1.5.0, transitive", b)
	}
	if _, found := first(r.Dependencies, "local"); found {
		t.Fatal("workspace links are the project's own code")
	}
	if r.Unresolved != 1 {
		t.Fatalf("unresolved = %d, want the file: dependency", r.Unresolved)
	}
}

func TestNPMRegistryReleases(t *testing.T) {
	tests := []struct {
		name     string
		p        npmPackage
		registry bool
	}{
		{"lodash", npmPackage{Resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}, true},
		{"@babel/core", npmPackage{Resolved: "https://registry.npmjs.org/@babel/core/-/core-7.24.4.tgz"}, true},
		{"@acme/ui", npmPackage{Resolved: "https://npm.acme.test/repository/npm/@acme%2fui/-/ui-1.0.0.tgz"}, true},
		{"lodash", npmPackage{Resolved: "http://verdaccio.internal:4873/lodash/-/lodash-4.17.21.tgz"}, true},
		{"lodash", npmPackage{Integrity: "sha512-x"}, true},
		{"lodash", npmPackage{InBundle: true}, true},
		{"lodash", npmPackage{}, false},
		{"lodash", npmPackage{Resolved: "git+ssh://git@github.com/acme/lodash.git#abc123", Integrity: "sha512-x"}, false},
		{"left-pad", npmPackage{Resolved: "https://codeload.github.com/stevemao/left-pad/tar.gz/v1.3.0", Integrity: "sha512-x"}, false},
		{"lodash", npmPackage{Resolved: "https://example.test/forks/lodash-4.17.21.tgz"}, false},
		{"lodash", npmPackage{Resolved: "https://registry.npmjs.org/other/-/other-1.0.0.tgz"}, false},
		{"tarlib", npmPackage{Resolved: "file:vendor/tarlib-1.0.0.tgz", Integrity: "sha512-x"}, false},
	}
	for _, tt := range tests {
		if got := npmFromRegistry(tt.p, tt.name); got != tt.registry {
			t.Errorf("npmFromRegistry(%s, %+v) = %v, want %v", tt.name, tt.p, got, tt.registry)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	ordered := []string{"0.9", "1.0.0-alpha", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.9.3", "1.10.0", "2.0.0", "10.0.0", "99999999999999999999999.0"}
	for i := range ordered {
		for j := range ordered {
			if got, want := compareVersions(ordered[i], ordered[j]), cmp.Compare(i, j); got != want {
				t.Errorf("compareVersions(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if compareVersions("1.0", "1.0.0") == 0 {
		t.Error("versions that differ only in form must still have a fixed order")
	}
}

func TestOnePerNamePrefersRankThenHighestVersion(t *testing.T) {
	got := onePerName([]candidate{
		{Dependency{Name: "a", Version: "1.0.0"}, 1},
		{Dependency{Name: "a", Version: "3.0.0"}, 1},
		{Dependency{Name: "a", Version: "2.0.0"}, 0},
		{Dependency{Name: "b", Version: "1.0.0"}, 2},
		{Dependency{Name: "b", Version: "1.2.0"}, 2},
	})
	want := []Dependency{{Name: "a", Version: "2.0.0"}, {Name: "b", Version: "1.2.0"}}
	if !slices.Equal(got, want) {
		t.Fatalf("onePerName = %+v, want %+v", got, want)
	}
}

func TestNPMV1PrefersTopLevelVersion(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "npm-v1", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseNPMLock(data)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, d := range r.Dependencies {
		names[d.Name] = true
	}
	if len(names) != 223 {
		t.Fatalf("names = %d, want the 223 installed package names", len(names))
	}
}

func TestNPMV1VisitsEveryNestedCopy(t *testing.T) {
	data := []byte(`{"lockfileVersion":1,"dependencies":{
		"a":{"version":"1.0.0","dependencies":{"x":{"version":"1.0.0"}}},
		"b":{"version":"1.0.0","dependencies":{"x":{"version":"2.0.0","dependencies":{"z":{"version":"3.0.0"},"w":{"version":"github:acme/w#abc123"}}}}}
	}}`)
	r, err := ParseNPMLock(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a": "1.0.0", "b": "1.0.0", "x": "2.0.0", "z": "3.0.0"}
	got := map[string]string{}
	for _, d := range r.Dependencies {
		got[d.Name] = d.Version
	}
	if !maps.Equal(got, want) || r.Unresolved != 1 {
		t.Fatalf("dependencies = %v, unresolved = %d, want %v and the git dependency under the second x", got, r.Unresolved, want)
	}
}

// Real lock files from npm 10, pnpm 7 to 9, yarn 1.22 and 4, Poetry 2.2 and uv 0.9 with an npm alias, a scoped
// alias, a tarball URL, a git dependency, a URL, a file: tarball and a local directory: only registry packages
// are reported, under their registry names. npm records the package.json version of a git or tarball install,
// and pnpm before 9.x keys a git package by host and commit (github.com/kevva/is-positive/97edff6f...), whose
// last segment starts with a digit like a version does.
func TestNonRegistrySourcesAreLeftOut(t *testing.T) {
	for fixture, names := range map[string][]string{
		"bundler-sources/Gemfile.lock":      {"gitgem", "localgem"},
		"composer-sources/composer.lock":    {"acme/http", "acme/vcs-lib", "acme/inline"},
		"yarn-v1-sources/yarn.lock":         {"string-width-cjs", "node-types", "@sindresorhus/is", "left-pad", "local-lib"},
		"poetry-sources/poetry.lock":        {"requests", "six", "locallib"},
		"uv-sources/uv.lock":                {"requests", "six", "locallib", "app"},
		"npm-duplicates/package-lock.json":  {"is-positive", "left-pad", "tarlib", "local-lib"},
		"pnpm-v5-duplicates/pnpm-lock.yaml": {"is-positive", "github.com/kevva/is-positive", "left-pad", "tarlib", "local-lib"},
		"pnpm-v6-duplicates/pnpm-lock.yaml": {"is-positive", "github.com/kevva/is-positive", "left-pad", "tarlib", "local-lib"},
		"pnpm-v9-duplicates/pnpm-lock.yaml": {"is-positive", "left-pad", "tarlib", "local-lib"},
		"yarn-berry-duplicates/yarn.lock":   {"is-positive", "tarlib", "local-lib"},
	} {
		format, _ := ForFile(filepath.Base(fixture))
		data, err := os.ReadFile(filepath.Join("testdata", fixture))
		if err != nil {
			t.Fatal(err)
		}
		r, err := format.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if d, found := first(r.Dependencies, name); found {
				t.Errorf("%s: %+v is not a registry release", fixture, d)
			}
		}
	}
}

func TestYarnClassicHeader(t *testing.T) {
	tests := []struct {
		header, name string
		local        bool
	}{
		{`lodash@^4.17.21`, "lodash", false},
		{`"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4"`, "@babel/code-frame", false},
		{`"string-width-cjs@npm:string-width@^4.2.0"`, "string-width", false},
		{`"node-types@npm:@types/node@^20.11.0"`, "@types/node", false},
		{`"alias@npm:real"`, "real", false},
		{`"range@>= 1.0.0 < 2"`, "range", false},
		{`"@scope/foo@https://registry.npmjs.org/@scope/foo/-/foo-1.0.0.tgz"`, "@scope/foo", true},
		{`"left-pad@github:stevemao/left-pad#v1.3.0"`, "left-pad", true},
		{`"lib@git+ssh://git@github.com/me/lib.git"`, "lib", true},
		{`"repo@me/repo#main"`, "repo", true},
		{`"local@file:./local"`, "local", true},
		{`"pkg@./vendor/pkg.tgz"`, "pkg", true},
		{`"ws@workspace:packages/ws"`, "ws", true},
		{`"@scope"`, "", true},
		{`""`, "", true},
	}
	for _, tt := range tests {
		name, local := yarnClassicHeader(tt.header)
		if name != tt.name || local != tt.local {
			t.Errorf("yarnClassicHeader(%s) = %q, %v, want %q, %v", tt.header, name, local, tt.name, tt.local)
		}
	}
}

func TestComposerDevBranchesAreUnresolved(t *testing.T) {
	r, err := ParseComposerLock([]byte(`{"packages":[{"name":"acme/lib","version":"dev-main","notification-url":"https://packagist.org/downloads/"},{"name":"acme/other","version":"2.x-dev","notification-url":"https://packagist.org/downloads/"},{"name":"psr/log","version":"v3.0.0","notification-url":"https://packagist.org/downloads/"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Dependencies) != 1 || r.Dependencies[0].Version != "3.0.0" || r.Unresolved != 2 {
		t.Fatalf("result = %+v", r)
	}
}

func TestGoModLocalReplacementIsUnresolved(t *testing.T) {
	r, err := ParseGoMod([]byte("module x\n\nrequire example.com/tools v1.0.0\n\nreplace example.com/tools => ../tools\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Dependencies) != 0 || r.Unresolved != 1 {
		t.Fatalf("result = %+v", r)
	}
}

func TestMalformedFilesFail(t *testing.T) {
	for _, f := range Formats {
		if f.FileName == "requirements.txt" || f.FileName == "gradle.lockfile" || f.FileName == "go.mod" || f.FileName == "Gemfile.lock" {
			continue
		}
		if f.FileName == "yarn.lock" {
			if _, err := f.Parse([]byte("__metadata:\n  version: [unclosed")); err == nil {
				t.Errorf("%s: want an error", f.FileName)
			}
			continue
		}
		if _, err := f.Parse([]byte("{not valid")); err == nil {
			t.Errorf("%s: want an error for malformed input", f.FileName)
		}
	}
}

func TestEmptyFilesHaveNoDependencies(t *testing.T) {
	for _, f := range Formats {
		r, err := f.Parse(nil)
		if f.FileName == "pnpm-lock.yaml" {
			continue
		}
		if err == nil && (len(r.Dependencies) != 0 || r.Unresolved != 0) {
			t.Errorf("%s: empty file = %+v", f.FileName, r)
		}
	}
}

func TestNormalizePyPIName(t *testing.T) {
	for in, want := range map[string]string{"Django": "django", "pyproject_hooks": "pyproject-hooks", "zope.interface": "zope-interface", "A__B--c": "a-b-c"} {
		if got := NormalizePyPIName(in); got != want {
			t.Errorf("NormalizePyPIName(%q) = %q, want %q", in, got, want)
		}
	}
}

func first(deps []Dependency, name string) (Dependency, bool) {
	for _, d := range deps {
		if d.Name == name {
			return d, true
		}
	}
	return Dependency{}, false
}

func show(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestPOMSingleByteEncodings(t *testing.T) {
	tests := []struct {
		encoding string
		text     []byte
		want     string
	}{
		{"ISO-8859-1", []byte("Caf\xe9 M\xfcller"), "Caf\u00e9 M\u00fcller"},
		{"latin1", []byte("\xa9 \xff"), "\u00a9 \u00ff"},
		{"windows-1252", []byte("\x80 \x93shop\x94 \x81"), "\u20ac \u201cshop\u201d \u0081"},
		{"us-ascii", []byte("plain"), "plain"},
	}
	for _, tt := range tests {
		data := slices.Concat([]byte(`<?xml version="1.0" encoding="`+tt.encoding+`"?><project><name>`), tt.text,
			[]byte(`</name><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>`))
		r, err := ParsePOM(data)
		if err != nil || len(r.Dependencies) != 1 {
			t.Errorf("%s: %+v, %v; want one dependency", tt.encoding, r, err)
		}
		decoded, err := singleByteCharsetReader(tt.encoding, bytes.NewReader(tt.text))
		if err != nil {
			t.Fatalf("%s: %v", tt.encoding, err)
		}
		if got, _ := io.ReadAll(decoded); string(got) != tt.want {
			t.Errorf("%s: decoded %q, want %q", tt.encoding, got, tt.want)
		}
	}

	if _, err := ParsePOM([]byte(`<?xml version="1.0" encoding="Shift_JIS"?><project/>`)); err == nil {
		t.Error("an encoding the parser cannot decode must be a parse error")
	}
}
