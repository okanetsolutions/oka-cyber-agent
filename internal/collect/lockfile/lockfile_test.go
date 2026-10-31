package lockfile

import (
	"os"
	"path/filepath"
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

func TestParsersAgainstRealLockFiles(t *testing.T) {
	tests := []struct {
		fixture    string
		count      int
		unresolved int
		spots      []spot
	}{
		{"composer/composer.lock", 7, 0, []spot{{"monolog/monolog", "3.12.1", unknown}, {"symfony/deprecation-contracts", "3.7.1", unknown}, {"phpunit/php-timer", "", unknown}}},
		{"npm-v3/package-lock.json", 74, 0, []spot{{"express", "4.19.2", yes}, {"@sentry/node", "7.100.0", yes}, {"lodash", "4.17.20", yes}, {"accepts", "1.3.8", no}}},
		{"npm-shrinkwrap/npm-shrinkwrap.json", 74, 0, []spot{{"express", "4.19.2", yes}}},
		{"npm-v1/package-lock.json", -1, 0, []spot{{"express", "4.17.1", unknown}, {"mocha", "8.0.1", unknown}}},
		{"yarn-v1/yarn.lock", 80, 0, []spot{{"express", "4.19.2", unknown}, {"@babel/code-frame", "7.24.2", unknown}}},
		{"yarn-berry/yarn.lock", 87, 0, []spot{{"express", "4.19.2", unknown}, {"resolve", "1.22.8", unknown}}},
		{"pnpm-v5/pnpm-lock.yaml", 73, 0, []spot{{"express", "4.18.2", yes}, {"react-dom", "18.2.0", yes}, {"accepts", "1.3.8", no}}},
		{"pnpm-v6/pnpm-lock.yaml", 74, 0, []spot{{"express", "4.19.2", yes}, {"react-dom", "18.3.1", yes}, {"typescript", "5.4.5", yes}, {"accepts", "1.3.8", no}}},
		{"pnpm-v9/pnpm-lock.yaml", 74, 0, []spot{{"express", "4.19.2", yes}, {"react-dom", "18.3.1", yes}, {"typescript", "5.4.5", yes}, {"accepts", "1.3.8", no}}},
		{"poetry-1/poetry.lock", 14, 0, []spot{{"django", "4.2.11", unknown}, {"requests", "2.31.0", unknown}, {"pytest", "8.1.1", unknown}}},
		{"poetry-2/poetry.lock", 14, 0, []spot{{"django", "4.2.11", unknown}, {"requests", "2.31.0", unknown}}},
		{"pipenv/Pipfile.lock", 16, 0, []spot{{"requests", "2.31.0", unknown}, {"flask", "3.0.3", unknown}, {"pytest", "8.1.1", unknown}}},
		{"uv/uv.lock", 18, 0, []spot{{"fastapi", "0.110.1", yes}, {"requests", "2.31.0", yes}, {"pytest", "8.1.1", yes}, {"starlette", "", no}}},
		{"requirements-hashes/requirements.txt", 12, 0, []spot{{"requests", "2.31.0", unknown}, {"charset-normalizer", "3.5.2", unknown}}},
		{"requirements-freeze/requirements.txt", 12, 0, []spot{{"pyproject-hooks", "1.3.3", unknown}}},
		{"requirements-mixed/requirements.txt", 5, 4, []spot{{"django", "4.2.11", unknown}, {"django-environ", "0.11.2", unknown}, {"psycopg2-binary", "2.9.9", unknown}, {"requests", "2.31.0", unknown}, {"pillow", "10.3.0", unknown}}},
		{"bundler/Gemfile.lock", 14, 0, []spot{{"sinatra", "4.0.0", yes}, {"nokogiri", "1.16.4", yes}, {"rack", "3.0.10", yes}, {"tilt", "2.9.0", no}}},
		{"gomod/go.mod", 25, 0, []spot{{"github.com/gin-gonic/gin", "1.9.1", yes}, {"golang.org/x/text", "0.14.0", yes}, {"golang.org/x/net", "0.10.0", no}, {"github.com/ugorji/go/codec", "1.2.12", no}}},
		{"cargo/Cargo.lock", 9, 0, []spot{{"serde", "1.0.229", yes}, {"tokio", "1.54.1", yes}, {"proc-macro2", "", no}}},
		{"gradle/gradle.lockfile", 11, 0, []spot{{"org.apache.logging.log4j:log4j-core", "2.14.1", unknown}, {"com.google.guava:guava", "32.1.3-jre", unknown}}},
		{"maven/pom.xml", 3, 3, []spot{{"org.apache.logging.log4j:log4j-core", "2.14.1", yes}, {"org.postgresql:postgresql", "42.7.3", yes}, {"junit:junit", "4.13.2", yes}}},
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
			for _, d := range r.Dependencies {
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
		"node_modules/a":{"version":"1.0.0"},
		"node_modules/a/node_modules/b":{"version":"2.0.0"},
		"node_modules/b":{"version":"1.5.0"},
		"node_modules/c":{"version":"file:../c"},
		"node_modules/local":{"resolved":"packages/local","link":true},
		"packages/local":{"version":"0.0.1"}
	}}`)
	r, err := ParseNPMLock(data)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := first(r.Dependencies, "b"); b.Version != "1.5.0" || *b.Direct {
		t.Fatalf("b = %+v, want the hoisted 1.5.0 first, transitive", b)
	}
	if _, found := first(r.Dependencies, "local"); found {
		t.Fatal("workspace links are the project's own code")
	}
	if r.Unresolved != 1 {
		t.Fatalf("unresolved = %d, want the file: dependency", r.Unresolved)
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

func TestComposerDevBranchesAreUnresolved(t *testing.T) {
	r, err := ParseComposerLock([]byte(`{"packages":[{"name":"acme/lib","version":"dev-main"},{"name":"acme/other","version":"2.x-dev"},{"name":"psr/log","version":"v3.0.0"}]}`))
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
