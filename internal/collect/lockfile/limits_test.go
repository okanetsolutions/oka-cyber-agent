package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
)

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

func repeated(head string, n int, line func(i int) string) []byte {
	var b strings.Builder
	b.WriteString(head)
	for i := range n {
		b.WriteString(line(i))
	}
	return []byte(b.String())
}

// Files any local user can write under a scan path with the name of a lock file. Before the limits, the first
// ended the process with a stack overflow, the dotted keys, table names and inline tables took gigabytes for 60
// kilobytes, the YAML files with equal keys took gigabytes for 160 kilobytes, the YAML files with many keys took a
// minute for a megabyte, and a file of the size limit that is all entries took a gigabyte or more in any format.
func TestHostileLockFilesAreRefusedAtOnce(t *testing.T) {
	const megabyte = 1 << 20
	equalKeys := func(head, line string) []byte {
		return repeated(head, 20000, func(int) string { return line })
	}
	tests := []struct {
		name     string
		file     string
		data     []byte
		tooLarge bool
	}{
		{"nested arrays", "Cargo.lock", []byte("a = " + strings.Repeat("[", 2*megabyte)), false},
		{"nested arrays up to the size limit", "poetry.lock", []byte("a = " + strings.Repeat("[", 20*megabyte)), false},
		{"closed nested arrays", "uv.lock", []byte("a = " + strings.Repeat("[", megabyte) + strings.Repeat("]", megabyte) + "\n"), false},
		{"dotted key", "uv.lock", []byte(strings.Repeat("a.", 30000) + "a = 1\n"), false},
		{"table name", "poetry.lock", []byte("[" + strings.Repeat("a.", 30000) + "a]\n"), false},
		{"array table name", "Cargo.lock", []byte("[[" + strings.Repeat("a.", 30000) + "a]]\n"), false},
		{"nested inline tables", "uv.lock", []byte("a = " + strings.Repeat("{a=", 20000)), false},
		{"dotted key in an inline table", "uv.lock", []byte("a = {" + strings.Repeat("a.", 30000) + "a = 1}\n"), false},
		{"more tables than a lock file", "uv.lock", []byte(strings.Repeat("[a]\n", maxTOMLEntries+1)), true},
		{"more array items than a lock file", "Cargo.lock", []byte("a = [" + strings.Repeat("1,", maxTOMLEntries) + "1]\n"), true},
		{"more packages than a lock file", "composer.lock", []byte(`{"packages": [` + strings.Repeat("{},", maxJSONEntries) + `{}]}`), true},
		{"more paths than a lock file", "package-lock.json", []byte(`{"packages": {"": {}` + strings.Repeat(`,"node_modules/a": {}`, maxJSONEntries/2)), true},
		{"more items than a lock file in JSON", "Pipfile.lock", []byte(`{"default": {"a": {"hashes": [` + strings.Repeat("1,", maxJSONEntries) + `1]}}}`), true},
		{"more lines than requirements.txt", "requirements.txt", []byte(strings.Repeat("django==4.2.11\n", maxLines+1)), true},
		{"more lines than go.mod", "go.mod", []byte(strings.Repeat("require example.com/a v1.0.0\n", maxLines+1)), true},
		{"more lines than gradle.lockfile", "gradle.lockfile", []byte(strings.Repeat("org.example:a:1.0.0=runtimeClasspath\n", maxLines+1)), true},
		{"more lines than Gemfile.lock", "Gemfile.lock", []byte("GEM\n" + strings.Repeat("    rack (3.0.10)\n", maxLines)), true},
		{"more lines than yarn.lock", "yarn.lock", []byte(strings.Repeat("ms@2.1.3:\n  version \"2.1.3\"\n", maxLines/2+1)), true},
		{"equal keys in pnpm packages", "pnpm-lock.yaml", equalKeys("lockfileVersion: '9.0'\npackages:\n", "  a: {}\n"), false},
		{"equal keys in a pnpm resolution", "pnpm-lock.yaml", equalKeys("lockfileVersion: '9.0'\npackages:\n  a@1:\n    resolution:\n", "      type: git\n"), false},
		{"equal keys in a pnpm importer", "pnpm-lock.yaml", equalKeys("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n", "      a: 1\n"), false},
		{"equal keys at the root of pnpm", "pnpm-lock.yaml", equalKeys("lockfileVersion: '9.0'\n", "packages: {}\n"), false},
		{"equal keys in yarn", "yarn.lock", equalKeys("__metadata:\n  version: 8\n", "a: {}\n"), false},
		{"equal keys in yarn dependencies", "yarn.lock", equalKeys("__metadata:\n  version: 8\na:\n  dependencies:\n", "    b: 1\n"), false},
		{"more keys than a lock file", "pnpm-lock.yaml", []byte("lockfileVersion: '9.0'\npackages:\n" + strings.Repeat("  a@1: {}\n", maxYAMLEntries/3+1)), true},
		{"more items than a lock file", "yarn.lock", []byte("__metadata:\n  version: 8\na: {" + strings.Repeat("a,", maxYAMLEntries) + "a}\n"), true},
		{"aliases to one mapping", "pnpm-lock.yaml", repeated("lockfileVersion: '9.0'\nm: &m {resolution: {type: git}}\npackages:\n", 20000, func(i int) string { return fmt.Sprintf("  a%d@1: *m\n", i) }), false},
		{"merge keys", "pnpm-lock.yaml", repeated("lockfileVersion: '9.0'\nm: &m {type: git}\npackages:\n", 20000, func(i int) string { return fmt.Sprintf("  a%d@1: {resolution: {<<: *m}}\n", i) }), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, ok := ForFile(tt.file)
			if !ok {
				t.Fatalf("no format for %s", tt.file)
			}
			var err error
			elapsed, allocated := spent(func() { _, err = format.Parse(tt.data) })
			if err == nil {
				t.Fatal("parsed without an error")
			}
			if errors.Is(err, ErrTooLarge) != tt.tooLarge {
				t.Errorf("err = %v; ErrTooLarge wanted: %v", err, tt.tooLarge)
			}
			if elapsed > 5*time.Second || allocated > 64*megabyte {
				t.Errorf("%d bytes took %v and allocated %d MB, want it refused within 5s and 64 MB", len(tt.data), elapsed, allocated/megabyte)
			}
		})
	}
}

// Lock files of the size of a large project, which the limits must leave alone: tens of thousands of packages,
// read in time proportional to their number.
func TestLargeLockFilesAreStillRead(t *testing.T) {
	const packages = 20000
	tests := []struct {
		file string
		data []byte
	}{
		{"pnpm-lock.yaml", repeated("lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      pkg0:\n        specifier: ^1.0.0\n        version: 1.0.0\n\npackages:\n\n", packages, func(i int) string {
			return fmt.Sprintf("  pkg%d@1.0.0:\n    resolution: {integrity: sha512-fwSOJsbbNzZ/CUFpqFBqYfYNLPR0khYr8QDEeJFLakDpOwQGqUs2s5PPDGeZKUwJLhQ1+5V5NK8jyJmQgCKILQ==}\n    engines: {node: '>= 0.10.0'}\n\n", i)
		})},
		{"yarn.lock", repeated("__metadata:\n  version: 8\n  cacheKey: 10c0\n\n", packages, func(i int) string {
			return fmt.Sprintf("\"pkg%d@npm:^1.0.0\":\n  version: 1.0.0\n  resolution: \"pkg%d@npm:1.0.0\"\n  dependencies:\n    pkg0: \"npm:^1.0.0\"\n  checksum: 10c0/fwSOJsbbNzZCUFpqFBqYfYNLPR0khYr8QDEeJFLakDpOwQGqUs2s5PPDGeZKUwJLhQ1\n  languageName: node\n  linkType: hard\n\n", i, i)
		})},
		{"Cargo.lock", repeated("version = 4\n\n", packages, func(i int) string {
			return fmt.Sprintf("[[package]]\nname = \"pkg%d\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"d71b6127be86fdcfddb610f7182ac57211d4b18a3e9c82eb2d17662f2227ad6a\"\ndependencies = [\n \"pkg0\",\n]\n\n", i)
		})},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			format, _ := ForFile(tt.file)
			var r Result
			var err error
			elapsed, _ := spent(func() { r, err = format.Parse(tt.data) })
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Dependencies) != packages || r.Unresolved != 0 {
				t.Fatalf("dependencies = %d, unresolved = %d; want %d and 0", len(r.Dependencies), r.Unresolved, packages)
			}
			if elapsed > 30*time.Second {
				t.Errorf("%d packages took %v", packages, elapsed)
			}
		})
	}
}

// The three TOML lock files of the fixtures, written by cargo, poetry and uv, are far inside the limits.
func TestRealTOMLLockFilesAreWithinTheLimits(t *testing.T) {
	files, err := filepath.Glob("testdata/*/*.lock")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, file := range files {
		if base := filepath.Base(file); base != "Cargo.lock" && base != "poetry.lock" && base != "uv.lock" {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkTOML(data); err != nil {
			t.Errorf("%s: %v", file, err)
		}
		checked++
	}
	if checked < 7 {
		t.Fatalf("checked %d TOML fixtures, want the 7 committed", checked)
	}
}

// checkTOML counts a bracket or a dot only where the library reads one: not in a comment nor in any of the four
// kinds of string, whatever quotes and escapes they hold, and always after one ends.
func TestCheckTOMLReadsStringsAndCommentsAsTheLibraryDoes(t *testing.T) {
	brackets := strings.Repeat("[", maxTOMLNesting+1)
	dots := strings.Repeat("a.", maxTOMLKeyParts)
	harmless := []string{
		`a = "` + brackets + `"`,
		`a = '` + brackets + `'`,
		`a = "\"` + brackets + `"`,
		`a = "\\"` + "\n" + `b = '\'`,
		`a = """` + brackets + "\n" + brackets + `"""`,
		`a = '''` + brackets + "\n" + brackets + `'''`,
		`a = """x"" ` + brackets + ` """`,
		`a = """x""""" # two quotes end the text`,
		`a = '''x''''' # two quotes end the text`,
		`a = """\"""` + brackets + `"""`,
		`a = """x \` + "\n" + brackets + `"""`,
		`a = ""`,
		`a = ''`,
		`a = """"""`,
		`a = 1 # ` + brackets,
		`# ` + brackets + dots,
		`"` + dots + `" = 1`,
		`'` + dots + `' = 1`,
		`a = "` + dots + `"`,
		`[a."` + dots + `"]`,
		`a = [[[[[[[[1]]]]]]]]`,
		`a = {b = {c = {d = {e = {f = {g = {h = 1}}}}}}}`,
		`a.b.c.d.e.f.g.h = 1.5`,
		`a = [1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5]`,
	}
	for _, document := range harmless {
		var decoded map[string]any
		if err := toml.Unmarshal([]byte(document), &decoded); err != nil {
			t.Fatalf("%q is not TOML the library reads: %v", document, err)
		}
		if err := checkTOML([]byte(document)); err != nil {
			t.Errorf("%q: %v", document, err)
		}
		for _, hostile := range []string{"\nz = " + brackets, "\n" + dots + "z = 1", "\rz = " + brackets} {
			if err := checkTOML([]byte(document + hostile)); err == nil {
				t.Errorf("%q followed by %q was accepted", document, hostile)
			}
		}
	}
	for _, document := range []string{
		"a = " + brackets,
		"a = " + strings.Repeat("{b = ", maxTOMLNesting+1),
		"a = [{b = [{c = [{d = [{e = [",
		dots + "z = 1",
		"[" + dots + "z]",
		"[[" + dots + "z]]",
		"a = {" + dots + "z = 1}",
		"# comment\ra = " + brackets,
		`a = "` + "\n" + brackets + `"`,
		`a = """x""""""` + "\n",
		`a = "unterminated`,
		`a = '''unterminated''`,
	} {
		if err := checkTOML([]byte(document)); err == nil {
			t.Errorf("%q was accepted", document)
		}
	}
}

// Whatever checkTOML accepts and the library decodes is no deeper than the limits say: the check counts every
// bracket and key part the library acts on.
func FuzzCheckTOML(f *testing.F) {
	for _, seed := range []string{
		"a = [[1, 2], [3]]\n[b.c]\nd = {e = {f = 1}}\n",
		"a = \"\"\"x\"\"\"\"\"\nb = '''y'''''\nc = [[[[\n",
		"a = \"\\\"[[[\"\n# [[[[\r[[x]]\ny.z = '[[['\n",
		"\"a.b\".'c.d' = [{e = [{f = 1.5}]}]\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<12 || checkTOML(data) != nil {
			return
		}
		var decoded map[string]any
		if toml.Unmarshal(data, &decoded) != nil {
			return
		}
		arrays, tables := decodedDepth(decoded)
		// A table can sit under a table name, a dotted key and, at every level of nesting, another dotted key.
		if maxTables := maxTOMLKeyParts * (maxTOMLNesting + 2); arrays > maxTOMLNesting || tables > maxTables {
			t.Fatalf("accepted %q, which decodes to arrays nested %d deep and tables %d deep", data, arrays, tables)
		}
	})
}

// decodedDepth returns how deep arrays are nested directly in arrays, and tables in anything, in a decoded value.
func decodedDepth(value any) (arrays, tables int) {
	switch v := value.(type) {
	case map[string]any:
		for _, item := range v {
			a, t := decodedDepth(item)
			arrays, tables = max(arrays, a), max(tables, t)
		}
		return arrays, tables + 1
	case []map[string]any:
		for _, item := range v {
			a, t := decodedDepth(item)
			arrays, tables = max(arrays, a), max(tables, t)
		}
		return arrays, tables
	case []any:
		for _, item := range v {
			a, t := decodedDepth(item)
			if _, nested := item.([]any); !nested {
				a = 0
			}
			arrays, tables = max(arrays, a), max(tables, t)
		}
		return arrays + 1, tables
	}
	return 0, 0
}

// libraryPNPMLock and libraryYarnBerry are how the parsers decoded YAML before they read mappings themselves: the
// YAML library alone, into these types.
type libraryPNPMReference string

func (p *libraryPNPMReference) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*p = libraryPNPMReference(node.Value)
		return nil
	}
	var ref struct {
		Version string `yaml:"version"`
	}
	if err := node.Decode(&ref); err != nil {
		return err
	}
	*p = libraryPNPMReference(ref.Version)
	return nil
}

type libraryPNPMDependencies struct {
	Dependencies         map[string]libraryPNPMReference `yaml:"dependencies"`
	DevDependencies      map[string]libraryPNPMReference `yaml:"devDependencies"`
	OptionalDependencies map[string]libraryPNPMReference `yaml:"optionalDependencies"`
}

type libraryPNPMLock struct {
	LockfileVersion string                             `yaml:"lockfileVersion"`
	Importers       map[string]libraryPNPMDependencies `yaml:"importers"`
	Packages        map[string]struct {
		Resolution struct {
			Type   string `yaml:"type"`
			Repo   string `yaml:"repo"`
			Commit string `yaml:"commit"`
		} `yaml:"resolution"`
	} `yaml:"packages"`
	libraryPNPMDependencies `yaml:",inline"`
}

type libraryYarnBerry map[string]struct {
	Version      string            `yaml:"version"`
	Resolution   string            `yaml:"resolution"`
	Dependencies map[string]string `yaml:"dependencies"`
}

func libraryPNPM(data []byte) (pnpmLock, error) {
	var decoded libraryPNPMLock
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		return pnpmLock{}, err
	}
	dependencies := func(d libraryPNPMDependencies) pnpmDependencies {
		references := func(m map[string]libraryPNPMReference) map[string]pnpmReference {
			out := map[string]pnpmReference{}
			for name, ref := range m {
				out[name] = pnpmReference(ref)
			}
			return out
		}
		return pnpmDependencies{references(d.Dependencies), references(d.DevDependencies), references(d.OptionalDependencies)}
	}
	lock := pnpmLock{LockfileVersion: decoded.LockfileVersion, Importers: map[string]pnpmDependencies{}, Packages: map[string]pnpmResolution{}, pnpmDependencies: dependencies(decoded.libraryPNPMDependencies)}
	for name, importer := range decoded.Importers {
		lock.Importers[name] = dependencies(importer)
	}
	for key, p := range decoded.Packages {
		lock.Packages[key] = pnpmResolution{p.Resolution.Type, p.Resolution.Repo, p.Resolution.Commit}
	}
	return lock, nil
}

// withoutNilMaps gives a map read from an absent or empty mapping one form, which the two ways of decoding differ in.
func withoutNilMaps(lock pnpmLock) pnpmLock {
	fill := func(d pnpmDependencies) pnpmDependencies {
		for _, m := range []*map[string]pnpmReference{&d.Dependencies, &d.DevDependencies, &d.OptionalDependencies} {
			if *m == nil {
				*m = map[string]pnpmReference{}
			}
		}
		return d
	}
	out := pnpmLock{LockfileVersion: lock.LockfileVersion, Importers: map[string]pnpmDependencies{}, Packages: map[string]pnpmResolution{}, pnpmDependencies: fill(lock.pnpmDependencies)}
	for name, importer := range lock.Importers {
		out.Importers[name] = fill(importer)
	}
	for key, resolution := range lock.Packages {
		out.Packages[key] = resolution
	}
	return out
}

func libraryYarn(data []byte) (map[string]yarnBerryEntry, error) {
	var decoded libraryYarnBerry
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	entries := map[string]yarnBerryEntry{}
	for key, e := range decoded {
		entries[key] = yarnBerryEntry{e.Version, e.Resolution, e.Dependencies}
	}
	return entries, nil
}

func sameYarnEntries(a, b map[string]yarnBerryEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for key, entry := range a {
		other, ok := b[key]
		if !ok || entry.Version != other.Version || entry.Resolution != other.Resolution || len(entry.Dependencies) != len(other.Dependencies) {
			return false
		}
		for name, spec := range entry.Dependencies {
			if otherSpec, ok := other.Dependencies[name]; !ok || spec != otherSpec {
				return false
			}
		}
	}
	return true
}

const oddPNPMLock = `lockfileVersion: 6.0
importers:
  .:
    dependencies:
      a: {specifier: ^1, version: 1.0.0}
      b: 2
      c: ~
      "d": '3.0'
      e: true
      1: 1.5
      ~: left out
      f: {specifier: ^1}
      g: {version: 7, specifier: ~}
      !!str h: !!str 8
    devDependencies: ~
    optionalDependencies: {}
  packages/x: ~
  2: {}
  packages/y:
    dependencies:
packages:
  /a@1.0.0:
    resolution: {integrity: x, type: git, repo: 5, commit: ~}
    engines: {node: '>=8', node2: [1, 2]}
  /b@2:
    resolution: ~
  /c@3: ~
  /d@4: {}
  7: {resolution: {type: !!str 12, tarball: {a: 1, a2: 2}}}
  "/e@5": {resolution: {commit: 0x1f}}
dependencies:
  x: 1.0.0
  y: null
unknown: [1, 2, {a: b}, &anchor c, *anchor]
time: {a: 2024-01-01T00:00:00.000Z}
`

const oddYarnBerry = `__metadata:
  version: 8
  cacheKey: 10c0
"a@npm:^1.0.0":
  version: 1.0.0
  resolution: "a@npm:1.0.0"
  dependencies:
    b: "npm:^2.0.0"
    c: 3
    d: ~
    1: 1.5
    ~: left out
  bin: {a: bin/a.js}
"b@npm:^2.0.0, b@npm:^2.1.0":
  version: 2.1
  resolution: "b@npm:2.1.0"
  dependencies: {}
c: ~
4: {version: ~, resolution: true}
"root@workspace:.":
  version: 0.0.0-use.local
  resolution: "root@workspace:."
  dependencies:
    a: "npm:^1.0.0"
  unknown: [&anchor x, *anchor]
`

// The mappings the parsers read themselves give what the library gave: for the lock files pnpm and yarn wrote, and
// for every kind of key and value the library accepts in their place.
func TestYAMLLockFilesDecodeAsTheLibraryDecodedThem(t *testing.T) {
	pnpm := map[string][]byte{"odd keys and values": []byte(oddPNPMLock)}
	yarn := map[string][]byte{"odd keys and values": []byte(oddYarnBerry)}
	fixtures, err := filepath.Glob("testdata/*/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		data, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case filepath.Base(fixture) == "pnpm-lock.yaml":
			pnpm[fixture] = data
		case strings.Contains(fixture, "yarn-berry"):
			yarn[fixture] = data
		}
	}
	pnpm["5000 packages"] = repeated("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      pkg1: {specifier: ^1.0.0, version: 1.0.0}\npackages:\n", 5000, func(i int) string {
		return fmt.Sprintf("  pkg%d@1.0.0:\n    resolution: {integrity: sha512-x}\n", i)
	})
	yarn["5000 packages"] = repeated("__metadata:\n  version: 8\n", 5000, func(i int) string {
		return fmt.Sprintf("\"pkg%d@npm:^1.0.0\":\n  version: 1.0.0\n  resolution: \"pkg%d@npm:1.0.0\"\n  dependencies:\n    pkg1: \"npm:^1.0.0\"\n", i, i)
	})
	if len(pnpm) < 8 || len(yarn) < 5 {
		t.Fatalf("%d pnpm and %d yarn documents, want the 6 and 3 committed fixtures among them", len(pnpm), len(yarn))
	}
	for name, data := range pnpm {
		want, err := libraryPNPM(data)
		if err != nil {
			t.Fatalf("%s: the library: %v", name, err)
		}
		got, err := decodePNPMLock(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, want := withoutNilMaps(got), withoutNilMaps(want); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: decoded %+v\nthe library gave %+v", name, got, want)
		}
	}
	for name, data := range yarn {
		want, err := libraryYarn(data)
		if err != nil {
			t.Fatalf("%s: the library: %v", name, err)
		}
		got, err := decodeYarnBerry(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !sameYarnEntries(got, want) {
			t.Errorf("%s: decoded %+v\nthe library gave %+v", name, got, want)
		}
	}
}

// What the library refuses in a place the parsers read, they refuse too.
func TestYAMLLockFilesFailWhereTheLibraryFailed(t *testing.T) {
	for _, document := range []string{
		"lockfileVersion: '9.0'\npackages:\n  a@1: {}\n  a@1: {}\n",
		"lockfileVersion: '9.0'\npackages:\n  1: {}\n  \"1\": {}\n",
		"lockfileVersion: '9.0'\npackages:\n  a@1: {resolution: {type: a, type: b}}\n",
		"lockfileVersion: '9.0'\npackages:\n  a@1: {resolution: {unknown: a, unknown: b}}\n",
		"lockfileVersion: '9.0'\npackages:\n  a@1: {resolution: [git]}\n",
		"lockfileVersion: '9.0'\npackages:\n  a@1: {resolution: {type: [git]}}\n",
		"lockfileVersion: '9.0'\npackages:\n  a@1: text\n",
		"lockfileVersion: '9.0'\npackages: [a, b]\n",
		"lockfileVersion: '9.0'\npackages: text\n",
		"lockfileVersion: '9.0'\npackages:\n  ? [a, b]\n  : {}\n",
		"lockfileVersion: '9.0'\nimporters: text\n",
		"lockfileVersion: '9.0'\nimporters:\n  .: text\n",
		"lockfileVersion: '9.0'\nimporters:\n  .: {dependencies: text}\n",
		"lockfileVersion: '9.0'\nimporters:\n  .: {dependencies: {a: [1]}}\n",
		"lockfileVersion: '9.0'\nimporters:\n  .: {dependencies: {a: {version: {b: 1}}}}\n",
		"lockfileVersion: '9.0'\nimporters:\n  .: {dependencies: {a: 1, a: 2}}\n",
		"lockfileVersion: '9.0'\ndependencies: {a: 1}\ndependencies: {b: 1}\n",
		"lockfileVersion: {a: 1}\n",
		"lockfileVersion: '9.0'\npackages: {a: {}\n",
		"- lockfileVersion: '9.0'\n",
	} {
		if _, err := libraryPNPM([]byte(document)); err == nil {
			t.Fatalf("the library reads %q", document)
		}
		if _, err := decodePNPMLock([]byte(document)); err == nil {
			t.Errorf("%q was decoded", document)
		}
	}
	for _, document := range []string{
		"__metadata:\n  version: 8\na: {}\na: {}\n",
		"__metadata:\n  version: 8\na: {version: 1, version: 2}\n",
		"__metadata:\n  version: 8\na: {unknown: 1, unknown: 2}\n",
		"__metadata:\n  version: 8\na: {version: [1]}\n",
		"__metadata:\n  version: 8\na: {resolution: {b: 1}}\n",
		"__metadata:\n  version: 8\na: {dependencies: text}\n",
		"__metadata:\n  version: 8\na: {dependencies: {b: [1]}}\n",
		"__metadata:\n  version: 8\na: {dependencies: {b: 1, b: 2}}\n",
		"__metadata:\n  version: 8\na: text\n",
		"- __metadata:\n",
	} {
		if _, err := libraryYarn([]byte(document)); err == nil {
			t.Fatalf("the library reads %q", document)
		}
		if _, err := decodeYarnBerry([]byte(document)); err == nil {
			t.Errorf("%q was decoded", document)
		}
	}
}

// The one thing the library read that the parsers refuse: an alias or a merge key where they read. pnpm and yarn
// write neither. Anywhere else in the file they are not looked at.
func TestYAMLLockFilesRefuseAliasesWhereTheyAreRead(t *testing.T) {
	for _, document := range []string{
		"lockfileVersion: '9.0'\nx: &x {a@1: {}}\npackages: *x\n",
		"lockfileVersion: '9.0'\nx: &x {}\npackages:\n  a@1: *x\n",
		"lockfileVersion: '9.0'\nx: &x {type: git}\npackages:\n  a@1: {resolution: *x}\n",
		"lockfileVersion: '9.0'\nx: &x {type: git}\npackages:\n  a@1: {resolution: {<<: *x}}\n",
		"lockfileVersion: '9.0'\nx: &x {b@1: {}}\npackages:\n  <<: *x\n  a@1: {}\n",
		"lockfileVersion: '9.0'\nx: &x 1.0.0\nimporters:\n  .: {dependencies: {a: *x}}\n",
		"lockfileVersion: '9.0'\nx: &x a\npackages:\n  *x : {}\n",
	} {
		if _, err := libraryPNPM([]byte(document)); err != nil {
			t.Fatalf("the library does not read %q: %v", document, err)
		}
		if _, err := decodePNPMLock([]byte(document)); !errors.Is(err, errYAMLAlias) {
			t.Errorf("%q: err = %v, want errYAMLAlias", document, err)
		}
	}
	unread := "lockfileVersion: '9.0'\nsettings: &x {a: 1}\noverrides: {<<: *x, b: *x}\npackages:\n  a@1.0.0: {resolution: {integrity: x}, engines: *x}\n"
	if lock, err := decodePNPMLock([]byte(unread)); err != nil || len(lock.Packages) != 1 {
		t.Errorf("an alias outside what is read: %+v, %v", lock, err)
	}
}

// A file within maxYAMLEntries is handed to the library, one over is not, and what is counted is what separates
// keys, values and collections: a dash or a question mark inside a word is not.
func TestYAMLEntries(t *testing.T) {
	for document, want := range map[string]int{
		"":                           0,
		"a: 1\n":                     2,
		"a: [1, 2]\r\n":              5,
		"? a\n: {b: c}\n":            6,
		"- a\n- b\n-\n":              6,
		"is-positive@3.1.0: x-y\n":   2,
		"sha512-ab/cd+ef==\n":        1,
		"what?\n--- # document\n-":   7,
		"a: -1\nb: ?x\nc: - d\nd: -": 9,
	} {
		if got := yamlEntries([]byte(document)); got != want {
			t.Errorf("yamlEntries(%q) = %d, want %d", document, got, want)
		}
	}
	// Commas in a comment are counted and cost the library nothing.
	document := func(commas int) []byte {
		return []byte("lockfileVersion: '9.0'\npackages:\n  pkg@1.0.0: {}\n# " + strings.Repeat(",", commas) + "\n")
	}
	within := document(maxYAMLEntries - yamlEntries(document(0)))
	if entries := yamlEntries(within); entries != maxYAMLEntries {
		t.Fatalf("entries = %d, want exactly %d", entries, maxYAMLEntries)
	}
	if r, err := ParsePNPMLock(within); err != nil || len(r.Dependencies) != 1 {
		t.Errorf("a file of %d entries: %d dependencies, %v", maxYAMLEntries, len(r.Dependencies), err)
	}
	if _, err := ParsePNPMLock(append(within, ',')); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a file over %d entries: err = %v, want ErrTooLarge", maxYAMLEntries, err)
	}
}

// A lock file is read for maxDependencies entries and, line by line, for maxLines lines: one more of either is not.
func TestDependencyAndLineLimits(t *testing.T) {
	pinned := func(n int) []byte {
		return repeated("", n, func(i int) string { return fmt.Sprintf("p%d==1\n", i) })
	}
	requirements, _ := ForFile("requirements.txt")
	if r, err := requirements.Parse(pinned(maxDependencies)); err != nil || len(r.Dependencies) != maxDependencies {
		t.Errorf("%d pins: %d dependencies, %v", maxDependencies, len(r.Dependencies), err)
	}
	if _, err := requirements.Parse(pinned(maxDependencies + 1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("%d pins: err = %v, want ErrTooLarge", maxDependencies+1, err)
	}
	comments := strings.Repeat("#\n", maxLines-1)
	if r, err := requirements.Parse([]byte(comments + "django==4.2.11\n")); err != nil || len(r.Dependencies) != 1 {
		t.Errorf("%d lines: %d dependencies, %v", maxLines, len(r.Dependencies), err)
	}
	if _, err := requirements.Parse([]byte(comments + "#\ndjango==4.2.11\n")); !errors.Is(err, ErrTooLarge) {
		t.Errorf("%d lines: err = %v, want ErrTooLarge", maxLines+1, err)
	}
}

// The same for JSON, where a string holds anything without being counted.
func TestJSONEntries(t *testing.T) {
	for document, want := range map[string]int{
		``:                               0,
		`{}`:                             1,
		`{"a": [1, 2, {"b": null}]}`:     5,
		`{"a,[{": "[,{\",[{\\", "b": 1}`: 2,
		`["unterminated, [`:              1,
	} {
		if got := jsonEntries([]byte(document)); got != want {
			t.Errorf("jsonEntries(%q) = %d, want %d", document, got, want)
		}
	}
	const pkg = `{"name": "psr/log", "version": "3.0.2", "notification-url": "https://packagist.org/downloads/"}`
	document := func(items int) []byte {
		return []byte(`{"packages": [` + pkg + `], "aliases": [` + strings.Repeat("1,", items) + `1]}`)
	}
	within := document(maxJSONEntries - jsonEntries(document(0)))
	if entries := jsonEntries(within); entries != maxJSONEntries {
		t.Fatalf("entries = %d, want exactly %d", entries, maxJSONEntries)
	}
	if r, err := ParseComposerLock(within); err != nil || len(r.Dependencies) != 1 {
		t.Errorf("a file of %d entries: %d dependencies, %v", maxJSONEntries, len(r.Dependencies), err)
	}
	if _, err := ParseComposerLock(document(maxJSONEntries - jsonEntries(document(0)) + 1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a file over %d entries: err = %v, want ErrTooLarge", maxJSONEntries, err)
	}
}

// The same for TOML: maxTOMLEntries keys, tables, arrays and items are read, one more is not.
func TestTOMLEntries(t *testing.T) {
	const crate = "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
	document := func(items int) []byte {
		return []byte(crate + "\n[metadata]\nitems = [" + strings.Repeat("1,", items) + "1]\n")
	}
	// The crate holds 5 entries, the metadata table 3, and every item of the array one.
	within := document(maxTOMLEntries - 8)
	if r, err := ParseCargoLock(within); err != nil || len(r.Dependencies) != 1 {
		t.Errorf("a file of %d entries: %d dependencies, %v", maxTOMLEntries, len(r.Dependencies), err)
	}
	if _, err := ParseCargoLock(document(maxTOMLEntries - 7)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a file over %d entries: err = %v, want ErrTooLarge", maxTOMLEntries, err)
	}
}
