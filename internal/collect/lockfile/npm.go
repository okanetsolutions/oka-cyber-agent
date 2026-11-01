package lockfile

import (
	"cmp"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

type npmPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	InBundle             bool              `json:"inBundle"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmV1Dependency struct {
	Version      string                     `json:"version"`
	Dependencies map[string]npmV1Dependency `json:"dependencies"`
}

// ParseNPMLock reads package-lock.json and npm-shrinkwrap.json. Lockfile versions 2 and 3 list installed
// paths under "packages"; version 1 nests "dependencies". When one name is installed in several versions, the
// hoisted (top level) one is kept, and among copies equally deep the highest version.
func ParseNPMLock(data []byte) (Result, error) {
	var lock struct {
		Packages     map[string]npmPackage      `json:"packages"`
		Dependencies map[string]npmV1Dependency `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	if len(lock.Packages) > 0 {
		return npmPackages(lock.Packages), nil
	}
	return npmV1(lock.Dependencies), nil
}

func npmPackages(packages map[string]npmPackage) Result {
	root := packages[""]
	declared := map[string]bool{}
	for _, deps := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies} {
		for name := range deps {
			declared[name] = true
		}
	}
	paths := make([]string, 0, len(packages))
	for path := range packages {
		if path != "" {
			paths = append(paths, path)
		}
	}
	slices.SortFunc(paths, func(a, b string) int {
		return cmp.Or(cmp.Compare(strings.Count(a, "node_modules/"), strings.Count(b, "node_modules/")), cmp.Compare(a, b))
	})
	var r Result
	var candidates []candidate
	for _, path := range paths {
		p := packages[path]
		i := strings.LastIndex(path, "node_modules/")
		if p.Link || i < 0 {
			continue
		}
		installedAs := path[i+len("node_modules/"):]
		name := cmp.Or(p.Name, installedAs)
		if !looksLikeVersion(p.Version) || !npmFromRegistry(p, name) {
			r.Unresolved++
			continue
		}
		isDirect := i == 0 && declared[installedAs]
		rank := strings.Count(path, "node_modules/")
		if isDirect {
			rank = 0
		}
		candidates = append(candidates, candidate{Dependency{Name: name, Version: p.Version, Direct: direct(isDirect)}, rank})
	}
	r.Dependencies = onePerName(candidates)
	return r
}

// npmFromRegistry tells registry releases from packages installed from git, a tarball URL or a file, whose
// version field is only what their package.json says. npm records a registry release with a resolved URL in the
// layout every npm registry serves, <registry>/<name>/-/<file>.tgz, or with no resolved URL at all when
// omit-lockfile-registry-resolved is set (it keeps the integrity) or when the package is bundled inside its parent.
func npmFromRegistry(p npmPackage, name string) bool {
	if p.Resolved == "" {
		return p.Integrity != "" || p.InBundle
	}
	u, err := url.Parse(p.Resolved)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	return strings.Contains(u.Path, "/"+name+"/-/") && strings.HasSuffix(u.Path, ".tgz")
}

func npmV1(dependencies map[string]npmV1Dependency) Result {
	var r Result
	var candidates []candidate
	level := dependencies
	for depth := 0; len(level) > 0; depth++ {
		next := map[string]npmV1Dependency{}
		for _, name := range sortedKeys(level) {
			d := level[name]
			if looksLikeVersion(d.Version) {
				candidates = append(candidates, candidate{Dependency{Name: name, Version: d.Version}, depth})
			} else {
				r.Unresolved++
			}
			for child, dep := range d.Dependencies {
				if _, seen := next[child]; !seen {
					next[child] = dep
				}
			}
		}
		level = next
	}
	r.Dependencies = onePerName(candidates)
	return r
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
