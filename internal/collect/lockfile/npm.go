package lockfile

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
)

type npmPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
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
// paths under "packages"; version 1 nests "dependencies". Hoisted (top level) entries come first, so they win
// when one name is installed in several versions.
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
	for _, path := range paths {
		p := packages[path]
		i := strings.LastIndex(path, "node_modules/")
		if p.Link || i < 0 {
			continue
		}
		installedAs := path[i+len("node_modules/"):]
		name := cmp.Or(p.Name, installedAs)
		if !looksLikeVersion(p.Version) {
			r.Unresolved++
			continue
		}
		topLevel := i == 0
		r.Dependencies = append(r.Dependencies, Dependency{Name: name, Version: p.Version, Direct: direct(topLevel && declared[installedAs])})
	}
	return r
}

func npmV1(dependencies map[string]npmV1Dependency) Result {
	var r Result
	level := dependencies
	for len(level) > 0 {
		next := map[string]npmV1Dependency{}
		for _, name := range sortedKeys(level) {
			d := level[name]
			if looksLikeVersion(d.Version) {
				r.Dependencies = append(r.Dependencies, Dependency{Name: name, Version: d.Version})
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
