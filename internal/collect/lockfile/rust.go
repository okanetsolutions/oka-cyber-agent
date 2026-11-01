package lockfile

import (
	"strings"

	"github.com/BurntSushi/toml"
)

// ParseCargoLock reads Cargo.lock. Only crates from crates.io are reported; workspace members have no source
// and their dependencies are the direct ones. A dependency is written "name" when the lock holds one version
// of that crate and "name version" when it holds several, so when a crate is locked in several versions the one
// a workspace member depends on is the direct one, which Format.Parse keeps.
func ParseCargoLock(data []byte) (Result, error) {
	var lock struct {
		Package []struct {
			Name         string   `toml:"name"`
			Version      string   `toml:"version"`
			Source       string   `toml:"source"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	declared := map[string]bool{}
	for _, p := range lock.Package {
		if p.Source != "" {
			continue
		}
		for _, dep := range p.Dependencies {
			name, version, versioned := strings.Cut(dep, " ")
			if !versioned {
				declared[name] = true
				continue
			}
			version, _, _ = strings.Cut(version, " ")
			declared[name+" "+version] = true
		}
	}
	var r Result
	for _, p := range lock.Package {
		if !strings.HasPrefix(p.Source, "registry+https://github.com/rust-lang/crates.io-index") && !strings.HasPrefix(p.Source, "sparse+https://index.crates.io/") {
			continue
		}
		if p.Name == "" || !looksLikeVersion(p.Version) {
			r.Unresolved++
			continue
		}
		isDirect := declared[p.Name+" "+p.Version] || declared[p.Name]
		r.Dependencies = append(r.Dependencies, Dependency{Name: p.Name, Version: p.Version, Direct: direct(isDirect)})
	}
	return r, nil
}
