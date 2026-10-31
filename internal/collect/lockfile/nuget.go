package lockfile

import "encoding/json"

// ParseNuGetLock reads packages.lock.json. Project references are the solution's own code and are left out.
func ParseNuGetLock(data []byte) (Result, error) {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	var r Result
	for _, framework := range sortedKeys(lock.Dependencies) {
		packages := lock.Dependencies[framework]
		for _, name := range sortedKeys(packages) {
			p := packages[name]
			if p.Type == "Project" {
				continue
			}
			if !looksLikeVersion(p.Resolved) {
				r.Unresolved++
				continue
			}
			r.Dependencies = append(r.Dependencies, Dependency{Name: name, Version: p.Resolved, Direct: direct(p.Type == "Direct")})
		}
	}
	return r, nil
}
