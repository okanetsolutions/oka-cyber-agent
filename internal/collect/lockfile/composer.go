package lockfile

import (
	"encoding/json"
	"strings"
)

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func ParseComposerLock(data []byte) (Result, error) {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	var r Result
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		version := p.Version
		if len(version) > 1 && (version[0] == 'v' || version[0] == 'V') && version[1] >= '0' && version[1] <= '9' {
			version = version[1:]
		}
		if p.Name == "" || version == "" || strings.HasPrefix(version, "dev-") || strings.HasSuffix(version, "-dev") {
			r.Unresolved++
			continue
		}
		r.Dependencies = append(r.Dependencies, Dependency{Name: p.Name, Version: version})
	}
	return r, nil
}
