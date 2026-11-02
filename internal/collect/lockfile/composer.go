package lockfile

import (
	"encoding/json"
	"strings"
)

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Type string `json:"type"`
	} `json:"dist"`
	NotificationURL string `json:"notification-url"`
}

// fromRepository tells whether composer took the package from a Composer repository (Packagist or a private
// mirror of it). Composer writes a notification-url only for those, and gives every package a git source, so the
// source type tells nothing. Path, VCS, inline package and artifact repositories have no notification-url, and
// their version is whatever the repository declares, not a registry release.
func (p composerPackage) fromRepository() bool {
	return p.NotificationURL != "" && p.Dist.Type != "path"
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
		if p.Name == "" || version == "" || strings.HasPrefix(version, "dev-") || strings.HasSuffix(version, "-dev") || !p.fromRepository() {
			r.Unresolved++
			continue
		}
		r.Dependencies = append(r.Dependencies, Dependency{Name: p.Name, Version: version})
	}
	return r, nil
}
