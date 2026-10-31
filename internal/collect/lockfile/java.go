package lockfile

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"strings"
)

// ParseGradleLockfile reads gradle.lockfile lines of the form group:artifact:version=configurations.
func ParseGradleLockfile(data []byte) (Result, error) {
	var r Result
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coordinates, _, _ := strings.Cut(line, "=")
		parts := strings.Split(coordinates, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || !looksLikeVersion(parts[2]) {
			r.Unresolved++
			continue
		}
		r.Dependencies = append(r.Dependencies, Dependency{Name: parts[0] + ":" + parts[1], Version: parts[2]})
	}
	return r, scanner.Err()
}

// ParsePOM reads the dependencies a pom.xml declares with a literal version. Versions from properties
// (${...}), ranges or a parent's dependencyManagement are not resolved here and count as unresolved.
func ParsePOM(data []byte) (Result, error) {
	var pom struct {
		Dependencies []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		} `xml:"dependencies>dependency"`
	}
	if err := xml.Unmarshal(data, &pom); err != nil {
		return Result{}, err
	}
	var r Result
	for _, d := range pom.Dependencies {
		group, artifact, version := strings.TrimSpace(d.GroupID), strings.TrimSpace(d.ArtifactID), strings.TrimSpace(d.Version)
		if group == "" || artifact == "" || strings.Contains(group+artifact, "${") || strings.Contains(version, "${") || !looksLikeVersion(version) || strings.ContainsAny(version, "[](),") {
			r.Unresolved++
			continue
		}
		r.Dependencies = append(r.Dependencies, Dependency{Name: group + ":" + artifact, Version: version, Direct: direct(true)})
	}
	return r, nil
}
