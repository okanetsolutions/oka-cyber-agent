package lockfile

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ParseYarnLock reads yarn.lock in both the classic (v1) format and the YAML based berry format (v2+).
func ParseYarnLock(data []byte) (Result, error) {
	if bytes.Contains(data, []byte("\n__metadata:")) || bytes.HasPrefix(data, []byte("__metadata:")) {
		return parseYarnBerry(data)
	}
	return parseYarnClassic(data)
}

func parseYarnClassic(data []byte) (Result, error) {
	var r Result
	var name string
	var skip bool
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line[0] != ' ' && strings.HasSuffix(line, ":") {
			name, skip = yarnClassicHeader(strings.TrimSuffix(line, ":"))
			continue
		}
		version, ok := strings.CutPrefix(line, "  version ")
		if !ok || name == "" {
			continue
		}
		if unquoted, err := strconv.Unquote(version); err == nil {
			version = unquoted
		}
		switch {
		case skip:
		case looksLikeVersion(version):
			r.Dependencies = append(r.Dependencies, Dependency{Name: name, Version: version})
		default:
			r.Unresolved++
		}
		name = ""
	}
	return r, scanner.Err()
}

// yarnClassicHeader returns the package name of an entry header such as
// `"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4"`, and whether the entry is local (file, link,
// workspace) rather than from the registry.
func yarnClassicHeader(header string) (string, bool) {
	first, _, _ := strings.Cut(header, ",")
	first = strings.Trim(strings.TrimSpace(first), `"`)
	at := strings.LastIndex(first, "@")
	if at <= 0 {
		return "", true
	}
	name, spec := first[:at], first[at+1:]
	if real, ok := strings.CutPrefix(spec, "npm:"); ok {
		if i := strings.LastIndex(real, "@"); i > 0 {
			name = real[:i]
		}
	}
	for _, local := range []string{"file:", "link:", "workspace:", "portal:", "patch:", "git", "http:", "https:", "github:"} {
		if strings.HasPrefix(spec, local) {
			return name, true
		}
	}
	return name, false
}

func parseYarnBerry(data []byte) (Result, error) {
	var entries map[string]struct {
		Version    string `yaml:"version"`
		Resolution string `yaml:"resolution"`
	}
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return Result{}, err
	}
	var r Result
	for _, key := range sortedKeys(entries) {
		if key == "__metadata" {
			continue
		}
		resolution := entries[key].Resolution
		i := strings.LastIndex(resolution, "@npm:")
		if i <= 0 {
			continue
		}
		name, version := resolution[:i], resolution[i+len("@npm:"):]
		if !looksLikeVersion(version) {
			r.Unresolved++
			continue
		}
		r.Dependencies = append(r.Dependencies, Dependency{Name: name, Version: version})
	}
	return r, nil
}
