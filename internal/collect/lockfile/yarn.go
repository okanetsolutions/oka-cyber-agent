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
// `"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4"`, and whether the entry comes from somewhere
// other than the registry (file, link, workspace, git, a URL), whose version is not a registry release.
// An npm alias (`string-width-cjs@npm:string-width@^4.2.0`) is reported under the real package name.
func yarnClassicHeader(header string) (string, bool) {
	first, _, _ := strings.Cut(header, ",")
	name, spec, ok := yarnDescriptor(strings.Trim(strings.TrimSpace(first), `"`))
	if !ok {
		return "", true
	}
	if target, alias := strings.CutPrefix(spec, "npm:"); alias {
		if name, spec, ok = yarnDescriptor(target); !ok {
			if name, spec = target, ""; !validYarnName(name) {
				return "", true
			}
		}
	}
	return name, strings.ContainsAny(spec, ":/") || strings.HasPrefix(spec, ".")
}

// yarnDescriptor splits name@spec at the first @ after the name, which for a scoped package (@scope/name)
// is the second one: the spec itself may contain @ (an alias target, a URL to a scoped tarball).
func yarnDescriptor(descriptor string) (string, string, bool) {
	at := strings.Index(descriptor[min(1, len(descriptor)):], "@") + 1
	if at <= 0 || !validYarnName(descriptor[:at]) {
		return "", "", false
	}
	return descriptor[:at], descriptor[at+1:], true
}

func validYarnName(name string) bool {
	scope, rest, scoped := strings.Cut(name, "/")
	if scoped {
		return len(scope) > 1 && scope[0] == '@' && rest != "" && !strings.ContainsAny(rest, "/@")
	}
	return name != "" && !strings.ContainsAny(name, "@:")
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
