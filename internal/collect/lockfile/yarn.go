package lockfile

import (
	"bufio"
	"bytes"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ParseYarnLock reads yarn.lock in both the classic (v1) format and the YAML based berry format (v2+). The file
// does not say which entries are direct, so when a name is locked in several versions it keeps the entry the
// project's own package.json asks for, as far as the lock file shows it, and otherwise the highest version.
func ParseYarnLock(data []byte) (Result, error) {
	if bytes.Contains(data, []byte("\n__metadata:")) || bytes.HasPrefix(data, []byte("__metadata:")) {
		return parseYarnBerry(data)
	}
	return parseYarnClassic(data)
}

type yarnClassicEntry struct {
	name, version string
	skip          bool
	descriptors   []string
}

// parseYarnClassic ranks first an entry with a descriptor (name@range) no other entry depends on: only a
// package.json can ask for it. When the project's range is also one a dependency uses, yarn merges both into
// one descriptor and the lock file cannot tell, so the highest version is kept.
func parseYarnClassic(data []byte) (Result, error) {
	var r Result
	var entries []yarnClassicEntry
	dependedOn := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line[0] != ' ' && strings.HasSuffix(line, ":") {
			header := strings.TrimSuffix(line, ":")
			name, skip := yarnClassicHeader(header)
			entries = append(entries, yarnClassicEntry{name: name, skip: skip, descriptors: yarnClassicDescriptors(header)})
			continue
		}
		if strings.HasPrefix(line, "    ") {
			if name, spec, ok := yarnClassicDependency(trimmed); ok {
				dependedOn[name+"@"+spec] = true
			}
			continue
		}
		version, ok := strings.CutPrefix(line, "  version ")
		if !ok || len(entries) == 0 {
			continue
		}
		if unquoted, err := strconv.Unquote(version); err == nil {
			version = unquoted
		}
		entries[len(entries)-1].version = version
	}
	if err := scanner.Err(); err != nil {
		return r, err
	}
	var candidates []candidate
	for _, e := range entries {
		switch {
		case e.name == "" || e.version == "" || e.skip:
		case looksLikeVersion(e.version):
			rank := 1
			if slices.ContainsFunc(e.descriptors, func(d string) bool { return !dependedOn[d] }) {
				rank = 0
			}
			candidates = append(candidates, candidate{Dependency{Name: e.name, Version: e.version}, rank})
		default:
			r.Unresolved++
		}
	}
	r.Dependencies = onePerName(candidates)
	return r, nil
}

func yarnClassicDescriptors(header string) []string {
	var descriptors []string
	for d := range strings.SplitSeq(header, ",") {
		descriptors = append(descriptors, strings.Trim(strings.TrimSpace(d), `"`))
	}
	return descriptors
}

// yarnClassicDependency reads a dependency line such as `"@babel/highlight" "^7.24.2"` or `ms 2.0.0`.
func yarnClassicDependency(line string) (string, string, bool) {
	var name, spec string
	var ok bool
	if rest, quoted := strings.CutPrefix(line, `"`); quoted {
		name, spec, ok = strings.Cut(rest, `" `)
	} else {
		name, spec, ok = strings.Cut(line, " ")
	}
	if unquoted, err := strconv.Unquote(spec); err == nil {
		spec = unquoted
	}
	return name, spec, ok
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

// parseYarnBerry ranks first the entries a workspace (the project or one of its packages) depends on.
func parseYarnBerry(data []byte) (Result, error) {
	var entries map[string]struct {
		Version      string            `yaml:"version"`
		Resolution   string            `yaml:"resolution"`
		Dependencies map[string]string `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return Result{}, err
	}
	fromWorkspace := map[string]bool{}
	for _, e := range entries {
		if !strings.Contains(e.Resolution, "@workspace:") {
			continue
		}
		for name, spec := range e.Dependencies {
			// Lock files before yarn 4 leave out the default npm: protocol.
			fromWorkspace[name+"@"+spec] = true
			fromWorkspace[name+"@npm:"+spec] = true
		}
	}
	var r Result
	var candidates []candidate
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
		rank := 1
		for descriptor := range strings.SplitSeq(key, ",") {
			if fromWorkspace[strings.TrimSpace(descriptor)] {
				rank = 0
			}
		}
		candidates = append(candidates, candidate{Dependency{Name: name, Version: version}, rank})
	}
	r.Dependencies = onePerName(candidates)
	return r, nil
}
