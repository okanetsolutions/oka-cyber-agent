package lockfile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

var pinnedRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$`)

// ParseRequirements reads requirements.txt. Only exact pins (==, ===) are resolved versions; every other
// requirement line is counted as unresolved.
func ParseRequirements(data []byte) (Result, error) {
	var r Result
	var logical strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if continued, ok := strings.CutSuffix(strings.TrimRight(line, " \t"), `\`); ok {
			logical.WriteString(continued)
			logical.WriteByte(' ')
			continue
		}
		logical.WriteString(line)
		requirement(logical.String(), &r)
		logical.Reset()
	}
	if logical.Len() > 0 {
		requirement(logical.String(), &r)
	}
	return r, scanner.Err()
}

func requirement(line string, r *Result) {
	if i := strings.Index(line, " #"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
		return
	}
	if i := strings.Index(line, ";"); i >= 0 {
		line = line[:i]
	}
	if i := strings.Index(line, " --"); i >= 0 {
		line = line[:i]
	}
	m := pinnedRequirement.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		r.Unresolved++
		return
	}
	r.Dependencies = append(r.Dependencies, Dependency{Name: NormalizePyPIName(m[1]), Version: m[2]})
}

type pythonSource struct {
	Type      string `toml:"type"`
	Registry  string `toml:"registry"`
	Editable  string `toml:"editable"`
	Virtual   string `toml:"virtual"`
	Directory string `toml:"directory"`
	Path      string `toml:"path"`
}

// ParsePoetryLock reads poetry.lock from Poetry 1.x and 2.x. Packages from a local directory or file are the
// project's own code and are left out.
func ParsePoetryLock(data []byte) (Result, error) {
	var lock struct {
		Package []struct {
			Name    string       `toml:"name"`
			Version string       `toml:"version"`
			Source  pythonSource `toml:"source"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	var r Result
	for _, p := range lock.Package {
		if p.Source.Type == "directory" || p.Source.Type == "file" {
			continue
		}
		if p.Name == "" || !looksLikeVersion(p.Version) {
			r.Unresolved++
			continue
		}
		r.Dependencies = append(r.Dependencies, Dependency{Name: NormalizePyPIName(p.Name), Version: p.Version})
	}
	return r, nil
}

func ParsePipfileLock(data []byte) (Result, error) {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	var r Result
	for _, section := range []map[string]struct {
		Version string `json:"version"`
	}{lock.Default, lock.Develop} {
		for _, name := range sortedKeys(section) {
			version, pinned := strings.CutPrefix(section[name].Version, "==")
			if !pinned || !looksLikeVersion(version) {
				r.Unresolved++
				continue
			}
			r.Dependencies = append(r.Dependencies, Dependency{Name: NormalizePyPIName(name), Version: version})
		}
	}
	return r, nil
}

// ParseUVLock reads uv.lock. The project itself (an editable or virtual source) is left out, and its
// dependencies and dependency groups are the direct ones.
func ParseUVLock(data []byte) (Result, error) {
	type reference struct {
		Name string `toml:"name"`
	}
	var lock struct {
		Package []struct {
			Name                 string                 `toml:"name"`
			Version              string                 `toml:"version"`
			Source               pythonSource           `toml:"source"`
			Dependencies         []reference            `toml:"dependencies"`
			DevDependencies      map[string][]reference `toml:"dev-dependencies"`
			OptionalDependencies map[string][]reference `toml:"optional-dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	declared := map[string]bool{}
	hasProject := false
	for _, p := range lock.Package {
		if p.Source.Editable == "" && p.Source.Virtual == "" {
			continue
		}
		hasProject = true
		refs := p.Dependencies
		for _, group := range p.DevDependencies {
			refs = append(refs, group...)
		}
		for _, group := range p.OptionalDependencies {
			refs = append(refs, group...)
		}
		for _, ref := range refs {
			declared[NormalizePyPIName(ref.Name)] = true
		}
	}
	var r Result
	for _, p := range lock.Package {
		if p.Source.Editable != "" || p.Source.Virtual != "" || p.Source.Directory != "" || p.Source.Path != "" {
			continue
		}
		if p.Name == "" || !looksLikeVersion(p.Version) {
			r.Unresolved++
			continue
		}
		name := NormalizePyPIName(p.Name)
		dep := Dependency{Name: name, Version: p.Version}
		if hasProject {
			dep.Direct = direct(declared[name])
		}
		r.Dependencies = append(r.Dependencies, dep)
	}
	return r, nil
}
