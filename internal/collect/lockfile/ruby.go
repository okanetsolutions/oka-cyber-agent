package lockfile

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

var (
	gemSpec     = regexp.MustCompile(`^    ([^ ()]+) \(([^)]+)\)$`)
	gemPlatform = regexp.MustCompile(`-(x86|x64|i386|i686|arm|aarch64|java|jruby|mingw|mswin|darwin|linux|universal|freebsd|solaris).*$`)
)

// ParseGemfileLock reads the specs of the GEM sections of Gemfile.lock, whatever their remote (rubygems.org or a
// private gem server). Gems from GIT and PATH sections are not registry releases and are counted as unresolved. A
// platform suffix (1.16.4-x86_64-linux) is removed.
func ParseGemfileLock(data []byte) (Result, error) {
	var r Result
	var section string
	declared := map[string]bool{}
	var specs []Dependency
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' {
			section = strings.TrimSpace(line)
			continue
		}
		switch section {
		case "GEM":
			if m := gemSpec.FindStringSubmatch(line); m != nil {
				specs = append(specs, Dependency{Name: m[1], Version: gemPlatform.ReplaceAllString(m[2], "")})
			}
		case "GIT", "PATH":
			if gemSpec.MatchString(line) {
				r.Unresolved++
			}
		case "DEPENDENCIES":
			name, _, _ := strings.Cut(strings.TrimSpace(line), " ")
			declared[strings.TrimSuffix(name, "!")] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return r, err
	}
	for _, s := range specs {
		if !looksLikeVersion(s.Version) {
			r.Unresolved++
			continue
		}
		s.Direct = direct(declared[s.Name])
		r.Dependencies = append(r.Dependencies, s)
	}
	return r, nil
}
