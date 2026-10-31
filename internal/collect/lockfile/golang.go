package lockfile

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

type goModule struct {
	path, version string
	indirect      bool
}

// ParseGoMod reads the require and replace directives of go.mod (Go 1.17 and later list every module the
// build uses there). Versions drop the leading "v", as in OSV.dev's Go ecosystem.
func ParseGoMod(data []byte) (Result, error) {
	var requires []goModule
	replacements := map[string]goModule{}
	var block string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line, comment, _ := strings.Cut(scanner.Text(), "//")
		fields := strings.Fields(line)
		indirect := strings.TrimSpace(comment) == "indirect" || strings.HasPrefix(strings.TrimSpace(comment), "indirect;")
		if len(fields) == 0 {
			continue
		}
		if block != "" {
			if fields[0] == ")" {
				block = ""
				continue
			}
			goDirective(block, fields, indirect, &requires, replacements)
			continue
		}
		if len(fields) == 2 && fields[1] == "(" {
			block = fields[0]
			continue
		}
		goDirective(fields[0], fields[1:], indirect, &requires, replacements)
	}
	if err := scanner.Err(); err != nil {
		return Result{}, err
	}
	var r Result
	for _, m := range requires {
		if replacement, ok := replacements[m.path+"@"+m.version]; ok {
			m.path, m.version = replacement.path, replacement.version
		} else if replacement, ok := replacements[m.path]; ok {
			m.path, m.version = replacement.path, replacement.version
		}
		version := strings.TrimPrefix(m.version, "v")
		if m.path == "" || !looksLikeVersion(version) {
			r.Unresolved++
			continue
		}
		r.Dependencies = append(r.Dependencies, Dependency{Name: m.path, Version: version, Direct: direct(!m.indirect)})
	}
	return r, nil
}

func goDirective(verb string, args []string, indirect bool, requires *[]goModule, replacements map[string]goModule) {
	for i := range args {
		if unquoted, err := strconv.Unquote(args[i]); err == nil {
			args[i] = unquoted
		}
	}
	switch verb {
	case "require":
		if len(args) >= 2 {
			*requires = append(*requires, goModule{path: args[0], version: args[1], indirect: indirect})
		}
	case "replace":
		arrow := -1
		for i, a := range args {
			if a == "=>" {
				arrow = i
			}
		}
		if arrow < 1 || len(args) < arrow+2 {
			return
		}
		from := args[0]
		if arrow == 2 {
			from += "@" + args[1]
		}
		to := goModule{path: args[arrow+1]}
		if len(args) > arrow+2 {
			to.version = args[arrow+2]
		}
		replacements[from] = to
	}
}
