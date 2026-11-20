package collect

import (
	"bufio"
	"cmp"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/okanetsolutions/oka-cyber-agent/internal/safeopen"
)

const aptListsPath = "/var/lib/apt/lists"

type aptPackage struct {
	name, version, architecture string
}

func setAPTOrigins(ctx context.Context, root string, packages []Package) {
	if len(packages) == 0 || ctx.Err() != nil {
		return
	}
	dir, err := os.Open(filepath.Join(root, aptListsPath))
	if err != nil {
		return
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return
	}
	// Sort to prefer InRelease over Release and keep ties between repositories deterministic.
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return cmp.Compare(a.Name(), b.Name()) })
	origins := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		prefix, signed := strings.CutSuffix(name, "_InRelease")
		if !signed {
			prefix = strings.TrimSuffix(name, "_Release")
		}
		if prefix == name || !strings.Contains(prefix, "_dists_") {
			continue
		}
		if _, seen := origins[prefix]; !seen {
			origins[prefix] = readAPTOrigin(dir, name)
		}
	}

	installed := make(map[string]bool, len(packages))
	for _, p := range packages {
		installed[p.Name] = true
	}
	// A list without release metadata can still provide an exact match and prevent a version fallback.
	exact := map[aptPackage]string{}
	type offer struct{ version, origin string }
	highest := map[string]offer{}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, "_Packages") {
			continue
		}
		origin := aptListOrigin(name, origins)
		for _, p := range readAPTPackages(dir, name, installed) {
			if exact[p] == "" {
				exact[p] = origin
			}
			best := highest[p.name]
			order := compareDebianVersions(p.version, best.version)
			if best.version == "" || order > 0 || (order == 0 && best.origin == "") {
				highest[p.name] = offer{p.version, origin}
			}
		}
	}
	for i, p := range packages {
		origin, found := exact[aptPackage{p.Name, p.Version, p.Architecture}]
		if !found {
			origin = highest[p.Name].origin
		}
		packages[i].Origin = origin
	}
}

func aptListOrigin(name string, origins map[string]string) string {
	// APT flattens URL paths with underscores. Find the longest release prefix shared by the list.
	for end := strings.LastIndexByte(name, '_'); end >= 0; end = strings.LastIndexByte(name, '_') {
		name = name[:end]
		if origin, found := origins[name]; found {
			return origin
		}
	}
	return ""
}

func openAPTFile(dir *os.File, name string) *os.File {
	f, err := safeopen.OpenAt(dir, name, os.O_RDONLY)
	if err != nil {
		return nil
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil
	}
	return f
}

func readAPTOrigin(dir *os.File, name string) string {
	f := openAPTFile(dir, name)
	if f == nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f) // ScanLines also strips CR from CRLF InRelease files.
	if !scanner.Scan() {
		return ""
	}
	if scanner.Text() == "-----BEGIN PGP SIGNED MESSAGE-----" {
		for scanner.Scan() && scanner.Text() != "" {
		}
		if !scanner.Scan() {
			return ""
		}
	}
	for line := scanner.Text(); line != "" && line != "-----BEGIN PGP SIGNATURE-----"; line = scanner.Text() {
		if value, found := strings.CutPrefix(line, "Origin:"); found {
			origin := strings.TrimSpace(value)
			if utf8.ValidString(origin) && utf8.RuneCountInString(origin) <= 255 &&
				strings.IndexFunc(origin, func(r rune) bool { return r < 0x20 || r == 0x7f }) == -1 {
				return origin
			}
			return ""
		}
		if !scanner.Scan() {
			break
		}
	}
	return ""
}

func readAPTPackages(dir *os.File, name string, installed map[string]bool) []aptPackage {
	f := openAPTFile(dir, name)
	if f == nil {
		return nil
	}
	defer f.Close()

	var packages []aptPackage
	err := readStanzas(f, ":", keepKeys("Package", "Version", "Architecture"), func(s map[string]string) {
		p := aptPackage{s["Package"], s["Version"], s["Architecture"]}
		if installed[p.name] && p.version != "" && p.architecture != "" {
			packages = append(packages, p)
		}
	})
	if err != nil {
		return nil
	}
	return packages
}

// Debian versions compare epoch, upstream version, then revision (deb-version(7)).
func compareDebianVersions(a, b string) int {
	epochA, upstreamA, revisionA := splitDebianVersion(a)
	epochB, upstreamB, revisionB := splitDebianVersion(b)
	if order := compareDebianVersionParts(epochA, epochB); order != 0 {
		return order
	}
	if order := compareDebianVersionParts(upstreamA, upstreamB); order != 0 {
		return order
	}
	return compareDebianVersionParts(revisionA, revisionB)
}

func splitDebianVersion(version string) (epoch, upstream, revision string) {
	epoch, upstream, found := strings.Cut(version, ":")
	if !found {
		epoch, upstream = "", version
	}
	if i := strings.LastIndexByte(upstream, '-'); i >= 0 {
		upstream, revision = upstream[:i], upstream[i+1:]
	}
	return epoch, upstream, revision
}

func compareDebianVersionParts(a, b string) int {
	for a != "" || b != "" {
		for {
			orderA, orderB := debianNonDigitOrder(a), debianNonDigitOrder(b)
			if order := cmp.Compare(orderA, orderB); order != 0 {
				return order
			}
			if orderA == 0 {
				break
			}
			a, b = a[1:], b[1:]
		}
		digitsA, restA := cutDebianDigits(a)
		digitsB, restB := cutDebianDigits(b)
		if order := cmp.Or(cmp.Compare(len(digitsA), len(digitsB)), strings.Compare(digitsA, digitsB)); order != 0 {
			return order
		}
		a, b = restA, restB
	}
	return 0
}

func debianNonDigitOrder(part string) int {
	if part == "" || (part[0] >= '0' && part[0] <= '9') {
		return 0
	}
	c := part[0]
	switch {
	case c == '~':
		return -1
	case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		return int(c)
	default:
		return int(c) + 256
	}
}

func cutDebianDigits(part string) (digits, rest string) {
	i := 0
	for i < len(part) && part[i] >= '0' && part[i] <= '9' {
		i++
	}
	return strings.TrimLeft(part[:i], "0"), part[i:]
}
