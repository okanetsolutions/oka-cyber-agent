package lockfile

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
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
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = singleByteCharsetReader
	if err := decoder.Decode(&pom); err != nil {
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

// singleByteCharsetReader decodes the encodings older pom.xml files declare besides UTF-8, which encoding/xml reads by
// itself. As the WHATWG Encoding Standard (and so every browser) does, ISO-8859-1 and US-ASCII are read as
// windows-1252, which agrees with both on every printable character.
func singleByteCharsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "windows-1252", "cp1252", "x-cp1252",
		"iso-8859-1", "iso8859-1", "iso_8859-1", "iso88591", "latin1", "latin-1", "l1", "cp819", "ibm819",
		"us-ascii", "ascii", "iso646-us":
	default:
		return nil, fmt.Errorf("unsupported encoding %q", label)
	}
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	decoded := make([]byte, 0, len(data))
	for _, b := range data {
		r := rune(b)
		if b >= 0x80 && b < 0xa0 {
			r = windows1252[b-0x80]
		}
		decoded = utf8.AppendRune(decoded, r)
	}
	return bytes.NewReader(decoded), nil
}

// windows1252 maps 0x80 to 0x9f; the five bytes it leaves undefined map to the same code point, as in WHATWG.
var windows1252 = [32]rune{
	'\u20ac', '\u0081', '\u201a', '\u0192', '\u201e', '\u2026', '\u2020', '\u2021',
	'\u02c6', '\u2030', '\u0160', '\u2039', '\u0152', '\u008d', '\u017d', '\u008f',
	'\u0090', '\u2018', '\u2019', '\u201c', '\u201d', '\u2022', '\u2013', '\u2014',
	'\u02dc', '\u2122', '\u0161', '\u203a', '\u0153', '\u009d', '\u017e', '\u0178',
}
