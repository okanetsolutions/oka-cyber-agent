package lockfile

import (
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// pnpmReference is a dependency reference in pnpm-lock.yaml: a plain version string in lockfile 5.x and a
// {specifier, version} mapping from 6.0 on.
type pnpmReference string

func pnpmReferenceOf(n *yaml.Node) (pnpmReference, error) {
	if n.Kind == yaml.ScalarNode {
		if n.ShortTag() == yamlNullTag {
			return "", nil
		}
		return pnpmReference(n.Value), nil
	}
	var version string
	err := yamlPairs(n, func(key string, value *yaml.Node) (err error) {
		if key == "version" {
			version, err = yamlString(value)
		}
		return err
	})
	return pnpmReference(version), err
}

type pnpmDependencies struct {
	Dependencies         map[string]pnpmReference
	DevDependencies      map[string]pnpmReference
	OptionalDependencies map[string]pnpmReference
}

// field reads the key of the root project or of an importer when it is one of its three dependency mappings.
func (d *pnpmDependencies) field(key string, value *yaml.Node) (err error) {
	switch key {
	case "dependencies":
		d.Dependencies, err = yamlMap(value, pnpmReferenceOf)
	case "devDependencies":
		d.DevDependencies, err = yamlMap(value, pnpmReferenceOf)
	case "optionalDependencies":
		d.OptionalDependencies, err = yamlMap(value, pnpmReferenceOf)
	}
	return err
}

type pnpmResolution struct {
	Type, Repo, Commit string
}

type pnpmLock struct {
	LockfileVersion string
	Importers       map[string]pnpmDependencies
	Packages        map[string]pnpmResolution
	pnpmDependencies
}

func decodePNPMLock(data []byte) (lock pnpmLock, err error) {
	root, err := parseYAML(data)
	if err != nil {
		return lock, err
	}
	err = yamlPairs(root, func(key string, value *yaml.Node) (err error) {
		switch key {
		case "lockfileVersion":
			lock.LockfileVersion, err = yamlString(value)
		case "importers":
			lock.Importers, err = yamlMap(value, pnpmImporter)
		case "packages":
			lock.Packages, err = yamlMap(value, pnpmPackage)
		default:
			err = lock.field(key, value)
		}
		return err
	})
	return lock, err
}

func pnpmImporter(n *yaml.Node) (importer pnpmDependencies, err error) {
	return importer, yamlPairs(n, importer.field)
}

func pnpmPackage(n *yaml.Node) (resolution pnpmResolution, err error) {
	err = yamlPairs(n, func(key string, value *yaml.Node) error {
		if key != "resolution" {
			return nil
		}
		return yamlPairs(value, func(key string, value *yaml.Node) (err error) {
			switch key {
			case "type":
				resolution.Type, err = yamlString(value)
			case "repo":
				resolution.Repo, err = yamlString(value)
			case "commit":
				resolution.Commit, err = yamlString(value)
			}
			return err
		})
	})
	return resolution, err
}

// ParsePNPMLock reads pnpm-lock.yaml lockfile versions 5.x, 6.x and 9.x. Direct dependencies are the ones
// listed by the root project or a workspace importer, which Format.Parse keeps when a name is locked in
// several versions.
func ParsePNPMLock(data []byte) (Result, error) {
	lock, err := decodePNPMLock(data)
	if err != nil {
		return Result{}, err
	}
	major, err := strconv.ParseFloat(strings.Trim(lock.LockfileVersion, `'"`), 64)
	if err != nil {
		return Result{}, fmt.Errorf("lockfileVersion %q: %w", lock.LockfileVersion, err)
	}

	declared := map[string]bool{}
	for _, importer := range append([]pnpmDependencies{lock.pnpmDependencies}, mapValues(lock.Importers)...) {
		for _, deps := range []map[string]pnpmReference{importer.Dependencies, importer.DevDependencies, importer.OptionalDependencies} {
			for name, ref := range deps {
				version := pnpmVersion(string(ref), major < 6)
				if !looksLikeVersion(version) {
					// An alias refers to the package by its key: /string-width/4.2.3, /string-width@4.2.3 or
					// string-width@4.2.3.
					name, version = pnpmPackageKey(string(ref), major)
				}
				declared[name+"@"+version] = true
			}
		}
	}

	var r Result
	for _, key := range sortedKeys(lock.Packages) {
		name, version := pnpmPackageKey(key, major)
		resolution := lock.Packages[key]
		if name == "" || !looksLikeVersion(version) || resolution.Type != "" || resolution.Repo != "" || resolution.Commit != "" {
			r.Unresolved++
			continue
		}
		r.Dependencies = append(r.Dependencies, Dependency{Name: name, Version: version, Direct: direct(declared[name+"@"+version])})
	}
	return r, nil
}

// pnpmPackageKey splits a registry package key: "/express/4.18.2" and "/react-dom/18.2.0_react@18.2.0" in 5.x,
// "/express@4.19.2" and "/react-dom@18.3.1(react@18.3.1)" in 6.x, "express@4.19.2" in 9.x. Before 9.x only
// registry keys start with a slash: a git or tarball package is keyed by its host
// ("github.com/kevva/is-positive/97edff6f...", "@codeload.github.com/...") or a file: path, and returns no name.
// From 9.x such a key holds the URL or path after the @, which is not a version.
func pnpmPackageKey(key string, major float64) (string, string) {
	if major < 9 {
		var registry bool
		if key, registry = strings.CutPrefix(key, "/"); !registry {
			return "", ""
		}
	}
	if i := strings.IndexByte(key, '('); i > 0 {
		key = key[:i]
	}
	legacy := major < 6
	sep := "@"
	if legacy {
		sep = "/"
	}
	i := strings.LastIndex(key, sep)
	if i <= 0 {
		return "", ""
	}
	return key[:i], pnpmVersion(key[i+1:], legacy)
}

func pnpmVersion(ref string, legacy bool) string {
	if i := strings.IndexByte(ref, '('); i > 0 {
		ref = ref[:i]
	}
	if legacy {
		if i := strings.IndexByte(ref, '_'); i > 0 {
			ref = ref[:i]
		}
	}
	return ref
}

func mapValues[V any](m map[string]V) []V {
	values := make([]V, 0, len(m))
	for _, k := range sortedKeys(m) {
		values = append(values, m[k])
	}
	return values
}
