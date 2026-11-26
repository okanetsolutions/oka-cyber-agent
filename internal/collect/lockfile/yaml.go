package lockfile

import (
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"
)

const (
	yamlNullTag  = "!!null"
	yamlStrTag   = "!!str"
	yamlMergeTag = "!!merge"

	// maxYAMLEntries bounds what parseYAML hands to the library (see yamlEntries). A pnpm-lock.yaml or a berry
	// yarn.lock holds one of the counted characters for every 13 to 16 bytes and some 22 for each package, so this
	// is a lock file of 13 to 15 megabytes, or of 45 000 packages, and takes the library some 300 megabytes at most.
	maxYAMLEntries = 1_000_000
)

var errYAMLAlias = errors.New("yaml: an alias or a merge key where the lock file is read")

// parseYAML returns the root node of the first document of data, or a zero node when there is none. Nothing is
// decoded into Go values here: see yamlPairs for why the library is not asked to.
func parseYAML(data []byte) (*yaml.Node, error) {
	if entries := yamlEntries(data); entries > maxYAMLEntries {
		return nil, fmt.Errorf("yaml: %w: %d entries", ErrTooLarge, entries)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.Kind == yaml.DocumentNode && len(document.Content) == 1 {
		return document.Content[0], nil
	}
	return &document, nil
}

// yamlEntries counts the characters that can start or separate the keys, values and collections of a YAML
// document. The library keeps a node of some 200 bytes for each of those, at most three for each character counted
// here, so the count bounds the memory a file takes whatever any local user wrote in it: without it 20 megabytes
// of "a," take gigabytes. Characters inside strings and comments are counted too, which only makes the bound
// stricter.
func yamlEntries(data []byte) int {
	entries := 0
	for i, c := range data {
		switch c {
		case '\n', '\r', ',', '[', '{', ':':
			entries++
		case '-', '?':
			// A dash inside a name, a version or a hash is followed by a letter or a digit and starts nothing.
			if i+1 == len(data) || !isASCIIAlphanumeric(data[i+1]) {
				entries++
			}
		}
	}
	return entries
}

func isASCIIAlphanumeric(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// yamlPairs calls field with every key and value of the mapping n, and with nothing when n is absent or null. It
// stands in for the library's own decoding of a mapping, which compares every key with every other one to find
// duplicates and writes one error for each equal pair, whatever it decodes into: a lock file of one megabyte takes
// it a minute, and one of 160 kilobytes of equal keys takes gigabytes of memory. Here a duplicate is found with a
// set and is the one error returned. Like the library, it calls two keys equal when their kind and text are, leaves
// out an entry whose key is null and reads any other scalar key as its text.
//
// An alias in the place of the mapping, of a key or of a value that is read, and a merge key, are refused: pnpm and
// yarn write neither, and following them would let a small file be read many times over. The value of a key that
// is not read is not looked at.
func yamlPairs(n *yaml.Node, field func(key string, value *yaml.Node) error) error {
	switch {
	case n.IsZero(), n.Kind == yaml.ScalarNode && n.ShortTag() == yamlNullTag:
		return nil
	case n.Kind == yaml.AliasNode:
		return errYAMLAlias
	case n.Kind != yaml.MappingNode:
		return fmt.Errorf("yaml: line %d: not a mapping", n.Line)
	}
	type identity struct {
		kind yaml.Kind
		text string
	}
	lines := make(map[identity]int, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		id := identity{k.Kind, k.Value}
		if line, seen := lines[id]; seen {
			return fmt.Errorf("yaml: line %d: mapping key %q already defined at line %d", k.Line, k.Value, line)
		}
		lines[id] = k.Line
		if k.Kind == yaml.ScalarNode && k.Value == "<<" && k.ShortTag() == yamlMergeTag {
			return errYAMLAlias
		}
		if k.Kind == yaml.ScalarNode && k.ShortTag() == yamlNullTag {
			continue
		}
		key, err := yamlString(k)
		if err != nil {
			return err
		}
		if err := field(key, v); err != nil {
			return err
		}
	}
	return nil
}

// yamlMap reads the mapping n into a Go map, with value decoding each value.
func yamlMap[V any](n *yaml.Node, value func(*yaml.Node) (V, error)) (map[string]V, error) {
	var out map[string]V
	err := yamlPairs(n, func(key string, v *yaml.Node) (err error) {
		if out == nil {
			out = make(map[string]V, len(n.Content)/2)
		}
		out[key], err = value(v)
		return err
	})
	return out, err
}

// yamlString reads a scalar as the library decodes one into a string: the text of a string, the text as written of
// a number or a boolean, "" for null. The library is only given scalars, never a mapping (see yamlPairs).
func yamlString(n *yaml.Node) (string, error) {
	switch {
	case n.Kind == yaml.AliasNode:
		return "", errYAMLAlias
	case n.Kind != yaml.ScalarNode:
		return "", fmt.Errorf("yaml: line %d: not a scalar", n.Line)
	case n.ShortTag() == yamlStrTag:
		return n.Value, nil
	}
	var s string
	err := n.Decode(&s)
	return s, err
}
