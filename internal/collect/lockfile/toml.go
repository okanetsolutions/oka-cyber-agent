package lockfile

import (
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
)

// What checkTOML accepts. The Cargo.lock, poetry.lock and uv.lock files under testdata nest arrays and inline
// tables two levels deep (uv nests a third when it records extras) and name tables with three key parts at most
// ([package.metadata.requires-dev]). They hold one key, table, array or array item for every 24 to 35 bytes, and
// the library keeps about half a kilobyte for each of them however short it is in the file, so maxTOMLEntries is
// what a lock file of 12 to 17 megabytes holds and takes the library some 300 megabytes at most.
const (
	maxTOMLNesting  = 8
	maxTOMLKeyParts = 8
	maxTOMLEntries  = 500_000
)

var (
	errTOMLNesting = errors.New("toml: arrays and inline tables are nested too deeply for a lock file")
	errTOMLKey     = errors.New("toml: a key has too many parts for a lock file")
	errTOMLString  = errors.New("toml: a string does not end")
)

// unmarshalTOML decodes a lock file that checkTOML accepts. Any local user can write a file with the name of a
// lock file, and the TOML library parses nested arrays by recursion without a depth limit (two megabytes of "["
// overflow the stack, which ends the process), while the memory it takes grows with the square of the depth of
// dotted keys, table names and inline tables (gigabytes for a file of 60 kilobytes).
func unmarshalTOML(data []byte, v any) error {
	if err := checkTOML(data); err != nil {
		return err
	}
	return toml.Unmarshal(data, v)
}

// checkTOML scans data once, without building anything, and refuses arrays and inline tables nested deeper than
// maxTOMLNesting, keys of more than maxTOMLKeyParts parts and files of more than maxTOMLEntries entries. It skips
// comments and the four kinds of TOML string as the library reads them, so a bracket or a dot inside one is not
// counted and one outside is never missed. It only has to be right about TOML the library accepts: the library
// stops at the first error, before it reads what follows.
func checkTOML(data []byte) error {
	depth, dots, entries := 0, 0, 0
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch c {
		case '[', '{', '=', ',', '.':
			if entries++; entries > maxTOMLEntries {
				return fmt.Errorf("toml: %w", ErrTooLarge)
			}
		}
		switch c {
		case '#':
			for i+1 < len(data) && !tomlNewline(data[i+1]) {
				i++
			}
		case '"', '\'':
			end, err := tomlStringEnd(data, i)
			if err != nil {
				return err
			}
			i = end
		case '[', '{':
			if depth++; depth > maxTOMLNesting {
				return errTOMLNesting
			}
			dots = 0
		case ']', '}':
			depth = max(depth-1, 0)
			dots = 0
		case '=', ',', '\n', '\r':
			dots = 0
		case '.':
			// A float or a date has one dot between two of the separators above, a key one less than it has parts.
			if dots++; dots >= maxTOMLKeyParts {
				return errTOMLKey
			}
		}
	}
	return nil
}

// The library ends a comment and refuses a single line string at a carriage return as at a line feed.
func tomlNewline(c byte) bool { return c == '\n' || c == '\r' }

// tomlStringEnd returns the index of the quote that closes the string starting at data[start]. A backslash
// escapes the next character in a basic string only. A multi-line string ends at the last three quotes of a run
// of three to five (its text may end with one or two quotes); a longer run is refused, as the library does.
func tomlStringEnd(data []byte, start int) (int, error) {
	quote := data[start]
	basic := quote == '"'
	if start+2 < len(data) && data[start+1] == quote && data[start+2] == quote {
		for i := start + 3; i < len(data); i++ {
			switch {
			case basic && data[i] == '\\':
				i++
			case data[i] == quote:
				run := 1
				for i+run < len(data) && data[i+run] == quote {
					run++
				}
				if run > 5 {
					return 0, errTOMLString
				}
				if run >= 3 {
					return i + run - 1, nil
				}
				i += run - 1
			}
		}
		return 0, errTOMLString
	}
	for i := start + 1; i < len(data); i++ {
		switch {
		case tomlNewline(data[i]):
			return 0, errTOMLString
		case basic && data[i] == '\\':
			i++
		case data[i] == quote:
			return i, nil
		}
	}
	return 0, errTOMLString
}
