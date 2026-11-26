package lockfile

import (
	"encoding/json"
	"fmt"
)

// maxJSONEntries bounds what UnmarshalJSON decodes. composer.lock, package-lock.json, Pipfile.lock and
// packages.lock.json hold one object, array or item for every 38 to 81 bytes, so 550 000 at most in a file of the
// default 20 megabyte limit.
const maxJSONEntries = 1_000_000

// UnmarshalJSON decodes a lock file, or a manifest next to one, of at most maxJSONEntries objects, arrays and
// items. A file any local user wrote can hold one for every two bytes, and what is decoded for each takes far more
// memory than that: 20 megabytes of "{}," as the packages of a composer.lock take a gigabyte.
func UnmarshalJSON(data []byte, v any) error {
	if entries := jsonEntries(data); entries > maxJSONEntries {
		return fmt.Errorf("json: %w: %d entries", ErrTooLarge, entries)
	}
	return json.Unmarshal(data, v)
}

// jsonEntries counts the objects, arrays and commas of a JSON document outside its strings.
func jsonEntries(data []byte) int {
	entries := 0
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			for i++; i < len(data) && data[i] != '"'; i++ {
				if data[i] == '\\' {
					i++
				}
			}
		case '{', '[', ',':
			entries++
		}
	}
	return entries
}
