package collect

import (
	"bufio"
	"io"
	"strings"
)

const maxLineBytes = 1 << 20

// readStanzas reads blank line separated records of "Key<sep>value" lines, as used by the dpkg status file and the apk database.
func readStanzas(r io.Reader, sep string, keep func(key string) bool, emit func(map[string]string)) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxLineBytes)
	record := map[string]string{}
	flush := func() {
		if len(record) > 0 {
			emit(record)
			record = map[string]string{}
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, sep)
		if !ok || !keep(key) {
			continue
		}
		record[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	flush()
	return nil
}

func keepKeys(keys ...string) func(string) bool {
	return func(key string) bool {
		for _, k := range keys {
			if k == key {
				return true
			}
		}
		return false
	}
}
