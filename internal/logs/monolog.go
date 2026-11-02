package logs

import (
	"regexp"
	"time"
)

var monologLine = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\] ([\w.-]+)\.(DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY): (.*)$`)

var errorLevels = map[string]bool{"ERROR": true, "CRITICAL": true, "ALERT": true, "EMERGENCY": true}

// ParseMonolog turns the first line of a Monolog (Laravel, Symfony) entry at ERROR or above into an
// app_error event. Stack trace lines that follow are not entry lines and are ignored.
func ParseMonolog(line, path string, now time.Time) (Event, bool) {
	m := monologLine.FindStringSubmatch(line)
	if m == nil || !errorLevels[m[3]] {
		return Event{}, false
	}
	at := now
	for _, layout := range []string{"2006-01-02T15:04:05.999999999Z07:00", "2006-01-02T15:04:05.999999999-0700", "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, m[1], now.Location()); err == nil {
			at = parsed
			break
		}
	}
	e := newEvent(SourceApp, KindAppError, at, line)
	e.set("level", m[3])
	e.set("file", path)
	return e, true
}
