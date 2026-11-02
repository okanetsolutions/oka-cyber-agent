package logs

import (
	"regexp"
	"time"
)

// SyslogLine is one line of a syslog file such as /var/log/auth.log or /var/log/secure.
type SyslogLine struct {
	At      time.Time
	Program string
	Message string
}

var (
	rfc3339Syslog = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) \S+ ([^\s\[:]+)(?:\[\d+\])?: (.*)$`)
	// RFC 3164 lines, with the facility.level token busybox syslogd adds (Alpine).
	bsdSyslog = regexp.MustCompile(`^([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) \S+ (?:[a-z0-9]+\.[a-z]+ )?([^\s\[:]+)(?:\[\d+\])?: (.*)$`)
)

// ParseSyslog reads the formats rsyslog and busybox write: RFC 3339 timestamps (Debian 12, Ubuntu 24.04)
// and the traditional "Oct 30 12:00:01" ones without a year (RHEL family, Alpine, older Debian), which are
// placed in the year that keeps them from being in the future.
func ParseSyslog(line string, now time.Time) (SyslogLine, bool) {
	if m := rfc3339Syslog.FindStringSubmatch(line); m != nil {
		at, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil {
			return SyslogLine{}, false
		}
		return SyslogLine{At: at, Program: m[2], Message: m[3]}, true
	}
	if m := bsdSyslog.FindStringSubmatch(line); m != nil {
		at, err := time.ParseInLocation("Jan _2 15:04:05 2006", m[1]+" "+now.Format("2006"), now.Location())
		if err != nil {
			return SyslogLine{}, false
		}
		if at.After(now.Add(24 * time.Hour)) {
			at = at.AddDate(-1, 0, 0)
		}
		return SyslogLine{At: at, Program: m[2], Message: m[3]}, true
	}
	return SyslogLine{}, false
}
