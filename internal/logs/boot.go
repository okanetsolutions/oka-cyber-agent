package logs

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var bootIDPattern = regexp.MustCompile(`(?i)^(?:[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$`)

func normalizeBootID(id string) string {
	if !bootIDPattern.MatchString(id) {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(id, "-", ""))
}

func (e *Event) setBootID(id string) {
	if id = normalizeBootID(id); id != "" {
		e.set("boot_id", id)
	}
}

type bootIdentity struct {
	id      string
	started time.Time
}

func (o Options) bootIdentity() bootIdentity {
	id, err := os.ReadFile(o.path("/proc/sys/kernel/random/boot_id"))
	if err != nil {
		return bootIdentity{}
	}
	stat, err := os.ReadFile(o.path("/proc/stat"))
	if err != nil {
		return bootIdentity{}
	}
	for _, line := range strings.Split(string(stat), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "btime" {
			seconds, err := strconv.ParseInt(f[1], 10, 64)
			if err == nil && seconds > 0 {
				return bootIdentity{normalizeBootID(strings.TrimSpace(string(id))), time.Unix(seconds, 0)}
			}
		}
	}
	return bootIdentity{}
}
