package logs

import (
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The combined log format, followed by extra fields (nginx adds "$http_x_forwarded_for"). Quoted fields may
// contain escaped quotes. The user is whatever the client sent as the user name of HTTP Basic authentication,
// which nginx logs for every request and Apache for a protected one, blanks and brackets included
// (curl -u 'a b:x'), so it runs up to the first " [" that a date and a quoted request follow. Both servers escape
// a quote in it, so it cannot hold that sequence itself, and it never runs across an unescaped quote: the
// request, the Referer and the User-Agent cannot lend it their text.
const combinedFields = `((?:[^"\\]|\\.)*?) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`

var (
	combinedLog = regexp.MustCompile(`^(\S+) (\S+) ` + combinedFields)
	// Apache vhost_combined puts "host:port " before the combined line. It is read only when the first word is
	// not an address: an optional prefix in one pattern let a plain line be read with its client as the prefix,
	// and the user then ran to a date and request planted in the Referer.
	vhostCombinedLog = regexp.MustCompile(`^(\S+) (\S+) (\S+) ` + combinedFields)
)

// ParseAccessLog turns one combined format access log line into an http_request event. vhost is the virtual
// host taken from the file name; a vhost_combined prefix in the line takes precedence.
func ParseAccessLog(line, vhost string) (Event, bool) {
	m := combinedLog.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	if _, err := netip.ParseAddr(m[1]); err != nil {
		if m = vhostCombinedLog.FindStringSubmatch(line); m == nil {
			return Event{}, false
		}
		host, _, _ := strings.Cut(m[1], ":")
		vhost = host
		m = m[1:]
	} else if _, err := netip.ParseAddr(m[2]); err == nil {
		// Two addresses before the user are another log format (a forwarded address first), whose fields this
		// parser would misread. Both servers log the identity as "-".
		return Event{}, false
	}
	address, err := netip.ParseAddr(m[1])
	if err != nil {
		return Event{}, false
	}
	at, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[4])
	if err != nil {
		return Event{}, false
	}
	e := newEvent(SourceWeb, KindHTTPRequest, at, line)
	e.SrcIP = address.String()
	method, path := splitRequest(m[5])
	e.set("method", method)
	e.set("path", path)
	status, _ := strconv.Atoi(m[6])
	e.set("status", status)
	if m[7] != "-" {
		bytes, _ := strconv.ParseInt(m[7], 10, 64)
		e.set("bytes", bytes)
	}
	if ua := unescape(m[9]); ua != "" && ua != "-" {
		e.set("user_agent", ua)
	}
	if vhost != "" {
		e.set("vhost", vhost)
	}
	return e, true
}

func splitRequest(request string) (string, string) {
	request = unescape(request)
	fields := strings.Fields(request)
	if len(fields) >= 2 && isHTTPMethod(fields[0]) {
		return fields[0], fields[1]
	}
	return "", request
}

func isHTTPMethod(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	replacer := strings.NewReplacer(`\"`, `"`, `\x22`, `"`, `\\`, `\`)
	return replacer.Replace(s)
}

// VhostFromPath derives the virtual host from an access log file name: "shop.example.com.access.log",
// "shop.example.com-access.log" and "shop.example.com_access_log" give "shop.example.com"; the default
// "access.log" and "access_log" give "".
func VhostFromPath(path string) string {
	name := filepath.Base(path)
	for _, suffix := range []string{".access.log", "-access.log", "_access.log", "_access_log", "-access_log", ".access_log"} {
		if host, ok := strings.CutSuffix(name, suffix); ok && host != "" {
			return host
		}
	}
	return ""
}
