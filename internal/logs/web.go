package logs

import (
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The combined log format, optionally prefixed by "host:port " (Apache vhost_combined) and followed by extra
// fields (nginx adds "$http_x_forwarded_for"). Quoted fields may contain escaped quotes.
var combinedLog = regexp.MustCompile(`^(?:(\S+) )?(\S+) \S+ (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`)

// ParseAccessLog turns one combined format access log line into an http_request event. vhost is the virtual
// host taken from the file name; a vhost_combined prefix in the line takes precedence.
func ParseAccessLog(line, vhost string) (Event, bool) {
	m := combinedLog.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	prefix, client := m[1], m[2]
	if prefix != "" {
		if _, err := netip.ParseAddr(prefix); err == nil {
			return Event{}, false
		}
		host, _, _ := strings.Cut(prefix, ":")
		vhost = host
	}
	address, err := netip.ParseAddr(client)
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
