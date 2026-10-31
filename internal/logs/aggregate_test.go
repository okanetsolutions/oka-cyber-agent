package logs

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sshFailure(ip, user string, at time.Time) Event {
	e := newEvent(SourceAuth, KindSSHLoginFailed, at, "Failed password for "+user+" from "+ip+" port 1 ssh2")
	e.SrcIP, e.Username = ip, user
	e.set("method", "password")
	return e
}

func request(ip, method, path, agent string, status int, at time.Time) Event {
	e := newEvent(SourceWeb, KindHTTPRequest, at, method+" "+path)
	e.SrcIP = ip
	e.set("method", method)
	e.set("path", path)
	e.set("status", status)
	if agent != "" {
		e.set("user_agent", agent)
	}
	return e
}

func TestFailedSSHLoginsAreAggregatedPerIPUserAndMinute(t *testing.T) {
	a := NewAggregator()
	base := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	for i := range 42 {
		a.Add(sshFailure("203.0.113.7", "admin", base.Add(time.Duration(i)*time.Second)))
	}
	a.Add(sshFailure("203.0.113.7", "root", base.Add(5*time.Second)))
	a.Add(sshFailure("203.0.113.7", "admin", base.Add(61*time.Second)))
	a.Add(sshFailure("198.51.100.4", "admin", base))
	if a.Pending() != 4 {
		t.Fatalf("pending = %d", a.Pending())
	}
	events := a.Flush()
	first := events[0]
	if first.Count != 42 || !first.FirstAt.Equal(base) || !first.LastAt.Equal(base.Add(41*time.Second)) || first.Message == "" || first.Fields["method"] != "password" {
		t.Fatalf("aggregate = %+v", first)
	}
	if len(events) != 4 || events[1].Username != "root" || events[2].Count != 1 || events[3].SrcIP != "198.51.100.4" {
		t.Fatalf("events = %+v", events)
	}
	if a.Pending() != 0 || len(a.Flush()) != 0 {
		t.Fatal("Flush must empty the aggregator")
	}
}

func TestWebRequestsAreKeptOnlyWhenSuspicious(t *testing.T) {
	at := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		e          Event
		suspicious bool
	}{
		{"normal page", request("203.0.113.7", "GET", "/products/42?page=2", "Mozilla/5.0", 200, at), false},
		{"form post", request("203.0.113.7", "POST", "/cart", "Mozilla/5.0", 302, at), false},
		{"not found", request("203.0.113.7", "GET", "/missing", "Mozilla/5.0", 404, at), true},
		{"server error", request("203.0.113.7", "GET", "/", "Mozilla/5.0", 500, at), true},
		{"delete method", request("203.0.113.7", "DELETE", "/api/orders/1", "curl/8", 204, at), true},
		{"tls on http port", request("203.0.113.7", "", "\x16\x03\x01", "", 200, at), true},
		{"long uri", request("203.0.113.7", "GET", "/"+string(make([]byte, maxURILength)), "Mozilla/5.0", 200, at), true},
		{"traversal", request("203.0.113.7", "GET", "/static/..%2f..%2fetc/passwd", "Mozilla/5.0", 200, at), true},
		{"sql injection", request("203.0.113.7", "GET", "/p?id=1%20UNION%20SELECT%201", "Mozilla/5.0", 200, at), true},
		{"log4shell user agent", request("203.0.113.7", "GET", "/", "${jndi:ldap://x/a}", 200, at), true},
		{"scanner", request("203.0.113.7", "GET", "/", "Mozilla/5.0 zgrab/0.x", 200, at), true},
		{"wordpress probe", request("203.0.113.7", "GET", "/wp-login.php", "Mozilla/5.0", 200, at), true},
		{"ignition rce", request("203.0.113.7", "POST", "/_ignition/execute-solution", "Mozilla/5.0", 200, at), true},
	}
	for _, tt := range tests {
		if got := Suspicious(tt.e); got != tt.suspicious {
			t.Errorf("%s: Suspicious = %v, want %v", tt.name, got, tt.suspicious)
		}
	}
}

func TestNormalTrafficIsCountedPerIPAndMinute(t *testing.T) {
	a := NewAggregator()
	at := time.Date(2026, 10, 31, 12, 0, 10, 0, time.UTC)
	a.Add(request("203.0.113.7", "GET", "/", "Mozilla/5.0", 200, at))
	a.Add(request("203.0.113.7", "GET", "/a", "Mozilla/5.0", 200, at.Add(time.Second)))
	a.Add(request("203.0.113.7", "POST", "/cart", "Mozilla/5.0", 302, at.Add(2*time.Second)))
	a.Add(request("203.0.113.7", "GET", "/missing", "Mozilla/5.0", 404, at.Add(3*time.Second)))
	a.Add(request("203.0.113.7", "GET", "/", "Mozilla/5.0", 200, at.Add(time.Minute)))
	events := a.Flush()
	if len(events) != 3 {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Kind != KindHTTPRequest || events[0].Fields["status"] != 404 {
		t.Fatalf("the 404 must stay a full request: %+v", events[0])
	}
	traffic := events[1]
	if traffic.Kind != KindHTTPTraffic || traffic.Source != SourceWeb || traffic.Count != 3 || traffic.SrcIP != "203.0.113.7" ||
		traffic.Fields["status_2xx"] != 2 || traffic.Fields["status_3xx"] != 1 || traffic.Fields["status_4xx"] != 0 || traffic.Fields["status_5xx"] != 0 ||
		!traffic.LastAt.Equal(at.Add(2*time.Second)) || traffic.Message == "" {
		t.Fatalf("traffic = %+v", traffic)
	}
	if events[2].Count != 1 {
		t.Fatalf("the next minute is a separate event: %+v", events[2])
	}
}

func TestOtherEventsPassThroughInOrder(t *testing.T) {
	a := NewAggregator()
	sudo := newEvent(SourceAuth, KindSudoCommand, testNow, "sudo")
	removed := RemovedEvent(SourceWeb, "/var/log/nginx/access.log", testNow)
	a.Add(sudo)
	a.Add(removed)
	events := a.Flush()
	if len(events) != 2 || events[0].Kind != KindSudoCommand || events[1].Kind != KindLogFileRemoved {
		t.Fatalf("events = %+v", events)
	}
}

func TestRealAccessLogsSplitIntoFullAndCounted(t *testing.T) {
	a := NewAggregator()
	for _, line := range readLines(t, filepath.Join("testdata", "web", "nginx.access.log")) {
		e, _ := ParseAccessLog(line, "")
		a.Add(Redact(e))
	}
	full, counted := 0, 0
	for _, e := range a.Flush() {
		switch e.Kind {
		case KindHTTPRequest:
			full++
		case KindHTTPTraffic:
			counted += e.Count
		}
	}
	if full != 7 || counted != 2 {
		t.Fatalf("full = %d, counted = %d; want the 7 probes in full and the 2 plain requests counted", full, counted)
	}
}

func TestSuspiciousTokensAreLoaded(t *testing.T) {
	if len(URITokens) != 4 || len(AnyTokens) < 40 {
		t.Fatalf("tokens = %d uri, %d any", len(URITokens), len(AnyTokens))
	}
	for _, token := range append(URITokens, AnyTokens...) {
		if token == "" || strings.HasPrefix(token, "# ") || strings.HasPrefix(token, "[") {
			t.Fatalf("bad token %q", token)
		}
	}
}

func TestBrowserUserAgentsAreNotSuspicious(t *testing.T) {
	for _, agent := range []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	} {
		if Suspicious(request("203.0.113.7", "GET", "/", agent, 200, testNow)) {
			t.Errorf("browser user agent flagged: %s", agent)
		}
	}
	if !Suspicious(request("203.0.113.7", "GET", "/a;rm -rf", "Mozilla/5.0 (X11; Linux x86_64)", 200, testNow)) {
		t.Error("a ; in the URI is suspicious")
	}
}
