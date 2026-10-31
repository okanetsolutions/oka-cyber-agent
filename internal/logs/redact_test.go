package logs

import (
	"strings"
	"testing"
)

func TestRedactQueryParameters(t *testing.T) {
	tests := map[string]string{
		"/login?username=alice&password=hunter2&next=/home":               "/login?username=[redacted]&password=[redacted]&next=/home",
		"/reset?Token=abc123":                                             "/reset?Token=[redacted]",
		"/cb?code=4/0AY0e&state=xyz":                                      "/cb?code=[redacted]&state=xyz",
		"/s3?X-Amz-Signature=deadbeef&X-Amz-Date=20261031":                "/s3?X-Amz-Signature=[redacted]&X-Amz-Date=20261031",
		"/products?id=1%27%20UNION%20SELECT%201,2--&api_key=k":            "/products?id=1%27%20UNION%20SELECT%201,2--&api_key=[redacted]",
		"/search?q=shoes&sort=price":                                      "/search?q=shoes&sort=price",
		"/a?PHPSESSID=s1;jsessionid=s2":                                   "/a?PHPSESSID=[redacted];jsessionid=[redacted]",
		"/a?pass%77ord=x":                                                 "/a?pass%77ord=[redacted]",
		"/a?email=&phone=":                                                "/a?email=&phone=",
		`"GET /x?auth=y HTTP/1.1" 200 1 "https://ref.example/?session=z"`: `"GET /x?auth=[redacted] HTTP/1.1" 200 1 "https://ref.example/?session=[redacted]"`,
	}
	for before, after := range tests {
		if got := RedactQuery(before); got != after {
			t.Errorf("RedactQuery(%q)\n got %q\nwant %q", before, got, after)
		}
	}
}

func TestRedactCommand(t *testing.T) {
	tests := map[string]string{
		"/usr/bin/mysql -u root -pS3cret shop":             "/usr/bin/mysql -u root -p[redacted] shop",
		"/usr/bin/mysql -u root -p S3cret shop":            "/usr/bin/mysql -u root -p [redacted] shop",
		"/usr/local/bin/tool --password hunter2 --verbose": "/usr/local/bin/tool --password [redacted] --verbose",
		"/usr/local/bin/tool --password=hunter2":           "/usr/local/bin/tool --password=[redacted]",
		"/usr/local/bin/tool --pass 'two words'":           "/usr/local/bin/tool --pass [redacted]",
		"/usr/bin/env PASSWORD=x TOKEN=y SECRET=z /app":    "/usr/bin/env PASSWORD=[redacted] TOKEN=[redacted] SECRET=[redacted] /app",
		"/usr/bin/env DB_PASSWORD=x API_TOKEN=y /app":      "/usr/bin/env DB_PASSWORD=[redacted] API_TOKEN=[redacted] /app",
		"/usr/bin/apt update":                              "/usr/bin/apt update",
		"/usr/bin/systemctl restart nginx":                 "/usr/bin/systemctl restart nginx",
	}
	for before, after := range tests {
		if got := RedactCommand(before); got != after {
			t.Errorf("RedactCommand(%q)\n got %q\nwant %q", before, got, after)
		}
	}
}

func TestRedactEvents(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

	typedPassword := newEvent(SourceAuth, KindSSHLoginFailed, testNow, "Failed password for invalid user Hunter2! from 203.0.113.7 port 51234 ssh2")
	typedPassword.Username = "Hunter2!"
	got := Redact(typedPassword)
	if got.Username != Redacted || got.Message != "Failed password for invalid user [redacted] from 203.0.113.7 port 51234 ssh2" {
		t.Fatalf("typed password = %+v", got)
	}

	valid := newEvent(SourceAuth, KindSSHLoginFailed, testNow, "Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2")
	valid.Username = "admin"
	if got := Redact(valid); got.Username != "admin" || got.Message != valid.Message {
		t.Fatalf("a valid user name must stay: %+v", got)
	}

	sudo := newEvent(SourceAuth, KindSudoCommand, testNow, "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/mysql -pS3cret")
	sudo.set("command", "/usr/bin/mysql -pS3cret")
	got = Redact(sudo)
	if strings.Contains(got.Message+got.Fields["command"].(string), "S3cret") {
		t.Fatalf("sudo password leaked: %+v", got)
	}
	if sudo.Fields["command"] != "/usr/bin/mysql -pS3cret" {
		t.Fatal("Redact must not modify the caller's fields")
	}

	web := newEvent(SourceWeb, KindHTTPRequest, testNow, `203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /a?token=t1&q=%3Cscript%3E HTTP/1.1" 200 1 "-" "Bearer `+jwt+`"`)
	web.set("path", "/a?token=t1&q=%3Cscript%3E")
	web.set("user_agent", "Bearer "+jwt)
	got = Redact(web)
	if got.Fields["path"] != "/a?token=[redacted]&q=%3Cscript%3E" || got.Fields["user_agent"] != "Bearer [redacted]" || strings.Contains(got.Message, "t1&") || strings.Contains(got.Message, jwt) {
		t.Fatalf("web = %+v", got)
	}

	app := newEvent(SourceApp, KindAppError, testNow, "[2026-10-31 19:00:03] production.ERROR: Mail to jane.doe@example.com failed {\"user\":\"jane%40example.org\"}")
	if got := Redact(app); strings.Contains(got.Message, "jane") {
		t.Fatalf("email leaked: %q", got.Message)
	}

	long := newEvent(SourceApp, KindAppError, testNow, strings.Repeat("é", MaxMessageLength))
	long.set("file", "/"+strings.Repeat("a", 2000))
	got = Redact(long)
	if len(got.Message) > MaxMessageLength || !strings.HasPrefix(got.Message, "é") || len(got.Fields["file"].(string)) != maxFieldLength {
		t.Fatalf("message length = %d, file length = %d", len(got.Message), len(got.Fields["file"].(string)))
	}
}
