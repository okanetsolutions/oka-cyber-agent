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
		"/search?q=%3Cscript%3E&page=2":                                   "/search?q=%3Cscript%3E&page=2",
		"/go?next=/account/orders?page=2":                                 "/go?next=/account/orders?page=2",
	}
	for before, after := range tests {
		if got := RedactQuery(before); got != after {
			t.Errorf("RedactQuery(%q)\n got %q\nwant %q", before, got, after)
		}
	}
}

func TestRedactNestedQueries(t *testing.T) {
	tests := map[string]string{
		"/login?next=/reset?token=SECRET1":                                 "/login?next=/reset?token=[redacted]",
		"/sso?redirect=https://app/cb?access_token=SECRET2":                "/sso?redirect=https://app/cb?access_token=[redacted]",
		"/sso?redirect=https://app/cb?state=s;session=SECRET&page=2":       "/sso?redirect=https://app/cb?state=s;session=[redacted]&page=2",
		"/sso?redirect=https%3A%2F%2Fapp%2Fcb%3Faccess_token%3DSECRET3":    "/sso?redirect=[redacted]",
		"/sso?redirect=https%253A%252F%252Fapp%252Fcb%253Ftoken%253DSEC4":  "/sso?redirect=[redacted]",
		"/sso?redirect=%zz%3Ftoken%3DSECRET5":                              "/sso?redirect=[redacted]",
		"/sso?next=token=SECRET6":                                          "/sso?next=token=[redacted]",
		"/sso?next=%2Faccount%3Fpage%3D2":                                  "/sso?next=%2Faccount%3Fpage%3D2",
		"/a?next=/b?next=/c?next=/d?next=/e?next=/f?token=SECRET7":         "/a?next=/b?next=/c?next=/d?next=/e?next=[redacted]",
		`"GET /login?next=/reset?token=SECRET8 HTTP/1.1" 302 0 "-" "curl"`: `"GET /login?next=/reset?token=[redacted] HTTP/1.1" 302 0 "-" "curl"`,
	}
	for before, after := range tests {
		got := RedactQuery(before)
		if got != after {
			t.Errorf("RedactQuery(%q)\n got %q\nwant %q", before, got, after)
		}
		if strings.Contains(got, "SEC") {
			t.Errorf("RedactQuery(%q) leaks a secret: %q", before, got)
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

		"/usr/bin/env API_KEY=xyz /app":                                                                                "/usr/bin/env API_KEY=[redacted] /app",
		"/usr/bin/env aws_secret_access_key=abc123 AWS_REGION=eu-west-1 /app":                                          "/usr/bin/env aws_secret_access_key=[redacted] AWS_REGION=eu-west-1 /app",
		"/usr/bin/env DB_PASS='two words' GITHUB_AUTH=g OAUTH_CREDENTIALS=c /a":                                        "/usr/bin/env DB_PASS=[redacted] GITHUB_AUTH=[redacted] OAUTH_CREDENTIALS=[redacted] /a",
		"alice : PWD=/srv ; USER=root ; ENV=AWS_SECRET_ACCESS_KEY=abc123 HOME=/root ; COMMAND=/usr/bin/aws s3 ls":      "alice : PWD=/srv ; USER=root ; ENV=AWS_SECRET_ACCESS_KEY=[redacted] HOME=/root ; COMMAND=/usr/bin/aws s3 ls",
		"/usr/bin/kubeadm join 10.0.0.1:6443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:ab": "/usr/bin/kubeadm join 10.0.0.1:6443 --token [redacted] --discovery-token-ca-cert-hash sha256:ab",
		"/usr/local/bin/tool --api-key=k1 --client-secret s2 --secret=s3 --pass p4":                                    "/usr/local/bin/tool --api-key=[redacted] --client-secret [redacted] --secret=[redacted] --pass [redacted]",
		"/usr/local/bin/vault login --DB_PASSWORD x --token-ttl 24h":                                                   "/usr/local/bin/vault login --DB_PASSWORD [redacted] --token-ttl 24h",
		"/usr/bin/curl -u admin:S3cret https://api.example/v1":                                                         "/usr/bin/curl -u admin:[redacted] https://api.example/v1",
		"/usr/bin/curl --user=admin:S3cret https://api.example/v1":                                                     "/usr/bin/curl --user=admin:[redacted] https://api.example/v1",
		"/usr/bin/curl -uadmin:S3cret https://api.example/v1":                                                          "/usr/bin/curl -uadmin:[redacted] https://api.example/v1",
		"/usr/bin/curl -H Authorization: Bearer opaque-token https://api.example":                                      "/usr/bin/curl -H Authorization: Bearer [redacted] https://api.example",
		"/usr/bin/curl -H 'Authorization: Bearer opaque-token' https://a.example":                                      "/usr/bin/curl -H 'Authorization: Bearer [redacted]' https://a.example",
		`/usr/bin/curl --header "X-Api-Key: k3y" -H "Accept: text/plain" -o out`:                                       `/usr/bin/curl --header "X-Api-Key: [redacted]" -H "Accept: text/plain" -o out`,
		"/usr/bin/curl -H Cookie: sid=abc; theme=dark -o /tmp/out https://a.example":                                   "/usr/bin/curl -H Cookie: [redacted] -o /tmp/out https://a.example",
		"/usr/bin/git clone https://deploy:ghp_secret@github.com/acme/app.git":                                         "/usr/bin/git clone https://deploy:[redacted]@github.com/acme/app.git",
		"/usr/bin/curl https://api.example/v1/items?api_key=k4&page=2":                                                 "/usr/bin/curl https://api.example/v1/items?api_key=[redacted]&page=2",

		"/usr/bin/gpg --keyring=/usr/share/keyrings/a.gpg --recv-keys ABC": "/usr/bin/gpg --keyring=/usr/share/keyrings/a.gpg --recv-keys ABC",
		"/usr/bin/mysql -u root shop":                                      "/usr/bin/mysql -u root shop",
		"/usr/bin/ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519":          "/usr/bin/ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519",
		"/usr/bin/curl -H 'Accept: application/json' https://a.example/":   "/usr/bin/curl -H 'Accept: application/json' https://a.example/",
		"/usr/bin/dd if=/dev/zero of=/tmp/x bs=1M count=1":                 "/usr/bin/dd if=/dev/zero of=/tmp/x bs=1M count=1",
		"/usr/bin/ssh -p 2222 git@github.com":                              "/usr/bin/ssh -p [redacted] git@github.com",
		"/usr/bin/systemctl edit --full oka-cyber-agent.service":           "/usr/bin/systemctl edit --full oka-cyber-agent.service",
		"/usr/bin/passwd alice":                                            "/usr/bin/passwd alice",
	}
	for before, after := range tests {
		if got := RedactCommand(before); got != after {
			t.Errorf("RedactCommand(%q)\n got %q\nwant %q", before, got, after)
		}
	}
}

func TestRedactText(t *testing.T) {
	tests := map[string]string{
		"[2026-10-31 19:00:03] production.ERROR: Request failed GET https://api.x/v1/items?api_key=SECRET4&page=2 {\"exception\":\"[object] (GuzzleHttp\\\\Exception\\\\ClientException(code: 401)\"}": "[2026-10-31 19:00:03] production.ERROR: Request failed GET https://api.x/v1/items?api_key=[redacted]&page=2 {\"exception\":\"[object] (GuzzleHttp\\\\Exception\\\\ClientException(code: 401)\"}",
		`[2026-10-31 19:00:03] production.ERROR: Callback failed {"url":"https://x/cb?token=SECRET5","attempt":2}`:                                                                                     `[2026-10-31 19:00:03] production.ERROR: Callback failed {"url":"https://x/cb?token=[redacted]","attempt":2}`,
		`[2026-10-31 19:00:03] production.ERROR: Login failed {"email_verified":false,"password":"hunter2","remember":true}`:                                                                           `[2026-10-31 19:00:03] production.ERROR: Login failed {"email_verified":false,"password":"[redacted]","remember":true}`,
		`[2026-10-31 19:00:03] production.ERROR: Webhook rejected {"headers":{"authorization":"Bearer opaque","x-request-id":"r1"}}`:                                                                   `[2026-10-31 19:00:03] production.ERROR: Webhook rejected {"headers":{"authorization":"[redacted]","x-request-id":"r1"}}`,
		`[2026-10-31 19:00:03] production.ERROR: Upstream said "bad \"token\"" {"api_token": "t\"0k", "id": 7}`:                                                                                        `[2026-10-31 19:00:03] production.ERROR: Upstream said "bad \"token\"" {"api_token": "[redacted]", "id": 7}`,
		"[2026-10-31 19:00:03] production.ERROR: Mailer failed: SMTP auth with password=hunter2 rejected":                                                                                              "[2026-10-31 19:00:03] production.ERROR: Mailer failed: SMTP auth with password=[redacted] rejected",
		"[2026-10-31 19:00:03] production.ERROR: Gateway call failed, Authorization: Bearer opaque-token, status 502":                                                                                  "[2026-10-31 19:00:03] production.ERROR: Gateway call failed, Authorization: Bearer [redacted], status 502",
		"[2026-10-31 19:00:03] production.ERROR: SQLSTATE[HY000] [1045] Access denied (Connection: mysql://shop:S3cret@db:3306/shop)":                                                                  "[2026-10-31 19:00:03] production.ERROR: SQLSTATE[HY000] [1045] Access denied (Connection: mysql://shop:[redacted]@db:3306/shop)",
		"[2026-10-31 19:00:03] production.ERROR: CSRF token mismatch. {\"exception\":\"TokenMismatchException(code: 419)\"}":                                                                           "[2026-10-31 19:00:03] production.ERROR: CSRF token mismatch. {\"exception\":\"TokenMismatchException(code: 419)\"}",
		"[2026-10-31 19:00:03] production.ERROR: Undefined variable $order at /var/www/shop/app/Order.php:42":                                                                                          "[2026-10-31 19:00:03] production.ERROR: Undefined variable $order at /var/www/shop/app/Order.php:42",
	}
	for before, after := range tests {
		if got := RedactText(before); got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
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

	monolog := "[2026-10-31 19:00:03] production.ERROR: Request failed GET https://api.x/v1/items?api_key=SECRET4&page=2 {\"password\":\"hunter2\"}"
	appError, ok := ParseMonolog(monolog, "/var/www/shop/storage/logs/laravel.log", testNow)
	if !ok {
		t.Fatal("not an app error")
	}
	if got := Redact(appError); strings.Contains(got.Message, "SECRET4") || strings.Contains(got.Message, "hunter2") || !strings.Contains(got.Message, "page=2") {
		t.Fatalf("app error = %q", got.Message)
	}

	long := newEvent(SourceApp, KindAppError, testNow, strings.Repeat("é", MaxMessageLength))
	long.set("file", "/"+strings.Repeat("a", 2000))
	got = Redact(long)
	if len(got.Message) > MaxMessageLength || !strings.HasPrefix(got.Message, "é") || len(got.Fields["file"].(string)) != maxFieldLength {
		t.Fatalf("message length = %d, file length = %d", len(got.Message), len(got.Fields["file"].(string)))
	}
}
