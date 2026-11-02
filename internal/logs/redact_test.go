package logs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
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
		"/usr/bin/env DB_PASS='two words' GITHUB_AUTH=g OAUTH_CREDENTIALS=c /a":                                        "/usr/bin/env DB_PASS='[redacted]' GITHUB_AUTH=[redacted] OAUTH_CREDENTIALS=[redacted] /a",
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

// TestRedactCommandSecretOptionAfterOtherOptions checks that an option which takes no value never swallows the
// secret option after it.
func TestRedactCommandSecretOptionAfterOtherOptions(t *testing.T) {
	tests := []struct{ before, after string }{
		{"/usr/bin/mysqldump --single-transaction --password=hunter2 db", "/usr/bin/mysqldump --single-transaction --password=[redacted] db"},
		{"/usr/local/bin/tool --verbose --password hunter2", "/usr/local/bin/tool --verbose --password [redacted]"},
		{"/usr/local/bin/tool --quiet --api-key abc", "/usr/local/bin/tool --quiet --api-key [redacted]"},
		{"/usr/local/bin/tool --single-transaction --token abc", "/usr/local/bin/tool --single-transaction --token [redacted]"},
		{"/usr/local/bin/tool --a --password=p1 --b --password=p2", "/usr/local/bin/tool --a --password=[redacted] --b --password=[redacted]"},
		{"/usr/bin/mysqldump --quick --lock-tables=false -pS3cret --databases shop", "/usr/bin/mysqldump --quick --lock-tables=false -p[redacted] --databases shop"},
		{"/usr/bin/mysql --batch -p S3cret -e 'select 1'", "/usr/bin/mysql --batch -p [redacted] -e 'select 1'"},
		{"/usr/bin/mysql -v -v -uroot -pS3cret", "/usr/bin/mysql -v -v -uroot -p[redacted]"},
		{"/usr/bin/mysql -p'two words' shop", "/usr/bin/mysql -p[redacted] shop"},
		{"/usr/bin/mysql --password='two words' --verbose shop", "/usr/bin/mysql --password=[redacted] --verbose shop"},
		{`/usr/bin/mysql --password "two \"words\"" --verbose shop`, "/usr/bin/mysql --password [redacted] --verbose shop"},
		{"/usr/local/bin/tool --password=hunter2 --token t0k --client-secret=c5 --verbose", "/usr/local/bin/tool --password=[redacted] --token [redacted] --client-secret=[redacted] --verbose"},
		{"/usr/local/bin/tool --token-ttl 24h --password-file /etc/pw --api-key k", "/usr/local/bin/tool --token-ttl 24h --password-file /etc/pw --api-key [redacted]"},
		{"/usr/local/bin/tool --password= --verbose", "/usr/local/bin/tool --password= --verbose"},
		{"/usr/bin/curl -s -u admin:S3cret --fail https://a.example", "/usr/bin/curl -s -u admin:[redacted] --fail https://a.example"},
		{"/usr/bin/curl --silent --user 'admin:two words' https://a.example", "/usr/bin/curl --silent --user 'admin:[redacted]' https://a.example"},
		{"/usr/bin/curl -u admin:'two words' https://a.example", "/usr/bin/curl -u admin:[redacted] https://a.example"},
		{"/usr/bin/curl --compressed -H 'Authorization: Bearer opaque' --token t1 https://a.example", "/usr/bin/curl --compressed -H 'Authorization: Bearer [redacted]' --token [redacted] https://a.example"},
		{"alice : TTY=pts/0 ; PWD=/home/alice/Bob's files ; USER=root ; COMMAND=/usr/bin/mysql --password=hunter2 -e 'select 1'", "alice : TTY=pts/0 ; PWD=/home/alice/Bob's files ; USER=root ; COMMAND=/usr/bin/mysql --password=[redacted] -e 'select 1'"},
		{"alice : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/mysqldump --single-transaction --password=hunter2 db", "alice : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/mysqldump --single-transaction --password=[redacted] db"},
		{"/usr/local/bin/tool --password", "/usr/local/bin/tool --password"},
		{"/usr/bin/curl -u --password=hunter2 https://a.example", "/usr/bin/curl -u --password=[redacted] https://a.example"},
		{`/usr/local/bin/tool a\\ --password=hunter2`, `/usr/local/bin/tool a\\ --password=[redacted]`},
	}
	for _, test := range tests {
		got := RedactCommand(test.before)
		if got != test.after {
			t.Errorf("RedactCommand(%q)\n got %q\nwant %q", test.before, got, test.after)
		}
		for _, secret := range []string{"hunter2", "S3cret", "abc", "p1", "p2", "two", "t0k", "c5", "opaque", "t1"} {
			if strings.Contains(got, secret) && !strings.Contains(test.after, secret) {
				t.Errorf("RedactCommand(%q) leaks %q: %q", test.before, secret, got)
			}
		}
	}
}

// FuzzRedactCommandSecretOption checks that a secret option or variable is redacted whatever arguments come
// before it.
func FuzzRedactCommandSecretOption(f *testing.F) {
	for _, seed := range []string{"/usr/bin/mysqldump --single-transaction", "/usr/bin/tool --verbose -v", "/usr/bin/curl -u", "/usr/bin/tool 'a b", "/usr/bin/tool a\\", "PWD=/x'y ; COMMAND=/usr/bin/tool -e '", "/usr/bin/curl -H 'Authorization: x", "/usr/bin/tool --password", "-H0Auth:", "--password -H 'Authorization: x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, prefix string) {
		if strings.Contains(prefix, "Zq9") {
			t.Skip()
		}
		for _, option := range []string{" --password=Zq9secret", " --password Zq9secret", " --api-key Zq9secret", " -p9Zq9secret", " -p Zq9secret", " -u admin:Zq9secret",
			" -storepass Zq9secret", " -passin=Zq9secret", " -pass pass:Zq9secret", " /usr/bin/mysql -pZq9secret", " /usr/bin/redis-cli -a Zq9secret", " API_TOKEN=Zq9secret"} {
			if got := RedactCommand(prefix + option); strings.Contains(got, "Zq9") {
				t.Fatalf("RedactCommand(%q) = %q", prefix+option, got)
			}
		}
	})
}

func TestRedactCommandPasswordVariables(t *testing.T) {
	tests := map[string]string{
		"alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; ENV=MYSQL_PWD=hunter2 ; COMMAND=/usr/bin/mysql": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; ENV=MYSQL_PWD=[redacted] ; COMMAND=/usr/bin/mysql",
		"/usr/bin/env MYSQL_PWD=hunter2 mysqldump db":                                                      "/usr/bin/env MYSQL_PWD=[redacted] mysqldump db",
		"/usr/bin/env mysql_pwd='two words' DB_PASSWD=x /app":                                              "/usr/bin/env mysql_pwd='[redacted]' DB_PASSWD=[redacted] /app",
		"alice : TTY=pts/0 ; PWD=/home/x ; USER=root ; COMMAND=/usr/bin/id":                                "alice : TTY=pts/0 ; PWD=/home/x ; USER=root ; COMMAND=/usr/bin/id",
		"/usr/bin/env PWD=/home/x OLDPWD=/tmp /app":                                                        "/usr/bin/env PWD=/home/x OLDPWD=/tmp /app",
	}
	for before, after := range tests {
		if got := RedactCommand(before); got != after {
			t.Errorf("RedactCommand(%q)\n got %q\nwant %q", before, got, after)
		}
	}
}

func TestRedactTextKeyValueSeparators(t *testing.T) {
	tests := map[string]string{
		"production.ERROR: Login failed array ( 'email' => 'a', 'password' => 'abc', 'remember' => true, )": "production.ERROR: Login failed array ( 'email' => 'a', 'password' => '[redacted]', 'remember' => true, )",
		`production.ERROR: Config {"secret" => "abc", "debug" => false}`:                                    `production.ERROR: Config {"secret" => "[redacted]", "debug" => false}`,
		"production.ERROR: Request ['api_key' => 'abc123', 'page' => 2]":                                    "production.ERROR: Request ['api_key' => '[redacted]', 'page' => 2]",
		"production.ERROR: Request ['password'=>'abc', 'page'=>2]":                                          "production.ERROR: Request ['password'=>'[redacted]', 'page'=>2]",
		`production.ERROR: Request ['password' => 'it\'s abc']`:                                             `production.ERROR: Request ['password' => '[redacted]']`,
		"production.ERROR: Array ( [password] => abc [page] => 2 )":                                         "production.ERROR: Array ( [password] => [redacted] [page] => 2 )",
		`production.ERROR: Login failed {"password":"abc","remember":true}`:                                 `production.ERROR: Login failed {"password":"[redacted]","remember":true}`,
		`production.ERROR: Login failed {"password" : "abc"}`:                                               `production.ERROR: Login failed {"password" : "[redacted]"}`,
		"production.ERROR: Mailer failed: password=abc rejected":                                            "production.ERROR: Mailer failed: password=[redacted] rejected",
		"production.ERROR: Mailer failed: password = abc rejected":                                          "production.ERROR: Mailer failed: password = [redacted] rejected",
		"production.ERROR: Mailer failed: password: abc rejected":                                           "production.ERROR: Mailer failed: password: [redacted] rejected",
		"production.ERROR: Mailer failed: password='two words' rejected":                                    "production.ERROR: Mailer failed: password='[redacted]' rejected",
	}
	for before, after := range tests {
		got := RedactText(before)
		if got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
		}
		if strings.Contains(got, "abc") || strings.Contains(got, "two words") {
			t.Errorf("RedactText(%q) leaks a secret: %q", before, got)
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

func TestRedactKeepsTextAfterAnInvalidByte(t *testing.T) {
	latin1 := newEvent(SourceApp, KindAppError, testNow, "production\xe9"+strings.Repeat("a", 2990))
	latin1.set("file", "/var/log/caf\xe9.log")
	latin1.Program = "app\xff"
	got := Redact(latin1)
	if want := "production\uFFFD" + strings.Repeat("a", MaxMessageLength-len("production\uFFFD")); got.Message != want {
		t.Fatalf("message = %q (%d bytes)", got.Message[:min(len(got.Message), 40)], len(got.Message))
	}
	if got.Fields["file"] != "/var/log/caf\uFFFD.log" || got.Program != "app\uFFFD" {
		t.Fatalf("file = %q, program = %q", got.Fields["file"], got.Program)
	}
	data, err := json.Marshal(got)
	if err != nil || !utf8.Valid(data) {
		t.Fatalf("marshal error %v, valid UTF-8 %v", err, utf8.Valid(data))
	}
}

func TestCut(t *testing.T) {
	tests := []struct {
		name, in string
		max      int
		want     string
	}{
		{"short", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"ascii", "hello world", 5, "hello"},
		{"rune ends at the limit", "ab€", 5, "ab€"},
		{"rune straddles the limit by one byte", "ab€", 4, "ab"},
		{"rune straddles the limit by two bytes", "ab€", 3, "ab"},
		{"four byte rune straddles the limit", "a😀b", 4, "a"},
		{"invalid byte early", "ab\xe9" + strings.Repeat("c", 20), 10, "ab\uFFFDccccc"},
		{"invalid byte at the limit", "abcd\xe9fg", 5, "abcd"},
		{"invalid bytes in a short string", "caf\xe9 cr\xe8me", 20, "caf\uFFFD cr\uFFFDme"},
		{"replacements grow past the limit", strings.Repeat("a\xe9", 4), 8, "a\uFFFDa\uFFFD"},
		{"replacement straddles the limit", "abcdef\xe9", 8, "abcdef"},
		{"stray continuation bytes", "ab\x80\x80\x80\x80cd", 20, "ab\uFFFDcd"},
		{"truncated rune inside", "a\xe2\x82b", 10, "a\uFFFDb"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cut(test.in, test.max); got != test.want {
				t.Fatalf("cut(%q, %d) = %q, want %q", test.in, test.max, got, test.want)
			}
		})
	}
}

func FuzzCut(f *testing.F) {
	for _, seed := range []string{"", "hello", "ab€cd", "a😀b", "ab\xe9cd", strings.Repeat("a\xe9", 50), "\x80\x80\x80\x80", "\xf0\x9f\x98"} {
		f.Add(seed, 7)
	}
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 1<<16 {
			t.Skip()
		}
		got := cut(s, max)
		if len(got) > max || !utf8.ValidString(got) {
			t.Fatalf("cut(%q, %d) = %q: %d bytes, valid %v", s, max, got, len(got), utf8.ValidString(got))
		}
		if utf8.ValidString(s) {
			if !strings.HasPrefix(s, got) || len(got) < min(len(s), max)-(utf8.UTFMax-1) {
				t.Fatalf("cut(%q, %d) = %q is not the longest whole rune prefix", s, max, got)
			}
		}
	})
}

// TestCutLargeInput checks that cut only looks at the bytes it keeps: a huge line with an invalid byte near
// the start still keeps max bytes, and a limit as large as the input is handled in one pass.
func TestCutLargeInput(t *testing.T) {
	huge := "ab\xe9" + strings.Repeat("x", 16<<20)
	if got := cut(huge, MaxMessageLength); len(got) != MaxMessageLength || !strings.HasPrefix(got, "ab\uFFFDx") {
		t.Fatalf("cut kept %d bytes", len(got))
	}
	mixed := strings.Repeat(strings.Repeat("y", 99)+"\xe9", 1<<15)
	got := cut(mixed, len(mixed))
	if len(got) > len(mixed) || len(got) < len(mixed)-utf8.UTFMax || !utf8.ValidString(got) {
		t.Fatalf("cut kept %d of %d bytes", len(got), len(mixed))
	}
}

func BenchmarkCut(b *testing.B) {
	for _, size := range []int{1 << 10, 1 << 14, 1 << 18} {
		s := "ab\xe9" + strings.Repeat("y\xe9", size)
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				cut(s, size)
			}
		})
	}
}

func TestSecretName(t *testing.T) {
	tests := map[string]bool{
		"password": true, "PASSWD": true, "pwd": true, "Pwd": true, "MYSQL_PWD": true, "passphrase": true,
		"storepass": true, "-srcstorepass": true, "--client-secret": true, "api_key": true, "X-Api-Key": true,
		"apiKey": true, "AWS_SECRET_ACCESS_KEY": true, "access.token": true, "oauth2-bearer": true,
		"Authorization": true, "Proxy-Authorization": true, "Private-Token": true, "Cookie": true, "Set-Cookie": true,
		"PHPSESSID": true, "session_id": true, "OAUTH_CREDENTIALS": true, "creds": true, "NODE_AUTH_TOKEN": true,
		"keystore_password": true, "keyring-passphrase": true, "Dpassword": true,

		"user": false, "host": false, "page": false, "TTY": false, "COMMAND": false, "ENV": false,
		"keyboard": false, "monkey": false, "keyword": false, "keywords": false, "author": false, "passive-ftp": false,
		"bypass": false, "GIT_ASKPASS": false, "SSH_ASKPASS": false, "askpass": false, "keyring": false,
		"keyserver": false, "recv-keys": false, "newkey": false, "keyout": false, "keystore": false,
		"importkeystore": false, "genkeypair": false, "pubkey": false, "ssh-publickey": false,
		"password-file": false, "token-ttl": false, "password-stdin": false, "SSH_AUTH_SOCK": false,
		"no-ask-password": false, "ask-vault-pass": false, "allow-unauthenticated": false, "skip-auth": false,
		"discovery-token-ca-cert-hash": false, "key-size": false,
	}
	for name, want := range tests {
		if got := secretName(name); got != want {
			t.Errorf("secretName(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestRedactCommandSecretOptionsWithOneDash covers options with a single dash and the password options of
// particular programs: keytool and openssl spell long options with one dash, and -p is a password only on its
// own, before a digit or quote, or for a MySQL client.
func TestRedactCommandSecretOptionsWithOneDash(t *testing.T) {
	tests := []struct{ before, after string }{
		{"/usr/bin/keytool -list -storepass changeit", "/usr/bin/keytool -list -storepass [redacted]"},
		{"/usr/bin/keytool -importkeystore -srcstorepass s1 -deststorepass=s2 -keypass s3", "/usr/bin/keytool -importkeystore -srcstorepass [redacted] -deststorepass=[redacted] -keypass [redacted]"},
		{"/usr/bin/openssl enc -aes-256-cbc -pass pass:hunter2 -in a", "/usr/bin/openssl enc -aes-256-cbc -pass [redacted] -in a"},
		{"/usr/bin/openssl pkcs12 -export -passin pass:hunter3 -passout pass:hunter4", "/usr/bin/openssl pkcs12 -export -passin [redacted] -passout [redacted]"},
		{"/usr/bin/openssl enc -k hunter5 -in a", "/usr/bin/openssl enc -k [redacted] -in a"},
		{"/usr/bin/curl --oauth2-bearer tok123 https://a.example", "/usr/bin/curl --oauth2-bearer [redacted] https://a.example"},
		{"/usr/bin/curl -H 'Private-Token: tok456' https://gitlab.example", "/usr/bin/curl -H 'Private-Token: [redacted]' https://gitlab.example"},
		{"/usr/bin/curl -b 'sid=abc; theme=dark' https://a.example", "/usr/bin/curl -b [redacted] https://a.example"},
		{"/usr/bin/redis-cli -h cache -a pw789 ping", "/usr/bin/redis-cli -h cache -a [redacted] ping"},
		{"/usr/bin/sshpass -p pw321 ssh host", "/usr/bin/sshpass -p [redacted] ssh host"},
		{"/usr/bin/java -Dspring.datasource.password=pw1 -jar app.jar", "/usr/bin/java -Dspring.datasource.password=[redacted] -jar app.jar"},
		{`/usr/bin/psql -c 'ALTER USER bob PASSWORD \'secret1\''`, `/usr/bin/psql -c 'ALTER USER bob PASSWORD \'[redacted]\''`},
		{"/usr/bin/psql -c ALTER USER bob PASSWORD 'secret2'", "/usr/bin/psql -c ALTER USER bob PASSWORD '[redacted]'"},
		{`/usr/bin/mysql -e 'CREATE USER app IDENTIFIED BY \'secret3\''`, `/usr/bin/mysql -e 'CREATE USER app IDENTIFIED BY \'[redacted]\''`},
		{`/usr/bin/mysql -e 'ALTER USER app IDENTIFIED WITH caching_sha2_password BY \'secret4\''`, `/usr/bin/mysql -e 'ALTER USER app IDENTIFIED WITH caching_sha2_password BY \'[redacted]\''`},
		{`/bin/sh -c 'mysql -pS3cret -e \'select 1\''`, `/bin/sh -c 'mysql -p[redacted] -e \'select 1\''`},
		{`/bin/sh -c "redis-cli -a pw555 ping"`, `/bin/sh -c "redis-cli -a [redacted] ping"`},
		{"/usr/bin/tool -p'two words' -p9x", "/usr/bin/tool -p[redacted] -p[redacted]"},
		{"/usr/bin/kubectl create secret generic db --from-literal=password=pw2", "/usr/bin/kubectl create secret generic db --from-literal=password=[redacted]"},
	}
	for _, test := range tests {
		if got := RedactCommand(test.before); got != test.after {
			t.Errorf("RedactCommand(%q)\n got %q\nwant %q", test.before, got, test.after)
		}
	}
}

// TestRedactCommandKeepsHarmlessCommands checks that options that look secret by name but take no value or name
// a file, and -p groups of flags, keep the command readable.
func TestRedactCommandKeepsHarmlessCommands(t *testing.T) {
	for _, command := range []string{
		"/usr/bin/tar -pczf /backup/etc.tgz /etc",
		"/usr/bin/find /var/www -perm 644 -print0",
		"/usr/bin/systemctl --no-ask-password restart nginx",
		"/usr/bin/ansible-playbook --ask-vault-pass site.yml",
		"/usr/bin/apt-get install --allow-unauthenticated nginx",
		"/usr/bin/docker login --password-stdin registry.example.com",
		"/usr/bin/ssh -o PasswordAuthentication=no -o PubkeyAuthentication=yes host",
		"/usr/bin/openssl req -newkey rsa:2048 -keyout /etc/ssl/a.key -out /etc/ssl/a.csr",
		"/usr/bin/keytool -list -keystore /etc/app/keystore.jks",
		"/usr/bin/keytool -genkeypair -alias app -keyalg RSA -keysize 2048",
		"/usr/bin/openssl x509 -pubkey -noout -in /etc/ssl/a.crt",
		"/usr/bin/git -c core.askPass=/usr/bin/true log --author=alice",
		"/usr/bin/passwd alice",
		"/usr/bin/kubectl get secrets -n prod",
		"/usr/bin/ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519",
		"/usr/bin/wget --passive-ftp ftp://mirror.example/a.iso",
		"/usr/bin/mysql -u root --password= shop",
		"alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/vim /etc/nginx/nginx.conf",
		"keycloak : TTY=pts/0 ; PWD=/opt/keycloak ; USER=root ; COMMAND=/usr/bin/id",
	} {
		if got := RedactCommand(command); got != command {
			t.Errorf("RedactCommand(%q)\n got %q", command, got)
		}
	}
}

func TestRedactTextPwdKeys(t *testing.T) {
	tests := map[string]string{
		"production.ERROR: Login failed pwd=hunter16 passwd=hunter17":                                             "production.ERROR: Login failed pwd=[redacted] passwd=[redacted]",
		`production.ERROR: Login failed {"pwd":"hunter18"}`:                                                       `production.ERROR: Login failed {"pwd":"[redacted]"}`,
		"production.ERROR: Login failed ['pwd' => 'hunter19']":                                                    "production.ERROR: Login failed ['pwd' => '[redacted]']",
		"production.ERROR: SQLSTATE[08001] connect failed: Uid=app;Pwd=S3cret;Server=db1":                         "production.ERROR: SQLSTATE[08001] connect failed: Uid=app;Pwd=[redacted];Server=db1",
		"production.ERROR: odbc_connect(Driver={ODBC Driver 18};Server=db;UID=sa;PWD=S3cret;Encrypt=yes)":         "production.ERROR: odbc_connect(Driver={ODBC Driver 18};Server=db;UID=sa;PWD=[redacted];Encrypt=yes)",
		"production.ERROR: SQLSTATE[HY000] [1045] Access denied for user 'app'@'localhost' (using password: YES)": "production.ERROR: SQLSTATE[HY000] [1045] Access denied for user 'app'@'localhost' (using password: YES)",
		"production.ERROR: env PWD=/var/www/shop OLDPWD=/root":                                                    "production.ERROR: env PWD=/var/www/shop OLDPWD=/root",
	}
	for before, after := range tests {
		if got := RedactText(before); got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
		}
	}
}

// TestRedactTextEscapedJSON covers JSON inside a JSON string, as Laravel repeats an exception message in the
// exception context of the same line, at one and two levels of escaping.
func TestRedactTextEscapedJSON(t *testing.T) {
	tests := map[string]string{
		`production.ERROR: ... {"exception":"[object] (Exception(code: 0): bad {\"password\":\"hunter14\"}"}`:              `production.ERROR: ... {"exception":"[object] (Exception(code: 0): bad {\"password\":\"[redacted]\"}"}`,
		`production.ERROR: Webhook failed {"payload":"{\"api_key\":\"k-777\",\"id\":7}"}`:                                  `production.ERROR: Webhook failed {"payload":"{\"api_key\":\"[redacted]\",\"id\":7}"}`,
		`production.ERROR: Retry {"job":"{\"payload\":\"{\\\"token\\\":\\\"t-888\\\"}\"}"}`:                                `production.ERROR: Retry {"job":"{\"payload\":\"{\\\"token\\\":\\\"[redacted]\\\"}\"}"}`,
		`production.ERROR: Login {"body":"{\"password\":\"a\\\"b c\",\"remember\":true}"}`:                                 `production.ERROR: Login {"body":"{\"password\":\"[redacted]\",\"remember\":true}"}`,
		`production.ERROR: Login {"body":"{\"password\" : \"hunter15\"}"}`:                                                 `production.ERROR: Login {"body":"{\"password\" : \"[redacted]\"}"}`,
		`production.ERROR: Login {"body":"password=hunter13\nnext"}`:                                                       `production.ERROR: Login {"body":"password=[redacted]\nnext"}`,
		`production.ERROR: Request {"headers":"{\"Cookie\":\"a=1; laravel_session=s9\"}","authenticated":false}`:           `production.ERROR: Request {"headers":"{\"Cookie\":\"[redacted]\"}","authenticated":false}`,
		`production.ERROR: Request {"exception":"[object] (Exception(code: 0): Invalid token \"t-999\" at /app/A.php:3)"}`: `production.ERROR: Request {"exception":"[object] (Exception(code: 0): Invalid token \"[redacted]\" at /app/A.php:3)"}`,
	}
	for before, after := range tests {
		if got := RedactText(before); got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
		}
	}

	line := `[2026-10-31 19:00:03] production.ERROR: Client error: POST https://api.x/login resulted in 401 {"password":"hunter14"} {"exception":"[object] (GuzzleHttp\\Exception\\ClientException(code: 401): Client error {\"password\":\"hunter14\"} at /var/www/shop/vendor/a.php:113)"}`
	e, ok := ParseMonolog(line, "/var/www/shop/storage/logs/laravel.log", testNow)
	if !ok {
		t.Fatal("not an app error")
	}
	if got := Redact(e); strings.Contains(got.Message, "hunter14") {
		t.Fatalf("app error = %q", got.Message)
	}
}

// secretShapes are the ways a secret is written in commands and text, with the secret Zq9 inside. Every
// redaction entry point must remove it from every shape it can meet.
var secretShapes = []string{
	"API_TOKEN=Zq9", "ENV=AWS_SECRET_ACCESS_KEY=Zq9", "MYSQL_PWD=Zq9", "PGPASSWORD='Zq9 x'",
	"--client-secret=Zq9", "--client-secret Zq9", "-storepass Zq9", "-storepass=Zq9", "--password='Zq9 x'",
	"token: Zq9", "password=Zq9", "pwd=Zq9", `"api_key":"Zq9"`, `"Password" : "Zq9"`, "'password' => 'Zq9'",
	"[secret] => Zq9", `{\"password\":\"Zq9\"}`, `{\\\"token\\\":\\\"Zq9\\\"}`, "Uid=a;Pwd=Zq9;",
	"https://deploy:Zq9@git.example/a.git", "https://Zq9Zq9Zq9Zq9Zq9Zq9Zq9Zq9Zq9Zq9Zq9@10.0.0.1/",
	"https://a.example/cb?access_token=Zq9&page=2", "https://a.example/go?next=/reset?token=Zq9",
	"https://a.example/go?next=%2Freset%3Ftoken%3DZq9", "https://a.example/go?next=%252Freset%253Ftoken%253DZq9",
	"-H 'Authorization: Bearer Zq9'", "-H 'Cookie: theme=dark; sid=Zq9'", `--header "X-Api-Key: Zq9"`,
	"Authorization: Bearer Zq9", "PASSWORD 'Zq9'", "IDENTIFIED BY 'Zq9'",
}

func TestRedactSecretShapes(t *testing.T) {
	for _, shape := range secretShapes {
		for name, redact := range map[string]func(string) string{"RedactCommand": RedactCommand, "RedactText": RedactText} {
			for _, s := range []string{shape, "/usr/bin/tool --verbose " + shape + " --quiet", "x " + shape + ", y"} {
				if got := redact(s); strings.Contains(got, "Zq9") {
					t.Errorf("%s(%q) = %q", name, s, got)
				}
			}
		}

		sudo := "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/local/bin/tool " + shape
		e, ok := ParseAuth("sudo", sudo, testNow)
		if !ok {
			t.Fatalf("not a sudo line: %q", sudo)
		}
		if got := Redact(e); strings.Contains(got.Message+fmt.Sprint(got.Fields), "Zq9") {
			t.Errorf("sudo %q = %q %v", shape, got.Message, got.Fields)
		}

		entry, err := json.Marshal(map[string]string{"__CURSOR": "s=1", "__REALTIME_TIMESTAMP": "1793473434341336", "SYSLOG_IDENTIFIER": "sudo", "_EXE": "/usr/bin/sudo", "_UID": "1000", "MESSAGE": "   " + sudo})
		if err != nil {
			t.Fatal(err)
		}
		je, err := ParseJournalEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		if e, ok := ParseAuth(je.Identifier, je.Message, je.At); !ok {
			t.Errorf("journal entry not parsed: %q", sudo)
		} else if got := Redact(e); strings.Contains(got.Message+fmt.Sprint(got.Fields), "Zq9") {
			t.Errorf("journal sudo %q = %q", shape, got.Message)
		}

		monolog := "[2026-10-31 19:00:03] production.ERROR: Call failed " + shape + ` {"exception":"[object] (Exception(code: 0): ` + strings.ReplaceAll(shape, `"`, `\"`) + `)"}`
		if e, ok := ParseMonolog(monolog, "/var/www/shop/storage/logs/laravel.log", testNow); !ok {
			t.Errorf("not an app error: %q", monolog)
		} else if got := Redact(e); strings.Contains(got.Message, "Zq9") {
			t.Errorf("app error %q = %q", monolog, got.Message)
		}
	}
}

// FuzzRedactSecretShapes checks every secret shape after arbitrary text, in commands and in free text.
func FuzzRedactSecretShapes(f *testing.F) {
	for _, seed := range []string{"/usr/bin/tool --verbose", "production.ERROR: failed", `{"exception":"[object] (`, "alice : PWD=/x'y ; COMMAND=/bin/sh -c '", "-u", "--password", "PWD="} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, prefix string) {
		if strings.Contains(prefix, "Zq9") {
			t.Skip()
		}
		for _, shape := range secretShapes {
			for name, redact := range map[string]func(string) string{"RedactCommand": RedactCommand, "RedactText": RedactText} {
				if got := redact(prefix + " " + shape); strings.Contains(got, "Zq9") {
					t.Fatalf("%s(%q) = %q", name, prefix+" "+shape, got)
				}
			}
		}
	})
}
