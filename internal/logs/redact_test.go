package logs

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
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
		"/a?sess_id=s1&SESS-ID=s2&api.key=k":                              "/a?sess_id=[redacted]&SESS-ID=[redacted]&api.key=[redacted]",
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

// TestRedactTextCommandLines covers command lines quoted in free text, such as an application error about a
// failed process.
func TestRedactTextCommandLines(t *testing.T) {
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
		"alice : PWD=/srv ; USER=root ; ENV=AWS_SECRET_ACCESS_KEY=abc123 HOME=/root ; COMMAND=/usr/bin/aws s3 ls":      "alice : PWD=[redacted] ; USER=root ; ENV=AWS_SECRET_ACCESS_KEY=[redacted] ; COMMAND=/usr/bin/aws s3 ls",
		"/usr/bin/kubeadm join 10.0.0.1:6443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:ab": "/usr/bin/kubeadm join 10.0.0.1:6443 --token [redacted] --discovery-token-ca-cert-hash sha256:ab",
		"/usr/local/bin/tool --api-key=k1 --client-secret s2 --secret=s3 --pass p4":                                    "/usr/local/bin/tool --api-key=[redacted] --client-secret [redacted] --secret=[redacted] --pass [redacted]",
		"/usr/local/bin/vault login --DB_PASSWORD x --token-ttl 24h":                                                   "/usr/local/bin/vault login --DB_PASSWORD [redacted] --token-ttl 24h",
		"/usr/bin/curl -u admin:S3cret https://api.example/v1":                                                         "/usr/bin/curl -u admin:[redacted] https://api.example/v1",
		"/usr/bin/curl --user=admin:S3cret https://api.example/v1":                                                     "/usr/bin/curl --user=admin:[redacted] https://api.example/v1",
		"/usr/bin/curl -uadmin:S3cret https://api.example/v1":                                                          "/usr/bin/curl -uadmin:[redacted] https://api.example/v1",
		"/usr/bin/curl -H Authorization: Bearer opaque-token https://api.example":                                      "/usr/bin/curl -H Authorization: Bearer [redacted] https://api.example",
		"/usr/bin/curl -H 'Authorization: Bearer opaque-token' https://a.example":                                      "/usr/bin/curl -H 'Authorization: Bearer [redacted]' https://a.example",
		`/usr/bin/curl --header "X-Api-Key: k3y" -H "Accept: text/plain" -o out`:                                       `/usr/bin/curl --header "X-Api-Key: [redacted]" -H "Accept: text/plain" -o out`,
		"/usr/bin/curl -H Cookie: sid=abc; theme=dark -o /tmp/out https://a.example":                                   "/usr/bin/curl -H Cookie: [redacted]",
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
		if got := RedactText(before); got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
		}
	}
}

// TestRedactTextSecretOptionAfterOtherOptions checks that an option which takes no value never swallows the
// secret option after it.
func TestRedactTextSecretOptionAfterOtherOptions(t *testing.T) {
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
		{"/usr/bin/curl -s -u admin:S3cret --fail https://a.example", "/usr/bin/curl -s -u admin:[redacted] --fail https://a.example"},
		{"/usr/bin/curl --silent --user 'admin:two words' https://a.example", "/usr/bin/curl --silent --user 'admin:[redacted]' https://a.example"},
		{"/usr/bin/curl -u admin:'two words' https://a.example", "/usr/bin/curl -u admin:[redacted] https://a.example"},
		{"/usr/bin/curl --compressed -H 'Authorization: Bearer opaque' --token t1 https://a.example", "/usr/bin/curl --compressed -H 'Authorization: Bearer [redacted]' --token [redacted] https://a.example"},
		{"alice : TTY=pts/0 ; PWD=/home/alice/Bob's files ; USER=root ; COMMAND=/usr/bin/mysql --password=hunter2 -e 'select 1'", "alice : TTY=pts/0 ; PWD=[redacted]'s files ; USER=root ; COMMAND=/usr/bin/mysql --password=[redacted] -e 'select 1'"},
		{"alice : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/mysqldump --single-transaction --password=hunter2 db", "alice : TTY=pts/0 ; PWD=[redacted] ; USER=root ; COMMAND=/usr/bin/mysqldump --single-transaction --password=[redacted] db"},
		{"/usr/local/bin/tool --password", "/usr/local/bin/tool --password"},
		{"/usr/bin/curl -u --password=hunter2 https://a.example", "/usr/bin/curl -u --password=[redacted] https://a.example"},
		{`/usr/local/bin/tool a\\ --password=hunter2`, `/usr/local/bin/tool a\\ --password=[redacted]`},
	}
	for _, test := range tests {
		got := RedactText(test.before)
		if got != test.after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", test.before, got, test.after)
		}
		for _, secret := range []string{"hunter2", "S3cret", "abc", "p1", "p2", "two", "t0k", "c5", "opaque", "t1"} {
			if strings.Contains(got, secret) && !strings.Contains(test.after, secret) {
				t.Errorf("RedactText(%q) leaks %q: %q", test.before, secret, got)
			}
		}
	}
}

// FuzzRedactTextSecretOption checks that a secret option or variable is redacted whatever arguments come
// before it.
func FuzzRedactTextSecretOption(f *testing.F) {
	for _, seed := range []string{"/usr/bin/mysqldump --single-transaction", "/usr/bin/tool --verbose -v", "/usr/bin/curl -u", "/usr/bin/tool 'a b", "/usr/bin/tool a\\", "PWD=/x'y ; COMMAND=/usr/bin/tool -e '", "/usr/bin/curl -H 'Authorization: x", "/usr/bin/tool --password", "-H0Auth:", "--password -H 'Authorization: x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, prefix string) {
		if strings.Contains(prefix, "Zq9") {
			t.Skip()
		}
		for _, option := range []string{" --password=Zq9secret", " --password Zq9secret", " --api-key Zq9secret", " -p9Zq9secret", " -p Zq9secret", " -u admin:Zq9secret",
			" -storepass Zq9secret", " -passin=Zq9secret", " -pass pass:Zq9secret", " /usr/bin/mysql -pZq9secret", " /usr/bin/redis-cli -a Zq9secret", " API_TOKEN=Zq9secret"} {
			if got := RedactText(prefix + option); strings.Contains(got, "Zq9") {
				t.Fatalf("RedactText(%q) = %q", prefix+option, got)
			}
		}
	})
}

func TestRedactTextPasswordVariables(t *testing.T) {
	tests := map[string]string{
		"alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; ENV=MYSQL_PWD=hunter2 ; COMMAND=/usr/bin/mysql": "alice : TTY=pts/0 ; PWD=[redacted] ; USER=root ; ENV=MYSQL_PWD=[redacted] ; COMMAND=/usr/bin/mysql",
		"/usr/bin/env MYSQL_PWD=hunter2 mysqldump db":                                                      "/usr/bin/env MYSQL_PWD=[redacted] mysqldump db",
		"/usr/bin/env mysql_pwd='two words' DB_PASSWD=x /app":                                              "/usr/bin/env mysql_pwd='[redacted]' DB_PASSWD=[redacted] /app",
		"alice : TTY=pts/0 ; PWD=/home/x ; USER=root ; COMMAND=/usr/bin/id":                                "alice : TTY=pts/0 ; PWD=[redacted] ; USER=root ; COMMAND=/usr/bin/id",
		"/usr/bin/env PWD=/home/x OLDPWD=/tmp /app":                                                        "/usr/bin/env PWD=[redacted] OLDPWD=[redacted] /app",
		"/usr/bin/env PWD=/S3cret OLDPWD=/hunter2 /app":                                                    "/usr/bin/env PWD=[redacted] OLDPWD=[redacted] /app",
	}
	for before, after := range tests {
		if got := RedactText(before); got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
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

// TestRedactTextStructuredValues covers a secret key whose value is a JSON array or object or a PHP array, as
// Laravel logs request headers (Symfony's HeaderBag holds a list per header): the whole value is redacted, up to
// its matching bracket or parenthesis, whatever it holds.
func TestRedactTextStructuredValues(t *testing.T) {
	tests := map[string]string{
		`production.ERROR: Webhook {"headers":{"authorization":["Bearer abcdef123456"],"x-api-key":["abcdef123456"],"php-auth-pw":["hunter2x"],"accept":["*/*"]}}`: `production.ERROR: Webhook {"headers":{"authorization":[redacted],"x-api-key":[redacted],"php-auth-pw":[redacted],"accept":["*/*"]}}`,
		`production.ERROR: Login {"password":["hunter2x"],"remember":true}`:                                                                                        `production.ERROR: Login {"password":[redacted],"remember":true}`,
		`production.ERROR: Login {"token":{"value":"abcdef","expires":1},"id":7}`:                                                                                  `production.ERROR: Login {"token":[redacted],"id":7}`,
		`production.ERROR: Login {"secret": [{"a": ["]}", "b\"]}"]}, 2], "id": 7}`:                                                                                 `production.ERROR: Login {"secret": [redacted], "id": 7}`,
		`production.ERROR: Login {"token":{"value":"abc`:                                                                                                           `production.ERROR: Login {"token":[redacted]`,
		`production.ERROR: Login {"password":[],"token":{},"id":7}`:                                                                                                `production.ERROR: Login {"password":[],"token":{},"id":7}`,
		`production.ERROR: Job {"payload":"{\"authorization\":[\"Bearer abc\"],\"id\":1}"}`:                                                                        `production.ERROR: Job {"payload":"{\"authorization\":[redacted],\"id\":1}"}`,
		`production.ERROR: Job {"payload":"{\"token\":{\"v\":\"a]}\\\"b\"},\"id\":2}"}`:                                                                            `production.ERROR: Job {"payload":"{\"token\":[redacted],\"id\":2}"}`,
		`production.ERROR: Job {"job":"{\"data\":\"{\\\"secret\\\":[\\\"abc\\\"],\\\"id\\\":3}\"}"}`:                                                               `production.ERROR: Job {"job":"{\"data\":\"{\\\"secret\\\":[redacted],\\\"id\\\":3}\"}"}`,
		"production.ERROR: Request Array ( [authorization] => Array ( [0] => Bearer abcdef123456 ) [accept] => Array ( [0] => text/html ) )":                       "production.ERROR: Request Array ( [authorization] => [redacted] [accept] => Array ( [0] => text/html ) )",
		"production.ERROR: Request Array ( [cookie] => Array ( [0] => a=1; b=(2) ) [id] => 7 )":                                                                    "production.ERROR: Request Array ( [cookie] => [redacted] [id] => 7 )",
		"production.ERROR: Request Array ( [token] => Array ( ) [id] => 7 )":                                                                                       "production.ERROR: Request Array ( [token] => Array ( ) [id] => 7 )",
		"production.ERROR: Request ['password' => ['a', 'b) c'], 'page' => 2]":                                                                                     "production.ERROR: Request ['password' => [redacted], 'page' => 2]",
		"production.ERROR: Request Array ( [secret] => Array ( [a] => Array ( [0] => x ) [b] => y ) [id] => 7 )":                                                   "production.ERROR: Request Array ( [secret] => [redacted] [id] => 7 )",
		"production.ERROR: Request Array ( [token] => Array ( [0] => abc":                                                                                          "production.ERROR: Request Array ( [token] => [redacted]",
	}
	for before, after := range tests {
		got := RedactText(before)
		if got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
		}
		for _, secret := range []string{"abcdef", "hunter2x", "abc\"", "b\\"} {
			if strings.Contains(got, secret) {
				t.Errorf("RedactText(%q) leaks %q: %q", before, secret, got)
			}
		}
	}
}

// One scan of a structured value records where every structure nested in it ends, so nested secret keys do not
// each read the rest of the text again: a 64 KB line of {"token":{"token":... would otherwise take seconds.
func TestStructureEndsRecordsNestedValues(t *testing.T) {
	s := `{"token":{"a":["]",{"b":1}],"c":"}"},"id":2}`
	ends := structureEnds{}
	at := strings.Index(s, ":") + 1
	end, ok := ends.valueEnd(s, at, ":", 0)
	if !ok || s[at:end] != `{"a":["]",{"b":1}],"c":"}"}` {
		t.Fatalf("value = %q, %v", s[at:end], ok)
	}
	want := structureEnds{{at, 0}: end, {strings.Index(s, "["), 0}: strings.Index(s, "],") + 1, {strings.Index(s, `{"b"`), 0}: strings.Index(s, "1}") + 2}
	if !maps.Equal(ends, want) {
		t.Fatalf("ends = %v, want %v", ends, want)
	}

	nested := strings.Repeat(`{"token":`, 8000)
	if got := RedactText(nested); got != `{"token":[redacted]` {
		t.Fatalf("nested = %q", got[:min(len(got), 40)])
	}
}

// TestRedactTextMultiLineArrays covers print_r and var_export output over several lines, as written by an
// application that keeps line breaks, and with its line breaks escaped inside a JSON string.
func TestRedactTextMultiLineArrays(t *testing.T) {
	printR := "Array\n(\n    [authorization] => Array\n        (\n            [0] => Bearer abcdef123456\n        )\n\n    [accept] => Array\n        (\n            [0] => text/html\n        )\n\n)\n"
	tests := map[string]string{
		"production.ERROR: Headers " + printR:                                                                                           "production.ERROR: Headers Array\n(\n    [authorization] => [redacted]\n\n    [accept] => Array\n        (\n            [0] => text/html\n        )\n\n)\n",
		`production.ERROR: Headers {"dump":"` + strings.ReplaceAll(printR, "\n", `\n`) + `"}`:                                           `production.ERROR: Headers {"dump":"Array\n(\n    [authorization] => [redacted]\n\n    [accept] => Array\n        (\n            [0] => text/html\n        )\n\n)\n"}`,
		"production.ERROR: Config array (\n  'password' => \n  array (\n    0 => 'a ) b',\n    1 => 'c',\n  ),\n  'debug' => false,\n)": "production.ERROR: Config array (\n  'password' => \n  [redacted],\n  'debug' => false,\n)",
	}
	for before, after := range tests {
		got := RedactText(before)
		if got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
		}
		if strings.Contains(got, "abcdef") || strings.Contains(got, "'a") {
			t.Errorf("RedactText(%q) leaks: %q", before, got)
		}
	}

	line := `[2026-10-31 19:00:03] production.ERROR: Webhook rejected {"headers":{"authorization":["Bearer abcdef123456"],"x-api-key":["abcdef123456"],"php-auth-pw":["hunter2x"]}}`
	e, ok := ParseMonolog(line, "/var/www/shop/storage/logs/laravel.log", testNow)
	if !ok {
		t.Fatal("not an app error")
	}
	if got := Redact(e); strings.Contains(got.Message, "abcdef") || strings.Contains(got.Message, "hunter2x") {
		t.Fatalf("app error = %q", got.Message)
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

	sudo, ok := ParseAuth("sudo", "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/mysql -pS3cret", testNow, "")
	if !ok {
		t.Fatal("not a sudo line")
	}
	got = Redact(sudo)
	if got.Message != "alice : TTY=pts/0 ; PWD=[redacted] ; USER=root ; COMMAND=/usr/bin/mysql [1 arg]" || got.Fields["command"] != "/usr/bin/mysql [1 arg]" {
		t.Fatalf("sudo = %+v", got)
	}

	web := newEvent(SourceWeb, KindHTTPRequest, testNow, `203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /a?token=t1&q=%3Cscript%3E HTTP/1.1" 200 1 "-" "Bearer `+jwt+`"`)
	web.set("path", "/a?token=t1&q=%3Cscript%3E")
	web.set("user_agent", "Bearer "+jwt)
	got = Redact(web)
	if web.Fields["path"] != "/a?token=t1&q=%3Cscript%3E" {
		t.Fatal("Redact must not modify the caller's fields")
	}
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
		"keystore_password": true, "keyring-passphrase": true, "Dpassword": true, "sess_id": true, "SESS-ID": true,
		"pass_wd": true, "api.key": true, "to-ken": true,
		// A switch word before a secret name proves nothing: require_password=x and skip_auth_token=x hold a value.
		"no-ask-password": true, "ask-vault-pass": true, "ask_password": true, "askPassword": true, "GIT_ASKPASS": true, "new_key": true, "allow-unauthenticated": true, "skip-auth": true,
		"require_password": true, "skip_auth_token": true, "allow_api_key": true, "ignore-token": true, "disable_secret": true, "no_pwd": true,

		"user": false, "host": false, "page": false, "TTY": false, "COMMAND": false, "ENV": false,
		"keyboard": false, "monkey": false, "keyword": false, "keywords": false, "author": false, "passive-ftp": false,
		"bypass": false, "keyring": false,
		"keyserver": false, "recv-keys": false, "keyout": false, "keystore": false,
		"importkeystore": false, "genkeypair": false, "pubkey": false, "ssh-publickey": false,

		"password-file": false, "token-ttl": false, "password-stdin": false, "SSH_AUTH_SOCK": false,
		"discovery-token-ca-cert-hash": false, "key-size": false, "pasbypasss": false,
	}
	for name, want := range tests {
		if got := secretName(name); got != want {
			t.Errorf("secretName(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestRedactTextSecretOptionsWithOneDash covers options with a single dash and the password options of
// particular programs: keytool and openssl spell long options with one dash, and -p is a password only on its
// own or with anything attached to it, since a password attached to -p cannot be told from a group of flags.
func TestRedactTextSecretOptionsWithOneDash(t *testing.T) {
	tests := []struct{ before, after string }{
		{"/usr/bin/keytool -list -storepass changeit", "/usr/bin/keytool -list -storepass [redacted]"},
		{"/usr/bin/keytool -importkeystore -srcstorepass s1 -deststorepass=s2 -keypass s3", "/usr/bin/keytool -importkeystore -srcstorepass [redacted] -deststorepass=[redacted] -keypass [redacted]"},
		{"/usr/bin/openssl enc -aes-256-cbc -pass pass:hunter2 -in a", "/usr/bin/openssl enc -aes-256-cbc -p[redacted] [redacted] -in a"},
		{"/usr/bin/openssl pkcs12 -export -passin pass:hunter3 -passout pass:hunter4", "/usr/bin/openssl pkcs12 -export -p[redacted] [redacted] -p[redacted] [redacted]"},
		{"/usr/bin/openssl enc -k hunter5 -in a", "/usr/bin/openssl enc -k [redacted] -in a"},
		{"/usr/bin/curl --oauth2-bearer tok123 https://a.example", "/usr/bin/curl --oauth2-bearer [redacted] https://a.example"},
		{"/usr/bin/curl -H 'Private-Token: tok456' https://gitlab.example", "/usr/bin/curl -H 'Private-Token: [redacted]' https://gitlab.example"},
		{"/usr/bin/curl -b 'sid=abc; theme=dark' https://a.example", "/usr/bin/curl -b [redacted] https://a.example"},
		{"/usr/bin/redis-cli -h cache -a pw789 ping", "/usr/bin/redis-cli -h cache -a [redacted] ping"},
		{"/usr/bin/sshpass -p pw321 ssh host", "/usr/bin/sshpass -p [redacted] ssh host"},
		{"/usr/bin/sshpass -ppw321 ssh host", "/usr/bin/sshpass -p[redacted] ssh host"},
		{"/usr/local/bin/tool -pHunter2", "/usr/local/bin/tool -p[redacted]"},
		{"/usr/bin/tar -pczf /backup/etc.tgz /etc", "/usr/bin/tar -p[redacted] /backup/etc.tgz /etc"},
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
		if got := RedactText(test.before); got != test.after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", test.before, got, test.after)
		}
	}
}

// TestRedactTextKeepsHarmlessCommands checks that options whose name tells where a secret is or what kind it
// is, rather than holding it, keep the command readable.
func TestRedactTextKeepsHarmlessCommands(t *testing.T) {
	for _, command := range []string{
		"/usr/bin/docker login --password-stdin registry.example.com",
		"/usr/bin/ssh -o PasswordAuthentication=no -o PubkeyAuthentication=yes host",
		"/usr/bin/openssl req -keyout /etc/ssl/a.key -out /etc/ssl/a.csr",
		"/usr/bin/keytool -list -keystore /etc/app/keystore.jks",
		"/usr/bin/keytool -genkeypair -alias app -keyalg RSA -keysize 2048",
		"/usr/bin/git log --author=alice",
		"/usr/bin/passwd alice",
		"/usr/bin/kubectl get secrets -n prod",
		"/usr/bin/ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519",
		"/usr/bin/wget --passive-ftp ftp://mirror.example/a.iso",
	} {
		if got := RedactText(command); got != command {
			t.Errorf("RedactText(%q)\n got %q", command, got)
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
		"production.ERROR: env PWD=/var/www/shop OLDPWD=/root":                                                    "production.ERROR: env PWD=[redacted] OLDPWD=[redacted]",
		"production.ERROR: odbc_connect(Driver={ODBC Driver 18};Server=db;UID=sa;PWD=/S3cret;Encrypt=yes)":        "production.ERROR: odbc_connect(Driver={ODBC Driver 18};Server=db;UID=sa;PWD=[redacted];Encrypt=yes)",
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
	"mysql://app:Zq9/x@db:3306/shop", "amqp://app:Zq9#x@mq", "redis://:Zq9?x@db", "mysql://app:Zq9@x/y@db/shop",
	"https://a.example/cb?access_token=Zq9&page=2", "https://a.example/go?next=/reset?token=Zq9",
	"https://a.example/go?next=%2Freset%3Ftoken%3DZq9", "https://a.example/go?next=%252Freset%253Ftoken%253DZq9",
	"-H 'Authorization: Bearer Zq9'", "-H 'Cookie: theme=dark; sid=Zq9'", `--header "X-Api-Key: Zq9"`,
	"Authorization: Bearer Zq9", "PASSWORD 'Zq9'", "IDENTIFIED BY 'Zq9'",
	`"authorization":["Bearer Zq9"]`, `{"password":["Zq9 x"]}`, `{"token":{"value":"Zq9"}}`, `"secret": [{"a": ["b", "Zq9"]}]`,
	`{\"authorization\":[\"Bearer Zq9\"]}`, `{\\\"token\\\":{\\\"v\\\":\\\"Zq9\\\"}}`, "[authorization] => Array ( [0] => Bearer Zq9 )",
	"[password] => Array\n(\n    [0] => Zq9\n)\n", `[token] => Array\n(\n    [0] => Zq9\n)\n`, "'password' => ['Zq9', 'x']", "'secret' => array (\n  0 => 'Zq9',\n)",
	// A URL password that starts with / or digits and /, and a port or path before the last @.
	"mysql://app:/Zq9@db/x", "mysql://app:12/Zq9@db/x", "mysql://app:/Zq9/@db", "https://x:8080/Zq9?e=a@b", "https://ghp_Zq9:x-oauth-basic@github.com/a",
	// A secret name after a switch word, with a value in every syntax.
	"require_password=Zq9", "skip_auth_token=Zq9", "NO_PASSWORD=Zq9", `{"allow_api_key":"Zq9"}`, `{\"ignore_token\":\"Zq9\"}`,
	"'disable_secret' => 'Zq9'", "[ask_pass] => Zq9", "https://a.example/x?skip_token=Zq9&page=2", "X-Skip-Auth-Token: Zq9",
	"--require-password=Zq9", "--skip-auth-token Zq9", "--no-ask-password Zq9", "ask_password=Zq9", `{"new_key":"Zq9"}`,
	// A value only a heuristic took for no secret: a working directory, a -p group of flags.
	"PWD=/Zq9", "OLDPWD=/Zq9", "Uid=sa;PWD=/Zq9;", "-pZq9", "sshpass -pZq9 ssh h",
}

func TestRedactSecretShapes(t *testing.T) {
	for _, shape := range secretShapes {
		for name, redact := range map[string]func(string) string{"RedactText": RedactText} {
			for _, s := range []string{shape, "/usr/bin/tool --verbose " + shape + " --quiet", "x " + shape + ", y"} {
				if got := redact(s); strings.Contains(got, "Zq9") {
					t.Errorf("%s(%q) = %q", name, s, got)
				}
			}
		}

		// A log line holds no line break: sudo escapes it, Monolog writes a blank or \n in JSON.
		oneLine := strings.ReplaceAll(shape, "\n", " ")
		sudo := "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/local/bin/tool " + oneLine
		e, ok := ParseAuth("sudo", sudo, testNow, "")
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
		if e, ok := ParseAuth(je.Identifier, je.Message, je.At, je.PID); !ok {
			t.Errorf("journal entry not parsed: %q", sudo)
		} else if got := Redact(e); strings.Contains(got.Message+fmt.Sprint(got.Fields), "Zq9") {
			t.Errorf("journal sudo %q = %q", shape, got.Message)
		}

		// Every other kind gets redactEverywhere on its message and fields, which reads no command line: options
		// are read as one in application errors only.
		if !commandOption(shape) {
			for _, kind := range []string{KindSSHLoginFailed, KindSuSession, KindHTTPRequest, KindHTTPTraffic, KindCronModified} {
				e := newEvent(SourceAuth, kind, testNow, "x "+oneLine+" y")
				for _, key := range []string{"path", "referer", "user_agent", "target_user"} {
					e.set(key, oneLine)
				}
				if got := Redact(e); strings.Contains(got.Message+fmt.Sprint(got.Fields), "Zq9") {
					t.Errorf("%s %q = %q %v", kind, shape, got.Message, got.Fields)
				}
			}
			if got := redactEverywhere(shape); strings.Contains(got, "Zq9") {
				t.Errorf("redactEverywhere(%q) = %q", shape, got)
			}
		}

		escaped := strings.NewReplacer(`"`, `\"`, "\n", `\n`).Replace(shape)
		monolog := "[2026-10-31 19:00:03] production.ERROR: Call failed " + oneLine + ` {"exception":"[object] (Exception(code: 0): ` + escaped + `)"}`
		if e, ok := ParseMonolog(monolog, "/var/www/shop/storage/logs/laravel.log", testNow); !ok {
			t.Errorf("not an app error: %q", monolog)
		} else if got := Redact(e); strings.Contains(got.Message, "Zq9") {
			t.Errorf("app error %q = %q", monolog, got.Message)
		}
	}
}

// commandOption tells whether a secret shape is a command option and its value, which only an application error
// reads as one.
func commandOption(shape string) bool {
	return strings.HasPrefix(shape, "-") || strings.HasPrefix(shape, "sshpass ")
}

// A switch word (no, ask, allow, skip, ignore, disable, require) before a secret name never keeps its value, in
// any syntax that holds one.
func TestRedactSecretNamesAfterSwitchWords(t *testing.T) {
	const value = "Zq9v4lu3"
	syntaxes := []string{"%s=" + value, `"%s":"` + value + `"`, `{\"%s\":\"` + value + `\"}`, "/login?%s=" + value + "&page=2", "%s: " + value, "'%s' => '" + value + "'"}
	options := []string{"--%s=" + value, "--%s " + value}
	for _, word := range []string{"no", "ask", "allow", "skip", "ignore", "disable", "require"} {
		for _, secret := range []string{"password", "auth_token", "api_key", "secret", "pwd"} {
			for _, sep := range []string{"_", "-"} {
				name := word + sep + strings.ReplaceAll(secret, "_", sep)
				for i, syntax := range slices.Concat(syntaxes, options) {
					s := "login failed " + fmt.Sprintf(syntax, name) + " retry"
					outs := map[string]string{"RedactText": RedactText(s)}
					if i < len(syntaxes) {
						outs["redactEverywhere"] = redactEverywhere(s)
						e := newEvent(SourceWeb, KindHTTPRequest, testNow, s)
						e.set("path", s)
						got := Redact(e)
						outs["Redact"] = got.Message + fmt.Sprint(got.Fields)
					}
					if strings.HasPrefix(syntax, "/login?") {
						outs["RedactQuery"] = RedactQuery(s)
					}
					for entry, out := range outs {
						if strings.Contains(out, value) {
							t.Errorf("%s(%q) = %q", entry, s, out)
						}
					}
				}
			}
		}
	}
	for before, after := range map[string]string{
		"require_password=hunter2":         "require_password=[redacted]",
		"skip_auth_token=abc":              "skip_auth_token=[redacted]",
		"GET /x?skip_token=abc":            "GET /x?skip_token=[redacted]",
		`{"allow_api_key":"abc"}`:          `{"allow_api_key":"[redacted]"}`,
		"/usr/bin/tool --no-password abc":  "/usr/bin/tool --no-password [redacted]",
		"/usr/bin/tool --skip-token=abc x": "/usr/bin/tool --skip-token=[redacted] x",
	} {
		if got := RedactText(before); got != after {
			t.Errorf("RedactText(%q) = %q, want %q", before, got, after)
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
			for name, redact := range map[string]func(string) string{"RedactText": RedactText} {
				if got := redact(prefix + " " + shape); strings.Contains(got, "Zq9") {
					t.Fatalf("%s(%q) = %q", name, prefix+" "+shape, got)
				}
			}
		}
	})
}

// An nginx line with user:password@ URLs in the request, the referer and the user agent, and the same strings
// in every event kind and every string an event carries: the passwords are redacted whatever the kind.
func TestRedactURLPasswordsInEveryEventKind(t *testing.T) {
	line := `203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /r?next=https://bob:s3cret@10.1.1.1/ HTTP/1.1" 404 153 "https://admin:hunter2@10.0.0.5/admin" "Mozilla/5.0 https://u:pw0rd@intranet/x" "-"`
	secrets := []string{"s3cret", "hunter2", "pw0rd"}
	leaked := func(e Event) string {
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if strings.Contains(string(data), secret) {
				return secret
			}
		}
		return ""
	}

	web, ok := ParseAccessLog(line, "shop")
	if !ok {
		t.Fatal("not an access log line")
	}
	got := Redact(web)
	if secret := leaked(got); secret != "" {
		t.Fatalf("%s leaked: %+v", secret, got)
	}
	want := `203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /r?next=https://bob:[redacted]@10.1.1.1/ HTTP/1.1" 404 153 "https://admin:[redacted]@10.0.0.5/admin" "Mozilla/5.0 https://u:[redacted]@intranet/x" "-"`
	if got.Message != want || got.Fields["path"] != "/r?next=https://bob:[redacted]@10.1.1.1/" || got.Fields["user_agent"] != "Mozilla/5.0 https://u:[redacted]@intranet/x" {
		t.Fatalf("web = %+v", got)
	}
	if !got.Suspicious {
		t.Fatal("a 404 stays suspicious")
	}

	kinds := []string{KindSSHLoginFailed, KindSSHLoginSucceeded, KindSudoCommand, KindSudoFailed, KindSuSession, KindUserCreated, KindUserGroupChanged, KindPasswordChanged, KindCronModified, KindHTTPRequest, KindHTTPTraffic, KindAppError, KindLogFileRemoved}
	for _, kind := range kinds {
		e := newEvent(SourceAuth, kind, testNow, line)
		e.Username = "https://admin:hunter2@10.0.0.5/"
		e.Program = "https://u:pw0rd@intranet/x"
		for _, key := range []string{"path", "referer", "user_agent", "command", "target_user", "file", "group"} {
			e.set(key, "https://bob:s3cret@10.1.1.1/ https://admin:hunter2@localhost:8080/")
		}
		if got := Redact(e); leaked(got) != "" {
			t.Errorf("%s: %s leaked: %+v", kind, leaked(got), got)
		}
	}
}

// A password runs from the first : after // to the last @ before a blank, a quote or >, so it may hold / ? # @
// and digits unescaped. That fails closed: a port, a path or a query before an @ is redacted with it, which is
// better than sending a password a port check took for a port.
func TestRedactURLUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"connect failed: mysql://app:pa/ss@db:3306/shop": "connect failed: mysql://app:[redacted]@db:3306/shop",
		"mysql://app:/secret@db/x":                       "mysql://app:[redacted]@db/x",
		"mysql://app:12/34@db/x":                         "mysql://app:[redacted]@db/x",
		"mysql://app:/@db":                               "mysql://app:[redacted]@db",
		"mysql://app:1234@db":                            "mysql://app:[redacted]@db",
		"mysql://app:@db":                                "mysql://app:[redacted]@db",
		"amqp://app:p#ss@db":                             "amqp://app:[redacted]@db",
		"redis://:p?ss@db:6379/0":                        "redis://:[redacted]@db:6379/0",
		"mysql://app:p@ss@db/shop":                       "mysql://app:[redacted]@db/shop",
		"postgres://app:pa:ss@db/shop":                   "postgres://app:[redacted]@db/shop",
		`{"dsn":"pgsql://app:p/w@db/shop","n":1}`:        `{"dsn":"pgsql://app:[redacted]@db/shop","n":1}`,
		`<mysql://app:p/w@db>, mail a@b`:                 `<mysql://app:[redacted]@db>, mail a@b`,
		"https://ghp_Zq9xx-yy@github.com/acme/app.git":   "https://[redacted]@github.com/acme/app.git",
		"https://ghp_Zq9xx:x-oauth-basic@github.com/a":   "https://[redacted]@github.com/a",
		"https://x:8080/a 'mysql://u:p@db'":              "https://x:8080/a 'mysql://u:[redacted]@db'",

		// Over-redaction accepted to fail closed: the @ of a path or query after a : ends the redacted span.
		"https://x:8080/p?e=a@b":                             "https://x:[redacted]@b",
		"https://deploy:S3cret@git.example/a.git?email=a@b":  "https://deploy:[redacted]@b",
		"mysql://app:pa/ss@db/shop?user=a@b x":               "mysql://app:[redacted]@b x",
		"https://x:8080#a@b https://y:443?u=c@d":             "https://x:[redacted]@b https://y:[redacted]@d",
		"https://[2001:db8::1]:8080/a@b":                     "https://[redacted]@b",
		"https://x/r?next=https://bob:s3/cr@10.1.1.1/&u=a@b": "https://[redacted]@b",

		// No @, or no : before it: no password.
		"https://git.example/acme/app.git":                      "https://git.example/acme/app.git",
		"https://deploy@git.example/acme/app.git":               "https://deploy@git.example/acme/app.git",
		"https://x/a?email=a@b":                                 "https://x/a?email=a@b",
		"https://x/u/@alice/posts":                              "https://x/u/@alice/posts",
		"https://x:8080/a/b?c=d":                                "https://x:8080/a/b?c=d",
		"see https://x:8080/a and mail me at bob @ example.org": "see https://x:8080/a and mail me at bob @ example.org",
	} {
		if got := redactURLUserinfo(in); got != want {
			t.Errorf("redactURLUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

// The reviewer's URLs and the over-redaction case, through every entry point: no part of the password survives.
func TestRedactURLPasswordsFailClosed(t *testing.T) {
	for _, s := range []string{
		"connect failed: mysql://app:/Zq9secret@db/x", "connect failed: mysql://app:12/Zq9@db/x", "mysql://app:/Zq9@db",
		"https://deploy:8080/Zq9?e=a@b", "https://x:8080/p?e=Zq9@b", "mysql://app:Zq9:8080/x@y@db",
	} {
		e := newEvent(SourceWeb, KindHTTPRequest, testNow, s)
		e.set("referer", s)
		got := Redact(e)
		for name, out := range map[string]string{"redactEverywhere": redactEverywhere(s), "RedactText": RedactText(s), "Redact": got.Message + fmt.Sprint(got.Fields)} {
			if strings.Contains(out, "Zq9") {
				t.Errorf("%s(%q) = %q", name, s, out)
			}
		}
	}
}

// A line of many URLs without a blank, an @ or a host end must not make each URL search the rest of the line:
// done that way, a 1 MB line took over 30 seconds.
func TestRedactURLUserinfoLargeInput(t *testing.T) {
	start := time.Now()
	for _, s := range []string{strings.Repeat("a://b:", 1<<19/6), strings.Repeat("a://b:@ ", 1<<19/8), strings.Repeat("a://b:1/", 1<<19/8) + "@", strings.Repeat("a://b@", 1<<19/6), strings.Repeat("a://b:@", 1<<19/7)} {
		got := redactURLUserinfo(s)
		if strings.Contains(s, ":@ ") && got != strings.Repeat("a://b:[redacted]@ ", 1<<19/8) {
			t.Fatalf("redacted %d bytes into %d", len(s), len(got))
		}
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("took %s", elapsed)
	}
}

// Every event gets the secret key/value rules, which must not take a PAM management group or the user agent
// after a referer ending in a secret word for a secret.
func TestRedactKeyValuesInEveryEventKind(t *testing.T) {
	for _, tc := range []struct{ kind, message, want string }{
		{KindPasswordChanged, "pam_unix(chpasswd:chauthtok): password changed for alice", "pam_unix(chpasswd:chauthtok): password changed for alice"},
		{KindSuSession, "pam_unix(su-l:session): session opened for user root(uid=0) by alice(uid=1000)", "pam_unix(su-l:session): session opened for user root(uid=0) by alice(uid=1000)"},
		{KindHTTPRequest, `203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /x HTTP/1.1" 404 1 "https://shop.example/account/auth" "Mozilla/5.0 (X11; Linux x86_64)"`, `203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /x HTTP/1.1" 404 1 "https://shop.example/account/auth" "Mozilla/5.0 (X11; Linux x86_64)"`},
		{KindHTTPRequest, `203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /x HTTP/1.1" 404 1 "-" "okhttp/4.9 (token: abc123)"`, `203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /x HTTP/1.1" 404 1 "-" "okhttp/4.9 (token: [redacted])"`},
		{KindCronModified, `(root) CMD (curl -s "https://x/?api_key=K1" -d password=hunter2)`, `(root) CMD (curl -s "https://x/?api_key=[redacted]" -d password=[redacted])`},
	} {
		if got := Redact(newEvent(SourceAuth, tc.kind, testNow, tc.message)); got.Message != tc.want {
			t.Errorf("%s: message = %q, want %q", tc.kind, got.Message, tc.want)
		}
	}
}

// secretNameVariants spells every secret word the ways applications and tools do: in upper case, split by a
// separator (sess_id, SESS-ID, pass_wd) and after another word (api.key, client-secret, DB_PWD).
func secretNameVariants() []string {
	names := []string{"sess_id", "SESS-ID", "Sess.Id", "api.key", "pass_wd", "client-secret", "DB_PWD", "x-auth-token", "access.Token"}
	for _, word := range secretWords {
		names = append(names, word, strings.ToUpper(word), "CLIENT_"+strings.ToUpper(word))
		for _, sep := range []string{"_", "-", "."} {
			for i := 1; i < len(word); i++ {
				names = append(names, word[:i]+sep+word[i:])
			}
			names = append(names, "api"+sep+word)
		}
	}
	return names
}

// Every redaction entry point redacts the value of every secret name spelling in every syntax it reads, since
// one rule (secretName) decides what is secret and no rule may skip a text that holds such a name.
func TestRedactEverySecretNameSpelling(t *testing.T) {
	const value = "Zq9v4lu3"
	pairs := []string{"%s=" + value, `"%s":"` + value + `"`, `"%s": "` + value + `"`, `{\"%s\":\"` + value + `\"}`, "'%s' => '" + value + "'", "[%s] => " + value, "%s: " + value, "--%s=" + value, "/login?%s=" + value + "&page=2",
		`"%s":["` + value + `"]`, `{\"%s\":{\"v\":\"` + value + `\"}}`, "[%s] => Array ( [0] => " + value + " )"}
	options := []string{"--%s " + value, "-H '%s: " + value + "'"}
	// One kind per case of Redact, and one it has no case for.
	kinds := []string{KindSSHLoginFailed, KindSudoCommand, KindHTTPRequest, KindAppError, KindCronModified}
	for _, name := range secretNameVariants() {
		if !secretName(name) {
			t.Fatalf("secretName(%q) = false", name)
		}
		if got := RedactQuery("/login?" + name + "=" + value + "&page=2"); strings.Contains(got, value) {
			t.Errorf("RedactQuery(?%s=) = %q", name, got)
		}
		for i, syntax := range slices.Concat(pairs, options) {
			s := "login failed " + fmt.Sprintf(syntax, name) + " retry"
			if got := RedactText(s); strings.Contains(got, value) {
				t.Errorf("RedactText(%q) = %q", s, got)
			}
			for _, kind := range kinds {
				e := newEvent(SourceAuth, kind, testNow, s)
				for _, key := range []string{"command", "path", "user_agent", "target_user"} {
					e.set(key, s)
				}
				got := Redact(e)
				if i < len(pairs) && strings.Contains(got.Message+fmt.Sprint(got.Fields), value) {
					t.Errorf("Redact(%s %q) = %q %v", kind, s, got.Message, got.Fields)
				}
				// Options are read as a command line in application error messages only.
				if kind == KindAppError && strings.Contains(got.Message, value) {
					t.Errorf("Redact(%s %q) = %q %v", kind, s, got.Message, got.Fields)
				}
			}
			// A sudo event keeps no argument at all.
			if e, ok := ParseAuth("sudo", "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/tool "+s, testNow, ""); !ok {
				t.Errorf("not a sudo line: %q", s)
			} else if got := Redact(e); strings.Contains(got.Message+fmt.Sprint(got.Fields), value) {
				t.Errorf("sudo %q = %q %v", s, got.Message, got.Fields)
			}
		}
	}
}

// FuzzMayHoldSecretName checks that the fast path of the key/value rule is never stricter than secretName:
// a text that holds a secret name is always looked at.
func FuzzMayHoldSecretName(f *testing.F) {
	for _, name := range append(secretNameVariants(), "keyring_password", "pas-bypass-s", "pasbypasss", "ask_password", "MONKEY_TOKEN", "Key") {
		f.Add("login failed ", name, "=x")
	}
	f.Fuzz(func(t *testing.T, before, name, after string) {
		if secretName(name) && !mayHoldSecretName(before+name+after) {
			t.Fatalf("secretName(%q) but mayHoldSecretName(%q) = false", name, before+name+after)
		}
	})
}

// redactTable runs RedactText and Redact on an application error over every pair and checks that none of the
// secrets is left.
func redactTable(t *testing.T, tests map[string]string, secrets ...string) {
	t.Helper()
	for before, after := range tests {
		got := RedactText(before)
		if got != after {
			t.Errorf("RedactText(%q)\n got %q\nwant %q", before, got, after)
		}
		e := Redact(newEvent(SourceApp, KindAppError, testNow, before))
		for _, secret := range secrets {
			if strings.Contains(got, secret) || strings.Contains(e.Message, secret) {
				t.Errorf("%q leaks %q: %q / %q", before, secret, got, e.Message)
			}
		}
	}
}

// Laravel's MySQL grammar writes identifiers in backticks, and a QueryException repeats the statement with its
// bindings in place.
func TestRedactBacktickKeys(t *testing.T) {
	redactTable(t, map[string]string{
		"SQLSTATE[HY000] [2002] Connection refused (Connection: mysql, SQL: select * from `users` where `api_token` = Zk3pQ9xLr7TtVb2N limit 1)": "SQLSTATE[HY000] [2002] Connection refused (Connection: mysql, SQL: select * from `users` where `api_token` = [redacted] limit 1)",
		"SQL: update `users` set `password` = $2y$12$abcdefghij, `remember_token` = 5hJ3kQzW8LmN where `id` = 42":                                "SQL: update `users` set `password` = [redacted], `remember_token` = [redacted] where `id` = 42",
		"SELECT * FROM users WHERE `username`='bob' AND `password`='hunter2'":                                                                    "SELECT * FROM users WHERE `username`='bob' AND `password`='[redacted]'",
		"SQL: update `users` set `users`.`api_token`=Zk3pQ9xLr7TtVb2N where `id` = 1":                                                            "SQL: update `users` set `users`.`api_token`=[redacted] where `id` = 1",
		"SQL: select * from `sessions` where `id` = 5 and `name` = `password`":                                                                   "SQL: select * from `sessions` where `id` = 5 and `name` = `password`",
	}, "Zk3p", "$2y$", "5hJ3", "hunter2")
}

// An INSERT matches its values to the columns by position, so with a secret column all of them go.
func TestRedactSQLInsertValues(t *testing.T) {
	redactTable(t, map[string]string{
		"SQL: insert into `users` (`name`, `email`, `password`, `api_token`) values (John, j@example.com, $2y$12$abcdef, PlainApiTok3n))": "SQL: insert into `users` (`name`, `email`, `password`, `api_token`) values [redacted]",
		`SQL: insert into "users" ("name", "password") values (John (admin), hunter2)) at /app/A.php:3`:                                   `SQL: insert into "users" ("name", "password") values [redacted]`,
		"SQL: INSERT INTO personal_access_tokens (name, token) VALUES ('api', 'hunter2')":                                                 "SQL: INSERT INTO personal_access_tokens (name, token) VALUES [redacted]",
		"SQL: insert into `orders` (`sku`, `total`) values (A-1, 42)":                                                                     "SQL: insert into `orders` (`sku`, `total`) values (A-1, 42)",
	}, "$2y$", "PlainApiTok3n", "hunter2")
}

// Symfony's Process quotes every argument of the command an error repeats.
func TestRedactQuotedArguments(t *testing.T) {
	redactTable(t, map[string]string{
		`The command "'mysql' '-uroot' '-pZq9hunter' 'app'" failed.`:                                     `The command "'mysql' '-uroot' '-p[redacted]' 'app'" failed.`,
		`The command "'mysqldump' '--user=forge' '--password' 'Zq9hunter' 'app'" failed.`:                `The command "'mysqldump' '--user=forge' '--password' [redacted] 'app'" failed.`,
		`The command "'mysqldump' '--password=Zq9hunter' 'app'" failed.`:                                 `The command "'mysqldump' '--password=[redacted]' 'app'" failed.`,
		`The command "'curl' '-u' 'admin:Zq9hunter' 'https://a.example/'" failed.`:                       `The command "'curl' '-u' 'admin:[redacted]' 'https://a.example/'" failed.`,
		`The command "'curl' '-uadmin:Zq9hunter' 'https://a.example/'" failed.`:                          `The command "'curl' '-uadmin:[redacted]' 'https://a.example/'" failed.`,
		`The command "'sshpass' '-p' 'Zq9hunter' 'ssh' 'root@db'" failed.`:                               `The command "'sshpass' '[redacted]' [redacted] 'ssh' 'root@db'" failed.`,
		`The command "'redis-cli' '-a' 'Zq9hunter' 'ping'" failed.`:                                      `The command "'redis-cli' '-a' [redacted] 'ping'" failed.`,
		`The command "'mysql' '-pZq9'\''hunter' 'app'" failed.`:                                          `The command "'mysql' '-p[redacted]' 'app'" failed.`,
		`/usr/bin/tool "-pZq9hunter" "--token" "Zq9hunter"`:                                              `/usr/bin/tool "-p[redacted]" "--token" [redacted]`,
		`it's: the command 'mysql' '-pZq9hunter' '--password' 'Zq9hunter' '-u' 'admin:Zq9hunter' failed`: `it's: the command 'mysql' '-p[redacted]' '--password' [redacted] '-u' 'admin:[redacted]' failed`,
		`a " then 'sh' '-c' '-p Zq9 hunter' and "--token Zq9hunter"`:                                     `a " then 'sh' '-c' '-p[redacted]' and "--token [redacted]"`,
		`The command "'ls' '-la' '/var/www'" failed.`:                                                    `The command "'ls' '-la' '/var/www'" failed.`,
	}, "Zq9", "hunter")
}

// PHP's json_encode escapes every slash, and a JSON string inside another escapes the backslash again.
func TestRedactURLWithEscapedSlashes(t *testing.T) {
	redactTable(t, map[string]string{
		`Gateway failed: {"callback":"https:\/\/merchant:S3cretPw@10.0.0.5:8443\/cb"}`: `Gateway failed: {"callback":"https:\/\/merchant:[redacted]@10.0.0.5:8443\/cb"}`,
		`{"dsn":"redis:\/\/:S3cretPw@cache:6379\/0"}`:                                  `{"dsn":"redis:\/\/:[redacted]@cache:6379\/0"}`,
		`{"job":"{\"url\":\"https:\\\/\\\/merchant:S3cretPw@db\\\/x\"}"}`:              `{"job":"{\"url\":\"https:\\\/\\\/merchant:[redacted]@db\\\/x\"}"}`,
		`{"remote":"https:\/\/ghp_S3cretPwS3cretPwS3cretPw@github.com\/a.git"}`:        `{"remote":"https:\/\/[redacted]@github.com\/a.git"}`,
		`{"docs":"https:\/\/example.com\/a\/b"}`:                                       `{"docs":"https:\/\/example.com\/a\/b"}`,
	}, "S3cretPw")
}

// An Authorization header keeps a scheme the agent knows and loses anything else whole.
func TestRedactAuthorizationSchemes(t *testing.T) {
	redactTable(t, map[string]string{
		`The command "curl -H 'Authorization: SSWS 00aBcD3fGh1j' https://x.okta.com/" failed.`: `The command "curl -H 'Authorization: [redacted]' https://x.okta.com/" failed.`,
		"Discord request failed: Authorization: Bot MTk4NjIyNDgz.Cl2FMQ.ZnCjm1XV":              "Discord request failed: Authorization: [redacted]",
		"upstream said Authorization: Bearer\t00aBcD3fGh1j, status 502":                        "upstream said Authorization: Bearer\t[redacted], status 502",
		"upstream said Proxy-Authorization:Bearer   00aBcD3fGh1j next":                         "upstream said Proxy-Authorization:Bearer   [redacted] next",
		"upstream said Authorization: Basic 00aBcD3fGh1j":                                      "upstream said Authorization: Basic [redacted]",
		"upstream said X-Api-Token: Token  00aBcD3fGh1j next":                                  "upstream said X-Api-Token: Token  [redacted] next",
		"HTTP_AUTHORIZATION=GenieKey 00aBcD3fGh1j":                                             "HTTP_AUTHORIZATION=[redacted]",
	}, "00aBcD3fGh1j", "MTk4", "ZnCjm1XV")
}

func TestRedactXMLElements(t *testing.T) {
	redactTable(t, map[string]string{
		"soap <password>hunter2</password> <apiKey>AKfoo123</apiKey> <user>bob</user>":                                       "soap <password>[redacted]</password> <apiKey>[redacted]</apiKey> <user>bob</user>",
		`<wsse:Username>bob</wsse:Username><wsse:Password Type="PasswordText">hunter2</wsse:Password><a>1</a>`:               `<wsse:Username>bob</wsse:Username><wsse:Password Type="PasswordText">[redacted]</wsse:Password><a>1</a>`,
		"<credentials><login>bob</login><value>hunter2</value></credentials><id>7</id>":                                      "<credentials>[redacted]</credentials><id>7</id>",
		`{"body":"<token>hunter2<\/token><id>7<\/id>"}`:                                                                      `{"body":"<token>[redacted]<\/token><id>7<\/id>"}`,
		"cut off <ns:secret attr='1'>hunter2 and the rest":                                                                   "cut off <ns:secret attr='1'>[redacted]",
		"<password></password> <password>***</password> <password/> <secret /> <b>bold</b> a < b > c <keyboard>x</keyboard>": "<password></password> <password>***</password> <password/> <secret /> <b>bold</b> a < b > c <keyboard>x</keyboard>",
	}, "hunter2", "AKfoo123")
}

func TestRedactSerializedValues(t *testing.T) {
	redactTable(t, map[string]string{
		`job failed O:16:"App\Jobs\Sync":3:{s:8:"password";s:7:"hunter2";s:5:"token";s:6:"tok123";s:2:"id";i:7;}`: `job failed O:16:"App\Jobs\Sync":3:{s:8:"password";s:7:"[redacted]";s:5:"token";s:6:"[redacted]";s:2:"id";i:7;}`,
		`a:2:{s:3:"pin";i:4321;s:8:"password";s:9:"a";s:1:"b";}`:                                                  `a:2:{s:3:"pin";i:[redacted];s:8:"password";s:9:"[redacted]";}`,
		`{"payload":"a:1:{s:8:\"password\";s:7:\"hunter2\";}"}`:                                                   `{"payload":"a:1:{s:8:\"password\";s:7:\"[redacted]\";}"}`,
		`a:1:{s:6:"secret";a:1:{i:0;s:7:"hunter2";}}`:                                                             `a:1:{s:6:"secret";[redacted]`,
		`{"payload":"a:1:{s:8:\"password\";s:3:\"a\\\"b\";s:2:\"id\";i:7;}"}`:                                     `{"payload":"a:1:{s:8:\"password\";s:3:\"[redacted]`,
		`a:2:{s:8:"password";N;s:5:"token";b:0;s:4:"name";s:3:"bob";}`:                                            `a:2:{s:8:"password";N;s:5:"token";b:[redacted];s:4:"name";s:3:"bob";}`,
	}, "hunter2", "tok123", "4321")
}

// A value that is itself a secret name is taken as a key too, so the string after it (often the real key) is
// redacted, and the real key is still read: no value placed before a key can shift which string is its value.
// Nested arrays, objects, integer keys, strings that hold fake entries and any depth of JSON escaping included.
func TestRedactSerializedValuesThatLookLikeKeys(t *testing.T) {
	deepEscape := strings.Repeat(`\`, maxEscapeDepth+1)
	redactTable(t, map[string]string{
		`a:2:{s:4:"type";s:8:"password";s:8:"password";s:7:"hunter2";}`:                                                     `a:2:{s:4:"type";s:8:"password";s:8:"[redacted]";s:7:"[redacted]";}`,
		`{"payload":"a:2:{s:4:\"type\";s:8:\"password\";s:8:\"password\";s:7:\"hunter2\";}"}`:                               `{"payload":"a:2:{s:4:\"type\";s:8:\"password\";s:8:\"[redacted]\";s:7:\"[redacted]\";}"}`,
		`{"job":"{\"payload\":\"a:2:{s:4:\\\"type\\\";s:8:\\\"password\\\";s:8:\\\"password\\\";s:7:\\\"hunter2\\\";}\"}"}`: `{"job":"{\"payload\":\"a:2:{s:4:\\\"type\\\";s:8:\\\"password\\\";s:8:\\\"[redacted]\\\";s:7:\\\"[redacted]\\\";}\"}"}`,
		`a:2:{i:0;s:6:"secret";s:8:"password";s:7:"hunter2";}`:                                                              `a:2:{i:0;s:6:"secret";s:8:"[redacted]";s:7:"[redacted]";}`,
		`a:3:{s:4:"type";s:5:"token";s:4:"type";s:8:"password";s:8:"password";s:7:"hunter2";}`:                              `a:3:{s:4:"type";s:5:"token";s:4:"[redacted]";s:8:"password";s:8:"[redacted]";s:7:"[redacted]";}`,
		`a:2:{s:4:"type";s:6:"secret";i:5;s:8:"password";s:7:"hunter2";}`:                                                   `a:2:{s:4:"type";s:6:"secret";i:[redacted];s:8:"password";s:7:"[redacted]";}`,
		`O:8:"stdClass":2:{s:4:"kind";s:6:"apikey";s:5:"token";s:6:"tok123";}`:                                              `O:8:"stdClass":2:{s:4:"kind";s:6:"apikey";s:5:"[redacted]";s:6:"[redacted]";}`,
		`a:2:{s:4:"list";a:1:{i:0;s:5:"token";}s:8:"password";s:7:"hunter2";}`:                                              `a:2:{s:4:"list";a:1:{i:0;s:5:"token";[redacted]`,
		`a:2:{s:4:"note";s:12:"";s:3:"pin";";s:8:"password";s:7:"hunter2";}`:                                                `a:2:{s:4:"note";s:12:"";s:3:"pin";[redacted]`,
		`a:1:{s:8:"password";s:7:` + deepEscape + `"hunter2` + deepEscape + `";}`:                                           `a:1:{s:8:"password";[redacted]`,
	}, "hunter2", "tok123")
}

// A value with blanks in it that a semicolon closes is a connection string entry.
func TestRedactValueUpToSemicolon(t *testing.T) {
	redactTable(t, map[string]string{
		"Server=tcp:db;User ID=sa;Password=correct horse battery;Encrypt=yes": "Server=tcp:db;User ID=sa;Password=[redacted];Encrypt=yes",
		"Server=db;Pwd=correct horse=battery ;Encrypt=yes":                    "Server=db;Pwd=[redacted] ;Encrypt=yes",
		"login failed: password=correct horse battery":                        "login failed: password=[redacted] horse battery",
		`{"dsn":"Server=db;Password=correct horse","id":7}`:                   `{"dsn":"Server=db;Password=[redacted] horse","id":7}`,
	}, "correct horse battery", "horse=battery")
}

func TestRedactShortSecretNames(t *testing.T) {
	for name, want := range map[string]bool{
		"pw": true, "PW": true, "user_pw": true, "userPw": true, "psw": true, "otp": true, "OTPCode": true, "totp": true,
		"pin": true, "PIN": true, "pin_code": true, "sid": true, "AccountSid": true, "csrf": true, "_csrf": true, "xsrf": true,
		"X-XSRF": true, "ticket": true, "signature": true, "X-Hub-Signature-256": true, "pw2": true, "data[pw]": true,
		"shipping": false, "inside": false, "consider": false, "pinned": false, "spin": false, "ticketing": false,
		"tsid": false, "optional": false, "pwn": false, "designature": false, "pin-length": false, "otp_type": false,
	} {
		if got := secretName(name); got != want {
			t.Errorf("secretName(%q) = %v, want %v", name, got, want)
		}
	}
	redactTable(t, map[string]string{
		"login failed user=bob pw=hunter2 otp=123456 pin=4321 psw=hunter3":                   "login failed user=bob pw=[redacted] otp=[redacted] pin=[redacted] psw=[redacted]",
		`Unauthenticated {"pw":"hunter2","otp":"123456","signature":"deadbeef","csrf":"k"}`:  `Unauthenticated {"pw":"[redacted]","otp":"[redacted]","signature":"[redacted]","csrf":"[redacted]"}`,
		"GET /cgi-bin/login.cgi?username=admin&pw=hunter2&otp=123456&sid=abcdef&ticket=ST-1": "GET /cgi-bin/login.cgi?username=[redacted]&pw=[redacted]&otp=[redacted]&sid=[redacted]&ticket=[redacted]",
		"shipping=express inside=1 spin=2 tsid=000001":                                       "shipping=express inside=1 spin=2 tsid=000001",
	}, "hunter2", "hunter3", "123456", "4321", "deadbeef", "abcdef", "ST-1")
}

// Credentials that carry no name are recognized by their own format, in every string of every event.
func TestRedactKnownTokens(t *testing.T) {
	// The examples are put together here so that no secret scanner takes this file for a leak.
	stripe, hooks := "_live_51H8abcDEFghiJKL", "hooks.slack.com"
	pem := "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA7hunter2\\n-----END RSA PRIVATE KEY-----"
	tests := map[string]string{
		"Stripe key sk" + stripe + "mnoPQRstu was rejected":                                                                                         "Stripe key [redacted] was rejected",
		"keys rk" + stripe + " sk_test" + stripe[len("_live"):]:                                                                                     "keys [redacted] [redacted]",
		"github ghp_16C7e42F292c6912E7710c838347Ae178B4a and github_pat_11ABCDEFG0abcdefghij_klmnop":                                                "github [redacted] and [redacted]",
		"gho_16C7e42F292c6912E7710c83 ghu_16C7e42F292c6912E7710c83 ghs_16C7e42F292c6912E7710c83 ghr_16C7e42F292c6912E7710c83":                       "[redacted] [redacted] [redacted] [redacted]",
		"slack xoxb-123456789012-abcdefABCDEF and xoxp-123456789012-abc":                                                                            "slack [redacted] and [redacted]",
		"cURL error 28 for https://" + hooks + "/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX":                                             "cURL error 28 for https://hooks.slack.com/services/[redacted]",
		`{"url":"https:\/\/` + hooks + `\/services\/T00000000\/B00000000\/XXXXXXXXXXXX"}`:                                                           `{"url":"https:\/\/hooks.slack.com\/services\/[redacted]"}`,
		"Client error: `POST https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage` resulted in a `400 Bad Request`": "Client error: `POST https://api.telegram.org/bot[redacted]/sendMessage` resulted in a `400 Bad Request`",
		"aws AKIAIOSFODNN7EXAMPLE and ASIAIOSFODNN7EXAMPLE":                                                                                         "aws [redacted] and [redacted]",
		"gitlab glpat-abcdefghij0123456789":                                                                                                         "gitlab [redacted]",
		"key " + pem + " loaded":                                                                                                                    "key [redacted] loaded",
		"key -----BEGIN PRIVATE KEY-----\\nMIIEowIBAAKCAQEA7hunter2":                                                                                "key [redacted]",
		"boot 0123456789abcdef0123456789abcdef session 5vJ2mQXo8sKq1ZcLr9TtVb2Nw8YcHd5Mf1Js6Ga0":                                                    "boot 0123456789abcdef0123456789abcdef session 5vJ2mQXo8sKq1ZcLr9TtVb2Nw8YcHd5Mf1Js6Ga0",
		"MAKIAIOSFODNN7EXAMPLEX task_list ghp_short botany/bot12:ab":                                                                                "MAKIAIOSFODNN7EXAMPLEX task_list ghp_short botany/bot12:ab",
	}
	for before, after := range tests {
		for _, kind := range []string{KindAppError, KindHTTPRequest, KindSSHLoginFailed, KindCommand} {
			e := newEvent(SourceApp, kind, testNow, before)
			e.set("user_agent", before)
			got := Redact(e)
			if got.Message != after || got.Fields["user_agent"] != after {
				t.Errorf("%s %q\n got %q / %q\nwant %q", kind, before, got.Message, got.Fields["user_agent"], after)
			}
		}
	}
}

// A long segment after a secret-named one in the path of a web request is a token. Nothing of that shape is
// touched in other events, whose fields hold boot and session IDs.
func TestRedactWebPathTokens(t *testing.T) {
	const token = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"
	tests := map[string]string{
		"/reset-password/" + token:                "/reset-password/[redacted]",
		"/password/reset/" + token + "?page=2":    "/password/reset/[redacted]?page=2",
		"/reset%2Dpassword/" + token + "/confirm": "/reset%2Dpassword/[redacted]/confirm",
		"/api/tokens/abc/" + token + "#" + token:  "/api/tokens/abc/[redacted]#" + token,
		"/password/reset":                         "/password/reset",
		"/orders/" + token:                        "/orders/" + token,
	}
	for path, want := range tests {
		line := `203.0.113.9 - - [23/Nov/2026:10:00:00 +0000] "GET ` + path + ` HTTP/1.1" 500 153 "https://shop.example` + path + `" "Mozilla/5.0"`
		e, ok := ParseAccessLog(line, "")
		if !ok {
			t.Fatalf("not an access log line: %q", line)
		}
		got := Redact(e)
		wantLine := `203.0.113.9 - - [23/Nov/2026:10:00:00 +0000] "GET ` + want + ` HTTP/1.1" 500 153 "https://shop.example` + want + `" "Mozilla/5.0"`
		if got.Fields["path"] != want || got.Message != wantLine {
			t.Errorf("path %q\n got %q / %q\nwant %q", path, got.Fields["path"], got.Message, want)
		}
	}

	if got := pathSecretSpans("GET /blog/password-tips HTTP/1.1 /files/" + token + " /auth?next=/files/" + token); got != nil {
		t.Errorf("a path after a blank or a ? is another path: %v", got)
	}

	command := newEvent(SourceCommands, KindCommand, testNow, "/usr/bin/id [0 args]")
	command.set("cwd", "/var/lib/sessions/"+token)
	command.set("boot_id", "0123456789abcdef0123456789abcdef")
	app := newEvent(SourceApp, KindAppError, testNow, "failed")
	app.set("file", "/var/www/auth-service/storage/logs/laravel-2026-11-23.log")
	for _, e := range []Event{command, app} {
		got := Redact(e)
		for k, v := range e.Fields {
			if got.Fields[k] != v {
				t.Errorf("%s field %s = %q, want %q", e.Kind, k, got.Fields[k], v)
			}
		}
	}
}

// afterIdentified reads backwards what this pattern, which it replaced, read over the whole text before a key.
var identifiedBefore = regexp.MustCompile(`(?i)\bidentified(?:\s+with\s+\S+)?\s+$`)

func TestAfterIdentifiedMatchesThePattern(t *testing.T) {
	words := []string{"identified", "IDentified", "with", "WITH", "plugin", "'a'", "unidentified", "-identified", "withx", "", " \f\r", "identified\twith\nplugin"}
	var texts []string
	for _, a := range words {
		for _, b := range words {
			for _, c := range words {
				for _, gap := range []string{"", " ", "\t\n"} {
					texts = append(texts, a+gap+b+gap+c, a+" "+b+gap+c+gap, a+gap+b+" "+c+" ")
				}
			}
		}
	}
	for _, text := range texts {
		for at := 0; at <= len(text); at++ {
			if got, want := afterIdentified(text, at), identifiedBefore.MatchString(text[:at]); got != want {
				t.Fatalf("afterIdentified(%q, %d) = %v, want %v", text, at, got, want)
			}
		}
	}
}

func FuzzAfterIdentified(f *testing.F) {
	f.Add("ALTER USER app IDENTIFIED WITH caching_sha2_password BY 'x'", 53)
	f.Fuzz(func(t *testing.T, text string, at int) {
		if at < 0 || at > len(text) {
			t.Skip()
		}
		if got, want := afterIdentified(text, at), identifiedBefore.MatchString(text[:at]); got != want {
			t.Fatalf("afterIdentified(%q, %d) = %v, want %v", text, at, got, want)
		}
	})
}

// TestRedactLongLinesInLinearTime redacts lines of the longest length the tailer returns (maxLineBytes) that
// are made of nothing but what one rule looks for. A rule that reads the rest of the line again for every key
// took up to 38 seconds for one such line (identified by by by ...), and seconds for several others. Each line
// must be redacted in seconds, also under the race detector, and four times the text must not cost more than
// twelve times as long: a quadratic scan costs sixteen times.
func TestRedactLongLinesInLinearTime(t *testing.T) {
	fill := func(size int, prefix, unit string) string {
		return (prefix + strings.Repeat(unit, size/len(unit)+1))[:size]
	}
	type line struct{ prefix, unit string }
	lines := map[string]line{
		"identified by":       {"identified ", "by "},
		"identified by by":    {"", "identified by "},
		"identified with by":  {"", "identified with x by 'p' "},
		"pam service":         {"", "(pass:"},
		"cookie":              {"", "Cookie:a "},
		"cookie pairs":        {"", "cookie=a "},
		"nested keys":         {"", "pass="},
		"nested keys colon":   {"", "token:"},
		"authorization":       {"", "Authorization: Bot "},
		"scheme and blanks":   {"", "token=Bearer     "},
		"semicolon far away":  {"", "pwd=a b "},
		"xml open":            {"", "<password>"},
		"xml unclosed tags":   {"", "<password><"},
		"xml close escapes":   {"<password>", `<\\\\\\\\`},
		"serialized":          {"", `s:4:"pass";s:1:"a";`},
		"serialized long":     {"", `s:4:"pass";s:9:"a";`},
		"serialized numbers":  {"", `s:4:"pass";i:`},
		"serialized names":    {"", `s:4:"pass";`},
		"insert":              {"", "insert into t (pass) values "},
		"backtick keys":       {"", "`pass`=`pass`="},
		"quoted options":      {"", `'-pa' '-u' 'a:b' `},
		"stray quotes":        {`'`, `"-p a '-p b `},
		"quoted option value": {"", `'-p `},
		"escaped urls":        {"", `x:\/\/a:b@c `},
		"path segments":       {"/password", "/a"},
		"private keys":        {"", "-----BEGIN PRIVATE KEY-----"},
		"known tokens":        {"", "ghp_aaaaaaaaaaaaaaaaaaa "},
		"nested query":        {"?a=", "b=%253D%2526"},
		"nested query params": {"?", "a=b%26c%3Dd%2526e%253Df&"},
		"quotes":              {"", `pass="a pass='b `},
		"escaped quotes":      {"", `\"pass\":\"a `},
		"structures":          {"", `"token":[`},
		"php arrays":          {"", "token=>array( "},
		"short names":         {"", "pw=otp=pin="},
	}
	redact := func(l line, size int) time.Duration {
		text := fill(size, l.prefix, l.unit)
		start := time.Now()
		Redact(newEvent(SourceApp, KindAppError, testNow, text))
		pathSecretSpans(text)
		return time.Since(start)
	}
	for name, l := range lines {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			quarter, whole := redact(l, maxLineBytes/4), redact(l, maxLineBytes)
			if whole > 30*time.Second || whole > time.Second && whole > 12*quarter {
				t.Fatalf("redacting %d bytes took %v, a quarter of them %v", maxLineBytes, whole, quarter)
			}
		})
	}
}
