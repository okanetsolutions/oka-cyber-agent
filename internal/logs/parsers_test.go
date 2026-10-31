package logs

import (
	"bufio"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func authEvents(t *testing.T, fixture string) []Event {
	t.Helper()
	var events []Event
	for _, line := range readLines(t, filepath.Join("testdata", "auth", fixture)) {
		l, ok := ParseSyslog(line, testNow)
		if !ok {
			if strings.Contains(line, "sshd") || strings.Contains(line, "sudo") || strings.Contains(line, "crontab") {
				t.Errorf("unparsed syslog line: %s", line)
			}
			continue
		}
		if e, ok := ParseAuth(l.Program, l.Message, l.At); ok {
			events = append(events, e)
		}
	}
	return events
}

func kindCounts(events []Event) map[string]int {
	counts := map[string]int{}
	for _, e := range events {
		key := e.Kind
		if reason, ok := e.Fields["reason"]; ok {
			key += ":" + reason.(string)
		}
		counts[key]++
	}
	return counts
}

func TestAuthLogsPerDistribution(t *testing.T) {
	tests := map[string]map[string]int{
		"debian-12.auth.log": {
			KindSSHLoginFailed: 2, KindSSHLoginSucceeded: 1, KindSudoCommand: 1, KindSudoFailed + ":incorrect_password": 1,
			KindSudoFailed + ":not_in_sudoers": 1, KindSuSession: 5, KindUserCreated: 3, KindUserGroupChanged: 4, KindPasswordChanged: 4,
		},
		"ubuntu-24.04.auth.log": {
			KindSSHLoginFailed: 2, KindSSHLoginSucceeded: 1, KindSudoCommand: 1, KindSudoFailed + ":incorrect_password": 1,
			KindSudoFailed + ":not_in_sudoers": 1, KindSuSession: 5, KindUserCreated: 3, KindUserGroupChanged: 4, KindPasswordChanged: 4,
		},
		"rocky-9.secure": {
			KindSSHLoginFailed: 2, KindSSHLoginSucceeded: 1, KindSudoCommand: 1, KindSudoFailed + ":incorrect_password": 1,
			KindSudoFailed + ":not_in_sudoers": 1, KindSuSession: 5, KindUserCreated: 3, KindUserGroupChanged: 4,
		},
		"alpine-3.20.messages": {
			KindSSHLoginFailed: 2, KindSSHLoginSucceeded: 1, KindSudoCommand: 2, KindSudoFailed + ":not_in_sudoers": 1,
			KindSuSession: 5, KindUserCreated: 3, KindUserGroupChanged: 3, KindPasswordChanged: 4,
		},
		"debian-12.cron.log": {KindCronModified: 3},
		"rocky-9.cron":       {KindCronModified: 3},
	}
	for fixture, want := range tests {
		t.Run(fixture, func(t *testing.T) {
			if got := kindCounts(authEvents(t, fixture)); !maps.Equal(got, want) {
				t.Fatalf("events = %v\nwant %v", got, want)
			}
		})
	}
}

func findEvent(t *testing.T, events []Event, kind string, match func(Event) bool) Event {
	t.Helper()
	for _, e := range events {
		if e.Kind == kind && (match == nil || match(e)) {
			return e
		}
	}
	t.Fatalf("no %s event", kind)
	return Event{}
}

func TestSSHEventFields(t *testing.T) {
	for _, fixture := range []string{"debian-12.auth.log", "rocky-9.secure", "alpine-3.20.messages"} {
		events := authEvents(t, fixture)
		invalid := findEvent(t, events, KindSSHLoginFailed, func(e Event) bool { return e.Username == "admin" })
		if invalid.SrcIP != "127.0.0.1" || invalid.Fields["invalid_user"] != true || invalid.Fields["method"] != "password" || invalid.Fields["port"].(int) == 0 || invalid.Source != SourceAuth || invalid.Count != 1 {
			t.Fatalf("%s: invalid user failure = %+v", fixture, invalid)
		}
		root := findEvent(t, events, KindSSHLoginFailed, func(e Event) bool { return e.Username == "root" })
		if root.Fields["invalid_user"] != false {
			t.Fatalf("%s: root failure = %+v", fixture, root)
		}
		accepted := findEvent(t, events, KindSSHLoginSucceeded, nil)
		if accepted.Username != "alice" || accepted.SrcIP != "127.0.0.1" || accepted.Fields["method"] != "password" {
			t.Fatalf("%s: accepted = %+v", fixture, accepted)
		}
	}
	if e := findEvent(t, authEvents(t, "rocky-9.secure"), KindSSHLoginSucceeded, nil); e.Program != "sshd-session" {
		t.Fatalf("Rocky 9 logs from sshd-session, program = %q", e.Program)
	}
}

func TestSudoSuAndAccountFields(t *testing.T) {
	events := authEvents(t, "debian-12.auth.log")
	cmd := findEvent(t, events, KindSudoCommand, nil)
	if cmd.Username != "alice" || cmd.Fields["target_user"] != "root" || cmd.Fields["command"] != "/usr/bin/ls /root" {
		t.Fatalf("sudo command = %+v", cmd)
	}
	denied := findEvent(t, events, KindSudoFailed, func(e Event) bool { return e.Fields["reason"] == "not_in_sudoers" })
	if denied.Username != "bob" {
		t.Fatalf("not in sudoers = %+v", denied)
	}
	su := findEvent(t, events, KindSuSession, func(e Event) bool { return e.Fields["target_user"] == "bob" })
	if su.Fields["reason"] != nil || su.Username != "" {
		t.Fatalf("su to bob by root without a login name = %+v", su)
	}
	created := findEvent(t, events, KindUserCreated, func(e Event) bool { return e.Username == "deploy" })
	if created.Fields["uid"] != 1002 {
		t.Fatalf("user created = %+v", created)
	}
	group := findEvent(t, events, KindUserGroupChanged, func(e Event) bool { return e.Fields["action"] == "remove" })
	if group.Username != "deploy" || group.Fields["group"] != "adm" {
		t.Fatalf("group removal = %+v", group)
	}
	privileged := findEvent(t, events, KindUserGroupChanged, func(e Event) bool { return e.Username == "deploy" && e.Fields["group"] == "sudo" })
	if privileged.Fields["action"] != "add" || privileged.Program != "usermod" {
		t.Fatalf("sudo group add = %+v", privileged)
	}
	alpine := findEvent(t, authEvents(t, "alpine-3.20.messages"), KindSuSession, func(e Event) bool { return e.Fields["target_user"] == "bob" })
	if alpine.Username != "root" {
		t.Fatalf("busybox su = %+v", alpine)
	}
	cron := authEvents(t, "rocky-9.cron")
	if cron[0].Username != "root" || cron[0].Fields["target_user"] != "alice" || cron[0].Fields["action"] != "replace" || cron[1].Fields["action"] != "edit" || cron[2].Fields["action"] != "delete" {
		t.Fatalf("cron events = %+v", cron)
	}
}

func TestAuthFailuresFromPAM(t *testing.T) {
	at := testNow
	e, ok := ParseAuth("su", "pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root", at)
	if !ok || e.Kind != KindSuSession || e.Username != "alice" || e.Fields["target_user"] != "root" || e.Fields["reason"] != "authentication_failure" {
		t.Fatalf("su failure = %+v", e)
	}
	e, ok = ParseAuth("su", "- pts/0 alice:root", at)
	if !ok || e.Fields["reason"] != "authentication_failure" {
		t.Fatalf("busybox su failure = %+v", e)
	}
	e, ok = ParseAuth("passwd", "pam_unix(passwd:chauthtok): password changed for deploy", at)
	if !ok || e.Kind != KindPasswordChanged || e.Username != "deploy" {
		t.Fatalf("passwd = %+v", e)
	}
	e, ok = ParseAuth("sudo", "   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/sh -c echo a ; echo b", at)
	if !ok || e.Fields["command"] != "/bin/sh -c echo a ; echo b" || e.Fields["reason"] != "incorrect_password" {
		t.Fatalf("sudo with ; in the command = %+v", e)
	}
	e, ok = ParseAuth("sshd", "Failed publickey for git from 2001:db8::7 port 50022 ssh2: ED25519 SHA256:abc", at)
	if !ok || e.SrcIP != "2001:db8::7" || e.Fields["method"] != "publickey" {
		t.Fatalf("publickey failure = %+v", e)
	}
	e, ok = ParseAuth("sshd", "Failed password for invalid user my password from 203.0.113.7 port 51234 ssh2", at)
	if !ok || e.Username != "my password" {
		t.Fatalf("user name with a space = %+v", e)
	}
	for _, ignored := range [][2]string{
		{"sshd", "Invalid user admin from 127.0.0.1 port 35656"},
		{"sshd", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=127.0.0.1"},
		{"sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)"},
		{"su", "(to alice) root on none"},
		{"su", "FAILED SU (to root) alice on pts/0"},
		{"usermod", "add 'alice' to shadow group 'sudo'"},
		{"useradd", "new group: name=alice, GID=1000"},
		{"crontab", "(root) END EDIT (alice)"},
		{"cron", "(root) CMD (true)"},
	} {
		if e, ok := ParseAuth(ignored[0], ignored[1], at); ok {
			t.Errorf("%s %q must not produce an event, got %+v", ignored[0], ignored[1], e)
		}
	}
}

func TestJournalEntries(t *testing.T) {
	var events []Event
	for _, line := range readLines(t, filepath.Join("testdata", "journal", "debian-12.jsonl")) {
		entry, err := ParseJournalEntry([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		if entry.Cursor == "" || entry.At.IsZero() || entry.Identifier == "" {
			t.Fatalf("entry = %+v", entry)
		}
		if e, ok := ParseAuth(entry.Identifier, entry.Message, entry.At); ok {
			events = append(events, e)
		}
	}
	want := map[string]int{
		KindUserCreated: 5, KindSuSession: 5, KindPasswordChanged: 4, KindUserGroupChanged: 4, KindSSHLoginFailed: 3,
		KindCronModified: 3, KindSudoFailed + ":incorrect_password": 1, KindSudoFailed + ":not_in_sudoers": 1, KindSudoCommand: 1,
	}
	if got := kindCounts(events); !maps.Equal(got, want) {
		t.Fatalf("events = %v\nwant %v", got, want)
	}
}

func TestJournalMessageAsBytes(t *testing.T) {
	entry, err := ParseJournalEntry([]byte(`{"__CURSOR":"s=1","__REALTIME_TIMESTAMP":"1793473415326553","SYSLOG_IDENTIFIER":"sshd","MESSAGE":[70,97,105,108,101,100,32,255]}`))
	if err != nil || entry.Message != "Failed \xff" || entry.At.Year() != 2026 {
		t.Fatalf("entry = %+v, err = %v", entry, err)
	}
}

func TestSyslogTimestamps(t *testing.T) {
	l, ok := ParseSyslog("2026-10-31T18:58:54.635741+00:00 host sshd[4392]: Invalid user admin", testNow)
	if !ok || !l.At.Equal(time.Date(2026, 10, 31, 18, 58, 54, 635741000, time.UTC)) || l.Program != "sshd" {
		t.Fatalf("RFC 3339 = %+v", l)
	}
	l, ok = ParseSyslog("Dec 31 23:59:59 host su: pam_unix(su:session): session opened", time.Date(2027, 1, 1, 0, 0, 5, 0, time.UTC))
	if !ok || l.At.Year() != 2026 || l.Program != "su" {
		t.Fatalf("a December line read in January belongs to last year: %+v", l)
	}
	l, ok = ParseSyslog("Oct  1 09:00:00 host authpriv.notice sudo:    alice : PWD=/ ; USER=root ; COMMAND=/bin/ls", testNow)
	if !ok || l.Program != "sudo" || l.At.Day() != 1 {
		t.Fatalf("busybox = %+v", l)
	}
	if _, ok := ParseSyslog("not a syslog line", testNow); ok {
		t.Fatal("garbage must not parse")
	}
}

func TestAccessLogs(t *testing.T) {
	for fixture, wantLines := range map[string]int{"nginx.access.log": 9, "apache2.access.log": 19} {
		lines := readLines(t, filepath.Join("testdata", "web", fixture))
		var events []Event
		for _, line := range lines {
			e, ok := ParseAccessLog(line, "shop.example.com")
			if !ok {
				t.Fatalf("%s: unparsed line %s", fixture, line)
			}
			events = append(events, e)
		}
		if len(events) != wantLines {
			t.Fatalf("%s: events = %d", fixture, len(events))
		}
		first := events[1]
		if first.SrcIP != "172.17.0.1" || first.Fields["method"] != "GET" || first.Fields["status"] != 200 || first.Fields["vhost"] != "shop.example.com" || first.Kind != KindHTTPRequest || first.Source != SourceWeb {
			t.Fatalf("%s: event = %+v", fixture, first)
		}
		quoted := events[len(events)-2]
		if quoted.Fields["user_agent"] != `agent with "quotes"` {
			t.Fatalf("%s: escaped quotes = %+v", fixture, quoted.Fields)
		}
		jndi := findEvent(t, events, KindHTTPRequest, func(e Event) bool {
			ua, _ := e.Fields["user_agent"].(string)
			return strings.HasPrefix(ua, "${jndi")
		})
		if jndi.Fields["path"] != "/" {
			t.Fatalf("jndi = %+v", jndi)
		}
	}
	e, ok := ParseAccessLog(`shop.example.com:443 2001:db8::1 - - [31/Oct/2026:19:00:00 +0000] "\x16\x03\x01" 400 0 "-" "-"`, "")
	if !ok || e.Fields["vhost"] != "shop.example.com" || e.SrcIP != "2001:db8::1" || e.Fields["method"] != "" || e.Fields["user_agent"] != nil {
		t.Fatalf("vhost_combined with a TLS handshake on the http port = %+v", e)
	}
	e, ok = ParseAccessLog(`203.0.113.7 - - [31/Oct/2026:19:00:00 +0000] "GET /x HTTP/1.1" 304 - "-" "curl"`, "")
	if !ok || e.Fields["bytes"] != nil || e.Fields["vhost"] != nil {
		t.Fatalf("no bytes and no vhost = %+v", e)
	}
	if _, ok := ParseAccessLog("2026/10/31 19:00:00 [error] 29#29: *1 open() failed", ""); ok {
		t.Fatal("error log lines are not access log lines")
	}
}

func TestVhostFromPath(t *testing.T) {
	for path, want := range map[string]string{
		"/var/log/nginx/access.log":                    "",
		"/var/log/nginx/shop.example.com.access.log":   "shop.example.com",
		"/var/log/apache2/shop.example.com-access.log": "shop.example.com",
		"/var/log/httpd/access_log":                    "",
		"/var/log/httpd/shop.example.com_access_log":   "shop.example.com",
		"/var/log/apache2/other_vhosts_access.log":     "other_vhosts",
	} {
		if got := VhostFromPath(path); got != want {
			t.Errorf("VhostFromPath(%s) = %q, want %q", path, got, want)
		}
	}
}

func TestMonolog(t *testing.T) {
	count := func(fixture string) []Event {
		var events []Event
		for _, line := range readLines(t, filepath.Join("testdata", "app", fixture)) {
			if e, ok := ParseMonolog(line, "/var/www/shop/storage/logs/"+fixture, testNow); ok {
				events = append(events, e)
			}
		}
		return events
	}
	events := count("monolog.log")
	if len(events) != 3 {
		t.Fatalf("monolog events = %d, want ERROR, CRITICAL and EMERGENCY", len(events))
	}
	if events[0].Fields["level"] != "ERROR" || events[0].Fields["file"] != "/var/www/shop/storage/logs/monolog.log" || events[0].FirstAt.Year() != 2026 || events[0].Kind != KindAppError || events[0].Source != SourceApp {
		t.Fatalf("event = %+v", events[0])
	}
	if laravel := count("laravel.log"); len(laravel) != 1 || laravel[0].FirstAt.Hour() != 19 {
		t.Fatalf("laravel events = %+v", laravel)
	}
}
