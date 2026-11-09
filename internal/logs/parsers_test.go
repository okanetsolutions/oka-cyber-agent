package logs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
		if e, ok := ParseAuth(l.Program, l.Message, l.At, l.PID); ok {
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
			KindSSHSessionOpened: 1, KindSSHSessionClosed: 1,
			KindSSHLoginFailed: 2, KindSSHLoginSucceeded: 1, KindSudoCommand: 1, KindSudoFailed + ":incorrect_password": 1,
			KindSudoFailed + ":not_in_sudoers": 1, KindSuSession: 5, KindUserCreated: 3, KindUserGroupChanged: 4, KindPasswordChanged: 4,
		},
		"ubuntu-24.04.auth.log": {
			KindSSHSessionOpened: 1, KindSSHSessionClosed: 1,
			KindSSHLoginFailed: 2, KindSSHLoginSucceeded: 1, KindSudoCommand: 1, KindSudoFailed + ":incorrect_password": 1,
			KindSudoFailed + ":not_in_sudoers": 1, KindSuSession: 5, KindUserCreated: 3, KindUserGroupChanged: 4, KindPasswordChanged: 4,
		},
		"rocky-9.secure": {
			KindSSHSessionOpened: 1, KindSSHSessionClosed: 1,
			KindSSHLoginFailed: 2, KindSSHLoginSucceeded: 1, KindSudoCommand: 1, KindSudoFailed + ":incorrect_password": 1,
			KindSudoFailed + ":not_in_sudoers": 1, KindSuSession: 5, KindUserCreated: 3, KindUserGroupChanged: 4,
		},
		"alpine-3.20.messages": {
			KindSSHLoginFailed: 2, KindSSHLoginSucceeded: 1, KindSudoCommand: 2, KindSudoFailed + ":not_in_sudoers": 1,
			KindSuSession: 5, KindUserCreated: 3, KindUserGroupChanged: 3, KindPasswordChanged: 4,
		},
		"debian-12.groups.log":         {KindUserCreated: 3, KindUserGroupChanged: 5},
		"ubuntu-24.04.groups.log":      {KindUserCreated: 3, KindUserGroupChanged: 5},
		"rocky-9.groups.secure":        {KindUserCreated: 3, KindUserGroupChanged: 5},
		"debian-12.sudo.log":           {KindSudoCommand: 8},
		"ubuntu-24.04.sudo.log":        {KindSudoCommand: 8},
		"rocky-9.sudo.secure":          {KindSudoCommand: 8},
		"debian-12.sudo-continued.log": {KindSudoCommand: 2},
		"debian-12.cron.log":           {KindCronModified: 3},
		"rocky-9.cron":                 {KindCronModified: 3},
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
	if cmd.Username != "alice" || cmd.Fields["target_user"] != "root" || cmd.Fields["command"] != "/usr/bin/ls [1 arg]" || !strings.HasSuffix(cmd.Message, "; COMMAND=/usr/bin/ls [1 arg]") {
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
	if cron[0].Username != "root" || cron[0].Fields["target_user"] != "alice" || cron[0].Fields["action"] != "replace" || cron[1].Fields["action"] != "replace" || cron[2].Fields["action"] != "delete" {
		t.Fatalf("cron events = %+v", cron)
	}
}

// The groups fixtures were captured on Debian 12, Ubuntu 24.04 and Rocky 9 (rsyslog) after root ran useradd
// alice, useradd -G sudo,adm mallory (wheel on Rocky), useradd -U -G sudo trudy, usermod -G adm mallory,
// groupmems -a and -d (refused by PAM in the container, and groupmems logs no change anyway), gpasswd -M
// alice,mallory adm and usermod -aG sudo alice.
func TestUseraddReportsSupplementaryGroups(t *testing.T) {
	for fixture, privileged := range map[string]string{"debian-12.groups.log": "sudo", "ubuntu-24.04.groups.log": "sudo", "rocky-9.groups.secure": "wheel"} {
		var changes []string
		for _, e := range authEvents(t, fixture) {
			if e.Kind == KindUserGroupChanged {
				changes = append(changes, fmt.Sprintf("%s %s %s %s", e.Program, e.Fields["action"], e.Username, e.Fields["group"]))
			}
		}
		want := []string{
			"useradd add mallory adm", "useradd add mallory " + privileged, "useradd add trudy " + privileged,
			"usermod remove mallory " + privileged, "usermod add alice " + privileged,
		}
		if !slices.Equal(changes, want) {
			t.Errorf("%s: group changes = %q\nwant %q", fixture, changes, want)
		}
	}
}

// The sudo fixtures were captured on Debian 12 (sudo 1.9.13), Ubuntu 24.04 and Rocky 9 (rsyslog) with alice
// allowed to run anything: a plain command, from the directory "/tmp/x ; USER=bob ; COMMAND=/bin/true", with
// arguments holding " ; USER=bob ; COMMAND=/bin/true", both, with a variable on the command line holding
// " ; COMMAND=/bin/true", with -g adm and with I/O logging (TSID). sudo writes the working directory, the
// variables and the arguments without escaping " ; ", so the target user is reported only when the line has
// one reading of it, and the command only when every reading gives the same executable and argument count.
func TestSudoFieldsAreNotTakenFromCraftedValues(t *testing.T) {
	type fields struct{ targetUser, command any }
	want := []fields{
		{"root", "/bin/ls [1 arg]"},
		{nil, "[unparsed]"},
		{nil, "[unparsed]"},
		{nil, "[unparsed]"},
		{nil, "[unparsed]"},
		{"root", "[unparsed]"},
		{"root", "/bin/sh [2 args]"},
		{"root", "/usr/bin/id [0 args]"},
	}
	for _, fixture := range []string{"debian-12.sudo.log", "ubuntu-24.04.sudo.log", "rocky-9.sudo.secure"} {
		events := authEvents(t, fixture)
		if len(events) != len(want) {
			t.Fatalf("%s: %d events, want %d", fixture, len(events), len(want))
		}
		for i, e := range events {
			got := fields{e.Fields["target_user"], e.Fields["command"]}
			if e.Kind != KindSudoCommand || e.Username != "alice" || got != want[i] || !strings.HasSuffix(e.Message, " ; COMMAND="+want[i].command.(string)) {
				t.Errorf("%s line %d: %s by %q target_user=%v command=%v, want %v", fixture, i+1, e.Kind, e.Username, got.targetUser, got.command, want[i])
			}
		}
	}
}

func TestSudoKeyOrder(t *testing.T) {
	for _, tc := range []struct {
		message, targetUser, command string
	}{
		{"alice : TTY=pts/0 ; PWD=/srv ; USER=postgres ; GROUP=postgres ; TSID=000001 ; ENV=PGDATA=/srv/db ; COMMAND=/usr/bin/psql -c select 1 ; select 2", "postgres", "/usr/bin/psql [6 args]"},
		{"alice : HOST=web1 ; TTY=pts/0 ; CHROOT=/jail ; PWD=/ ; USER=root ; COMMAND=/bin/ls", "root", "/bin/ls [0 args]"},
		{"alice : TTY=pts/0 ; PWD=/tmp/USER=bob ; USER=root ; COMMAND=/bin/ls", "root", "/bin/ls [0 args]"},
		{"alice : TTY=pts/0 ; PWD=/tmp/a ; USER=bob ; USER=root ; COMMAND=/bin/ls", "root", "/bin/ls [0 args]"},
		{"alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo USER=bob ; GROUP=x", "root", "/bin/echo [3 args]"},
		{"alice : TTY=pts/0 ; PWD=/ ; USER=root ; ENV=A=1 ; USER=bob ; COMMAND=/bin/ls", "", "/bin/ls [0 args]"},
		{"alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/x ; USER=bob ; COMMAND=/y ; USER=root ; COMMAND=/bin/sh", "", "[unparsed]"},
		{"alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=", "root", "[unparsed]"},
	} {
		e, ok := ParseAuth("sudo", tc.message, testNow, "")
		if !ok {
			t.Errorf("%q: no event", tc.message)
			continue
		}
		user, _ := e.Fields["target_user"].(string)
		command, _ := e.Fields["command"].(string)
		if user != tc.targetUser || command != tc.command {
			t.Errorf("%q: target_user=%q command=%q, want %q and %q", tc.message, user, command, tc.targetUser, tc.command)
		}
	}
	if _, ok := ParseAuth("sudo", "alice : TTY=pts/0 ; PWD=/x ; COMMAND=/bin/ls", testNow, ""); ok {
		t.Error("a line without USER is not a sudo command")
	}
}

// A sudo event keeps only the executable and the number of arguments of the command, and no variable: tools
// take passwords through options of their own and positional arguments, which no redaction rule knows of all.
func TestSudoKeepsNoArguments(t *testing.T) {
	const prefix = "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
	for _, tc := range []struct{ command, want string }{
		{"/usr/bin/ldapmodify -x -D cn=admin -w hunter2pw", "/usr/bin/ldapmodify [5 args]"},
		{"/opt/mssql-tools18/bin/sqlcmd -S host -U sa -P S3cretPw", "/opt/mssql-tools18/bin/sqlcmd [6 args]"},
		{"/usr/bin/htpasswd -b /etc/nginx/.htpasswd bob S3cretPw", "/usr/bin/htpasswd [4 args]"},
		{"/usr/bin/smbclient //h/s -U bob%S3cretPw", "/usr/bin/smbclient [3 args]"},
		{"/usr/local/bin/aws configure set aws_secret_access_key S3cretPw", "/usr/local/bin/aws [4 args]"},
		{"/usr/bin/redis-cli -h x AUTH S3cretPw", "/usr/bin/redis-cli [4 args]"},
		{"/usr/sbin/rabbitmqctl add_user bob S3cretPw", "/usr/sbin/rabbitmqctl [3 args]"},
		{"/usr/bin/mysql -pS3cretPw shop", "/usr/bin/mysql [2 args]"},
		{`/bin/sh -c 'mysql -pS3cretPw -e \'select 1\''`, "/bin/sh [2 args]"},
		{"/bin/sh -c mysql -pS3cretPw -e select 1", "/bin/sh [6 args]"},
	} {
		for _, line := range []string{
			prefix + "COMMAND=" + tc.command,
			prefix + "ENV=MYSQL_PWD=S3cretPw REDISCLI_AUTH=hunter2pw ; COMMAND=" + tc.command,
			prefix + "ENV=A=1 ; B=S3cretPw ; COMMAND=" + tc.command,
			"alice : 3 incorrect password attempts ; " + prefix[len("alice : "):] + "COMMAND=" + tc.command,
		} {
			e, ok := ParseAuth("sudo", line, testNow, "")
			if !ok {
				t.Fatalf("not a sudo line: %q", line)
			}
			got := Redact(e)
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "S3cretPw") || strings.Contains(string(data), "hunter2pw") {
				t.Errorf("%q leaks a password: %s", line, data)
			}
			if got.Fields["command"] != tc.want || got.Fields["target_user"] != "root" || !strings.HasSuffix(got.Message, " ; COMMAND="+tc.want) {
				t.Errorf("%q: command = %v, target_user = %v, message = %q, want %q", line, got.Fields["command"], got.Fields["target_user"], got.Message, tc.want)
			}
			if strings.Contains(line, "ENV=") && !strings.HasSuffix(got.Message, " ; USER=root ; ENV=[redacted] ; COMMAND="+tc.want) {
				t.Errorf("%q: message = %q", line, got.Message)
			}
		}
	}
}

// A working directory or variable that copies sudo's own fields can only turn the command into [unparsed]: it
// can neither change the executable or argument count reported nor bring an argument into the message.
func TestSudoCraftedFieldsHideNoArgument(t *testing.T) {
	for _, tc := range []struct{ line, command, message string }{
		{"alice : TTY=pts/0 ; PWD=/tmp/x ; USER=root ; COMMAND=/usr/bin/id ; USER=root ; COMMAND=/usr/bin/ldapmodify -w hunter2pw", "[unparsed]", "alice : TTY=pts/0 ; PWD=[redacted] ; USER=root ; COMMAND=[unparsed]"},
		{"alice : TTY=pts/0 ; PWD=/tmp/x ; USER=root ; COMMAND=/usr/bin/ldapmodify -w ; USER=root ; COMMAND=/usr/bin/ldapmodify -w hunter2pw", "[unparsed]", "alice : TTY=pts/0 ; PWD=[redacted] ; USER=root ; COMMAND=[unparsed]"},
		{"alice : TTY=pts/0 ; PWD=/tmp/x ; ENV=y ; USER=root ; ENV=MYSQL_PWD=hunter2pw ; COMMAND=/usr/bin/mysql", "/usr/bin/mysql [0 args]", "alice : TTY=pts/0 ; PWD=[redacted] ; ENV=[redacted] ; COMMAND=/usr/bin/mysql [0 args]"},
		{"alice : TTY=pts/0 ; PWD=/ ; USER=root ; ENV=A=x ; COMMAND=/bin/true ; COMMAND=/usr/bin/redis-cli AUTH hunter2pw", "[unparsed]", "alice : TTY=pts/0 ; PWD=[redacted] ; USER=root ; ENV=[redacted] ; COMMAND=[unparsed]"},
		{"alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/htpasswd -b f bob hunter2pw ; COMMAND=/bin/true", "/usr/bin/htpasswd [6 args]", "alice : TTY=pts/0 ; PWD=[redacted] ; USER=root ; COMMAND=/usr/bin/htpasswd [6 args]"},
	} {
		e, ok := ParseAuth("sudo", tc.line, testNow, "")
		if !ok {
			t.Fatalf("not a sudo line: %q", tc.line)
		}
		got := Redact(e)
		if got.Fields["command"] != tc.command || got.Message != tc.message || strings.Contains(fmt.Sprint(got.Fields), "hunter2pw") {
			t.Errorf("%q:\n got %q %v\nwant %q %q", tc.line, got.Message, got.Fields, tc.message, tc.command)
		}
	}
}

// The fixture was captured on Debian 12 (sudo 1.9.13) with alice running /bin/true with 150 arguments and
// -w S3cretPass, then with three times as many: sudo logs a command longer than 960 bytes in several lines, the
// later ones "alice : (command continued) <arguments>". They hold only arguments and give no event.
func TestSudoContinuedCommandLines(t *testing.T) {
	events := authEvents(t, "debian-12.sudo-continued.log")
	if len(events) != 2 {
		t.Fatalf("%d events, want 2: %+v", len(events), events)
	}
	for _, e := range events {
		data, err := json.Marshal(Redact(e))
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind != KindSudoCommand || e.Fields["command"] != "/bin/true [130 args]" || strings.Contains(string(data), "S3cretPass") || strings.Contains(string(data), "arg129") {
			t.Errorf("event = %s", data)
		}
	}
}

// Only sudo's own fields and the failures it is known to log reach an event: a line of any other shape is
// dropped, or keeps only its fields when it has those of a command, so its text can never carry an argument.
func TestSudoShipsNoUnparsedText(t *testing.T) {
	for _, tc := range []struct{ line, kind, reason, message string }{
		{line: "   alice : (command continued) -D cn=admin -w S3cretPass -f /tmp/x.ldif"},
		{line: "alice : (command continued) x ; PWD=/ ; USER=root ; COMMAND=/bin/true -w S3cretPass"},
		{line: "alice : (command continued) 3 incorrect password attempts -w S3cretPass"},
		{line: "alice : unable to execute /usr/bin/ldapmodify -w S3cretPass: Permission denied"},
		{line: "alice : S3cretPass"},
		{line: "alice : PWD=/ ; S3cretPass"},
		{line: "alice : 3 incorrect password attempts -w S3cretPass ; TTY=pts/0"},
		{
			"alice : command not found -w S3cretPass ; PWD=/ ; USER=root ; COMMAND=/usr/bin/ldapmodify -w S3cretPass",
			KindSudoFailed, "other", "alice : [unparsed] ; PWD=/ ; USER=root ; COMMAND=/usr/bin/ldapmodify [2 args]",
		},
		{
			"alice : 3 incorrect password attempts -w S3cretPass ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
			KindSudoFailed, "other", "alice : [unparsed] ; PWD=/ ; USER=root ; COMMAND=/bin/ls [0 args]",
		},
		{
			"alice : 3 incorrect password attempts ; TTY=pts/0 ; S3cretPass ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
			KindSudoFailed, "incorrect_password", "alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls [0 args]",
		},
		{
			"alice : TTY=pts/0 ; PWD=/tmp/a ; S3cretPass ; USER=root ; COMMAND=/bin/ls",
			KindSudoCommand, "", "alice : TTY=pts/0 ; PWD=/tmp/a ; USER=root ; COMMAND=/bin/ls [0 args]",
		},
		{
			"bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/x ; S3cretPass",
			KindSudoFailed, "not_in_sudoers", "bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/x",
		},
		{
			"bob : user NOT authorized on host ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
			KindSudoFailed, "other", "bob : user NOT authorized on host ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls [0 args]",
		},
	} {
		e, ok := ParseAuth("sudo", tc.line, testNow, "")
		if tc.kind == "" {
			if ok {
				t.Errorf("%q must give no event, got %+v", tc.line, e)
			}
			continue
		}
		if !ok {
			t.Errorf("%q gave no event", tc.line)
			continue
		}
		reason, _ := e.Fields["reason"].(string)
		data, err := json.Marshal(Redact(e))
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind != tc.kind || reason != tc.reason || e.Message != tc.message || strings.Contains(string(data), "S3cretPass") {
			t.Errorf("%q:\n got %s %q %q\nwant %s %q %q", tc.line, e.Kind, reason, e.Message, tc.kind, tc.reason, tc.message)
		}
	}
}

// FuzzSudoKeepsNoArguments checks that whatever a user puts in the working directory, the variables and the
// arguments of a sudo command, no argument reaches the event, and the command reported is the one sudo ran or
// [unparsed].
func FuzzSudoKeepsNoArguments(f *testing.F) {
	f.Add("/tmp/x ; USER=root ; COMMAND=/bin/true", "A=1 ; COMMAND=/bin/ls", "-w ; USER=bob ; COMMAND=/bin/x 'a b'")
	f.Add("/", "", "-x -D cn=admin -w")
	f.Add("/Bob's files", "MYSQL_PWD=x", "-c 'mysql -p\\'x\\''")
	f.Fuzz(func(t *testing.T, pwd, env, args string) {
		if strings.Contains(pwd+env+args, "Zq9") {
			t.Skip()
		}
		command := "/usr/bin/tool " + args + " Zq9secret"
		line := "alice : TTY=pts/0 ; PWD=" + pwd + " ; USER=root ; "
		if env != "" {
			line += "ENV=" + env + " Zq9env ; "
		}
		line += "COMMAND=" + command
		e, ok := ParseAuth("sudo", line, testNow, "")
		if !ok {
			return
		}
		got := Redact(e)
		if strings.Contains(got.Message+fmt.Sprint(got.Fields), "Zq9") {
			t.Fatalf("%q leaks: %q %v", line, got.Message, got.Fields)
		}
		if c := e.Fields["command"]; c != unparsedCommand && c != commandSummary(command) {
			t.Fatalf("%q: command = %q, want %q or %q", line, c, commandSummary(command), unparsedCommand)
		}
	})
}

// The cron fixtures were captured on Debian 12 (cron, rsyslog) and Rocky 9 (cronie, rsyslog) after root ran
// crontab -u alice with a file, crontab -u alice -e with an editor that added a line, crontab -u alice -e
// with an editor that changed nothing, and crontab -u alice -r.
func TestCrontabEditIsOneChange(t *testing.T) {
	for _, fixture := range []string{"debian-12.cron.log", "rocky-9.cron"} {
		lines := readLines(t, filepath.Join("testdata", "auth", fixture))
		count := func(lines []string) int {
			n := 0
			for _, line := range lines {
				l, ok := ParseSyslog(line, testNow)
				if !ok {
					t.Fatalf("%s: unparsed line %q", fixture, line)
				}
				if e, ok := ParseAuth(l.Program, l.Message, l.At, l.PID); ok && e.Kind == KindCronModified {
					n++
				}
			}
			return n
		}
		if n := count(lines[1:4]); n != 1 {
			t.Errorf("%s: BEGIN EDIT, REPLACE, END EDIT gave %d cron_modified events, want 1", fixture, n)
		}
		if n := count(lines[4:6]); n != 0 {
			t.Errorf("%s: an edit that changed nothing gave %d cron_modified events, want 0", fixture, n)
		}
	}
}

func TestAuthFailuresFromPAM(t *testing.T) {
	at := testNow
	e, ok := ParseAuth("su", "pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root", at, "")
	if !ok || e.Kind != KindSuSession || e.Username != "alice" || e.Fields["target_user"] != "root" || e.Fields["reason"] != "authentication_failure" {
		t.Fatalf("su failure = %+v", e)
	}
	e, ok = ParseAuth("su", "- pts/0 alice:root", at, "")
	if !ok || e.Fields["reason"] != "authentication_failure" {
		t.Fatalf("busybox su failure = %+v", e)
	}
	e, ok = ParseAuth("passwd", "pam_unix(passwd:chauthtok): password changed for deploy", at, "")
	if !ok || e.Kind != KindPasswordChanged || e.Username != "deploy" {
		t.Fatalf("passwd = %+v", e)
	}
	e, ok = ParseAuth("sudo", "   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/sh -c echo a ; echo b", at, "")
	if !ok || e.Fields["command"] != "/bin/sh [6 args]" || e.Fields["reason"] != "incorrect_password" {
		t.Fatalf("sudo with ; in the command = %+v", e)
	}
	e, ok = ParseAuth("sshd", "Failed publickey for git from 2001:db8::7 port 50022 ssh2: ED25519 SHA256:abc", at, "")
	if !ok || e.SrcIP != "2001:db8::7" || e.Fields["method"] != "publickey" {
		t.Fatalf("publickey failure = %+v", e)
	}
	e, ok = ParseAuth("sshd", "Failed password for invalid user my password from 203.0.113.7 port 51234 ssh2", at, "")
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
		{"useradd", "add 'mallory' to shadow group 'sudo'"},
		{"gpasswd", "members of group adm set by root to alice,mallory"},
		{"useradd", "new group: name=alice, GID=1000"},
		{"crontab", "(root) BEGIN EDIT (alice)"},
		{"crontab", "(root) END EDIT (alice)"},
		{"cron", "(root) CMD (true)"},
	} {
		if e, ok := ParseAuth(ignored[0], ignored[1], at, ""); ok {
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
		if !TrustedAuthEntry(entry) {
			t.Fatalf("genuine entry rejected: %+v", entry)
		}
		if e, ok := ParseAuth(entry.Identifier, entry.Message, entry.At, entry.PID); ok {
			events = append(events, e)
		}
	}
	want := map[string]int{
		KindUserCreated: 5, KindSuSession: 5, KindPasswordChanged: 4, KindUserGroupChanged: 4, KindSSHLoginFailed: 3,
		KindCronModified: 2, KindSudoFailed + ":incorrect_password": 1, KindSudoFailed + ":not_in_sudoers": 1, KindSudoCommand: 1,
	}
	if got := kindCounts(events); !maps.Equal(got, want) {
		t.Fatalf("events = %v\nwant %v", got, want)
	}
}

// debian-12-forged.jsonl was captured on Debian 12 after an unprivileged user (uid 1000) ran logger -t sshd,
// logger -p auth.info -t useradd, systemd-cat -t sshd with sh and with a copy of dash named sshd in its home,
// and the real /usr/sbin/useradd with an LD_PRELOAD library that prints a "new user" line; root ran useradd
// twice.
func TestJournalRejectsForgedAuthEntries(t *testing.T) {
	var genuine []Event
	var forged int
	for _, line := range readLines(t, filepath.Join("testdata", "journal", "debian-12-forged.jsonl")) {
		entry, err := ParseJournalEntry([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		e, ok := ParseAuth(entry.Identifier, entry.Message, entry.At, entry.PID)
		if !TrustedAuthEntry(entry) {
			if entry.UID != "1000" || !ok {
				t.Fatalf("rejected entry = %+v", entry)
			}
			forged++
			continue
		}
		if ok {
			genuine = append(genuine, e)
		}
	}
	if forged != 5 || len(genuine) != 2 || genuine[0].Username != "mallory" || genuine[1].Username != "deploy" {
		t.Fatalf("forged = %d, genuine = %+v", forged, genuine)
	}
}

func TestTrustedAuthEntry(t *testing.T) {
	for _, tc := range []struct {
		identifier, uid, exe, comm string
		want                       bool
	}{
		{"sshd", "0", "/usr/sbin/sshd", "sshd", true},
		{"sshd-session.pam", "0", "/usr/lib/ssh/sshd-session.pam", "sshd-session.pam", true},
		{"sshd.pam", "0", "/usr/sbin/sshd.pam", "sshd.pam", true},
		{"systemd-logind", "0", "/usr/lib/systemd/systemd-logind", "systemd-logind", true},
		{"systemd-logind", "0", "/lib/systemd/systemd-logind", "systemd-logind", true},
		{"systemd-logind", "1000", "/usr/lib/systemd/systemd-logind", "systemd-logind", false},
		{"systemd-logind", "0", "/usr/bin/logger", "systemd-logind", false},
		{"systemd-logind", "0", "", "systemd-logind", true},
		{"systemd-logind", "1000", "", "systemd-logind", false},
		{"sshd", "0", "/usr/sbin/sshd (deleted)", "sshd", true},
		{"sshd-session", "0", "/usr/lib/openssh/sshd-session", "sshd-session", true},
		{"sshd", "0", "/usr/libexec/openssh/sshd-session", "sshd-session", true},
		{"sshd-session", "0", "/usr/lib/ssh/sshd-session", "sshd-session", true},
		{"sudo", "1000", "/usr/bin/sudo", "sudo", true},
		{"sudo", "1000", "/usr/lib/cargo/bin/sudo", "sudo", true},
		{"su", "1000", "/bin/su", "su", true},
		{"crontab", "0", "", "crontab", true},
		{"sshd", "1000", "/usr/sbin/sshd", "sshd", false},
		{"useradd", "1000", "/usr/sbin/useradd", "useradd", false},
		{"sshd", "0", "/usr/bin/logger", "logger", false},
		{"sshd", "0", "/usr/sbin/sudo", "sudo", false},
		{"sudo", "1000", "/home/alice/bin/sudo", "sudo", false},
		{"sudo", "1000", "/usr/bin/../../home/alice/sudo", "sudo", false},
		{"crontab", "1000", "", "crontab", false},
		{"sshd", "0", "", "logger", false},
		{"cron", "0", "/usr/sbin/cron", "cron", false},
	} {
		entry := JournalEntry{Identifier: tc.identifier, UID: tc.uid, Exe: tc.exe, Comm: tc.comm}
		if got := TrustedAuthEntry(entry); got != tc.want {
			t.Errorf("TrustedAuthEntry(%+v) = %v, want %v", entry, got, tc.want)
		}
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
