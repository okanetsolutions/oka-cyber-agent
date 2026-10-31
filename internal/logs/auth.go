package logs

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AuthIdentifiers are the programs whose messages the auth source reads, as journald SYSLOG_IDENTIFIER
// values and syslog program names. OpenSSH 9.8 moved per connection logging to sshd-session.
var AuthIdentifiers = []string{"sshd", "sshd-session", "sudo", "su", "useradd", "usermod", "groupadd", "gpasswd", "passwd", "chpasswd", "crontab"}

var (
	sshFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)`)
	sshAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)

	sudoLine = regexp.MustCompile(`^\s*(\S+) : (.*)$`)

	suSessionOpened = regexp.MustCompile(`^pam_unix\(su(?:-l)?:session\): session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]*)(?:\(uid=\d+\))?`)
	suAuthFailure   = regexp.MustCompile(`^pam_unix\(su(?:-l)?:auth\): authentication failure;.*`)
	busyboxSu       = regexp.MustCompile(`^([+-]) (\S+) ([^:\s]+):(\S+)$`)

	userCreated  = regexp.MustCompile(`^new user: name=([^,]+), UID=(\d+)`)
	usermodAdd   = regexp.MustCompile(`^add '([^']+)' to group '([^']+)'$`)
	usermodDel   = regexp.MustCompile(`^delete '([^']+)' from group '([^']+)'$`)
	gpasswdAdd   = regexp.MustCompile(`^user (\S+) added by \S+ to group (\S+)$`)
	gpasswdDel   = regexp.MustCompile(`^user (\S+) removed by \S+ from group (\S+)$`)
	passwordPAM  = regexp.MustCompile(`^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (\S+)$`)
	crontabEvent = regexp.MustCompile(`^\((\S+)\) (REPLACE|DELETE|BEGIN EDIT) \((\S+)\)$`)
	keyValue     = regexp.MustCompile(`(\w+)=(\S*)`)
)

// ParseAuth turns one auth message into an event. Each attempt or change is reported once even when PAM
// and the program both log it: OpenSSH's own lines are used for logins (one ssh_login_failed per attempt,
// "Invalid user" lines are not counted again), sudo's own lines for sudo, and PAM's lines for su and
// password changes.
func ParseAuth(program, message string, at time.Time) (Event, bool) {
	switch program {
	case "sshd", "sshd-session", "sshd-auth":
		return parseSSH(program, message, at)
	case "sudo":
		return parseSudo(message, at)
	case "su":
		return parseSu(message, at)
	case "useradd":
		if m := userCreated.FindStringSubmatch(message); m != nil {
			e := authEvent(KindUserCreated, program, message, at)
			e.Username = m[1]
			uid, _ := strconv.Atoi(m[2])
			e.set("uid", uid)
			return e, true
		}
	case "usermod", "gpasswd":
		return parseGroupChange(program, message, at)
	case "passwd", "chpasswd":
		if m := passwordPAM.FindStringSubmatch(message); m != nil {
			e := authEvent(KindPasswordChanged, program, message, at)
			e.Username = m[1]
			return e, true
		}
	case "crontab":
		if m := crontabEvent.FindStringSubmatch(message); m != nil {
			e := authEvent(KindCronModified, program, message, at)
			e.Username = m[1]
			e.set("action", strings.ToLower(strings.TrimPrefix(m[2], "BEGIN ")))
			e.set("target_user", m[3])
			return e, true
		}
	}
	return Event{}, false
}

func authEvent(kind, program, message string, at time.Time) Event {
	e := newEvent(SourceAuth, kind, at, message)
	e.Program = program
	return e
}

func parseSSH(program, message string, at time.Time) (Event, bool) {
	if m := sshFailed.FindStringSubmatch(message); m != nil {
		e := authEvent(KindSSHLoginFailed, program, message, at)
		e.Username = m[3]
		e.SrcIP = m[4]
		e.set("invalid_user", m[2] != "")
		e.set("method", m[1])
		port, _ := strconv.Atoi(m[5])
		e.set("port", port)
		return e, true
	}
	if m := sshAccepted.FindStringSubmatch(message); m != nil {
		e := authEvent(KindSSHLoginSucceeded, program, message, at)
		e.Username = m[2]
		e.SrcIP = m[3]
		e.set("method", m[1])
		port, _ := strconv.Atoi(m[4])
		e.set("port", port)
		return e, true
	}
	return Event{}, false
}

// parseSudo reads "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/ls" and the failure variants
// "alice : 3 incorrect password attempts ; ..." and "bob : user NOT in sudoers ; ...".
func parseSudo(message string, at time.Time) (Event, bool) {
	m := sudoLine.FindStringSubmatch(message)
	if m == nil || strings.HasPrefix(message, "pam_") {
		return Event{}, false
	}
	parts := strings.Split(m[2], " ; ")
	values := map[string]string{}
	var status string
	for i, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if ok && (key == "TTY" || key == "PWD" || key == "USER" || key == "COMMAND" || key == "ENV" || key == "GROUP") {
			if key == "COMMAND" {
				value = strings.Join(parts[i:], " ; ")[len("COMMAND="):]
				values[key] = value
				break
			}
			values[key] = value
			continue
		}
		if i == 0 {
			status = part
		}
	}
	kind := KindSudoCommand
	var reason string
	switch {
	case status == "":
	case strings.Contains(status, "incorrect password attempt"):
		kind, reason = KindSudoFailed, "incorrect_password"
	case strings.Contains(status, "NOT in sudoers"), strings.Contains(status, "not in the sudoers file"):
		kind, reason = KindSudoFailed, "not_in_sudoers"
	case strings.Contains(status, "command not allowed"):
		kind, reason = KindSudoFailed, "command_not_allowed"
	default:
		kind, reason = KindSudoFailed, "other"
	}
	if values["COMMAND"] == "" && kind == KindSudoCommand {
		return Event{}, false
	}
	e := authEvent(kind, "sudo", message, at)
	e.Username = m[1]
	if user := values["USER"]; user != "" {
		e.set("target_user", user)
	}
	if command := values["COMMAND"]; command != "" {
		e.set("command", command)
	}
	if reason != "" {
		e.set("reason", reason)
	}
	return e, true
}

func parseSu(message string, at time.Time) (Event, bool) {
	if m := suSessionOpened.FindStringSubmatch(message); m != nil {
		e := authEvent(KindSuSession, "su", message, at)
		e.Username = m[2]
		e.set("target_user", m[1])
		return e, true
	}
	if suAuthFailure.MatchString(message) {
		values := map[string]string{}
		for _, kv := range keyValue.FindAllStringSubmatch(message, -1) {
			values[kv[1]] = kv[2]
		}
		e := authEvent(KindSuSession, "su", message, at)
		e.Username = values["ruser"]
		if e.Username == "" {
			e.Username = values["logname"]
		}
		if target := values["user"]; target != "" {
			e.set("target_user", target)
		}
		e.set("reason", "authentication_failure")
		return e, true
	}
	if m := busyboxSu.FindStringSubmatch(message); m != nil {
		e := authEvent(KindSuSession, "su", message, at)
		e.Username = m[3]
		e.set("target_user", m[4])
		if m[1] == "-" {
			e.set("reason", "authentication_failure")
		}
		return e, true
	}
	return Event{}, false
}

func parseGroupChange(program, message string, at time.Time) (Event, bool) {
	for _, rule := range []struct {
		re     *regexp.Regexp
		action string
	}{{usermodAdd, "add"}, {usermodDel, "remove"}, {gpasswdAdd, "add"}, {gpasswdDel, "remove"}} {
		if m := rule.re.FindStringSubmatch(message); m != nil {
			e := authEvent(KindUserGroupChanged, program, message, at)
			e.Username = m[1]
			e.set("group", m[2])
			e.set("action", rule.action)
			return e, true
		}
	}
	return Event{}, false
}
