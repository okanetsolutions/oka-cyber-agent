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
	crontabEvent = regexp.MustCompile(`^\((\S+)\) (REPLACE|DELETE) \((\S+)\)$`)
	keyValue     = regexp.MustCompile(`(\w+)=(\S*)`)
)

// ParseAuth turns one auth message into an event. Each attempt or change is reported once even when PAM
// and the program both log it: OpenSSH's own lines are used for logins (one ssh_login_failed per attempt,
// "Invalid user" lines are not counted again), sudo's own lines for sudo, and PAM's lines for su and
// password changes. crontab -e logs BEGIN EDIT and END EDIT around every edit, also one that changes
// nothing, and REPLACE only when the crontab was saved changed, so only REPLACE and DELETE are changes.
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
		// useradd -G logs the supplementary groups of the new account the way usermod does.
		return parseGroupChange(program, message, at)
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
			e.set("action", strings.ToLower(m[2]))
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
	var status string
	if key, _, ok := strings.Cut(parts[0], "="); !ok || !sudoKeys[key] {
		status = parts[0]
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
	splits := sudoSplits(parts)
	if len(splits) == 0 && kind == KindSudoCommand {
		return Event{}, false
	}
	e := authEvent(kind, "sudo", message, at)
	e.Username = m[1]
	if user, ok := agreed(splits, func(s sudoSplit) string { return s.user }); ok && user != "" {
		e.set("target_user", user)
	}
	if command, ok := agreed(splits, func(s sudoSplit) string { return s.command }); ok && command != "" {
		e.set("command", command)
	}
	if reason != "" {
		e.set("reason", reason)
	}
	return e, true
}

var sudoKeys = map[string]bool{"HOST": true, "TTY": true, "CHROOT": true, "PWD": true, "USER": true, "GROUP": true, "TSID": true, "ENV": true, "COMMAND": true}

type sudoSplit struct{ user, command string }

// sudoSplits returns every way the " ; " separated parts of a sudo line can be read as sudo's log format,
// which writes its keys in a fixed order: ... PWD=cwd ; USER=runas ; [GROUP=group ; ] [TSID=id ; ]
// [ENV=vars ; ] COMMAND=command and arguments. sudo does not escape " ; " or "KEY=" in the working directory,
// the ENV values or the arguments, which a user chooses, so a crafted line can be read in more than one way.
// The user and group names and the session ID are taken as single parts.
func sudoSplits(parts []string) []sudoSplit {
	var splits []sudoSplit
	for i, part := range parts {
		user, ok := strings.CutPrefix(part, "USER=")
		if !ok || user == "" {
			continue
		}
		k := i + 1
		if k < len(parts) && strings.HasPrefix(parts[k], "GROUP=") {
			k++
		}
		if k < len(parts) && strings.HasPrefix(parts[k], "TSID=") {
			k++
		}
		commandAt := func(j int) {
			if strings.HasPrefix(parts[j], "COMMAND=") {
				splits = append(splits, sudoSplit{user: user, command: strings.TrimPrefix(strings.Join(parts[j:], " ; "), "COMMAND=")})
			}
		}
		switch {
		case k == len(parts):
		case strings.HasPrefix(parts[k], "ENV="):
			for j := k + 1; j < len(parts); j++ {
				commandAt(j)
			}
		default:
			commandAt(k)
		}
	}
	return splits
}

// agreed returns the value every split gives, so a field is reported only when the line has one reading of
// it and never a value the user who ran sudo planted in a working directory or an argument.
func agreed(splits []sudoSplit, field func(sudoSplit) string) (string, bool) {
	if len(splits) == 0 {
		return "", false
	}
	value := field(splits[0])
	for _, s := range splits[1:] {
		if field(s) != value {
			return "", false
		}
	}
	return value, true
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
