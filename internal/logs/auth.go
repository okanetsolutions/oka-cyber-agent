package logs

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// AuthIdentifiers are the programs whose messages the auth source reads, as journald SYSLOG_IDENTIFIER
// values and syslog program names. OpenSSH 9.8 moved per connection logging to sshd-session;
// Alpine names the PAM-enabled executables sshd.pam and sshd-session.pam.
var AuthIdentifiers = []string{"sshd", "sshd-session", "sshd.pam", "sshd-session.pam", "systemd-logind", "sudo", "su", "useradd", "usermod", "groupadd", "gpasswd", "passwd", "chpasswd", "crontab"}

var (
	sshFailed    = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)`)
	sshSession   = regexp.MustCompile(`^pam_unix\(sshd:session\): session (opened|closed) for user ([^\s(]+)(?:\(uid=\d+\))?(?: by .*|$)`)
	logindOpened = regexp.MustCompile(`^New session ([A-Za-z0-9]+) of user (\S+)\.$`)
	logindClosed = regexp.MustCompile(`^Removed session ([A-Za-z0-9]+)\.$`)
	sshAccepted  = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)

	// sudo-rs (Ubuntu 26.04) leaves its TTY field empty without a terminal, so its "alice :  PWD=/" has two blanks.
	sudoLine = regexp.MustCompile(`^\s*(\S+) : +(.*)$`)

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
// pid comes from the syslog header or journald _PID; an absent PID leaves the session key unset.
func ParseAuth(program, message string, at time.Time, pid string) (Event, bool) {
	switch program {
	case "sshd", "sshd-session", "sshd-auth", "sshd.pam", "sshd-session.pam":
		e, ok := parseSSH(program, message, at)
		if ok && pid != "" && e.Kind != KindSSHLoginFailed {
			e.set("session", pid)
		}
		return e, ok
	case "systemd-logind":
		if m := logindOpened.FindStringSubmatch(message); m != nil {
			e := authEvent(KindSSHSessionOpened, program, message, at)
			e.Username = m[2]
			e.set("logind_session", m[1])
			return e, true
		}
		if m := logindClosed.FindStringSubmatch(message); m != nil {
			e := authEvent(KindSSHSessionClosed, program, message, at)
			e.set("logind_session", m[1])
			return e, true
		}
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
	if m := sshSession.FindStringSubmatch(message); m != nil {
		kind := KindSSHSessionOpened
		if m[1] == "closed" {
			kind = KindSSHSessionClosed
		}
		e := authEvent(kind, program, message, at)
		e.Username = m[2]
		return e, true
	}
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
// "alice : 3 incorrect password attempts ; ..." and "bob : user NOT in sudoers ; ...". The arguments of the
// command and the values of ENV are never kept, in the fields or in the message (see sudoCommand). Only what is
// read is kept: sudo's own fields and a failure in sudoFailures. A line with an unknown status is kept only when
// it has the fields of a command, with the status replaced by unparsedStatus, and any other line is dropped.
func parseSudo(message string, at time.Time) (Event, bool) {
	m := sudoLine.FindStringSubmatchIndex(message)
	if m == nil || strings.HasPrefix(message, "pam_") {
		return Event{}, false
	}
	body := message[m[4]:m[5]]
	// sudo logs a command longer than its syslog line limit in several lines, the later ones
	// "alice : (command continued) <more arguments>", which hold nothing but arguments.
	if strings.HasPrefix(body, "(command continued)") {
		return Event{}, false
	}
	parts := strings.Split(body, " ; ")
	var status []string
	if !isSudoField(parts[0]) {
		status, parts = []string{parts[0]}, parts[1:]
	}
	splits := sudoSplits(parts)
	kind, reason := KindSudoCommand, ""
	if status != nil {
		kind, reason = KindSudoFailed, sudoFailureReason(status[0])
		if reason == "" {
			status[0], reason = unparsedStatus, "other"
		}
	}
	if len(splits) == 0 && (status == nil || status[0] == unparsedStatus) {
		return Event{}, false
	}
	command := sudoCommand(splits)
	e := authEvent(kind, "sudo", message[:m[4]]+strings.Join(append(status, withoutArguments(parts, command)...), " ; "), at)
	e.Username = message[m[2]:m[3]]
	if user, ok := agreed(splits, func(s sudoSplit) string { return s.user }); ok && user != "" {
		e.set("target_user", user)
	}
	if slices.ContainsFunc(parts, isCommandPart) {
		e.set("command", command)
	}
	if tsid, ok := agreed(splits, func(s sudoSplit) string { return s.tsid }); ok && tsid != "" {
		e.set("tsid", tsid)
	}
	// TTY precedes the unescaped working directory, variables and command arguments.
	prefix := parts
	if len(prefix) > 0 && strings.HasPrefix(prefix[0], "HOST=") {
		prefix = prefix[1:]
	}
	if len(prefix) > 0 {
		if tty, ok := strings.CutPrefix(prefix[0], "TTY="); ok && tty != "" {
			e.set("tty", tty)
		}
	}
	if reason != "" {
		e.set("reason", reason)
	}
	return e, true
}

// unparsedStatus replaces the status of a sudo line that is not one of sudoFailures, whose text could be anything.
const unparsedStatus = "[unparsed]"

// sudoFailures are the statuses sudo logs before the fields of a command it refused, in sudo's own words.
var sudoFailures = []struct {
	status *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`^\d+ incorrect password attempts?$`), "incorrect_password"},
	{regexp.MustCompile(`^(?:user NOT in sudoers|\S+ is not in the sudoers file\.?(?: +This incident will be reported\.)?)$`), "not_in_sudoers"},
	{regexp.MustCompile(`^command not allowed$`), "command_not_allowed"},
	{regexp.MustCompile(`^user NOT authorized on host$`), "other"},
}

func sudoFailureReason(status string) string {
	for _, f := range sudoFailures {
		if f.status.MatchString(status) {
			return f.reason
		}
	}
	return ""
}

// unparsedCommand is the command of a sudo line whose readings do not agree on the executable or the number of
// arguments.
const unparsedCommand = "[unparsed]"

// sudoCommand is the command a sudo line ran as its executable and its number of arguments, such as
// "/usr/bin/ldapmodify [5 args]". The arguments themselves are never kept: many tools take a password as an
// option of their own or as a positional argument (ldapmodify -w, htpasswd -b, redis-cli AUTH), which no
// redaction rule can know of all. Every reading of the line must give the same executable and count, so a
// working directory or variable crafted to look like sudo's fields cannot change them; otherwise the command
// is unparsedCommand. sudo 1.9.13 and later quote an argument with blanks, older versions do not, so there each
// word counts.
func sudoCommand(splits []sudoSplit) string {
	command, ok := agreed(splits, func(s sudoSplit) string { return commandSummary(s.command) })
	if !ok || command == "" {
		return unparsedCommand
	}
	return command
}

func commandSummary(command string) string {
	tokens := commandTokens(command)
	if len(tokens) == 0 {
		return ""
	}
	executable := command[tokens[0].start:tokens[0].end]
	if n := len(tokens) - 1; n != 1 {
		return executable + " [" + strconv.Itoa(n) + " args]"
	}
	return executable + " [1 arg]"
}

// withoutArguments replaces everything from the first COMMAND part on with command, and the parts from the
// first ENV part up to there with ENV=[redacted]. Taking the first of each, wherever a crafted working
// directory puts it, leaves no variable or argument of any reading of the line in the message. A part before
// them that is not one of sudo's fields (the rest of a working directory with " ; " in it) is left out too.
func withoutArguments(parts []string, command string) []string {
	end := slices.IndexFunc(parts, isCommandPart)
	if end < 0 {
		end = len(parts)
	}
	kept := slices.Clone(parts[:end])
	if env := slices.IndexFunc(kept, func(p string) bool { return strings.HasPrefix(p, "ENV=") }); env >= 0 {
		kept = append(kept[:env], "ENV="+Redacted)
	}
	kept = slices.DeleteFunc(kept, func(p string) bool { return !isSudoField(p) })
	if end < len(parts) {
		kept = append(kept, "COMMAND="+command)
	}
	return kept
}

func isCommandPart(part string) bool {
	return strings.HasPrefix(part, "COMMAND=")
}

func isSudoField(part string) bool {
	key, _, ok := strings.Cut(part, "=")
	return ok && sudoKeys[key]
}

var sudoKeys = map[string]bool{"HOST": true, "TTY": true, "CHROOT": true, "PWD": true, "USER": true, "GROUP": true, "TSID": true, "ENV": true, "COMMAND": true}

type sudoSplit struct{ user, command, tsid string }

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
		tsid := ""
		if k < len(parts) && strings.HasPrefix(parts[k], "TSID=") {
			tsid = strings.TrimPrefix(parts[k], "TSID=")
			k++
		}
		commandAt := func(j int) {
			if isCommandPart(parts[j]) {
				splits = append(splits, sudoSplit{user: user, tsid: tsid, command: strings.TrimPrefix(strings.Join(parts[j:], " ; "), "COMMAND=")})
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
