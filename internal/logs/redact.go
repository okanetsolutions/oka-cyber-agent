package logs

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	Redacted = "[redacted]"

	MaxMessageLength = 2000
	maxFieldLength   = 1024
	maxNameLength    = 255
)

var (
	sensitiveParameterWords = []string{"pass", "pwd", "secret", "token", "key", "auth", "session", "sessid", "sig", "code", "jwt", "mail", "phone", "user", "login"}

	queryParameter   = regexp.MustCompile(`([?&;])([^=&;#\s"?]+)=([^&;#\s"]*)`)
	jwtShaped        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+`)
	emailAddress     = regexp.MustCompile(`[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	passwordOption   = regexp.MustCompile(`(?i)(^|\s)(--password|--pass)(=|\s+)("[^"]*"|'[^']*'|\S+)`)
	shortPassword    = regexp.MustCompile(`(^|\s)-p(\s+)("[^"]*"|'[^']*'|\S+)`)
	attachedPassword = regexp.MustCompile(`(^|\s)-p([^\s-]\S*)`)
	secretVariable   = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET))=("[^"]*"|'[^']*'|\S+)`)
	sshUserName      = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
)

// Redact removes secrets and personal data from an event before it reaches the spool:
//   - query parameter values whose name looks sensitive (attack payloads in other parameters stay, they are evidence),
//   - JWT shaped strings and email addresses anywhere,
//   - password style arguments of sudo commands,
//   - SSH user names on failed logins that are not valid user names, since people type passwords into the user prompt.
//
// It then cuts the message and fields to the server's limits.
func Redact(e Event) Event {
	if e.Fields != nil {
		fields := make(map[string]any, len(e.Fields))
		for k, v := range e.Fields {
			fields[k] = v
		}
		e.Fields = fields
	}
	switch e.Kind {
	case KindSSHLoginFailed:
		if e.Username != "" && !sshUserName.MatchString(e.Username) {
			e.Message = strings.Replace(e.Message, " "+e.Username+" from ", " "+Redacted+" from ", 1)
			e.Username = Redacted
		}
	case KindSudoCommand, KindSudoFailed:
		e.Message = RedactCommand(e.Message)
		if command, ok := e.Fields["command"].(string); ok {
			e.Fields["command"] = RedactCommand(command)
		}
	case KindHTTPRequest:
		e.Message = RedactQuery(e.Message)
		if path, ok := e.Fields["path"].(string); ok {
			e.Fields["path"] = RedactQuery(path)
		}
	}
	e.Message = cut(redactEverywhere(e.Message), MaxMessageLength)
	e.Username = cut(redactEverywhere(e.Username), maxNameLength)
	e.Program = cut(e.Program, maxNameLength)
	for k, v := range e.Fields {
		if s, ok := v.(string); ok {
			e.Fields[k] = cut(redactEverywhere(s), maxFieldLength)
		}
	}
	return e
}

func redactEverywhere(s string) string {
	s = jwtShaped.ReplaceAllString(s, Redacted)
	return emailAddress.ReplaceAllString(s, Redacted)
}

// RedactQuery replaces the values of sensitive query parameters in every URL of s.
func RedactQuery(s string) string {
	return queryParameter.ReplaceAllStringFunc(s, func(match string) string {
		m := queryParameter.FindStringSubmatch(match)
		if m[3] == "" || !sensitiveParameter(m[2]) {
			return match
		}
		return m[1] + m[2] + "=" + Redacted
	})
}

func sensitiveParameter(name string) bool {
	if decoded, err := url.QueryUnescape(name); err == nil {
		name = decoded
	}
	name = strings.ToLower(name)
	for _, word := range sensitiveParameterWords {
		if strings.Contains(name, word) {
			return true
		}
	}
	return false
}

// RedactCommand replaces the values of password style arguments (-p, --password, --pass) and of
// PASSWORD=, TOKEN= and SECRET= style variables.
func RedactCommand(s string) string {
	s = passwordOption.ReplaceAllString(s, "$1$2$3"+Redacted)
	s = shortPassword.ReplaceAllString(s, "$1-p$2"+Redacted)
	s = attachedPassword.ReplaceAllString(s, "$1-p"+Redacted)
	return secretVariable.ReplaceAllString(s, "$1="+Redacted)
}

func cut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
