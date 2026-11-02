package logs

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	Redacted = "[redacted]"

	MaxMessageLength = 2000
	maxFieldLength   = 1024
	maxNameLength    = 255

	// maxNestedQueries bounds how deep a query parameter value is searched for a nested query, decoded or not.
	maxNestedQueries = 4
)

var (
	sensitiveParameterWords = []string{"pass", "pwd", "secret", "token", "key", "auth", "session", "sessid", "sig", "code", "jwt", "mail", "phone", "user", "login"}
	secretVariableWords     = []string{"KEY", "SECRET", "TOKEN", "PASS", "CREDENTIAL", "AUTH"}
	secretOptionSuffixes    = []string{"token", "password", "passwd", "pass", "passphrase", "secret", "api-key", "apikey", "access-key", "secret-key", "credential", "credentials"}
	authSchemes             = []string{"basic", "bearer", "digest", "token", "negotiate", "apikey", "aws4-hmac-sha256"}

	queryParameter   = regexp.MustCompile(`([?&;])([^=&;#\s"?]+)=([^&;#\s"]*)`)
	jwtShaped        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+`)
	emailAddress     = regexp.MustCompile(`[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	urlPassword      = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@'"]*):[^/\s@'"]+@`)
	longOption       = regexp.MustCompile(`(^|\s)--([A-Za-z0-9][A-Za-z0-9_-]*)(=|\s+)("[^"]*"|'[^']*'|\S+)`)
	shortPassword    = regexp.MustCompile(`(^|\s)-p(\s+)("[^"]*"|'[^']*'|\S+)`)
	attachedPassword = regexp.MustCompile(`(^|\s)-p([^\s-]\S*)`)
	userPassword     = regexp.MustCompile(`(^|\s)(-u|--user)(=|\s*)(["']?)([^\s:"']*):("[^"]*"|'[^']*'|[^\s"']+)`)
	secretHeader     = regexp.MustCompile(`(?i)(?:^|\s)(?:-H|--header)(?:=|\s*)(["']?)\s*(?:proxy-authorization|authorization|cookie|x-api-key|x-auth-token)\s*:`)
	variableName     = regexp.MustCompile(`(?i)(?:^|[\s"'(=])([A-Z_][A-Z0-9_]*)=`)
	secretKeyValue   = regexp.MustCompile(`(?i)(["']?)\b([a-z0-9_.-]*(?:pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization|cookie)[a-z0-9_.-]*)(["']?\s*[:=]\s*)`)
	sshUserName      = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
)

// Redact removes secrets and personal data from an event before it reaches the spool:
//   - query parameter values whose name looks sensitive, also in a query nested in another parameter's value
//     (attack payloads in other parameters stay, they are evidence),
//   - JWT shaped strings and email addresses anywhere,
//   - passwords in URLs, and secret options, variables and headers of sudo commands,
//   - secret looking key=value or key: value pairs in application errors,
//   - SSH user names on failed logins that are not valid user names, since people type passwords into the user prompt.
//
// Detection must not lose what redaction hides, so whether a web request is suspicious is decided on the raw
// request first and kept on the event; nothing else of the raw line is kept. It then cuts the message and
// fields to the server's limits.
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
		e.Suspicious = Suspicious(e)
		e.Message = RedactQuery(e.Message)
		if path, ok := e.Fields["path"].(string); ok {
			e.Fields["path"] = RedactQuery(path)
		}
	case KindAppError:
		e.Message = RedactText(e.Message)
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

// RedactQuery replaces the values of sensitive query parameters in every URL of s. A value that holds a query
// of its own (a redirect target such as next=/reset?token=x) is redacted the same way, and when only its
// percent decoded form holds a sensitive parameter, the whole value is replaced.
func RedactQuery(s string) string {
	return redactQuery(s, maxNestedQueries)
}

func redactQuery(s string, depth int) string {
	return queryParameter.ReplaceAllStringFunc(s, func(match string) string {
		m := queryParameter.FindStringSubmatch(match)
		if m[3] == "" {
			return match
		}
		if sensitiveParameter(m[2]) {
			return m[1] + m[2] + "=" + Redacted
		}
		return m[1] + m[2] + "=" + redactNestedQuery(m[3], depth)
	})
}

// redactNestedQuery redacts sensitive parameters of a query inside a parameter value. A sensitive parameter
// that shows only after percent decoding cannot be redacted in place, so the whole value goes.
func redactNestedQuery(value string, depth int) string {
	if !strings.ContainsAny(value, "?&;=%") {
		return value
	}
	if depth == 0 {
		return Redacted
	}
	value = strings.TrimPrefix(redactQuery("&"+value, depth-1), "&")
	decoded := value
	for range maxNestedQueries {
		next := percentDecode(decoded)
		if next == decoded {
			break
		}
		decoded = next
		if strings.ContainsAny(decoded, "?&;=") && redactQuery("&"+decoded, depth-1) != "&"+decoded {
			return Redacted
		}
	}
	return value
}

// percentDecode decodes the valid %XX escapes of s and leaves anything else as it is, so a stray % cannot hide
// what follows it.
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

func sensitiveParameter(name string) bool {
	return containsAny(strings.ToLower(percentDecode(name)), sensitiveParameterWords)
}

// RedactCommand replaces secrets in a command line: password style arguments (-p, and long options such as
// --password, --token, --secret, --api-key or --client-secret), variables whose name contains KEY, SECRET,
// TOKEN, PASS, CREDENTIAL or AUTH, the password of -u/--user user:password, Authorization, Cookie and
// X-Api-Key headers, the password in a URL and sensitive query parameters.
func RedactCommand(s string) string {
	s = redactSecretHeaders(s)
	s = urlPassword.ReplaceAllString(s, "$1:"+Redacted+"@")
	s = userPassword.ReplaceAllString(s, "$1$2$3$4$5:"+Redacted)
	s = longOption.ReplaceAllStringFunc(s, func(match string) string {
		m := longOption.FindStringSubmatch(match)
		if !secretOption(m[2]) {
			return match
		}
		return m[1] + "--" + m[2] + m[3] + Redacted
	})
	s = shortPassword.ReplaceAllString(s, "$1-p$2"+Redacted)
	s = attachedPassword.ReplaceAllString(s, "$1-p"+Redacted)
	s = redactSecretVariables(s)
	return RedactQuery(s)
}

func secretOption(name string) bool {
	name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	for _, suffix := range secretOptionSuffixes {
		if name == suffix || strings.HasSuffix(name, "-"+suffix) {
			return true
		}
	}
	return false
}

// redactSecretVariables replaces the values of NAME=value variables whose name looks secret. A variable may
// be the value of another one, as in sudo's ENV=AWS_SECRET_ACCESS_KEY=x, so the search goes on inside values.
func redactSecretVariables(s string) string {
	var b strings.Builder
	for {
		loc := variableName.FindStringSubmatchIndex(s)
		if loc == nil {
			b.WriteString(s)
			return b.String()
		}
		name := strings.ToUpper(s[loc[2]:loc[3]])
		b.WriteString(s[:loc[1]])
		s = s[loc[1]:]
		if !containsAny(name, secretVariableWords) {
			continue
		}
		if n := commandValueLength(s); n > 0 {
			b.WriteString(Redacted)
			s = s[n:]
		}
	}
}

// commandValueLength is the length of the shell word at the start of s: a quoted string or a run of
// non-space characters.
func commandValueLength(s string) int {
	if s == "" {
		return 0
	}
	if quote := s[0]; quote == '"' || quote == '\'' {
		if i := strings.IndexByte(s[1:], quote); i >= 0 {
			return i + 2
		}
		return len(s)
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return i
	}
	return len(s)
}

func containsAny(s string, words []string) bool {
	for _, word := range words {
		if strings.Contains(s, word) {
			return true
		}
	}
	return false
}

// redactSecretHeaders replaces the value of -H/--header Authorization, Cookie and API key headers, keeping an
// authorization scheme such as Bearer. sudo logs the arguments of a command without quotes on older versions,
// so an unquoted value runs up to the next option or URL.
func redactSecretHeaders(s string) string {
	var b strings.Builder
	for {
		loc := secretHeader.FindStringSubmatchIndex(s)
		if loc == nil {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:loc[1]])
		rest := s[loc[1]:]
		end := len(rest)
		if quote := s[loc[2]:loc[3]]; quote != "" {
			if i := strings.Index(rest, quote); i >= 0 {
				end = i
			}
		} else {
			end = unquotedArgumentsEnd(rest)
		}
		b.WriteString(redactHeaderValue(rest[:end]))
		s = rest[end:]
	}
}

func unquotedArgumentsEnd(s string) int {
	end := 0
	for i, field := range strings.Fields(s) {
		at := end + strings.Index(s[end:], field)
		if i > 0 && (strings.HasPrefix(field, "-") || strings.Contains(field, "://")) {
			return end
		}
		end = at + len(field)
	}
	return len(s)
}

func redactHeaderValue(value string) string {
	trimmed := strings.TrimLeft(value, " \t")
	if trimmed == "" {
		return value
	}
	lead := value[:len(value)-len(trimmed)]
	if scheme, rest, ok := strings.Cut(trimmed, " "); ok && strings.TrimSpace(rest) != "" && isAuthScheme(scheme) {
		return lead + scheme + " " + Redacted
	}
	return lead + Redacted
}

func isAuthScheme(word string) bool {
	for _, scheme := range authSchemes {
		if strings.EqualFold(word, scheme) {
			return true
		}
	}
	return false
}

// RedactText redacts free text such as an application error: sensitive query parameters, passwords in URLs
// and the values of secret looking key=value and key: value pairs, quoted (JSON context) or not.
func RedactText(s string) string {
	s = RedactQuery(s)
	s = urlPassword.ReplaceAllString(s, "$1:"+Redacted+"@")
	var b strings.Builder
	for {
		loc := secretKeyValue.FindStringIndex(s)
		if loc == nil {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:loc[1]])
		s = s[loc[1]:]
		if scheme, rest, ok := strings.Cut(s, " "); ok && isAuthScheme(scheme) && secretValueLength(rest) > 0 {
			b.WriteString(scheme + " ")
			s = rest
		}
		n := secretValueLength(s)
		switch {
		case n == 0:
		case s[0] == '"' || s[0] == '\'':
			b.WriteString(s[:1] + Redacted + s[:1])
		default:
			b.WriteString(Redacted)
		}
		s = s[n:]
	}
}

// secretValueLength is the length of the value at the start of s: a quoted string or a run up to the next
// separator. A value already redacted is left alone.
func secretValueLength(s string) int {
	if s == "" || strings.HasPrefix(s, Redacted) {
		return 0
	}
	if quote := s[0]; quote == '"' || quote == '\'' {
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
			case quote:
				return i + 1
			}
		}
		return len(s)
	}
	end := strings.IndexAny(s, " \t,;&}])\"'")
	if end < 0 {
		end = len(s)
	}
	return end
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
