package logs

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
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

// A name is secret (see secretName) when, lower cased and without leading dashes and separators, it contains one
// of secretWords. The same rule decides for command options, variables, query parameters, key/value pairs, JSON
// and PHP array keys and HTTP headers, so a new place a secret can hide only needs a new way to find names.
var (
	secretWords = []string{"pass", "pwd", "secret", "token", "key", "cred", "auth", "cookie", "session", "sessid"}

	// notSecretParts are words that contain a secret word by chance, public keys, and the keytool and openssl
	// commands that make a key or key store. They are cut out of a name before it is checked, so GIT_ASKPASS or
	// --keyring stay readable while keyring_password does not.
	notSecretParts = []string{"askpass", "keyboard", "keyword", "monkey", "passive", "bypass", "compass", "passthrough", "keyring", "keyserver", "keystore", "genkey", "pubkey", "publickey"}
	// notSecretNames are whole names known to hold no secret: author is not authorization, gpg and openssl
	// options that name a key file, format or algorithm, and kubeadm's public CA certificate hash.
	notSecretNames = []string{"author", "authors", "newkey", "keyout", "keyform", "keyalg", "recvkeys", "discoverytokencacerthash"}
	// notSecretSuffixes end names whose value is where or what kind of secret, not the secret: --password-file,
	// --token-ttl, --password-stdin, SSH_AUTH_SOCK.
	notSecretSuffixes = []string{"file", "path", "dir", "sock", "stdin", "ttl", "size", "length", "bits", "type"}
	// switchWords start options that turn a behaviour on or off and take no value, such as --no-ask-password or
	// --allow-unauthenticated, so the argument after them is not a secret.
	switchWords = []string{"no", "ask", "allow", "skip", "ignore", "disable", "require"}
	// notSecretValues are values that cannot be a secret: --password-authentication=no, "authenticated":true.
	notSecretValues = []string{"yes", "no", "true", "false", "on", "off", "null", "none", "nil"}

	// personalParameterWords are query parameters that are not secrets by name but hold personal data, one time
	// codes or signatures.
	personalParameterWords = []string{"sig", "code", "jwt", "mail", "phone", "user", "login"}
	pamGroups              = []string{"auth", "account", "session", "password", "chauthtok"}
	authSchemes            = []string{"basic", "bearer", "digest", "token", "negotiate", "apikey", "aws4-hmac-sha256"}

	// attachedPasswordTools take their password attached to -p (-pS3cret). For other programs -p followed by a
	// letter is a group of flags (tar -pczf) or a longer option name (openssl -pass).
	attachedPasswordTools = []string{"mysql", "mysqldump", "mysqladmin", "mysqlimport", "mysqlshow", "mysqlcheck", "mysqlpump", "mysqlbinlog", "mysqlslap", "mariadb", "mariadb-dump", "mariadb-admin", "mariadb-import", "mariadb-show", "mariadb-check", "mariadb-binlog", "mariadb-slap"}
	// shortSecretOptions are single letter options whose next argument is a password, per program, besides -p.
	shortSecretOptions = map[string]string{"redis-cli": "a", "valkey-cli": "a", "keydb-cli": "a", "openssl": "k", "curl": "b"}

	queryParameter = regexp.MustCompile(`([?&;])([^=&;#\s"?]+)=([^&;#\s"]*)`)
	jwtShaped      = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+`)
	emailAddress   = regexp.MustCompile(`[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	urlUserinfo    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)([^/?#\s:@'"]*)(:[^/?#\s'"]*)?@`)
	// secretKeyValue finds a key and the separator after it: key=value, key: value, 'key' => value,
	// [key] => value and "key": with its quotes escaped to any depth (\"key\": inside a JSON string), or a key
	// followed by blanks or a parenthesis, which counts only when a quoted value follows (SQL PASSWORD 'x',
	// PASSWORD('x'), token "x").
	secretKeyValue = regexp.MustCompile(`(\\*["']|\[)?([A-Za-z0-9_][A-Za-z0-9_.-]*)(\\*["']|\])?(\s*(?:=>|[:=])\s*|\s*\(\s*|\s+)`)
	identifiedBy   = regexp.MustCompile(`(?i)\bidentified(?:\s+with\s+\S+)?\s+$`)
	sshUserName    = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	// phpArray starts an array as print_r (Array) and var_export (array) write it, the parenthesis after blanks,
	// line breaks or line breaks escaped in a JSON string.
	phpArray = regexp.MustCompile(`^(?i:array)(?:\s|\\+[nrt])*\(`)
	// emptyStructure is a structured value that holds nothing: [], {}, Array ( ).
	emptyStructure = regexp.MustCompile(`^(?i:array)?(?:[\s\[\]{}()]|\\+[nrt])*$`)
)

// Redact removes secrets and personal data from an event before it reaches the spool. In every string of every
// event, the message, the user name, the program and each field (see redactEverywhere):
//   - values of sensitive query parameters, also in a query nested in another parameter's value (attack
//     payloads in other parameters stay, they are evidence),
//   - URL passwords, JWT shaped strings and email addresses,
//   - the values of secret key/value pairs, JSON and PHP array entries (also JSON escaped inside a JSON
//     string, and the whole value when it is a JSON array or object or a PHP array) and SQL password literals.
//
// sudo events carry no command arguments and no variables at all (see sudoCommand). Before that, by kind:
//   - in application errors also the secret options of a command line the text quotes,
//   - SSH user names on failed logins that are not valid user names, since people type passwords into the user prompt.
//
// Secret means a name secretName accepts. Detection must not lose what redaction hides, so whether a web request
// is suspicious is decided on the raw request first and kept on the event; nothing else of the raw line is kept.
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
	case KindHTTPRequest:
		e.Suspicious = Suspicious(e)
	case KindAppError:
		e.Message = RedactText(e.Message)
	}
	e.Message = cut(redactEverywhere(e.Message), MaxMessageLength)
	e.Username = cut(redactEverywhere(e.Username), maxNameLength)
	e.Program = cut(redactEverywhere(e.Program), maxNameLength)
	for k, v := range e.Fields {
		if s, ok := v.(string); ok {
			e.Fields[k] = cut(redactEverywhere(s), maxFieldLength)
		}
	}
	return e
}

// redactEverywhere is the last pass over every string an event carries, whatever its kind, so that a URL with
// a password in a referer or a user agent is redacted like one in an application error.
func redactEverywhere(s string) string {
	s = RedactQuery(redactURLUserinfo(s))
	s = redactSpans(s, keyValueSpans(s))
	s = jwtShaped.ReplaceAllString(s, Redacted)
	return emailAddress.ReplaceAllString(s, Redacted)
}

// secretName tells whether a name (an option, variable, parameter, key or header) holds a secret: it contains
// one of secretWords once lower cased, its leading dashes and its separators (- _ . and blanks) removed, and
// it is not one of the known exceptions above.
func secretName(name string) bool {
	lower := strings.ToLower(strings.TrimLeft(name, "-"))
	if first, rest, ok := strings.Cut(lower, "-"); ok && rest != "" && slices.Contains(switchWords, first) {
		return false
	}
	if first, rest, ok := strings.Cut(lower, "_"); ok && rest != "" && slices.Contains(switchWords, first) {
		return false
	}
	n := normalizedName(lower)
	if slices.Contains(notSecretNames, n) {
		return false
	}
	// A part is cut out as a blank, not joined, so the words found are words of the name and of any text
	// holding it (see mayHoldSecretName).
	for _, part := range notSecretParts {
		n = strings.ReplaceAll(n, part, " ")
	}
	n = strings.TrimSpace(n)
	for _, suffix := range notSecretSuffixes {
		if strings.HasSuffix(n, suffix) {
			return false
		}
	}
	return holdsSecretWord(n)
}

// holdsSecretWord is the test secretName ends with, on a normalized name.
func holdsSecretWord(normalized string) bool {
	return containsAny(normalized, secretWords)
}

// mayHoldSecretName is false only when no name in s can be secret, so a rule may skip such a text. It runs
// secretName's own normalization and word test on the whole text: a name is a run of s, its normalized form is a
// run of the normalized s, so a secret word secretName finds in it is found here too.
func mayHoldSecretName(s string) bool {
	return holdsSecretWord(normalizedName(s))
}

func normalizedName(name string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '-', '_', '.', ' ', '\t':
			return -1
		}
		return unicode.ToLower(r)
	}, strings.TrimLeft(name, "-"))
}

// harmlessValue is a value of a secret name that is no secret: empty, masked (***), a boolean or null, and the
// working directory in PWD and OLDPWD (sudo's PWD= field), while pwd=x elsewhere is a password.
func harmlessValue(name, value string) bool {
	v := strings.ToLower(value)
	if strings.Trim(v, "*") == "" || slices.Contains(notSecretValues, v) {
		return true
	}
	n := normalizedName(name)
	return (n == "pwd" || n == "oldpwd") && strings.HasPrefix(value, "/")
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
		if sensitiveParameter(m[2], m[3]) {
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

func sensitiveParameter(name, value string) bool {
	name = percentDecode(name)
	if secretName(name) {
		return !harmlessValue(name, percentDecode(value))
	}
	return containsAny(strings.ToLower(name), personalParameterWords)
}

// RedactText redacts free text such as an application error: sensitive query parameters, passwords in URLs,
// the values of secret key=value and key: value pairs, JSON and PHP array entries, quoted or not and with their
// quotes escaped to any depth, SQL password literals, and secret options of a command line the text quotes
// (a failed process).
func RedactText(s string) string {
	s = RedactQuery(redactURLUserinfo(s))
	return redactSpans(s, keyValueSpans(s), secretArgumentSpans(s, 0, maxQuotedCommands))
}

// redactSpans replaces the union of the spans every rule found in s, each run of overlapping or touching spans
// by one Redacted. Every rule looks at the same text, so what one rule hides can never hide a secret from
// another (a program name that tells what -p means, the -H before a header).
func redactSpans(s string, found ...[]span) string {
	spans := slices.Concat(found...)
	if len(spans) == 0 {
		return s
	}
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	var b strings.Builder
	last := 0
	for i := 0; i < len(spans); {
		start, end := spans[i].start, spans[i].end
		for i++; i < len(spans) && spans[i].start <= end; i++ {
			end = max(end, spans[i].end)
		}
		b.WriteString(s[last:start])
		b.WriteString(Redacted)
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

// redactURLUserinfo replaces the password of user:password@ in a URL, and a user name that is not a valid one
// (an access token used as the user, https://ghp_x@github.com).
func redactURLUserinfo(s string) string {
	return urlUserinfo.ReplaceAllStringFunc(s, func(match string) string {
		m := urlUserinfo.FindStringSubmatch(match)
		switch {
		case m[3] != "":
			return m[1] + m[2] + ":" + Redacted + "@"
		case m[2] != "" && !sshUserName.MatchString(m[2]):
			return m[1] + Redacted + "@"
		}
		return match
	})
}

// maxQuotedCommands bounds how deep a quoted argument is searched as a command line of its own
// (sh -c 'mysql -pS3cret').
const maxQuotedCommands = 2

// secretArgumentSpans looks at every argument of a command line in turn. An argument is only taken as the
// value of the option before it when that option is a secret one or -u/--user, so an option that takes no value
// (--single-transaction --password=x) never hides the secret option after it. A value that looks like an option
// (--password --token x) is redacted and still read as an option. A quoted part with blanks in it is read as a
// command line too, as sudo writes the script of sh -c 'mysql -pS3cret' or an error quotes a failed command.
func secretArgumentSpans(s string, offset, depth int) []span {
	var spans []span
	expect := argPlain
	tool := ""
	for _, t := range commandTokens(s) {
		arg := s[t.start:t.end]
		if !strings.HasPrefix(arg, "-") {
			if name := programName(arg); slices.Contains(attachedPasswordTools, name) || shortSecretOptions[name] != "" {
				tool = name
			}
		}
		next, from := secretArgument(arg, tool)
		switch {
		case expect == argSecret:
			from = 0
		case expect == argUser && strings.Contains(arg, ":"):
			from = userPassword(arg, 0)
		}
		switch {
		case from >= 0:
			end := t.end
			if quote := arg[:1]; from > 0 && (quote == "'" || quote == `"`) && len(arg) > 1 && strings.HasSuffix(arg, quote) {
				end--
			}
			if t.start+from < end {
				spans = append(spans, span{offset + t.start + from, offset + end})
			}
		case depth > 0:
			for _, q := range t.quoted {
				if strings.ContainsAny(s[q.start:q.end], " \t") {
					spans = append(spans, secretArgumentSpans(s[q.start+1:q.end-1], offset+q.start+1, depth-1)...)
				}
			}
		}
		expect = next
	}
	return spans
}

const (
	argPlain = iota
	argSecret
	argUser
)

// secretArgument tells what the argument after arg is (a secret, a user:password or anything) and where the
// secret inside arg starts, -1 when it holds none. Any option, with one dash or two, whose name is secret takes
// a secret: its value after = or the next argument. -p takes a password too, attached only when a digit or a
// quote follows it or the program is a MySQL client, and so do the letters of shortSecretOptions for their
// program.
func secretArgument(arg, tool string) (next, from int) {
	body := strings.TrimLeft(arg, "-")
	dashes := len(arg) - len(body)
	if dashes == 0 || dashes > 2 || body == "" {
		return argPlain, -1
	}
	if dashes == 1 {
		letter := body[0]
		short := letter == 'p' || strings.IndexByte(shortSecretOptions[tool], letter) >= 0
		switch {
		case short && len(body) == 1:
			return argSecret, -1
		case letter == 'p' && (!isLetter(body[1]) || slices.Contains(attachedPasswordTools, tool)):
			return argPlain, 2
		case body == "u":
			return argUser, -1
		case letter == 'u':
			return argPlain, userPassword(arg, 2)
		}
	}
	name, value, hasValue := strings.Cut(body, "=")
	switch {
	case dashes == 2 && userOption(name) && !hasValue:
		return argUser, -1
	case dashes == 2 && userOption(name):
		return argPlain, userPassword(arg, len(arg)-len(value))
	case !secretName(name):
	case !hasValue:
		return argSecret, -1
	case !harmlessValue(name, unquote(value)):
		return argPlain, len(arg) - len(value)
	}
	return argPlain, -1
}

func userOption(name string) bool {
	name = strings.ToLower(name)
	return name == "user" || strings.HasSuffix(name, "-user")
}

func isLetter(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// programName is the base name of the program an argument runs, as in /usr/bin/mysql or COMMAND=/usr/bin/mysql.
func programName(arg string) string {
	arg = unquote(arg)
	if i := strings.LastIndexAny(arg, "/="); i >= 0 {
		arg = arg[i+1:]
	}
	return arg
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// userPassword is where the password of a user:password value starting at arg[from] begins, -1 without one.
func userPassword(arg string, from int) int {
	colon := strings.IndexByte(arg[from:], ':')
	if colon < 0 {
		return -1
	}
	return from + colon + 1
}

// commandToken is an argument at s[start:end] and its quoted parts, quotes included.
type commandToken struct {
	start, end int
	quoted     []span
}

type span struct{ start, end int }

// commandTokens splits a command line into arguments at blanks. A quote opens a quoted part only at the start
// of an argument, after = or :, after a short option (-p'x y') or after another quoted or escaped part, and
// only when it is closed later. A backslash never joins two arguments. sudo quotes arguments that contain
// blanks, but a quote inside a word (a directory named Bob's files in PWD) must not join the rest of the line
// into one argument and hide the options there.
func commandTokens(s string) []commandToken {
	var tokens []commandToken
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		start := i
		quotable := true
		var quoted []span
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			c := s[i]
			switch {
			case c == '\\' && i+1 < len(s) && s[i+1] != ' ' && s[i+1] != '\t':
				i += 2
				quotable = true
				continue
			case (c == '\'' || c == '"') && quotable:
				if end := closingQuote(s, i); end > 0 {
					quoted = append(quoted, span{i, end + 1})
					i = end + 1
					continue
				}
			}
			quotable = c == '=' || c == ':' || (i == start+1 && s[start] == '-')
			i++
		}
		tokens = append(tokens, commandToken{start, i, quoted})
	}
	return tokens
}

// closingQuote is the index of the quote that closes the one at s[open], or -1. A backslash escapes the next
// character inside both kinds of quotes: sudo writes a quote inside a single quoted argument as \'.
func closingQuote(s string, open int) int {
	quote := s[open]
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case quote:
			return i
		}
	}
	return -1
}

func containsAny(s string, words []string) bool {
	for _, word := range words {
		if strings.Contains(s, word) {
			return true
		}
	}
	return false
}

func isAuthScheme(word string) bool {
	for _, scheme := range authSchemes {
		if strings.EqualFold(word, scheme) {
			return true
		}
	}
	return false
}

// keyValueSpans finds the value after every secret key found by secretKeyValue. A bare value ends at the next
// blank or punctuation, and a cookie runs to the end of its string. After a key, secret or not, the search goes
// on right after the separator, since a value may hold a key of its own (ENV=AWS_SECRET_KEY=x,
// "exception":"... {\"password\":\"x\"}").
func keyValueSpans(s string) []span {
	if !mayHoldSecretName(s) && !strings.Contains(strings.ToLower(s), "identified") {
		return nil
	}
	var spans []span
	structures := structureEnds{}
	for pos := 0; pos < len(s); {
		loc := secretKeyValue.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		for i := range loc {
			if loc[i] >= 0 {
				loc[i] += pos
			}
		}
		keyStart, sepStart, sepEnd := loc[4], loc[8], loc[9]
		key, sep := s[keyStart:loc[5]], s[sepStart:sepEnd]
		// The backslashes before the key's quote tell how deep the key is escaped, as in \"key\" inside a JSON string.
		level := 0
		if loc[2] >= 0 {
			level = loc[3] - loc[2] - 1
		}
		switch {
		case loc[2] < 0 && keyStart > 0 && isWordByte(s[keyStart-1]):
			pos = keyStart + 1
			continue
		case pamServiceType(s, keyStart, sepStart, sepEnd):
		case loc[2] < 0 && loc[6] >= 0 && strings.TrimSpace(sep) == "":
			// A quoted string that ends in a secret word and the quoted string after it, as a referer ending in
			// /auth and the user agent of an access log line, are not a key and its value.
		case secretName(key) || strings.EqualFold(key, "by") && identifiedBy.MatchString(s[:keyStart]):
			if end, ok := structures.valueEnd(s, sepEnd, strings.TrimSpace(sep), level); ok {
				if !emptyStructure.MatchString(s[sepEnd:end]) {
					spans = append(spans, span{sepEnd, end})
				}
			} else if start, end := secretValue(s[sepEnd:], key, strings.TrimSpace(sep)); end > start {
				spans = append(spans, span{sepEnd + start, sepEnd + end})
			}
		}
		pos = sepEnd
	}
	return spans
}

// pamServiceType tells whether s[keyStart:sepEnd] is the service in a PAM module's (service:type), as in
// pam_unix(chpasswd:chauthtok), whose name holds a secret word while what follows is a PAM management group.
func pamServiceType(s string, keyStart, sepStart, sepEnd int) bool {
	if keyStart == 0 || s[keyStart-1] != '(' || s[sepStart:sepEnd] != ":" {
		return false
	}
	group, _, ok := strings.Cut(s[sepEnd:], ")")
	return ok && slices.Contains(pamGroups, group)
}

func isWordByte(c byte) bool {
	return isLetter(c) || '0' <= c && c <= '9' || c == '_'
}

// secretValue is where the value at the start of s after a secret key lies, start == end to keep it. A quoted
// value keeps its quotes, escaped to any depth: the value of \"key\":\"x\" is closed by the next quote preceded by
// the same escaping. After a blank or a parenthesis (sep "" or "(") only a quoted value counts. An authorization
// scheme such as Bearer is kept.
func secretValue(s, key, sep string) (start, end int) {
	if strings.HasPrefix(s, Redacted) {
		return 0, 0
	}
	if open, quote := openingQuote(s); quote != 0 {
		start := open + 1
		end := len(s)
		for i := start; i < len(s); i++ {
			if s[i] == quote && closesQuote(backslashesBefore(s, i, start), open) {
				end = i - open
				break
			}
		}
		if value := s[start:max(end, start)]; strings.HasPrefix(value, Redacted) || harmlessValue(key, value) {
			return 0, 0
		}
		return start, max(end, start)
	}
	if sep == "" || sep == "(" {
		return 0, 0
	}
	end = bareValueEnd(s, key)
	value := s[:end]
	if end == 0 || harmlessValue(key, value) {
		return 0, 0
	}
	if rest, ok := strings.CutPrefix(s[end:], " "); ok && isAuthScheme(value) {
		if strings.HasPrefix(rest, Redacted) {
			return 0, 0
		}
		if n := bareValueEnd(rest, key); n > 0 {
			return end + 1, end + 1 + n
		}
	}
	return 0, end
}

// openingQuote finds a quote at the start of s after open backslashes, 0 when s does not start with one.
func openingQuote(s string) (open int, quote byte) {
	for open < len(s) && s[open] == '\\' {
		open++
	}
	if open < len(s) && (s[open] == '"' || s[open] == '\'') {
		return open, s[open]
	}
	return 0, 0
}

// closesQuote tells whether a quote preceded by count backslashes closes a string opened with open of them.
// Each level of escaping doubles the backslashes and adds one: a level 0 string ends at a quote after an even
// number (\\"), a level 1 string (\"...\") at one after 1, 5, 9 and so on, while \\\" is a level 2 quote inside.
func closesQuote(count, open int) bool {
	return count >= open && (count-open)%(2*(open+1)) == 0
}

func backslashesBefore(s string, i, from int) int {
	n := 0
	for i--; i >= from && s[i] == '\\'; i-- {
		n++
	}
	return n
}

// structureEnds remembers where the structured values of one text end, by their start and escaping level. A
// scan records the end of every structure nested in the one it reads, so the secret keys nested in the value of
// another ({"token":{"token":...) reuse it rather than each reading the rest of the text again.
type structureEnds map[[2]int]int

// valueEnd is where the JSON array or object, or the PHP print_r or var_export array (Array ( [0] => x ), also over
// several lines or with its line breaks escaped in a JSON string), that starts s[at:] after a secret key and its
// separator ends: at its matching bracket or parenthesis, or at the end of s when it is not closed. ok is false
// when s[at:] is not one, so the value is read as a quoted or bare one. A bracket or parenthesis inside a string
// does not count: a string opens and closes with a quote escaped level times, as in closesQuote, or with a single
// quote when level is 0. A print_r array is not quoted, so its block closes at a parenthesis after a blank, the
// way print_r and var_export write it.
func (ends structureEnds) valueEnd(s string, at int, sep string, level int) (end int, ok bool) {
	value := s[at:]
	if sep == "" || sep == "(" || strings.HasPrefix(value, Redacted) {
		return 0, false
	}
	if end, ok := ends[[2]int{at, level}]; ok {
		return end, true
	}
	php := phpArray.MatchString(value)
	if !php && !strings.HasPrefix(value, "[") && !strings.HasPrefix(value, "{") {
		return 0, false
	}
	var open []int
	closeAt := func(end int) bool {
		ends[[2]int{open[len(open)-1], level}] = end
		open = open[:len(open)-1]
		return len(open) == 0
	}
scan:
	for i := at; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\'' && level == 0:
			if !closesQuote(backslashesBefore(s, i, at), level) {
				continue
			}
			closing := -1
			for j := i + 1; j < len(s); j++ {
				if s[j] == c && closesQuote(backslashesBefore(s, j, i+1), level) {
					closing = j
					break
				}
			}
			if closing < 0 {
				break scan
			}
			i = closing
		case php:
			if (c == 'a' || c == 'A') && (i == at || !isWordByte(s[i-1])) {
				if loc := phpArray.FindStringIndex(s[i:]); loc != nil {
					open = append(open, i)
					i += loc[1] - 1
				}
			} else if c == ')' && afterBlank(s, i) && closeAt(i+1) {
				return i + 1, true
			}
		case c == '[' || c == '{':
			open = append(open, i)
		case c == ']' || c == '}':
			if closeAt(i + 1) {
				return i + 1, true
			}
		}
	}
	for len(open) > 0 {
		closeAt(len(s))
	}
	return len(s), true
}

// afterBlank tells whether s[i] follows a blank, a line break or a line break escaped in a JSON string (\n), or
// directly the parenthesis that opens an empty array.
func afterBlank(s string, i int) bool {
	if i == 0 {
		return false
	}
	switch c := s[i-1]; {
	case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(':
		return true
	case c == 'n' || c == 'r' || c == 't':
		return i >= 2 && s[i-2] == '\\'
	}
	return false
}

// bareValueEnd is the length of an unquoted value at the start of s: a run up to a blank, punctuation or an
// escaped quote, and for a cookie the rest of its string.
func bareValueEnd(s, key string) int {
	cookie := strings.Contains(normalizedName(key), "cookie")
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && strings.IndexByte(`"'nrt`, s[i+1]) >= 0:
			return i
		case c == '"' || c == '\'' || c == '\n':
			return i
		case !cookie && strings.IndexByte(" \t,;&}])<", c) >= 0:
			return i
		}
	}
	return len(s)
}

// cut returns s as valid UTF-8 of at most max bytes. Log lines are not always UTF-8 (a Latin-1 byte in an
// application log), so invalid bytes are replaced rather than ending the text there. Only the first max bytes
// are looked at, and a rune split by the limit is dropped whole.
func cut(s string, max int) string {
	if len(s) > max {
		s = trimPartialRune(s[:max])
	}
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if len(s) > max {
		s = trimPartialRune(s[:max])
	}
	return s
}

// trimPartialRune drops the start of a rune that is cut short at the end of s, at most utf8.UTFMax-1 bytes.
func trimPartialRune(s string) string {
	for i := len(s) - 1; i >= 0 && i > len(s)-utf8.UTFMax; i-- {
		if utf8.RuneStart(s[i]) {
			if !utf8.FullRuneInString(s[i:]) {
				return s[:i]
			}
			break
		}
	}
	return s
}
