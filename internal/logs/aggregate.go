package logs

import (
	"bufio"
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"time"
)

const maxURILength = 512

//go:embed testdata/suspicious_tokens.txt
var suspiciousTokensFile string

// URITokens are matched case insensitively against the URI of web requests, AnyTokens against the URI and
// the user agent.
var URITokens, AnyTokens = parseTokens(suspiciousTokensFile)

func parseTokens(text string) ([]string, []string) {
	var uri, anywhere []string
	section := &anywhere
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "" || line == "#" || strings.HasPrefix(line, "# "):
		case line == "[uri]":
			section = &uri
		case line == "[any]":
			section = &anywhere
		default:
			*section = append(*section, strings.ToLower(line))
		}
	}
	return uri, anywhere
}

var normalMethods = []string{"GET", "HEAD", "POST", "OPTIONS"}

// Suspicious reports whether a web request is sent in full: an error status, an unusual method, a very long
// URI, or a URI or user agent containing a suspicious token.
func Suspicious(e Event) bool {
	status, _ := e.Fields["status"].(int)
	method, _ := e.Fields["method"].(string)
	path, _ := e.Fields["path"].(string)
	agent, _ := e.Fields["user_agent"].(string)
	if status >= 400 || !slices.Contains(normalMethods, method) || len(path) > maxURILength {
		return true
	}
	path, agent = strings.ToLower(path), strings.ToLower(agent)
	for _, token := range URITokens {
		if strings.Contains(path, token) {
			return true
		}
	}
	for _, token := range AnyTokens {
		if strings.Contains(path, token) || strings.Contains(agent, token) {
			return true
		}
	}
	return false
}

type sshKey struct {
	ip, user string
	minute   time.Time
}

type commandKey struct {
	session, auid, cwd, executable, tty string
	argc                                int
	minute                              time.Time
}

type commandBudget struct {
	minute   time.Time
	total    int
	sessions map[string]int
}

type trafficKey struct {
	ip     string
	minute time.Time
}

// Aggregator keeps what detection needs and condenses the noise: failed SSH logins become one event per IP,
// user name and minute, and web requests Redact did not mark suspicious one http_traffic event per IP and
// minute with counts per status class. Everything else passes through.
type Aggregator struct {
	commands     map[commandKey]*Event
	commandOrder []commandKey
	budget       commandBudget
	dropped      int
	events       []Event
	ssh          map[sshKey]*Event
	sshOrder     []sshKey
	traffic      map[trafficKey]*Event
	trafficOrder []trafficKey
}

func NewAggregator() *Aggregator {
	return &Aggregator{commands: map[commandKey]*Event{}, ssh: map[sshKey]*Event{}, traffic: map[trafficKey]*Event{}}
}

func (a *Aggregator) Add(e Event) {
	switch {
	case e.Kind == KindCommand:
		field := func(k string) string { s, _ := e.Fields[k].(string); return s }
		argc, _ := e.Fields["arg_count"].(int)
		key := commandKey{field("ses"), field("auid"), field("cwd"), field("executable"), field("tty"), argc, e.FirstAt.Truncate(time.Minute)}
		if existing := a.commands[key]; existing != nil {
			merge(existing, e)
			return
		}
		if !a.budget.minute.Equal(key.minute) {
			// A stale replay must not reset the budget for the current minute.
			if key.minute.Before(a.budget.minute) {
				a.dropped += max(e.Count, 1)
				return
			}
			a.budget = commandBudget{minute: key.minute, sessions: map[string]int{}}
		}
		session := key.session + ":" + key.auid
		if a.budget.total >= 512 || a.budget.sessions[session] >= 60 {
			a.dropped += max(e.Count, 1)
			return
		}
		a.budget.total++
		a.budget.sessions[session]++
		a.commands[key] = &e
		a.commandOrder = append(a.commandOrder, key)
	case e.Kind == KindSSHLoginFailed:
		key := sshKey{e.SrcIP, e.Username, e.FirstAt.Truncate(time.Minute)}
		if existing, ok := a.ssh[key]; ok {
			merge(existing, e)
			return
		}
		a.ssh[key] = &e
		a.sshOrder = append(a.sshOrder, key)
	case e.Kind == KindHTTPRequest && !e.Suspicious:
		key := trafficKey{e.SrcIP, e.FirstAt.Truncate(time.Minute)}
		existing, ok := a.traffic[key]
		if !ok {
			traffic := newEvent(SourceWeb, KindHTTPTraffic, e.FirstAt, "")
			traffic.SrcIP = e.SrcIP
			traffic.Count = 0
			traffic.Fields = map[string]any{"status_2xx": 0, "status_3xx": 0, "status_4xx": 0, "status_5xx": 0}
			existing = &traffic
			a.traffic[key] = existing
			a.trafficOrder = append(a.trafficOrder, key)
		}
		merge(existing, e)
		existing.Message = fmt.Sprintf("requests from %s: %d", existing.SrcIP, existing.Count)
		if status, _ := e.Fields["status"].(int); status >= 200 && status < 600 {
			class := fmt.Sprintf("status_%dxx", status/100)
			existing.Fields[class] = existing.Fields[class].(int) + 1
		}
	default:
		a.events = append(a.events, e)
	}
}

func merge(into *Event, e Event) {
	into.Count += max(e.Count, 1)
	if e.FirstAt.Before(into.FirstAt) {
		into.FirstAt = e.FirstAt
	}
	if e.LastAt.After(into.LastAt) {
		into.LastAt = e.LastAt
	}
}

// Pending is the number of events Flush would return.
func (a *Aggregator) Pending() int {
	return len(a.events) + len(a.ssh) + len(a.traffic) + len(a.commands)
}

// Flush returns the pending events and starts over. A minute that spans two flushes yields two events for
// the same key; their counts add up.
func (a *Aggregator) Flush() []Event {
	out := a.events
	for _, key := range a.commandOrder {
		out = append(out, *a.commands[key])
	}
	for _, key := range a.sshOrder {
		out = append(out, *a.ssh[key])
	}
	for _, key := range a.trafficOrder {
		out = append(out, *a.traffic[key])
	}
	budget, dropped := a.budget, a.dropped
	*a = *NewAggregator()
	a.budget, a.dropped = budget, dropped
	return out
}

// TakeDropped returns the commands rejected by the per-minute budgets since the last call.
func (a *Aggregator) TakeDropped() int { n := a.dropped; a.dropped = 0; return n }
