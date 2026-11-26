package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/trustedcmd"
)

// SD_MESSAGE_SESSION_START from systemd's sd-messages.h.
const logindSessionStart = "8d45620c1a4348dbb17410da57c60c66"

// JournalEntry is one journald entry. UID, Exe, Comm, PID, BootID, SystemdSession and AuditSession
// are trusted fields journald fills in; Identifier, MessageID, SessionID and Leader are chosen by the sender.
type JournalEntry struct {
	Cursor         string
	Transport      string
	AuditID        string
	Identifier     string
	Message        string
	At             time.Time
	UID            string
	Exe            string
	Comm           string
	PID            string
	MessageID      string
	SessionID      string
	Leader         string
	BootID         string
	SystemdSession string
	AuditSession   string
}

// ParseJournalEntry reads one line of journalctl --output=json. MESSAGE is a string, or an array of bytes
// when it is not valid UTF-8.
func ParseJournalEntry(line []byte) (JournalEntry, error) {
	var raw struct {
		Cursor         string          `json:"__CURSOR"`
		Transport      string          `json:"_TRANSPORT"`
		AuditID        string          `json:"_AUDIT_ID"`
		SourceRealtime string          `json:"_SOURCE_REALTIME_TIMESTAMP"`
		Realtime       string          `json:"__REALTIME_TIMESTAMP"`
		Identifier     string          `json:"SYSLOG_IDENTIFIER"`
		Message        json.RawMessage `json:"MESSAGE"`
		UID            string          `json:"_UID"`
		Exe            string          `json:"_EXE"`
		Comm           string          `json:"_COMM"`
		PID            string          `json:"_PID"`
		MessageID      string          `json:"MESSAGE_ID"`
		SessionID      string          `json:"SESSION_ID"`
		Leader         string          `json:"LEADER"`
		BootID         string          `json:"_BOOT_ID"`
		SystemdSession string          `json:"_SYSTEMD_SESSION"`
		AuditSession   string          `json:"_AUDIT_SESSION"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return JournalEntry{}, err
	}
	e := JournalEntry{Transport: raw.Transport, AuditID: raw.AuditID, Cursor: raw.Cursor, Identifier: raw.Identifier, UID: raw.UID, Exe: raw.Exe, Comm: raw.Comm, PID: raw.PID,
		MessageID: raw.MessageID, SessionID: raw.SessionID, Leader: raw.Leader, BootID: raw.BootID,
		SystemdSession: raw.SystemdSession, AuditSession: raw.AuditSession}
	if raw.Transport == "audit" && raw.SourceRealtime != "" {
		raw.Realtime = raw.SourceRealtime
	}
	if micros, err := strconv.ParseInt(raw.Realtime, 10, 64); err == nil {
		e.At = time.UnixMicro(micros).UTC()
	}
	var text string
	if err := json.Unmarshal(raw.Message, &text); err == nil {
		e.Message = text
	} else {
		var bytes []byte
		var ints []int
		if json.Unmarshal(raw.Message, &ints) == nil {
			for _, b := range ints {
				bytes = append(bytes, byte(b))
			}
		}
		e.Message = string(bytes)
	}
	return e, nil
}

var (
	// authBinaries are the executables allowed to log under each auth identifier. OpenSSH 9.8 and later log
	// per connection lines from sshd-session, under either identifier depending on the distribution.
	authBinaries = map[string][]string{
		"systemd-logind":   {"systemd-logind"},
		"sshd.pam":         {"sshd.pam", "sshd-session.pam"},
		"sshd-session.pam": {"sshd.pam", "sshd-session.pam"},
		"sshd":             {"sshd", "sshd-session"},
		"sshd-session":     {"sshd", "sshd-session"},
		"sudo":             {"sudo"},
		"su":               {"su"},
		"useradd":          {"useradd"},
		"usermod":          {"usermod"},
		"groupadd":         {"groupadd"},
		"gpasswd":          {"gpasswd"},
		"passwd":           {"passwd"},
		"chpasswd":         {"chpasswd"},
		"crontab":          {"crontab"},
	}
	// setIDPrograms run set-user-ID or set-group-ID, so journald records the invoking user's UID. The dynamic
	// loader ignores LD_PRELOAD for them and an unprivileged user cannot ptrace them, so a process running
	// the real binary only logs what the binary itself logs.
	setIDPrograms = []string{"sudo", "su", "passwd", "gpasswd", "crontab"}
	// systemBinDirs are the root owned directories the auth binaries are installed in: OpenSSH's
	// sshd-session lives in /usr/lib/openssh (Debian), /usr/libexec/openssh (RHEL), /usr/lib/ssh (Alpine)
	// or /usr/libexec/ssh (openSUSE), Ubuntu's sudo-rs in /usr/lib/cargo/bin, and logind in
	// /usr/lib/systemd or /lib/systemd.
	systemBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib/openssh", "/usr/libexec/openssh", "/usr/lib/ssh", "/usr/libexec/ssh", "/usr/libexec", "/usr/lib/cargo/bin", "/usr/lib/systemd", "/lib/systemd"}
)

// TrustedAuthEntry reports whether an entry that claims an auth identifier was really logged by that
// program. Any local user can pick SYSLOG_IDENTIFIER (logger -t sshd), so it is checked against _TRANSPORT,
// _EXE and _UID. The executable must be the expected binary in a system directory, and the sender must run as
// root unless the program is set-user-ID: a user can load code into a binary that is not (LD_PRELOAD=x.so
// /usr/sbin/sshd) and make it log anything. journald cannot read _EXE when a short lived process exited
// first; such an entry is accepted only from root with the expected _COMM, because a user could exit early
// on purpose.
//
// The entry must also have arrived the way the program logs: these programs call syslog(3), and logind uses
// journald's own protocol. A user chooses what the real binary prints (sudo -p 'root : ... COMMAND=/bin/x' as
// its prompt, crontab -l), and with its output connected to the journal (systemd-cat -t sudo sudo -p ...) that
// text is an entry of the real sudo under the name sudo, with _TRANSPORT=stdout.
//
// One forgery remains: _UID is taken when a message is sent, but journald reads _EXE when it handles the
// message. A process that sends a line to the syslog socket and at once becomes sudo (execve) is recorded as
// /usr/bin/sudo when journald is kept busy long enough, which a flood of messages from other processes
// achieves about one time in three (see testdata/journal/rocky-9-exec-race.jsonl). Nothing journald records
// tells such an entry from a real one of a set-user-ID program.
func TrustedAuthEntry(e JournalEntry) bool {
	return e.Transport == authTransport(e.Identifier) && trustedSender(e)
}

func authTransport(identifier string) string {
	if identifier == "systemd-logind" {
		return "journal"
	}
	return "syslog"
}

// trustedSender is TrustedAuthEntry without the transport: whether the executable, the user and the command
// name are those of the program the identifier names.
func trustedSender(e JournalEntry) bool {
	binaries, ok := authBinaries[e.Identifier]
	if !ok {
		return false
	}
	if e.Exe == "" {
		return e.UID == "0" && slices.Contains(binaries, e.Comm)
	}
	exe := strings.TrimSuffix(e.Exe, " (deleted)")
	if !slices.Contains(systemBinDirs, path.Dir(exe)) || !slices.Contains(binaries, path.Base(exe)) {
		return false
	}
	return e.UID == "0" || slices.Contains(setIDPrograms, e.Identifier)
}

// StartFunc starts a command and returns its standard output and a function that waits for it to exit.
type StartFunc func(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, error)

// Journal follows journald entries of the given identifiers with journalctl. It resumes after Cursor, and
// starts at the current end of the journal when there is no cursor, so no history is uploaded.
type Journal struct {
	Identifiers []string
	Audit       bool
	Cursor      string
	Start       StartFunc
}

func (j *Journal) Args() []string {
	args := []string{"--follow", "--output=json", "--no-pager", "--quiet"}
	if j.Audit {
		args = append(args, "_TRANSPORT=audit", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_SOURCE_REALTIME_TIMESTAMP,_TRANSPORT,_BOOT_ID,_AUDIT_ID,_UID,MESSAGE")
	}
	for _, id := range j.Identifiers {
		args = append(args, "--identifier="+id)
	}
	if j.Cursor != "" {
		return append(args, "--after-cursor="+j.Cursor)
	}
	return append(args, "--lines=0")
}

// Run streams entries to emit until the context ends or journalctl exits. The cursor advances with every
// entry, so a restarted Run continues where the previous one stopped.
func (j *Journal) Run(ctx context.Context, emit func(JournalEntry)) error {
	start := j.Start
	if start == nil {
		start = startCommand
	}
	stdout, wait, err := start(ctx, "journalctl", j.Args()...)
	if err != nil {
		return err
	}
	reader := bufio.NewReaderSize(stdout, 64<<10)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if entry, parseErr := ParseJournalEntry(line); parseErr == nil && entry.Cursor != "" {
				j.Cursor = entry.Cursor
				emit(entry)
			}
		}
		if err != nil {
			stdout.Close()
			waitErr := wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if waitErr != nil {
				return fmt.Errorf("journalctl: %w", waitErr)
			}
			if errors.Is(err, io.EOF) {
				return errors.New("journalctl exited")
			}
			return err
		}
	}
}

func startCommand(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, error) {
	path, err := trustedcmd.Look(name)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = trustedcmd.Env("SYSTEMD_COLORS=0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return stdout, cmd.Wait, nil
}
