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

// JournalEntry is one journald entry. UID, Exe and Comm are the trusted fields journald fills in from the
// sender's kernel credentials and /proc, which a client cannot set; Identifier is chosen by the client.
type JournalEntry struct {
	Cursor     string
	Identifier string
	Message    string
	At         time.Time
	UID        string
	Exe        string
	Comm       string
}

// ParseJournalEntry reads one line of journalctl --output=json. MESSAGE is a string, or an array of bytes
// when it is not valid UTF-8.
func ParseJournalEntry(line []byte) (JournalEntry, error) {
	var raw struct {
		Cursor     string          `json:"__CURSOR"`
		Realtime   string          `json:"__REALTIME_TIMESTAMP"`
		Identifier string          `json:"SYSLOG_IDENTIFIER"`
		Message    json.RawMessage `json:"MESSAGE"`
		UID        string          `json:"_UID"`
		Exe        string          `json:"_EXE"`
		Comm       string          `json:"_COMM"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return JournalEntry{}, err
	}
	e := JournalEntry{Cursor: raw.Cursor, Identifier: raw.Identifier, UID: raw.UID, Exe: raw.Exe, Comm: raw.Comm}
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
		"sshd":         {"sshd", "sshd-session"},
		"sshd-session": {"sshd", "sshd-session"},
		"sudo":         {"sudo"},
		"su":           {"su"},
		"useradd":      {"useradd"},
		"usermod":      {"usermod"},
		"groupadd":     {"groupadd"},
		"gpasswd":      {"gpasswd"},
		"passwd":       {"passwd"},
		"chpasswd":     {"chpasswd"},
		"crontab":      {"crontab"},
	}
	// setIDPrograms run set-user-ID or set-group-ID, so journald records the invoking user's UID. The dynamic
	// loader ignores LD_PRELOAD for them and an unprivileged user cannot ptrace them, so a process running
	// the real binary only logs what the binary itself logs.
	setIDPrograms = []string{"sudo", "su", "passwd", "gpasswd", "crontab"}
	// systemBinDirs are the root owned directories the auth binaries are installed in: OpenSSH's
	// sshd-session lives in /usr/lib/openssh (Debian), /usr/libexec/openssh (RHEL), /usr/lib/ssh (Alpine)
	// or /usr/libexec/ssh (openSUSE), and Ubuntu's sudo-rs in /usr/lib/cargo/bin.
	systemBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib/openssh", "/usr/libexec/openssh", "/usr/lib/ssh", "/usr/libexec/ssh", "/usr/libexec", "/usr/lib/cargo/bin"}
)

// TrustedAuthEntry reports whether an entry that claims an auth identifier was really logged by that
// program. Any local user can pick SYSLOG_IDENTIFIER (logger -t sshd), so it is checked against _EXE and
// _UID. The executable must be the expected binary in a system directory, and the sender must run as root
// unless the program is set-user-ID: a user can load code into a binary that is not (LD_PRELOAD=x.so
// /usr/sbin/sshd) and make it log anything. journald cannot read _EXE when a short lived process exited
// first; such an entry is accepted only from root with the expected _COMM, because a user could exit early
// on purpose.
func TrustedAuthEntry(e JournalEntry) bool {
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
	Cursor      string
	Start       StartFunc
}

func (j *Journal) Args() []string {
	args := []string{"--follow", "--output=json", "--no-pager", "--quiet"}
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
