// Package auditcontrol manages the single, fixed opt-in audit rule, outside the unprivileged agent.
package auditcontrol

import (
	"context"
	_ "embed"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/trustedcmd"
)

const (
	FlagPath   = "/var/lib/oka-cyber-agent/commands.enabled"
	RulePath   = "/etc/audit/rules.d/oka-cyber-commands.rules"
	StatusPath = "/run/oka-cyber-audit/status"
	Service    = "oka-cyber-audit.service"
	PathUnit   = "oka-cyber-audit.path"
)

//go:embed commands.rules
var rules []byte

// Helper has no runtime input except the existence of FlagPath. Root and Run are injected by tests only.
type Helper struct {
	Root string
	Run  func(context.Context, string, ...string) ([]byte, error)
}

func (h Helper) path(p string) string { return filepath.Join(h.Root, p) }

// Apply loads only the packaged rules, or deletes only the rules with our fixed key. It never runs
// augenrules: reloading the host's entire policy can discard unrelated runtime rules.
func (h Helper) Apply(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	run := h.Run
	if run == nil {
		run = runCommand
	}
	on := false
	if info, err := os.Lstat(h.path(FlagPath)); err == nil {
		on = info.Mode().IsRegular() && info.Size() == 0
	} else if !errors.Is(err, fs.ErrNotExist) {
		return h.status("flag_unreadable")
	}
	if err := h.status("applying"); err != nil {
		return err
	}
	status, err := run(ctx, "auditctl", "-s")
	if err != nil {
		if !on {
			_ = os.Remove(h.path(RulePath))
		}
		return h.status("audit_control_unavailable")
	}
	if on && !auditdRunning(string(status)) {
		return h.status("auditd_missing")
	}
	data := []byte("-D -k oka_cyber_commands\n")
	if on {
		data = rules
	}
	// The parent is root-owned, outside the agent's writable namespace. Refuse a final symlink.
	f, err := os.OpenFile(h.path(RulePath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Remove the directory entry, never follow an existing symlink or overwrite its target.
		if err = os.Remove(h.path(RulePath)); err == nil {
			f, err = os.OpenFile(h.path(RulePath), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		}
	}
	if err != nil {
		return h.status("rule_write_failed")
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return h.status("rule_write_failed")
	}
	_, err = run(ctx, "auditctl", "-R", RulePath)
	if !on || err != nil {
		if removeErr := os.Remove(h.path(RulePath)); removeErr != nil {
			return h.status("rule_remove_failed")
		}
	}
	if err != nil {
		return h.status("rule_apply_failed")
	}
	if on {
		return h.status("on")
	}
	return h.status("off")
}

func auditdRunning(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "pid" && f[1] != "0" {
			return true
		}
	}
	return false
}

func (h Helper) status(status string) error {
	// RuntimeDirectory is root-owned; neither the agent nor the panel can forge this acknowledgement.
	tmp := h.path(StatusPath + ".new")
	if err := os.WriteFile(tmp, []byte(status+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, h.path(StatusPath))
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, err := trustedcmd.Look(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = trustedcmd.Env()
	// Do not forward command output to the journal or include it in errors.
	return cmd.Output()
}
