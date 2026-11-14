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

	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
	"github.com/okanetsolutions/oka-cyber-agent/internal/trustedcmd"
)

const (
	FlagPath   = "/run/oka-cyber-agent/commands.enabled"
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
	// PathChanged is edge triggered and a flag change during this run joins the running start job, so
	// apply again until the flag still says what was applied.
	for {
		on := h.flagOn()
		if err := h.apply(ctx, run, on); err != nil {
			return err
		}
		if h.flagOn() == on || ctx.Err() != nil {
			return nil
		}
	}
}

func (h Helper) flagOn() bool {
	info, err := os.Lstat(h.path(FlagPath))
	return err == nil && info.Mode().IsRegular() && info.Size() == 0
}

func (h Helper) apply(ctx context.Context, run func(context.Context, string, ...string) ([]byte, error), on bool) error {
	previous, _ := os.ReadFile(h.path(StatusPath))
	_, ruleErr := os.Lstat(h.path(RulePath))
	mayHaveRule := ruleErr == nil || string(previous) == "on\n" || string(previous) == "applying\n" || string(previous) == "rule_apply_failed\n" || string(previous) == "rule_remove_failed\n" || string(previous) == "rule_write_failed\n"
	if err := h.status("applying"); err != nil {
		return err
	}
	if !on {
		if err := os.Remove(h.path(RulePath)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return h.status("rule_remove_failed")
		}
		if _, err := run(ctx, "auditctl", "-D", "-k", "oka_cyber_commands"); err != nil {
			if mayHaveRule {
				return h.status("rule_remove_failed")
			}
			return h.status("audit_control_unavailable")
		}
		return h.status("off")
	}
	status, err := run(ctx, "auditctl", "-s")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return h.status("auditd_missing")
		}
		return h.status("audit_control_unavailable")
	}
	if strings.Contains("\n"+string(status)+"\n", "\nenabled 0\n") {
		return h.status("audit_disabled")
	}
	if on && !auditdRunning(string(status)) {
		return h.status("auditd_missing")
	}
	// Keep deletion out of the persistent template: augenrules treats the last -D line specially,
	// which could otherwise replace the administrator's global deletion directive at boot.
	if err := config.WriteFileAtomic(h.path(RulePath), rules, 0o600, nil); err != nil {
		return h.status("rule_write_failed")
	}
	_, err = run(ctx, "auditctl", "-D", "-k", "oka_cyber_commands")
	if err == nil {
		_, err = run(ctx, "auditctl", "-R", RulePath)
	}
	if err != nil {
		if removeErr := os.Remove(h.path(RulePath)); removeErr != nil {
			return h.status("rule_remove_failed")
		}
	}
	if err != nil {
		return h.status("rule_apply_failed")
	}
	return h.status("on")
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
	if err := os.MkdirAll(filepath.Dir(h.path(StatusPath)), 0o755); err != nil {
		return err
	}
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

// Cleanup is used only during uninstall, after the agent and path unit have stopped. A locked audit policy
// needs operator intervention (usually a reboot); do not claim the running kernel rule was removed.
func (h Helper) Cleanup(ctx context.Context) error {
	_, ruleErr := os.Lstat(h.path(RulePath))
	if err := os.Remove(h.path(FlagPath)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := h.Apply(ctx); err != nil {
		return err
	}
	status, err := os.ReadFile(h.path(StatusPath))
	if err != nil {
		return err
	}
	if string(status) == "off\n" || errors.Is(ruleErr, fs.ErrNotExist) && string(status) == "audit_control_unavailable\n" {
		return nil
	}
	return errors.New("command audit rule removal could not be confirmed; check audit policy before uninstalling")
}
