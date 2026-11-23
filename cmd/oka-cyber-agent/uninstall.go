package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/auditcontrol"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
	"github.com/okanetsolutions/oka-cyber-agent/internal/trustedcmd"
)

const (
	installedBinaryPath = "/usr/local/bin/oka-cyber-agent"
	packagedBinaryPath  = "/usr/bin/oka-cyber-agent"
	installedUnitPath   = "/etc/systemd/system/" + agent.ServiceName
	updateService       = "oka-cyber-agent-update.service"
	updateTimer         = "oka-cyber-agent-update.timer"
	updateTimerPath     = "/etc/systemd/system/" + updateTimer
	installerLibDir     = "/usr/local/lib/oka-cyber-agent"
	serviceUser         = "oka-cyber"
)

var executablePath = func() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(self)
}

var geteuid = os.Geteuid

// newUninstaller returns the uninstaller for the real host; self is the resolved path of the running binary.
var newUninstaller = func(self string) agent.Uninstaller {
	u := agent.Uninstaller{
		ConfigDir:  config.DefaultDir,
		StateDir:   config.DefaultStateDir,
		UnitPath:   installedUnitPath,
		User:       serviceUser,
		Systemctl:  systemctl(),
		UserExists: userExists,
		DeleteUser: deleteUser,
	}
	u.ExtraPaths = []string{"/etc/systemd/system/" + auditcontrol.Service, "/etc/systemd/system/" + auditcontrol.PathUnit, "/usr/share/oka-cyber-agent", "/run/oka-cyber-audit", "/run/oka-cyber-agent", updateTimerPath, "/etc/systemd/system/" + updateService, installerLibDir}
	u.StopUpdates = stopUpdates(u.Systemctl, updateTimerPath, "/etc/systemd/system/"+updateService)
	u.RemoveAudit = func(ctx context.Context) error {
		if u.Systemctl != nil {
			if _, err := os.Stat(u.ExtraPaths[1]); err == nil {
				if err := u.Systemctl(ctx, "disable", "--now", auditcontrol.PathUnit); err != nil {
					return err
				}
				if err := u.Systemctl(ctx, "disable", "--now", auditcontrol.Service); err != nil {
					return err
				}
			}
		}
		return (auditcontrol.Helper{}).Cleanup(ctx)
	}
	if self == installedBinaryPath {
		u.BinaryPath = installedBinaryPath
	}
	return u
}

func uninstallCommand(ctx context.Context, args []string, io streams) int {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	flags.SetOutput(io.stderr)
	yes := flags.Bool("yes", false, "do not ask for confirmation")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	self, _ := executablePath()
	if self == packagedBinaryPath {
		fmt.Fprintln(io.stderr, "uninstall: this agent was installed from a package. Remove it with your package manager: apt purge oka-cyber-agent, or dnf remove oka-cyber-agent")
		return exitFailure
	}
	if geteuid() != 0 {
		fmt.Fprintln(io.stderr, "uninstall: run as root, for example: sudo oka-cyber-agent uninstall")
		return exitFailure
	}
	u := newUninstaller(self)
	if !*yes {
		fmt.Fprintf(io.stdout, "This stops the agent and removes %s, %s, %s and the %s user. Continue? [y/N] ", u.ConfigDir, u.StateDir, u.UnitPath, u.User)
		answer, _ := bufio.NewReader(io.stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(io.stdout, "Aborted.")
			return exitFailure
		}
	}
	removed, err := u.Uninstall(ctx)
	for _, path := range removed {
		fmt.Fprintf(io.stdout, "Removed %s\n", path)
	}
	if err != nil {
		fmt.Fprintf(io.stderr, "uninstall: %v\n", err)
		if errors.Is(err, agent.ErrServiceNotStopped) {
			fmt.Fprintf(io.stderr, "Stop the service with: systemctl disable --now %s, then run uninstall again.\n", agent.ServiceName)
		}
		return exitFailure
	}
	fmt.Fprintln(io.stdout, "Oka Cyber Agent is uninstalled. Revoke this server in your Oka Cyber dashboard so its token stops working.")
	return exitOK
}

// stopUpdates disables the daily update timer and stops an update that is running, when install.sh wrote the
// timer at timerPath. Without the service file at servicePath no update can run, and systemctl stop would fail
// on the unit that is not loaded, which would make uninstall impossible.
func stopUpdates(systemctl func(ctx context.Context, args ...string) error, timerPath, servicePath string) func(context.Context) error {
	return func(ctx context.Context) error {
		if systemctl == nil {
			return nil
		}
		if _, err := os.Lstat(timerPath); err != nil {
			return nil
		}
		if err := systemctl(ctx, "disable", "--now", updateTimer); err != nil {
			return err
		}
		if _, err := os.Lstat(servicePath); err != nil {
			return nil
		}
		return systemctl(ctx, "stop", updateService)
	}
}

func userExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

func deleteUser(ctx context.Context, name string) error {
	cmd, err := trustedCommand(ctx, "userdel", name)
	if err != nil {
		if cmd, err = trustedCommand(ctx, "deluser", name); err != nil {
			return err
		}
	}
	return cmd.Run()
}

// trustedCommand prepares a system command from the fixed system directories with a fixed environment. These
// commands run as root, and a PATH kept by sudo or set in root's shell can hold a directory others can write to.
func trustedCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	path, err := trustedcmd.Look(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = trustedcmd.Env()
	return cmd, nil
}

// systemctl returns a runner for systemctl, or nil when systemd is not the running init system (the check
// sd_booted does), because then no agent service can be running.
func systemctl() func(ctx context.Context, args ...string) error {
	if _, err := trustedcmd.Look("systemctl"); err != nil {
		return nil
	}
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		return nil
	}
	return func(ctx context.Context, args ...string) error {
		cmd, err := trustedCommand(ctx, "systemctl", args...)
		if err != nil {
			return err
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			if msg := strings.TrimSpace(string(out)); msg != "" {
				return fmt.Errorf("%w: %s", err, msg)
			}
			return err
		}
		return nil
	}
}
