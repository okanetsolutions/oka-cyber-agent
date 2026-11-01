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
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

const (
	installedBinaryPath = "/usr/local/bin/oka-cyber-agent"
	packagedBinaryPath  = "/usr/bin/oka-cyber-agent"
	installedUnitPath   = "/etc/systemd/system/" + agent.ServiceName
	serviceUser         = "oka-cyber"
)

var executablePath = func() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(self)
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
	if os.Geteuid() != 0 {
		fmt.Fprintln(io.stderr, "uninstall: run as root, for example: sudo oka-cyber-agent uninstall")
		return exitFailure
	}
	u := agent.Uninstaller{
		ConfigDir:  config.DefaultDir,
		StateDir:   config.DefaultStateDir,
		UnitPath:   installedUnitPath,
		User:       serviceUser,
		UserExists: userExists,
		DeleteUser: deleteUser,
	}
	if self == installedBinaryPath {
		u.BinaryPath = installedBinaryPath
	}
	u.Systemctl = systemctl()
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

func userExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

func deleteUser(ctx context.Context, name string) error {
	if _, err := exec.LookPath("userdel"); err == nil {
		return exec.CommandContext(ctx, "userdel", name).Run()
	}
	return exec.CommandContext(ctx, "deluser", name).Run()
}

// systemctl returns a runner for systemctl, or nil when systemd is not the running init system (the check
// sd_booted does), because then no agent service can be running.
func systemctl() func(ctx context.Context, args ...string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		return nil
	}
	return func(ctx context.Context, args ...string) error {
		out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
		if err != nil {
			if msg := strings.TrimSpace(string(out)); msg != "" {
				return fmt.Errorf("%w: %s", err, msg)
			}
			return err
		}
		return nil
	}
}
