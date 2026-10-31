package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

const (
	installedBinaryPath = "/usr/local/bin/oka-cyber-agent"
	installedUnitPath   = "/etc/systemd/system/" + agent.ServiceName
)

func uninstallCommand(ctx context.Context, args []string, io streams) int {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	flags.SetOutput(io.stderr)
	yes := flags.Bool("yes", false, "do not ask for confirmation")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(io.stderr, "uninstall: run as root, for example: sudo oka-cyber-agent uninstall")
		return exitFailure
	}
	u := agent.Uninstaller{
		ConfigDir: config.DefaultDir,
		StateDir:  config.DefaultStateDir,
		UnitPath:  installedUnitPath,
	}
	if self, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(self); err == nil && resolved == installedBinaryPath {
			u.BinaryPath = installedBinaryPath
		}
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		u.Systemctl = func(ctx context.Context, args ...string) error {
			return exec.CommandContext(ctx, "systemctl", args...).Run()
		}
	}
	if !*yes {
		fmt.Fprintf(io.stdout, "This stops the agent and removes %s, %s and %s. Continue? [y/N] ", u.ConfigDir, u.StateDir, u.UnitPath)
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
		return exitFailure
	}
	fmt.Fprintln(io.stdout, "Oka Cyber Agent is uninstalled. Revoke this server in your Oka Cyber dashboard so its token stops working.")
	return exitOK
}
