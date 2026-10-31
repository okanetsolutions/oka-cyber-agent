package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	// exitRevoked tells systemd not to restart the agent (RestartPreventExitStatus) once the server revoked it.
	exitRevoked = 77
)

type streams struct {
	stdin          io.Reader
	stdout, stderr io.Writer
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], streams{os.Stdin, os.Stdout, os.Stderr})
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, io streams) int {
	if len(args) == 0 {
		usage(io.stderr)
		return exitUsage
	}
	switch args[0] {
	case "enroll":
		return enrollCommand(ctx, args[1:], io)
	case "run":
		return runCommand(ctx, args[1:], io)
	case "status":
		return statusCommand(ctx, args[1:], io)
	case "inventory":
		return inventoryCommand(ctx, args[1:], io)
	case "uninstall":
		return uninstallCommand(ctx, args[1:], io)
	case "version", "--version":
		fmt.Fprintf(io.stdout, "oka-cyber-agent %s\n", agent.Version)
		return exitOK
	case "help", "-h", "--help":
		usage(io.stdout)
		return exitOK
	default:
		fmt.Fprintf(io.stderr, "unknown command %q\n\n", args[0])
		usage(io.stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: oka-cyber-agent <command> [flags]

Commands:
  enroll     Enroll this server: oka-cyber-agent enroll --url <tenant URL> --token <enrollment token>
  run        Report to Oka Cyber every interval (what the systemd service runs).
  status     Show enrollment and the last report.
  inventory  Print the inventory this server would report, as JSON. Sends nothing.
  uninstall  Stop the service and remove the agent, its configuration and its state.
  version    Print the agent version.
  help       Show this help.

Run "oka-cyber-agent <command> -h" for the flags of a command.
Source and documentation: https://github.com/okanetsolutions/oka-cyber-agent
`)
}
