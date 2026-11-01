package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "oka-cyber-agent %s\n", agent.Version)
		return 0
	case "inventory":
		return inventoryCommand(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: oka-cyber-agent <command> [flags]

Commands:
  inventory  Print the inventory this server would report, as JSON. Sends nothing.
  version    Print the agent version.
  help       Show this help.

Source and documentation: https://github.com/okanetsolutions/oka-cyber-agent
`)
}

func inventoryCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(stderr)
	services := flags.Bool("services", true, "include listening services")
	root := flags.String("root", "/", "read the host from this directory instead of /")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	collectors, err := collect.Defaults(collect.Options{Root: *root, CollectServices: *services})
	if err != nil {
		fmt.Fprintf(stderr, "inventory: %v\n", err)
		return 1
	}
	inv, err := collect.Run(ctx, collectors...)
	if err != nil {
		fmt.Fprintf(stderr, "inventory: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(inv); err != nil {
		fmt.Fprintf(stderr, "inventory: %v\n", err)
		return 1
	}
	return 0
}
