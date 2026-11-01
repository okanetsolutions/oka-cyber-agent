package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

func inventoryCommand(ctx context.Context, args []string, io streams) int {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(io.stderr)
	configDir := flags.String("config-dir", config.DefaultDir, "configuration directory, read for collect_services when present")
	services := flags.Bool("services", true, "include listening services")
	root := flags.String("root", collectRoot, "read the host from this directory instead of /")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	collectServices := *services
	if cfg, err := config.Load(*configDir); err == nil && !cfg.CollectServices {
		collectServices = false
	}
	collectors, err := collect.Defaults(collect.Options{Root: *root, CollectServices: collectServices})
	if err != nil {
		fmt.Fprintf(io.stderr, "inventory: %v\n", err)
		return exitFailure
	}
	inv, err := collect.Run(ctx, collectors...)
	if err != nil {
		fmt.Fprintf(io.stderr, "inventory: %v\n", err)
		return exitFailure
	}
	encoder := json.NewEncoder(io.stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(inv); err != nil {
		fmt.Fprintf(io.stderr, "inventory: %v\n", err)
		return exitFailure
	}
	return exitOK
}
