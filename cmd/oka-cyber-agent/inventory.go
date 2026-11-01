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
	configDir := flags.String("config-dir", config.DefaultDir, "configuration directory, read for the collection options when present")
	services := flags.Bool("services", true, "include listening services (when the configuration allows it)")
	dependencies := flags.Bool("dependencies", true, "include dependency files (when the configuration allows it)")
	root := flags.String("root", collectRoot, "read the host from this directory instead of /")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	cfg, err := config.LoadOptions(*configDir)
	if err != nil {
		fmt.Fprintf(io.stderr, "inventory: %v\n", err)
		return exitFailure
	}
	cfg.CollectServices = cfg.CollectServices && *services
	cfg.CollectDependencyFiles = cfg.CollectDependencyFiles && *dependencies
	options := collectOptions(cfg)
	options.Root = *root
	collectors, err := collect.Defaults(options)
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
