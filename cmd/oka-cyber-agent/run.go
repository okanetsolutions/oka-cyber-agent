package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

var collectRoot = "/"

func runCommand(ctx context.Context, args []string, io streams) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.stderr)
	configDir := flags.String("config-dir", config.DefaultDir, "configuration directory")
	stateDir := flags.String("state-dir", config.DefaultStateDir, "state directory")
	once := flags.Bool("once", false, "report once and exit")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(io.stderr, nil))

	cfg, err := config.Load(*configDir)
	if err != nil {
		logger.Error("cannot start", "error", err)
		return exitFailure
	}
	token, err := config.LoadToken(*configDir)
	if err != nil {
		logger.Error("cannot start", "error", err)
		return exitFailure
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		logger.Error("cannot start", "error", fmt.Errorf("state directory: %w", err))
		return exitFailure
	}
	client, err := api.New(cfg.URL, api.Options{Token: api.Secret(token), InsecureDev: cfg.InsecureDev, AgentVersion: agent.Version})
	if err != nil {
		logger.Error("cannot start", "error", err)
		return exitFailure
	}
	a := &agent.Agent{
		Config:   cfg,
		StateDir: *stateDir,
		Client:   client,
		Logger:   logger,
		Collect: func(ctx context.Context) (*collect.Inventory, error) {
			return collect.Run(ctx, collect.Defaults(collect.Options{Root: collectRoot, CollectServices: cfg.CollectServices})...)
		},
	}

	if *once {
		err = a.Cycle(ctx)
	} else {
		logger.Info("agent started", "version", agent.Version, "url", cfg.URL, "server_id", cfg.ServerID)
		err = a.Run(ctx)
	}
	switch {
	case errors.Is(err, agent.ErrRevoked):
		logger.Error("stopping", "error", err)
		return exitRevoked
	case err != nil:
		logger.Error("stopping", "error", err)
		return exitFailure
	}
	return exitOK
}
