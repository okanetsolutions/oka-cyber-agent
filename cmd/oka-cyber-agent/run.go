package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

var collectRoot = "/"

// retrySleep is the API client's wait between retries; nil keeps the client's default.
var retrySleep func(ctx context.Context, d time.Duration) error

// reportWait is the agent's wait between reports; nil keeps the agent's default.
var reportWait func(ctx context.Context, d time.Duration) error

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

	// Taken before reading the files, so a re-enroll that lands while the agent starts is not missed.
	watcher := config.NewWatcher(*configDir)
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
	client, err := api.New(cfg.URL, api.Options{Token: api.Secret(token), InsecureDev: cfg.InsecureDev, AgentVersion: agent.Version, Sleep: retrySleep})
	if err != nil {
		logger.Error("cannot start", "error", err)
		return exitFailure
	}
	a := &agent.Agent{
		Config:        cfg,
		StateDir:      *stateDir,
		Client:        client,
		Logger:        logger,
		Wait:          reportWait,
		ConfigChanged: watcher.Changed,
		Collect: func(ctx context.Context) (*collect.Inventory, error) {
			collectors, err := collect.Defaults(collectOptions(cfg))
			if err != nil {
				return nil, err
			}
			return collect.Run(ctx, collectors...)
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
	case errors.Is(err, agent.ErrConfigChanged):
		logger.Info("stopping", "reason", err)
		return exitRestart
	case err != nil && *once:
		logger.Error("report failed", "error", err)
		return exitFailure
	case err != nil:
		logger.Error("stopping", "error", err)
		return exitFailure
	}
	return exitOK
}

func collectOptions(cfg config.Config) collect.Options {
	o := collect.Options{Root: collectRoot, CollectServices: cfg.CollectServices}
	if cfg.CollectDependencyFiles {
		o.Dependencies = &collect.DependencyOptions{
			ScanPaths:    cfg.ScanPaths,
			ExcludePaths: cfg.ExcludePaths,
			MaxDepth:     cfg.MaxDepth,
			MaxFileSize:  cfg.MaxFileSize,
			GoBinaries:   cfg.CollectGoBinaries,
		}
	}
	return o
}
