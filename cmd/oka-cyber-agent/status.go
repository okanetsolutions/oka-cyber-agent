package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

var serviceState = func(ctx context.Context) string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "unknown (no systemd)"
	}
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", agent.ServiceName).Output()
	return strings.TrimSpace(string(out))
}

func statusCommand(ctx context.Context, args []string, io streams) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(io.stderr)
	configDir := flags.String("config-dir", config.DefaultDir, "configuration directory")
	stateDir := flags.String("state-dir", config.DefaultStateDir, "state directory")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	w := io.stdout
	line := func(label, value string) { fmt.Fprintf(w, "%-17s %s\n", label+":", value) }
	line("Version", agent.Version)

	cfg, err := config.Load(*configDir)
	if errors.Is(err, config.ErrNotEnrolled) {
		line("Enrolled", "no")
		return exitFailure
	}
	if err != nil {
		line("Enrolled", "unknown")
		fmt.Fprintf(io.stderr, "status: %v\n", err)
		return exitFailure
	}
	line("Enrolled", "yes")
	line("URL", cfg.URL)
	line("Server ID", cfg.ServerID)
	line("Agent token", tokenState(*configDir))
	line("Service", serviceState(ctx))

	state, err := agent.LoadState(*stateDir)
	if err != nil {
		fmt.Fprintf(io.stderr, "status: %v\n", err)
	}
	interval := state.ReportIntervalSeconds
	if interval == 0 {
		interval = cfg.ReportIntervalSeconds
	}
	now := time.Now()
	line("Report interval", fmt.Sprintf("%ds", interval))
	line("Last heartbeat", when(state.LastHeartbeatAt, now))
	line("Last inventory", when(state.LastInventoryAt, now))
	if state.LastError == "" {
		line("Last error", "none")
	} else {
		line("Last error", state.LastError+" ("+when(state.LastErrorAt, now)+")")
	}
	writeHints(w, cfg)
	return exitOK
}

func tokenState(dir string) string {
	path := config.TokenPath(dir)
	_, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing (" + path + ")"
	case err != nil:
		return "unknown (" + err.Error() + ")"
	}
	return "present (" + path + ")"
}

func when(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmt.Sprintf("%s (%s ago)", t.UTC().Format(time.RFC3339), now.Sub(t).Round(time.Second))
}

func writeHints(w io.Writer, cfg config.Config) {
	if cfg.InsecureDev {
		fmt.Fprintln(w, "\nWarning: insecure_dev is on, so plain http is allowed. Use it for local development only.")
	}
}
