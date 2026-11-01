package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/api"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

const enrollmentTokenEnv = "OKA_CYBER_ENROLLMENT_TOKEN"

func enrollCommand(ctx context.Context, args []string, io streams) int {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(io.stderr)
	tenantURL := flags.String("url", "", "your Oka Cyber tenant URL, for example https://acme.oka.example")
	token := flags.String("token", "", "enrollment token from the dashboard (or set "+enrollmentTokenEnv+")")
	insecureDev := flags.Bool("insecure-dev", false, "allow a plain http URL, for local development only")
	force := flags.Bool("force", false, "enroll again even if this server is already enrolled")
	configDir := flags.String("config-dir", config.DefaultDir, "configuration directory")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *token == "" {
		*token = os.Getenv(enrollmentTokenEnv)
	}
	if *tenantURL == "" || *token == "" {
		fmt.Fprintln(io.stderr, "enroll: --url and --token are required")
		flags.Usage()
		return exitUsage
	}
	if err := config.ValidateURL(*tenantURL, *insecureDev); err != nil {
		fmt.Fprintf(io.stderr, "enroll: %v\n", err)
		return exitUsage
	}

	existing, existingErr := config.Load(*configDir)
	_, tokenErr := config.LoadToken(*configDir)
	if !*force {
		switch {
		case existingErr == nil && tokenErr == nil:
			fmt.Fprintf(io.stdout, "Already enrolled as server %s at %s. Use --force to enroll again.\n", existing.ServerID, existing.URL)
			return exitOK
		case !errors.Is(existingErr, config.ErrNotEnrolled) || !errors.Is(tokenErr, config.ErrNotEnrolled):
			// Only one of the two files is usable (an earlier enroll was interrupted, or a file was deleted or
			// broken). Enrolling over it creates a second server in the dashboard, so the user must ask for it.
			fmt.Fprintf(io.stderr, "enroll: %s holds an incomplete or unreadable enrollment:\n", *configDir)
			for _, err := range []error{existingErr, tokenErr} {
				if err != nil {
					fmt.Fprintf(io.stderr, "  %v\n", err)
				}
			}
			if errors.Is(existingErr, fs.ErrPermission) || errors.Is(tokenErr, fs.ErrPermission) {
				fmt.Fprintln(io.stderr, "Run enroll as root, for example with sudo.")
			}
			fmt.Fprintln(io.stderr, "To replace it, revoke the old server in the dashboard if it is listed, then enroll again with --force.")
			return exitFailure
		}
	}
	// The server spends the enrollment token as soon as it answers, so check first that the agent token it
	// returns can be saved.
	if err := config.CheckWritable(*configDir); err != nil {
		fmt.Fprintf(io.stderr, "enroll: cannot save the agent token in %s: %v\n", *configDir, err)
		if errors.Is(err, fs.ErrPermission) {
			fmt.Fprintln(io.stderr, "Run enroll as root, for example with sudo.")
		}
		return exitFailure
	}

	host, err := collect.Run(ctx, collect.OSCollector{Root: collectRoot})
	if err != nil {
		fmt.Fprintf(io.stderr, "enroll: %v\n", err)
		return exitFailure
	}
	client, err := api.New(*tenantURL, api.Options{InsecureDev: *insecureDev, AgentVersion: agent.Version})
	if err != nil {
		fmt.Fprintf(io.stderr, "enroll: %v\n", err)
		return exitUsage
	}
	resp, err := client.Enroll(ctx, api.EnrollRequest{
		EnrollmentToken: api.Secret(*token),
		Hostname:        host.OS.Hostname,
		OSFamily:        host.OS.Family,
		OSName:          host.OS.Name,
		OSVersion:       host.OS.Version,
		Kernel:          host.OS.Kernel,
		Architecture:    host.OS.Architecture,
		AgentVersion:    agent.Version,
	})
	if err != nil {
		fmt.Fprintf(io.stderr, "enroll: %v\n", err)
		return exitFailure
	}

	cfg := config.Default()
	if existingErr == nil {
		cfg = existing
	} else if !errors.Is(existingErr, config.ErrNotEnrolled) {
		fmt.Fprintf(io.stderr, "enroll: ignoring the unreadable previous configuration: %v\n", existingErr)
	}
	cfg.URL = strings.TrimRight(*tenantURL, "/")
	cfg.ServerID = string(resp.ServerID)
	cfg.InsecureDev = *insecureDev
	if resp.ReportIntervalSeconds > 0 {
		cfg.ReportIntervalSeconds = min(max(resp.ReportIntervalSeconds, config.MinReportIntervalSeconds), config.MaxReportIntervalSeconds)
	}
	access := tokenAccess(ctx)
	if err := config.SaveToken(*configDir, string(resp.AgentToken), access); err != nil {
		fmt.Fprintf(io.stderr, "enroll: the server enrolled this host as server %s, but saving its agent token failed: %v\n", cfg.ServerID, err)
		fmt.Fprintf(io.stderr, "The agent token was not stored and the enrollment token may be used up. Revoke server %s in the dashboard, then enroll again with a new enrollment token.\n", cfg.ServerID)
		return exitFailure
	}
	if err := config.Save(*configDir, cfg); err != nil {
		fmt.Fprintf(io.stderr, "enroll: the agent token of server %s was saved, but saving the configuration failed: %v\n", cfg.ServerID, err)
		fmt.Fprintf(io.stderr, "To finish by hand, write %s with url: %s and server_id: \"%s\". Otherwise revoke server %s in the dashboard and enroll again with --force.\n",
			filepath.Join(*configDir, config.FileName), cfg.URL, cfg.ServerID, cfg.ServerID)
		return exitFailure
	}
	fmt.Fprintf(io.stdout, "Enrolled as server %s.\n", cfg.ServerID)
	if access.Mode&0o040 != 0 {
		fmt.Fprintf(io.stdout, "systemd is older than %d, so the agent token is readable by the %s group instead of passed to the service as a credential.\n", config.MinCredentialsSystemdVersion, serviceUser)
	}
	if existingErr == nil {
		fmt.Fprintln(io.stdout, "A running agent service restarts with this enrollment within about a minute. If the service is stopped, start it with: systemctl enable --now oka-cyber-agent")
	} else {
		fmt.Fprintln(io.stdout, "Start reporting with: systemctl enable --now oka-cyber-agent")
	}
	return exitOK
}

// tokenAccess decides who may read the agent token. Only root asks systemctl for its version, because only root
// can give the token to the service group.
func tokenAccess(ctx context.Context) config.TokenAccess {
	euid := os.Geteuid()
	if euid != 0 {
		return config.TokenAccessFor(euid, 0, -1)
	}
	return config.TokenAccessFor(euid, systemdVersion(ctx), groupID(serviceUser))
}

// systemdVersion works without a running systemd (a chroot or an image build), where the unit still runs on the
// installed systemd at the next boot. It returns 0 when systemctl is missing.
func systemdVersion(ctx context.Context) int {
	out, err := exec.CommandContext(ctx, "systemctl", "--version").Output()
	if err != nil {
		return 0
	}
	return config.ParseSystemdVersion(string(out))
}

func groupID(name string) int {
	group, err := user.LookupGroup(name)
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return -1
	}
	return gid
}
