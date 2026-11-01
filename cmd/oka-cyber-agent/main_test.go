package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, streams{strings.NewReader(stdin), &stdout, &stderr})
	return result{code, stdout.String(), stderr.String()}
}

func withoutRetryDelay(t *testing.T) {
	t.Helper()
	previous := retrySleep
	retrySleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { retrySleep = previous })
}

func useFixtureHost(t *testing.T) {
	t.Helper()
	previous := collectRoot
	collectRoot = filepath.Join("..", "..", "internal", "collect", "testdata", "hosts", "debian-12")
	t.Cleanup(func() { collectRoot = previous })
}

type fakeTenant struct {
	mu              sync.Mutex
	paths           []string
	bodies          map[string]map[string]any
	auth            map[string]string
	enrollStatus    int
	heartbeatStatus int
	inventoryStatus int
	enrolls         int
}

func newFakeTenant(t *testing.T) (*fakeTenant, *httptest.Server) {
	tenant := &fakeTenant{bodies: map[string]map[string]any{}, auth: map[string]string{}, enrollStatus: http.StatusCreated, heartbeatStatus: http.StatusOK, inventoryStatus: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("body is not gzip: %v", err)
			return
		}
		data, _ := io.ReadAll(zr)
		var body map[string]any
		_ = json.Unmarshal(data, &body)
		tenant.mu.Lock()
		tenant.paths = append(tenant.paths, r.Method+" "+r.URL.Path)
		tenant.bodies[r.URL.Path] = body
		tenant.auth[r.URL.Path] = r.Header.Get("Authorization")
		enrollStatus, heartbeatStatus, inventoryStatus := tenant.enrollStatus, tenant.heartbeatStatus, tenant.inventoryStatus
		if r.URL.Path == "/cyber-agent/v1/enroll" {
			tenant.enrolls++
		}
		serverID := 41 + tenant.enrolls
		tenant.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cyber-agent/v1/enroll":
			w.WriteHeader(enrollStatus)
			fmt.Fprintf(w, `{"server_id":%d,"agent_token":"agent-secret","report_interval_seconds":300}`, serverID)
		case "/cyber-agent/v1/heartbeat":
			w.WriteHeader(heartbeatStatus)
			io.WriteString(w, `{"report_interval_seconds":300}`)
		case "/cyber-agent/v1/inventory":
			w.WriteHeader(inventoryStatus)
			io.WriteString(w, `{"changed":true,"report_interval_seconds":300}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return tenant, srv
}

func (f *fakeTenant) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func TestVersionAndHelp(t *testing.T) {
	if r := runCLI(t, "", "version"); r.code != exitOK || !strings.Contains(r.stdout, agent.Version) {
		t.Fatalf("version = %+v", r)
	}
	if r := runCLI(t, "", "help"); r.code != exitOK || r.stdout == "" {
		t.Fatalf("help = %+v", r)
	}
	if r := runCLI(t, ""); r.code != exitUsage || r.stdout != "" || r.stderr == "" {
		t.Fatalf("no command = %+v, want usage on stderr", r)
	}
	if r := runCLI(t, "", "explode"); r.code != exitUsage {
		t.Fatalf("unknown command = %+v", r)
	}
}

func TestEnrollRunStatusEndToEnd(t *testing.T) {
	useFixtureHost(t)
	tenant, srv := newFakeTenant(t)
	configDir, stateDir := t.TempDir(), t.TempDir()

	r := runCLI(t, "", "enroll", "--url", srv.URL, "--token", "enroll-secret", "--insecure-dev", "--config-dir", configDir)
	if r.code != exitOK || !strings.Contains(r.stdout, "42") {
		t.Fatalf("enroll = %+v", r)
	}
	if strings.Contains(r.stdout+r.stderr, "secret") {
		t.Fatal("enroll output leaks a token")
	}
	enrollBody := tenant.bodies["/cyber-agent/v1/enroll"]
	if enrollBody["enrollment_token"] != "enroll-secret" || enrollBody["os_family"] != "debian" || enrollBody["os_version"] != "12" {
		t.Fatalf("enroll body = %v", enrollBody)
	}
	cfg, err := config.Load(configDir)
	if err != nil || cfg.ServerID != "42" || cfg.URL != srv.URL || !cfg.InsecureDev {
		t.Fatalf("config = %+v, err = %v", cfg, err)
	}
	if token, err := config.LoadToken(configDir); err != nil || token != "agent-secret" {
		t.Fatalf("token = %q, err = %v", token, err)
	}

	r = runCLI(t, "", "run", "--once", "--config-dir", configDir, "--state-dir", stateDir)
	if r.code != exitOK {
		t.Fatalf("run = %+v", r)
	}
	if strings.Contains(r.stdout+r.stderr, "agent-secret") {
		t.Fatal("run output leaks the agent token")
	}
	got := strings.Join(tenant.requests(), ",")
	if got != "POST /cyber-agent/v1/enroll,POST /cyber-agent/v1/heartbeat,PUT /cyber-agent/v1/inventory" {
		t.Fatalf("requests = %s", got)
	}
	if tenant.auth["/cyber-agent/v1/inventory"] != "Bearer agent-secret" {
		t.Fatal("inventory must carry the agent token")
	}
	if packages, _ := tenant.bodies["/cyber-agent/v1/inventory"]["packages"].([]any); len(packages) != 88 {
		t.Fatalf("inventory packages = %d, want 88", len(packages))
	}

	previous := serviceState
	serviceState = func(context.Context) string { return "active" }
	t.Cleanup(func() { serviceState = previous })
	r = runCLI(t, "", "status", "--config-dir", configDir, "--state-dir", stateDir)
	if r.code != exitOK || !strings.Contains(r.stdout, "42") || !strings.Contains(r.stdout, srv.URL) || strings.Contains(r.stdout, "agent-secret") {
		t.Fatalf("status = %+v", r)
	}
}

func TestEnrollIsIdempotentUnlessForced(t *testing.T) {
	useFixtureHost(t)
	tenant, srv := newFakeTenant(t)
	configDir := t.TempDir()
	args := []string{"enroll", "--url", srv.URL, "--token", "t", "--insecure-dev", "--config-dir", configDir}
	if r := runCLI(t, "", args...); r.code != exitOK {
		t.Fatalf("enroll = %+v", r)
	}
	if r := runCLI(t, "", args...); r.code != exitOK || len(tenant.requests()) != 1 {
		t.Fatalf("second enroll = %+v after %d requests, want a no op", r, len(tenant.requests()))
	}
	if r := runCLI(t, "", append(args, "--force")...); r.code != exitOK || len(tenant.requests()) != 2 {
		t.Fatalf("forced enroll = %+v after %d requests", r, len(tenant.requests()))
	}
}

func TestForcedReenrollSendsTheNewServerItsFirstInventory(t *testing.T) {
	useFixtureHost(t)
	tenant, srv := newFakeTenant(t)
	configDir, stateDir := t.TempDir(), t.TempDir()
	enroll := []string{"enroll", "--url", srv.URL, "--token", "t", "--insecure-dev", "--config-dir", configDir}
	runOnce := []string{"run", "--once", "--config-dir", configDir, "--state-dir", stateDir}
	for _, args := range [][]string{enroll, runOnce, append(enroll, "--force"), runOnce} {
		if r := runCLI(t, "", args...); r.code != exitOK {
			t.Fatalf("%v = %+v", args, r)
		}
	}
	got := strings.Join(tenant.requests(), ",")
	want := "POST /cyber-agent/v1/enroll,POST /cyber-agent/v1/heartbeat,PUT /cyber-agent/v1/inventory," +
		"POST /cyber-agent/v1/enroll,POST /cyber-agent/v1/heartbeat,PUT /cyber-agent/v1/inventory"
	if got != want {
		t.Fatalf("requests = %s, want %s", got, want)
	}
	if state, err := agent.LoadState(stateDir, "43"); err != nil || state.LastInventoryAt.IsZero() {
		t.Fatalf("state = %+v, err = %v; want the inventory recorded for the new server", state, err)
	}
}

func TestEnrollChecksTheConfigDirBeforeSpendingTheToken(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to a read only directory")
	}
	useFixtureHost(t)
	tenant, srv := newFakeTenant(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	configDir := filepath.Join(parent, "oka-cyber-agent")
	r := runCLI(t, "", "enroll", "--url", srv.URL, "--token", "enroll-secret", "--insecure-dev", "--config-dir", configDir)
	if r.code != exitFailure {
		t.Fatalf("enroll = %+v, want a failure", r)
	}
	if requests := tenant.requests(); len(requests) != 0 {
		t.Fatalf("requests = %v, want none: the enrollment token must not be spent", requests)
	}
	if strings.Contains(r.stdout+r.stderr, "secret") {
		t.Fatal("enroll output leaks a token")
	}
}

func TestEnrollReportsAnAgentTokenItCouldNotSave(t *testing.T) {
	useFixtureHost(t)
	for _, blocked := range []string{config.TokenFileName, config.FileName} {
		t.Run(blocked, func(t *testing.T) {
			tenant, srv := newFakeTenant(t)
			configDir := t.TempDir()
			// A directory in place of the file passes the write check but makes the final rename fail.
			if err := os.Mkdir(filepath.Join(configDir, blocked), 0o700); err != nil {
				t.Fatal(err)
			}
			r := runCLI(t, "", "enroll", "--url", srv.URL, "--token", "enroll-secret", "--insecure-dev", "--config-dir", configDir)
			if r.code != exitFailure || len(tenant.requests()) != 1 {
				t.Fatalf("enroll = %+v after %d requests, want a failure after one enroll", r, len(tenant.requests()))
			}
			if !strings.Contains(r.stderr, "42") {
				t.Fatalf("stderr = %q, want the enrolled server id reported", r.stderr)
			}
			if strings.Contains(r.stdout+r.stderr, "secret") {
				t.Fatal("enroll output leaks a token")
			}
		})
	}
}

func TestEnrollKeepsLocalOptionsOnForcedReenroll(t *testing.T) {
	useFixtureHost(t)
	_, srv := newFakeTenant(t)
	configDir := t.TempDir()
	args := []string{"enroll", "--url", srv.URL, "--token", "t", "--insecure-dev", "--config-dir", configDir}
	runCLI(t, "", args...)
	cfg, _ := config.Load(configDir)
	cfg.CollectServices = false
	if err := config.Save(configDir, cfg); err != nil {
		t.Fatal(err)
	}
	runCLI(t, "", append(args, "--force")...)
	if cfg, _ := config.Load(configDir); cfg.CollectServices {
		t.Fatal("re-enrolling must keep collect_services: false")
	}
}

func TestEnrollValidation(t *testing.T) {
	configDir := t.TempDir()
	tests := map[string][]string{
		"missing token": {"enroll", "--url", "https://acme.oka.example", "--config-dir", configDir},
		"missing url":   {"enroll", "--token", "t", "--config-dir", configDir},
		"plain http":    {"enroll", "--url", "http://acme.oka.example", "--token", "t", "--config-dir", configDir},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if r := runCLI(t, "", args...); r.code != exitUsage {
				t.Fatalf("result = %+v, want usage error", r)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(configDir, config.FileName)); !os.IsNotExist(err) {
		t.Fatal("a rejected enroll must not write configuration")
	}
}

func TestEnrollTokenFromEnvironment(t *testing.T) {
	useFixtureHost(t)
	tenant, srv := newFakeTenant(t)
	t.Setenv(enrollmentTokenEnv, "from-env")
	if r := runCLI(t, "", "enroll", "--url", srv.URL, "--insecure-dev", "--config-dir", t.TempDir()); r.code != exitOK {
		t.Fatalf("enroll = %+v", r)
	}
	if tenant.bodies["/cyber-agent/v1/enroll"]["enrollment_token"] != "from-env" {
		t.Fatal("the enrollment token must be read from the environment")
	}
}

func TestEnrollWithRejectedTokenWritesNothing(t *testing.T) {
	useFixtureHost(t)
	tenant, srv := newFakeTenant(t)
	tenant.enrollStatus = http.StatusUnauthorized
	configDir := t.TempDir()
	if r := runCLI(t, "", "enroll", "--url", srv.URL, "--token", "bad", "--insecure-dev", "--config-dir", configDir); r.code != exitFailure {
		t.Fatalf("enroll = %+v", r)
	}
	entries, _ := os.ReadDir(configDir)
	if len(entries) != 0 {
		t.Fatalf("config dir has %d entries, want none", len(entries))
	}
}

func TestRunExitsWithRevokedCodeOn401(t *testing.T) {
	useFixtureHost(t)
	tenant, srv := newFakeTenant(t)
	configDir := t.TempDir()
	runCLI(t, "", "enroll", "--url", srv.URL, "--token", "t", "--insecure-dev", "--config-dir", configDir)
	tenant.mu.Lock()
	tenant.heartbeatStatus = http.StatusUnauthorized
	tenant.mu.Unlock()
	if r := runCLI(t, "", "run", "--config-dir", configDir, "--state-dir", t.TempDir()); r.code != exitRevoked {
		t.Fatalf("run = %+v, want exit %d", r, exitRevoked)
	}
}

func TestRunOnceFailsWhenTheReportFails(t *testing.T) {
	useFixtureHost(t)
	withoutRetryDelay(t)
	tests := map[string]func(*fakeTenant, *httptest.Server){
		"heartbeat 500": func(f *fakeTenant, _ *httptest.Server) { f.heartbeatStatus = http.StatusInternalServerError },
		"inventory 500": func(f *fakeTenant, _ *httptest.Server) { f.inventoryStatus = http.StatusInternalServerError },
		"network error": func(_ *fakeTenant, srv *httptest.Server) { srv.Close() },
	}
	for name, breakTenant := range tests {
		t.Run(name, func(t *testing.T) {
			tenant, srv := newFakeTenant(t)
			configDir, stateDir := t.TempDir(), t.TempDir()
			if r := runCLI(t, "", "enroll", "--url", srv.URL, "--token", "t", "--insecure-dev", "--config-dir", configDir); r.code != exitOK {
				t.Fatalf("enroll = %+v", r)
			}
			tenant.mu.Lock()
			breakTenant(tenant, srv)
			tenant.mu.Unlock()
			if r := runCLI(t, "", "run", "--once", "--config-dir", configDir, "--state-dir", stateDir); r.code != exitFailure {
				t.Fatalf("run --once = %+v, want exit %d", r, exitFailure)
			}
			if state, _ := agent.LoadState(stateDir, "42"); state.LastError == "" {
				t.Fatal("the failure must be recorded for the status command")
			}
		})
	}
}

func TestRunAndStatusWithoutEnrollment(t *testing.T) {
	configDir, stateDir := t.TempDir(), t.TempDir()
	if r := runCLI(t, "", "run", "--once", "--config-dir", configDir, "--state-dir", stateDir); r.code != exitFailure {
		t.Fatalf("run = %+v", r)
	}
	if r := runCLI(t, "", "status", "--config-dir", configDir, "--state-dir", stateDir); r.code != exitFailure {
		t.Fatalf("status = %+v", r)
	}
}

func TestInventoryPrintsTheSnapshotAsJSON(t *testing.T) {
	useFixtureHost(t)
	r := runCLI(t, "", "inventory", "--services=false", "--config-dir", t.TempDir())
	if r.code != exitOK {
		t.Fatalf("inventory = %+v", r)
	}
	var inv collect.Inventory
	if err := json.Unmarshal([]byte(r.stdout), &inv); err != nil {
		t.Fatalf("stdout is not an inventory: %v", err)
	}
	if inv.OS.OSVEcosystem != "Debian:12" || len(inv.Packages) != 88 || len(inv.Services) != 0 {
		t.Fatalf("inventory = %s, %d packages, %d services", inv.OS.OSVEcosystem, len(inv.Packages), len(inv.Services))
	}
	if r := runCLI(t, "", "inventory", "--upload"); r.code != exitUsage {
		t.Fatalf("unknown flag = %+v", r)
	}
}

func TestUninstallRequiresRootAndConfirmation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test checks the non root refusal")
	}
	if r := runCLI(t, "y\n", "uninstall", "--yes"); r.code != exitFailure {
		t.Fatalf("uninstall as non root = %+v, want a refusal", r)
	}
}
