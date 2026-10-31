package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
	"github.com/okanetsolutions/oka-cyber-agent/internal/collect"
)

func TestRunVersionPrintsBuildVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), agent.Version) {
		t.Fatalf("stdout %q does not contain version %q", stdout.String(), agent.Version)
	}
}

func TestRunWithoutCommandIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stderr.Len() == 0 || stdout.Len() != 0 {
		t.Fatalf("usage must go to stderr only, stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunUnknownCommandIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"explode"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRunHelpGoesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if stdout.Len() == 0 {
		t.Fatal("help printed nothing")
	}
}

func TestRunInventoryPrintsTheSnapshotAsJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := filepath.Join("..", "..", "internal", "collect", "testdata", "hosts", "debian-12")
	if code := run(context.Background(), []string{"inventory", "--root", root, "--services=false"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	var inv collect.Inventory
	if err := json.Unmarshal(stdout.Bytes(), &inv); err != nil {
		t.Fatalf("stdout is not an inventory: %v", err)
	}
	if inv.OS.OSVEcosystem != "Debian:12" || len(inv.Packages) != 88 || len(inv.Services) != 0 {
		t.Fatalf("inventory = %s, %d packages, %d services", inv.OS.OSVEcosystem, len(inv.Packages), len(inv.Services))
	}
}

func TestRunInventoryRejectsUnknownFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"inventory", "--upload"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}
