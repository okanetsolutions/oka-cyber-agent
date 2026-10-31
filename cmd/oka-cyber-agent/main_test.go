package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/okanetsolutions/oka-cyber-agent/internal/agent"
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
