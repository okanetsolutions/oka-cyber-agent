package main

import (
	"context"
	"io"
	"testing"
)

func TestAuditHelperAcceptsNoArguments(t *testing.T) {
	for _, args := range [][]string{{"audit-rules", "on"}, {"audit-rules", "/tmp/rules"}, {"audit-rules", "-D"}} {
		if code := run(context.Background(), args, streams{stdout: io.Discard, stderr: io.Discard}); code != exitUsage {
			t.Fatalf("accepted input %q", args)
		}
	}
}
