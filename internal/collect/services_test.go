package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func procRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, table := range []string{"tcp", "tcp6"} {
		copyFile(t, filepath.Join("testdata", "proc", "net", table), filepath.Join(root, "proc", "net", table))
	}
	process := func(pid, comm string, sockets map[string]string) {
		dir := filepath.Join(root, "proc", pid)
		if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for fd, target := range sockets {
			if err := os.Symlink(target, filepath.Join(dir, "fd", fd)); err != nil {
				t.Fatal(err)
			}
		}
	}
	process("812", "nginx", map[string]string{"0": "/dev/null", "6": "socket:[21202848]"})
	process("813", "nginx", map[string]string{"6": "socket:[21202848]"})
	process("1450", "redis-server", map[string]string{"7": "socket:[21214876]", "8": "pipe:[1]"})
	if err := os.MkdirAll(filepath.Join(root, "proc", "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestServicesCollectorListsListeningSocketsWithOwners(t *testing.T) {
	inv, err := Run(context.Background(), ServicesCollector{Root: procRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	want := []Service{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, Process: "nginx"},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 3306},
		{Protocol: "tcp6", Address: "::1", Port: 6379, Process: "redis-server"},
	}
	if !slices.Equal(inv.Services, want) {
		t.Fatalf("services = %+v\nwant %+v", inv.Services, want)
	}
	raw, err := json.Marshal(inv.Services)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, service := range decoded {
		if _, ok := service["pid"]; ok {
			t.Fatalf("service %v has a pid, which changes on every restart", service)
		}
	}
}

func TestServicesCollectorWithoutProcNetIsEmpty(t *testing.T) {
	inv, err := Run(context.Background(), ServicesCollector{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Services) != 0 {
		t.Fatalf("services = %+v", inv.Services)
	}
}

func TestParseProcNetAddress(t *testing.T) {
	tests := map[string]string{
		"0100007F":                         "127.0.0.1",
		"00000000":                         "0.0.0.0",
		"00000000000000000000000001000000": "::1",
		"0000000000000000FFFF00000100007F": "::ffff:127.0.0.1",
	}
	for input, want := range tests {
		got, ok := parseProcNetAddress(input)
		if !ok || got.String() != want {
			t.Errorf("parseProcNetAddress(%q) = %v, %v; want %s", input, got, ok, want)
		}
	}
	if _, ok := parseProcNetAddress("zz"); ok {
		t.Error("invalid hex must be rejected")
	}
}
