package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func procRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
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
	process("1500", "example-dns", map[string]string{"3": "socket:[51255178]", "4": "socket:[51255179]"})
	if err := os.MkdirAll(filepath.Join(root, "proc", "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func collectServices(t *testing.T, root string) []Service {
	t.Helper()
	inv, err := Run(context.Background(), ServicesCollector{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return inv.Services
}

func TestServicesCollectorListsListeningSocketsWithOwners(t *testing.T) {
	services := collectServices(t, procRoot(t))
	want := []Service{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, Process: "nginx"},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 3306},
		{Protocol: "tcp6", Address: "::1", Port: 6379, Process: "redis-server"},
		{Protocol: "udp", Address: "0.0.0.0", Port: 51820},
		{Protocol: "udp", Address: "192.0.2.10", Port: 8053, Process: "example-dns"},
		{Protocol: "udp6", Address: "2001:db8::10", Port: 8053},
		{Protocol: "udp6", Address: "::", Port: 41641},
	}
	if !slices.Equal(services, want) {
		t.Fatalf("services = %+v\nwant %+v", services, want)
	}
	raw, err := json.Marshal(services)
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

func TestServicesCollectorUsesConfiguredEphemeralPortRange(t *testing.T) {
	root := procRoot(t)
	dir := filepath.Join(root, "proc/sys/net/ipv4")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ip_local_port_range"), []byte("8053\t9000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	services := collectServices(t, root)
	want := []Service{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, Process: "nginx"},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 3306},
		{Protocol: "tcp6", Address: "::1", Port: 6379, Process: "redis-server"},
		{Protocol: "udp", Address: "0.0.0.0", Port: 32768},
		{Protocol: "udp", Address: "0.0.0.0", Port: 51820},
		{Protocol: "udp", Address: "0.0.0.0", Port: 60999},
		{Protocol: "udp6", Address: "::", Port: 41641},
	}
	if !slices.Equal(services, want) {
		t.Fatalf("services = %+v\nwant %+v", services, want)
	}
}

func TestServicesCollectorFallsBackAndIgnoresChangingEphemeralPorts(t *testing.T) {
	root := procRoot(t)
	before := collectServices(t, root)
	if err := os.MkdirAll(filepath.Join(root, "proc/sys/net/ipv4/ip_local_port_range"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "proc/net/udp")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(data), "00000000:8000", "00000000:8001", 1)
	if changed == string(data) {
		t.Fatal("fixture has no ephemeral port 32768")
	}
	if err := os.WriteFile(path, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	if after := collectServices(t, root); !slices.Equal(before, after) {
		t.Fatalf("services after ephemeral port changed = %+v\nwant %+v", after, before)
	}
}

func TestServicesCollectorWithoutUDP6Table(t *testing.T) {
	root := procRoot(t)
	want := slices.DeleteFunc(collectServices(t, root), func(s Service) bool { return s.Protocol == "udp6" })
	if err := os.Remove(filepath.Join(root, "proc/net/udp6")); err != nil {
		t.Fatal(err)
	}
	if got := collectServices(t, root); !slices.Equal(got, want) {
		t.Fatalf("services = %+v\nwant %+v", got, want)
	}
}

func TestParseProcNetRequiresUnconnectedBoundUDP(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "proc", "net", "udp"))
	if err != nil {
		t.Fatal(err)
	}
	const listener = "0A0200C0:1F75 00000000:0000 07"
	for _, row := range []string{
		"0A0200C0:1F75 140200C0:0000 07",
		"0A0200C0:1F75 00000000:0035 07",
		"0A0200C0:0000 00000000:0000 07",
		"0A0200C0:1F75 00000000:0000 01",
	} {
		input := strings.ReplaceAll(string(data), listener, row)
		sockets, err := parseProcNet(strings.NewReader(input), "udp", portRange{32768, 60999})
		if err != nil {
			t.Fatal(err)
		}
		if len(sockets) != 1 || sockets[0].port != 51820 {
			t.Errorf("sockets for %q = %+v, want only port 51820", row, sockets)
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
