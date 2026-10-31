package collect

import (
	"context"
	"strings"
	"testing"
)

func TestOSCollectorPerDistribution(t *testing.T) {
	tests := []struct {
		host, family, name, version, ecosystem string
	}{
		{"debian-12", FamilyDebian, "Debian GNU/Linux", "12", "Debian:12"},
		{"debian-sid", FamilyDebian, "Debian GNU/Linux", "", ""},
		{"ubuntu-22.04", FamilyDebian, "Ubuntu", "22.04", "Ubuntu:22.04:LTS"},
		{"ubuntu-24.04", FamilyDebian, "Ubuntu", "24.04", "Ubuntu:24.04:LTS"},
		{"ubuntu-25.10", FamilyDebian, "Ubuntu", "25.10", "Ubuntu:25.10"},
		{"alpine-3.20", FamilyAlpine, "Alpine Linux", "3.20.10", "Alpine:v3.20"},
		{"rocky-9", FamilyRHEL, "Rocky Linux", "9.8", "Rocky Linux:9"},
		{"almalinux-9", FamilyRHEL, "AlmaLinux", "9.8", "AlmaLinux:9"},
		{"rhel-9", FamilyRHEL, "Red Hat Enterprise Linux", "9.8", "Red Hat:9"},
		{"arch", "arch", "Arch Linux", "20261025.0.616225", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			inv := &Inventory{}
			if err := (OSCollector{Root: hostRoot(tt.host), Uname: fixedUname}).Collect(context.Background(), inv); err != nil {
				t.Fatal(err)
			}
			want := OS{
				Hostname:     "web-1",
				Family:       tt.family,
				Name:         tt.name,
				Version:      tt.version,
				Kernel:       "6.1.0-26-amd64",
				Architecture: "x86_64",
				OSVEcosystem: tt.ecosystem,
			}
			if inv.OS != want {
				t.Fatalf("OS = %+v\nwant %+v", inv.OS, want)
			}
		})
	}
}

func TestOSCollectorWithoutOSReleaseKeepsUnameFacts(t *testing.T) {
	inv := &Inventory{}
	if err := (OSCollector{Root: t.TempDir(), Uname: fixedUname}).Collect(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	if inv.OS.Kernel != "6.1.0-26-amd64" || inv.OS.OSVEcosystem != "" || inv.OS.Family != "" {
		t.Fatalf("OS = %+v", inv.OS)
	}
}

func TestParseOSReleaseUnquotesValues(t *testing.T) {
	values, err := ParseOSRelease(strings.NewReader("# comment\nNAME=\"Debian \\\"GNU\\\"/Linux\"\nID=debian\nPRETTY='Single quoted'\n\nbroken line\n"))
	if err != nil {
		t.Fatal(err)
	}
	if values["NAME"] != `Debian "GNU"/Linux` || values["ID"] != "debian" || values["PRETTY"] != "Single quoted" {
		t.Fatalf("values = %#v", values)
	}
}
