package collect

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The rhel-9 host is a UBI 9 container: its image packages came from the RHEL CDN, httpd was installed from
// ubi-9-appstream-rpms, unzip with `dnf install ./unzip.rpm` (@commandline) and zip with `rpm -i`, which leaves
// no dnf history.
func TestRPMRHEL9EcosystemPerRepository(t *testing.T) {
	inv := collectHost(t, "rhel-9", filepath.Join("testdata", "rpm", "rhel-9.txt"))
	tests := map[string]string{
		"openssl-libs":  "Red Hat:enterprise_linux:9::baseos",    // rhel-9-for-x86_64-baseos-rpms
		"bash":          "Red Hat:enterprise_linux:9::baseos",    // rhel-9-for-x86_64-baseos-rpms
		"gdb-gdbserver": "Red Hat:enterprise_linux:9::appstream", // rhel-9-for-x86_64-appstream-rpms
		"httpd":         "Red Hat:enterprise_linux:9::appstream", // ubi-9-appstream-rpms
		"mod_lua":       "Red Hat:enterprise_linux:9::appstream", // ubi-9-appstream-rpms
		"unzip":         "Red Hat:enterprise_linux:9::baseos",    // @commandline: no OSV ecosystem, OS default
		"zip":           "Red Hat:enterprise_linux:9::baseos",    // rpm -i: not in the history, OS default
	}
	for name, want := range tests {
		if got := findPackage(t, inv, name).Ecosystem; got != want {
			t.Errorf("%s ecosystem = %q, want %q", name, got, want)
		}
	}
	appstream := 0
	for _, p := range inv.Packages {
		if p.Ecosystem == "Red Hat:enterprise_linux:9::appstream" {
			appstream++
		}
	}
	if appstream != 15 {
		t.Errorf("appstream packages = %d, want the 15 dnf reports from appstream repositories", appstream)
	}
}

func rhel9RootWithHistory(t *testing.T, history []byte) string {
	t.Helper()
	root := t.TempDir()
	copyFile(t, filepath.Join(hostRoot("rhel-9"), "etc", "os-release"), filepath.Join(root, "etc", "os-release"))
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "rpm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if history != nil {
		path := filepath.Join(root, dnfHistoryPath)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, history, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRPMRHEL9WithoutUsableHistoryKeepsTheOSEcosystem(t *testing.T) {
	real, err := os.ReadFile(filepath.Join(hostRoot("rhel-9"), dnfHistoryPath))
	if err != nil {
		t.Fatal(err)
	}
	histories := map[string][]byte{
		"missing":   nil,
		"garbage":   []byte("not a database"),
		"truncated": real[:16*1024],
	}
	for name, history := range histories {
		t.Run(name, func(t *testing.T) {
			root := rhel9RootWithHistory(t, history)
			inv, err := Run(context.Background(),
				OSCollector{Root: root, Uname: fixedUname},
				RPMCollector{Root: root, Run: func(context.Context, string, ...string) ([]byte, error) {
					return os.ReadFile(filepath.Join("testdata", "rpm", "rhel-9.txt"))
				}},
			)
			if err != nil {
				t.Fatalf("Run = %v; an unusable dnf history must not fail the inventory", err)
			}
			if len(inv.Packages) != 201 {
				t.Fatalf("packages = %d, want 201", len(inv.Packages))
			}
			for _, p := range inv.Packages {
				if p.Ecosystem != "Red Hat:enterprise_linux:9::baseos" {
					t.Fatalf("%s ecosystem = %q, want the OS default", p.Name, p.Ecosystem)
				}
			}
		})
	}
}

func TestDNFRepositoriesMatchesDNF(t *testing.T) {
	repositories, err := dnfRepositories(context.Background(), hostRoot("rhel-9"))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[rpmNEVRA]string{
		{"openssl-libs", "1:3.5.8-2.el9_8", "x86_64"}: "rhel-9-for-x86_64-baseos-rpms",
		{"httpd", "2.4.62-13.el9_8.9", "x86_64"}:      "ubi-9-appstream-rpms",
		{"unzip", "6.0-60.el9", "x86_64"}:             "@commandline",
	}
	for nevra, want := range tests {
		if got := repositories[nevra]; got != want {
			t.Errorf("%v repository = %q, want %q", nevra, got, want)
		}
	}
	if _, ok := repositories[rpmNEVRA{"zip", "3.0-35.el9", "x86_64"}]; ok {
		t.Error("zip was installed with rpm -i and must have no repository")
	}
}

// serverEcosystemRule is copied from InventorySnapshotValidator in Oka Core.
var serverEcosystemRule = regexp.MustCompile(`\A(?:Debian|Ubuntu|Alpine|Rocky Linux|AlmaLinux|Red Hat)(?::[A-Za-z0-9.+:_-]{1,100})?\z|\A(?:Packagist|npm|PyPI|RubyGems|Go|crates\.io|Maven|NuGet)\z`)

func TestRedHatPackageEcosystem(t *testing.T) {
	tests := []struct {
		versionID, repoid, want string
	}{
		{"9.8", "rhel-9-for-x86_64-baseos-rpms", "Red Hat:enterprise_linux:9::baseos"},
		{"9.8", "rhel-9-for-aarch64-appstream-rpms", "Red Hat:enterprise_linux:9::appstream"},
		{"9.8", "codeready-builder-for-rhel-9-x86_64-rpms", "Red Hat:enterprise_linux:9::crb"},
		{"9.8", "rhui-rhel-9-for-x86_64-appstream-rhui-rpms", "Red Hat:enterprise_linux:9::appstream"},
		{"9.8", "rhel-9-baseos-rhui-rpms", "Red Hat:enterprise_linux:9::baseos"},
		{"9.8", "ubi-9-appstream-rpms", "Red Hat:enterprise_linux:9::appstream"},
		{"9.8", "AppStream", "Red Hat:enterprise_linux:9::appstream"},
		{"9.8", "rhel-9-for-x86_64-highavailability-rpms", "Red Hat:enterprise_linux:9::highavailability"},
		{"9.8", "rhel-9-for-x86_64-resilientstorage-rpms", "Red Hat:enterprise_linux:9::resilientstorage"},
		{"9.8", "rhel-9-for-x86_64-rt-rpms", "Red Hat:enterprise_linux:9::realtime"},
		{"9.8", "rhel-9-for-x86_64-nfv-rpms", "Red Hat:enterprise_linux:9::nfv"},
		{"9.8", "rhel-9-for-x86_64-supplementary-rpms", "Red Hat:enterprise_linux:9::supplementary"},
		{"9.8", "rhel-9-for-x86_64-sap-netweaver-rpms", "Red Hat:enterprise_linux:9::sap"},
		{"9.8", "rhel-9-for-x86_64-sap-solutions-rpms", "Red Hat:enterprise_linux:9::sap_hana"},
		{"9.8", "fast-datapath-for-rhel-9-x86_64-rpms", "Red Hat:enterprise_linux:9::fastdatapath"},
		{"9.4", "rhel-9-for-x86_64-baseos-eus-rpms", "Red Hat:rhel_eus:9.4::baseos"},
		{"9.4", "rhel-9-for-x86_64-appstream-e4s-rpms", "Red Hat:rhel_e4s:9.4::appstream"},
		{"8.8", "rhel-8-for-x86_64-baseos-aus-rpms", "Red Hat:rhel_aus:8.8::baseos"},
		{"8.10", "rhel-8-for-x86_64-appstream-rpms", "Red Hat:enterprise_linux:8::appstream"},
		{"10.2", "rhel-10-for-x86_64-appstream-rpms", ""},
		{"10.0", "rhel-10-for-x86_64-baseos-eus-rpms", "Red Hat:enterprise_linux_eus:10.0"},
		{"10.2", "fast-datapath-for-rhel-10-x86_64-rpms", "Red Hat:enterprise_linux:10::fastdatapath"},
		{"9.8", "epel", ""},
		{"9.8", "@commandline", ""},
		{"9.8", "@System", ""},
		{"9.8", "", ""},
		{"7.9", "rhel-7-server-rpms", ""},
		{"9.4 beta", "rhel-9-for-x86_64-baseos-eus-rpms", ""},
	}
	for _, tt := range tests {
		got := redHatPackageEcosystem(tt.versionID, tt.repoid)
		if got != tt.want {
			t.Errorf("redHatPackageEcosystem(%q, %q) = %q, want %q", tt.versionID, tt.repoid, got, tt.want)
		}
		if got != "" && !serverEcosystemRule.MatchString(got) {
			t.Errorf("%q does not pass the server's ecosystem rule", got)
		}
	}
}

func TestOSVEcosystemPassesTheServerRuleOrIsEmpty(t *testing.T) {
	for _, release := range []map[string]string{
		{"ID": "rhel", "VERSION_ID": "9.8"},
		{"ID": "rhel", "VERSION_ID": "10.2"},
		{"ID": "rhel", "VERSION_ID": "10"},
		{"ID": "rhel", "VERSION_ID": "7.9"},
		{"ID": "rhel", "VERSION_ID": "10.2 beta"},
		{"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION": "24.04.5 LTS (Noble Numbat)"},
		{"ID": "debian", "VERSION_ID": "12\n"},
	} {
		got := OSVEcosystem(release)
		if got != "" && !serverEcosystemRule.MatchString(got) {
			t.Errorf("OSVEcosystem(%v) = %q, which the server rejects", release, got)
		}
	}
	if got := OSVEcosystem(map[string]string{"ID": "rhel", "VERSION_ID": "7.9"}); got != "" {
		t.Errorf("RHEL 7 = %q, want no ecosystem", got)
	}
}
