package collect

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDpkgDebian12(t *testing.T) {
	inv := collectHost(t, "debian-12", "")
	if len(inv.Packages) != 88 {
		t.Fatalf("packages = %d, want 88", len(inv.Packages))
	}
	libc := findPackage(t, inv, "libc6")
	want := Package{Ecosystem: "Debian:12", Name: "libc6", Version: "2.36-9+deb12u14", Architecture: "amd64", SourcePackage: "glibc", SourceVersion: "2.36-9+deb12u14"}
	if libc != want {
		t.Fatalf("libc6 = %+v\nwant %+v", libc, want)
	}
	bash := findPackage(t, inv, "bash")
	if bash.Version != "5.2.15-2+b13" || bash.SourcePackage != "bash" || bash.SourceVersion != "5.2.15-2" {
		t.Fatalf("bash = %+v, want the binNMU version and the source version from Source:", bash)
	}
	if len(inv.SkippedFiles) != 0 {
		t.Fatalf("skipped = %v", inv.SkippedFiles)
	}
}

func TestDpkgUbuntu2204(t *testing.T) {
	inv := collectHost(t, "ubuntu-22.04", "")
	if len(inv.Packages) != 101 {
		t.Fatalf("packages = %d, want 101", len(inv.Packages))
	}
	ssl := findPackage(t, inv, "libssl3")
	if ssl.Ecosystem != "Ubuntu:22.04" || ssl.Version != "3.0.2-0ubuntu1.30" || ssl.SourcePackage != "openssl" {
		t.Fatalf("libssl3 = %+v", ssl)
	}
}

func TestDpkgLeavesOutPackagesWithOnlyConfigFilesLeft(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "dpkg", "removed-login.status"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	packages, err := ParseDpkgStatus(f, "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 87 {
		t.Fatalf("packages = %d, want 87", len(packages))
	}
	for _, p := range packages {
		if p.Name == "login" {
			t.Fatal("login is removed (config-files) and must not be reported")
		}
	}
}

func TestDpkgOnUnsupportedDistributionIsSkipped(t *testing.T) {
	inv := collectHost(t, "debian-sid", "")
	if len(inv.Packages) != 0 {
		t.Fatalf("packages = %d, want none without an OSV ecosystem", len(inv.Packages))
	}
	want := []SkippedFile{{Path: dpkgStatusPath, Reason: ReasonUnsupportedDistribution}}
	if !slices.Equal(inv.SkippedFiles, want) {
		t.Fatalf("skipped = %v, want %v", inv.SkippedFiles, want)
	}
}

func TestDpkgUnreadableStatusFailsTheInventory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of mode")
	}
	root := t.TempDir()
	copyFile(t, filepath.Join(hostRoot("debian-12"), "etc", "os-release"), filepath.Join(root, "etc", "os-release"))
	status := filepath.Join(root, "var", "lib", "dpkg", "status")
	copyFile(t, filepath.Join(hostRoot("debian-12"), "var", "lib", "dpkg", "status"), status)
	if err := os.Chmod(status, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), OSCollector{Root: root, Uname: fixedUname}, DpkgCollector{Root: root}); err == nil {
		t.Fatal("an unreadable package database must fail the inventory instead of reporting no packages")
	}
}

func TestAPKAlpine320(t *testing.T) {
	inv := collectHost(t, "alpine-3.20", "")
	if len(inv.Packages) != 14 {
		t.Fatalf("packages = %d, want 14", len(inv.Packages))
	}
	crypto := findPackage(t, inv, "libcrypto3")
	want := Package{Ecosystem: "Alpine:v3.20", Name: "libcrypto3", Version: "3.3.7-r0", Architecture: "x86_64", SourcePackage: "openssl", SourceVersion: "3.3.7-r0"}
	if crypto != want {
		t.Fatalf("libcrypto3 = %+v\nwant %+v", crypto, want)
	}
}

func TestRPMRocky9(t *testing.T) {
	var gotArgs []string
	root := hostRoot("rocky-9")
	inv, err := Run(context.Background(),
		OSCollector{Root: root, Uname: fixedUname},
		RPMCollector{Root: root, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotArgs = append([]string{name}, args...)
			return os.ReadFile(filepath.Join("testdata", "rpm", "rocky-9.txt"))
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gotArgs, []string{"rpm", "-qa", "--queryformat", rpmQueryFormat}) {
		t.Fatalf("command = %q", gotArgs)
	}
	if len(inv.Packages) != 146 {
		t.Fatalf("packages = %d, want 146 (147 rows minus gpg-pubkey)", len(inv.Packages))
	}
	for _, p := range inv.Packages {
		if p.Name == "gpg-pubkey" {
			t.Fatal("gpg-pubkey entries are keys, not packages")
		}
	}
	ssl := findPackage(t, inv, "openssl-libs")
	want := Package{Ecosystem: "Rocky Linux:9", Name: "openssl-libs", Version: "1:3.5.5-2.el9_8", Architecture: "x86_64", SourcePackage: "openssl", SourceVersion: "1:3.5.5-2.el9_8"}
	if ssl != want {
		t.Fatalf("openssl-libs = %+v\nwant %+v", ssl, want)
	}
	if bash := findPackage(t, inv, "bash"); strings.Contains(bash.Version, ":") {
		t.Fatalf("bash = %+v, epoch 0 must not be prefixed", bash)
	}
}

func TestRPMRHEL9(t *testing.T) {
	inv := collectHost(t, "rhel-9", filepath.Join("testdata", "rpm", "rhel-9.txt"))
	ssl := findPackage(t, inv, "openssl-libs")
	if ssl.Ecosystem != "Red Hat:9" || ssl.Version != "1:3.5.8-2.el9_8" {
		t.Fatalf("openssl-libs = %+v", ssl)
	}
	if len(inv.Packages) != 186 {
		t.Fatalf("packages = %d, want 186", len(inv.Packages))
	}
}

func TestRPMKeepsMostRecentlyInstalledOfSameNameAndArch(t *testing.T) {
	output := "kernel-core\t0\t5.14.0\t503.14.1.el9_5\tx86_64\tkernel-5.14.0-503.14.1.el9_5.src.rpm\t1730000000\n" +
		"kernel-core\t0\t5.14.0\t503.26.1.el9_5\tx86_64\tkernel-5.14.0-503.26.1.el9_5.src.rpm\t1740000000\n" +
		"kernel-core\t0\t5.14.0\t427.13.1.el9_4\tx86_64\tkernel-5.14.0-427.13.1.el9_4.src.rpm\t1720000000\n" +
		"glibc\t0\t2.34\t125.el9_5.1\ti686\tglibc-2.34-125.el9_5.1.src.rpm\t1730000000\n" +
		"glibc\t0\t2.34\t125.el9_5.1\tx86_64\tglibc-2.34-125.el9_5.1.src.rpm\t1730000000\n"
	packages, err := ParseRPMQuery(strings.NewReader(output), "Rocky Linux:9")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 3 {
		t.Fatalf("packages = %+v, want one kernel-core and two glibc architectures", packages)
	}
	if packages[0].Name != "kernel-core" || packages[0].Version != "5.14.0-503.26.1.el9_5" || packages[0].SourcePackage != "kernel" {
		t.Fatalf("kernel-core = %+v, want the latest install", packages[0])
	}
}

func TestRPMDatabaseOnDebianIsIgnored(t *testing.T) {
	root := t.TempDir()
	copyFile(t, filepath.Join(hostRoot("debian-12"), "etc", "os-release"), filepath.Join(root, "etc", "os-release"))
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "rpm"), 0o755); err != nil {
		t.Fatal(err)
	}
	inv, err := Run(context.Background(), OSCollector{Root: root, Uname: fixedUname}, RPMCollector{Root: root, Run: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("rpm must not run on a Debian host")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Packages) != 0 || len(inv.SkippedFiles) != 0 {
		t.Fatalf("inventory = %+v", inv)
	}
}

func TestParseSourceRPM(t *testing.T) {
	tests := map[string][3]string{
		"openssl-3.0.7-27.el9.src.rpm":        {"openssl", "3.0.7-27.el9", "true"},
		"python3.11-pip-22.3.1-4.el9.src.rpm": {"python3.11-pip", "22.3.1-4.el9", "true"},
		"(none)":                              {"", "", "false"},
		"broken.src.rpm":                      {"", "", "false"},
	}
	for input, want := range tests {
		name, version, ok := parseSourceRPM(input)
		if name != want[0] || version != want[1] || (ok != (want[2] == "true")) {
			t.Errorf("parseSourceRPM(%q) = %q, %q, %v; want %v", input, name, version, ok, want)
		}
	}
}

func TestNoPackageDatabaseCollectsNothing(t *testing.T) {
	inv := collectHost(t, "ubuntu-24.04", "")
	if len(inv.Packages) != 0 || len(inv.SkippedFiles) != 0 {
		t.Fatalf("inventory = %+v", inv)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
