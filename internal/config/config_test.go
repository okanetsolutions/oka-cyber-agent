package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig() Config {
	cfg := Default()
	cfg.URL = "https://acme.oka.example"
	cfg.ServerID = "42"
	return cfg
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.CollectServices = false
	if err := Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != cfg {
		t.Fatalf("loaded = %+v, want %+v", loaded, cfg)
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
}

func TestParseAppliesDefaultsForMissingKeys(t *testing.T) {
	cfg, err := Parse([]byte("url: https://acme.oka.example\nserver_id: \"7\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReportIntervalSeconds != DefaultReportIntervalSeconds || !cfg.CollectServices {
		t.Fatalf("cfg = %+v, want defaults", cfg)
	}
}

func TestParseRejectsUnknownKeysAndBadValues(t *testing.T) {
	tests := map[string]string{
		"unknown key":        "url: https://a.example\nserver_id: \"1\"\ncolect_services: false\n",
		"http url":           "url: http://a.example\nserver_id: \"1\"\n",
		"missing server id":  "url: https://a.example\n",
		"interval too short": "url: https://a.example\nserver_id: \"1\"\nreport_interval_seconds: 5\n",
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestLoadWithoutConfigIsNotEnrolled(t *testing.T) {
	if _, err := Load(t.TempDir()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
	if _, err := LoadToken(t.TempDir()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		url      string
		insecure bool
		ok       bool
	}{
		{"https://acme.oka.example", false, true},
		{"https://acme.oka.example/", false, true},
		{"http://localhost:8000", true, true},
		{"http://acme.oka.example", false, false},
		{"ftp://acme.oka.example", true, false},
		{"acme.oka.example", false, false},
		{"https://user:pass@acme.oka.example", false, false},
		{"https://acme.oka.example/?x=1", false, false},
	}
	for _, tt := range tests {
		err := ValidateURL(tt.url, tt.insecure)
		if (err == nil) != tt.ok {
			t.Errorf("ValidateURL(%q, %v) = %v, want ok=%v", tt.url, tt.insecure, err, tt.ok)
		}
	}
}

func TestTokenIsPrivateAndPreferredFromSystemdCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := SaveToken(dir, "agent-secret", TokenAccessFor(os.Geteuid(), 0, -1)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, TokenFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token mode = %v, want 0600", info.Mode().Perm())
	}
	token, err := LoadToken(dir)
	if err != nil || token != "agent-secret" {
		t.Fatalf("LoadToken = %q, %v", token, err)
	}

	credentials := t.TempDir()
	if err := os.WriteFile(filepath.Join(credentials, TokenFileName), []byte("from-credential\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentials)
	token, err = LoadToken(dir)
	if err != nil || token != "from-credential" {
		t.Fatalf("LoadToken under systemd = %q, %v", token, err)
	}
}

func TestTokenAccessFor(t *testing.T) {
	const gid = 990
	tests := []struct {
		name                       string
		euid, systemdVersion, sgid int
		want                       TokenAccess
	}{
		{"not root", 1000, 239, gid, TokenAccess{Mode: 0o600}},
		{"systemd with credentials", 0, 247, gid, TokenAccess{Owner: &Owner{UID: 0, GID: 0}, Mode: 0o600}},
		{"recent systemd", 0, 257, gid, TokenAccess{Owner: &Owner{UID: 0, GID: 0}, Mode: 0o600}},
		{"systemd 239 (RHEL 8)", 0, 239, gid, TokenAccess{Owner: &Owner{UID: 0, GID: gid}, Mode: 0o640}},
		{"systemd 239 without the service group", 0, 239, -1, TokenAccess{Owner: &Owner{UID: 0, GID: 0}, Mode: 0o600}},
		{"unknown systemd version", 0, 0, gid, TokenAccess{Owner: &Owner{UID: 0, GID: 0}, Mode: 0o600}},
	}
	for _, tt := range tests {
		got := TokenAccessFor(tt.euid, tt.systemdVersion, tt.sgid)
		if got.Mode != tt.want.Mode || (got.Owner == nil) != (tt.want.Owner == nil) || (got.Owner != nil && *got.Owner != *tt.want.Owner) {
			t.Errorf("%s: TokenAccessFor = %+v (owner %+v), want %+v (owner %+v)", tt.name, got, got.Owner, tt.want, tt.want.Owner)
		}
	}
}

func TestParseSystemdVersion(t *testing.T) {
	tests := map[string]int{
		"systemd 239 (239-82.el8)\n+PAM +AUDIT +SELINUX\n": 239,
		"systemd 252 (252.39-1~deb12u1)\n+PAM +AUDIT\n":    252,
		"systemd 255 (255.4-1ubuntu8.10)\n":                255,
		"":                                                 0,
		"systemctl: command not found\n":                   0,
		"systemd unknown\n":                                0,
		"+PAM +AUDIT\nsystemd 239 (on the wrong line)\n":   0,
	}
	for out, want := range tests {
		if got := ParseSystemdVersion(out); got != want {
			t.Errorf("ParseSystemdVersion(%q) = %d, want %d", out, got, want)
		}
	}
}

func TestSaveTokenReadableByTheServiceGroup(t *testing.T) {
	dir := t.TempDir()
	access := TokenAccess{Owner: &Owner{UID: os.Getuid(), GID: os.Getgid()}, Mode: 0o640}
	if err := SaveToken(dir, "agent-secret", access); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, TokenFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("token mode = %v, want 0640", info.Mode().Perm())
	}
	if token, err := LoadToken(dir); err != nil || token != "agent-secret" {
		t.Fatalf("LoadToken = %q, %v", token, err)
	}
}

func TestSavedConfigNeverContainsTheToken(t *testing.T) {
	dir := t.TempDir()
	if err := SaveToken(dir, "agent-secret", TokenAccessFor(os.Geteuid(), 0, -1)); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, validConfig()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "agent-secret") {
		t.Fatal("config.yaml must not contain the token")
	}
}

func TestCheckWritableCreatesTheDirAndLeavesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "oka-cyber-agent")
	if err := CheckWritable(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries = %v, err = %v; want an empty directory", entries, err)
	}
	if err := CheckWritable(filepath.Join(dir, "missing", "\x00")); err == nil {
		t.Fatal("want an error for a path that cannot be created")
	}
}

func TestWriteFileAtomicSetsTheOwnerBeforeTheFileAppears(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may give a file to any owner")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := WriteFileAtomic(path, []byte("{}\n"), 0o600, &Owner{UID: os.Getuid(), GID: os.Getgid()}); err != nil {
		t.Fatalf("WriteFileAtomic to its own user = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("{}\n"), 0o600, &Owner{UID: 0, GID: 0}); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("WriteFileAtomic to root = %v, want a permission error", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("entries = %v, err = %v; want nothing written when the owner cannot be set", entries, err)
	}
}

func TestReadRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadRegularFile(path, 5); err != nil || string(data) != "12345" {
		t.Fatalf("ReadRegularFile = %q, %v", data, err)
	}
	if _, err := ReadRegularFile(path, 4); err == nil {
		t.Fatal("want an error for a file larger than the limit")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(link, 5); err == nil {
		t.Fatal("want a symlink refused")
	}
	if _, err := ReadRegularFile(dir, 5); err == nil {
		t.Fatal("want a directory refused")
	}
	if _, err := ReadRegularFile(filepath.Join(dir, "missing"), 5); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadRegularFile of a missing file = %v, want fs.ErrNotExist", err)
	}
}
