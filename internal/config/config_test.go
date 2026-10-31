package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
	if !reflect.DeepEqual(loaded, cfg) {
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
	if cfg.ReportIntervalSeconds != DefaultReportIntervalSeconds || !cfg.CollectServices || !cfg.CollectDependencyFiles || cfg.CollectGoBinaries {
		t.Fatalf("cfg = %+v, want defaults", cfg)
	}
	if !slices.Equal(cfg.ScanPaths, DefaultScanPaths) || cfg.MaxDepth != 6 || cfg.MaxFileSize != 20<<20 {
		t.Fatalf("cfg = %+v, want the default dependency scan", cfg)
	}
}

func TestParseRejectsUnknownKeysAndBadValues(t *testing.T) {
	tests := map[string]string{
		"unknown key":        "url: https://a.example\nserver_id: \"1\"\ncolect_services: false\n",
		"http url":           "url: http://a.example\nserver_id: \"1\"\n",
		"missing server id":  "url: https://a.example\n",
		"interval too short": "url: https://a.example\nserver_id: \"1\"\nreport_interval_seconds: 5\n",
		"relative scan path": "url: https://a.example\nserver_id: \"1\"\nscan_paths: [srv]\n",
		"relative exclusion": "url: https://a.example\nserver_id: \"1\"\nexclude_paths: [tmp]\n",
		"depth zero":         "url: https://a.example\nserver_id: \"1\"\nmax_depth: 0\n",
		"file size too big":  "url: https://a.example\nserver_id: \"1\"\nmax_file_size: 999999999999\n",
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
	if err := SaveToken(dir, "agent-secret"); err != nil {
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

func TestSavedConfigNeverContainsTheToken(t *testing.T) {
	dir := t.TempDir()
	if err := SaveToken(dir, "agent-secret"); err != nil {
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

func TestLoadOptionsWithoutEnrollment(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadOptions(dir)
	if err != nil || !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("LoadOptions without a file = %+v, %v; want the defaults", cfg, err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("collect_dependency_files: false\nscan_paths: [/data]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadOptions(dir)
	if err != nil || cfg.CollectDependencyFiles || !slices.Equal(cfg.ScanPaths, []string{"/data"}) {
		t.Fatalf("LoadOptions = %+v, %v", cfg, err)
	}
}
