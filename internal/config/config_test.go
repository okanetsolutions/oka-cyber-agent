package config

import (
	"errors"
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
