// Package config loads and stores the local configuration in /etc/oka-cyber-agent.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	DefaultDir      = "/etc/oka-cyber-agent"
	DefaultStateDir = "/var/lib/oka-cyber-agent"
	FileName        = "config.yaml"
	TokenFileName   = "token"

	DefaultReportIntervalSeconds = 300
	MinReportIntervalSeconds     = 60
	MaxReportIntervalSeconds     = 86400
)

var ErrNotEnrolled = errors.New("not enrolled: run oka-cyber-agent enroll --url <tenant URL> --token <enrollment token>")

type Config struct {
	URL                   string `yaml:"url"`
	ServerID              string `yaml:"server_id"`
	ReportIntervalSeconds int    `yaml:"report_interval_seconds"`
	InsecureDev           bool   `yaml:"insecure_dev,omitempty"`
	CollectServices       bool   `yaml:"collect_services"`
}

func Default() Config {
	return Config{
		ReportIntervalSeconds: DefaultReportIntervalSeconds,
		CollectServices:       true,
	}
}

func Load(dir string) (Config, error) {
	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, ErrNotEnrolled
	}
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func Parse(data []byte) (Config, error) {
	cfg := Default()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if err := ValidateURL(c.URL, c.InsecureDev); err != nil {
		return err
	}
	if c.ServerID == "" {
		return errors.New("server_id is required")
	}
	if c.ReportIntervalSeconds < MinReportIntervalSeconds || c.ReportIntervalSeconds > MaxReportIntervalSeconds {
		return fmt.Errorf("report_interval_seconds must be between %d and %d", MinReportIntervalSeconds, MaxReportIntervalSeconds)
	}
	return nil
}

// ValidateURL accepts an https tenant URL. Plain http is only allowed with insecureDev, for local testing.
func ValidateURL(raw string, insecureDev bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("url %q is not an absolute URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("url %q must not contain credentials, a query or a fragment", raw)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && insecureDev:
		return nil
	case u.Scheme == "http":
		return fmt.Errorf("url %q must use https (plain http is only allowed with --insecure-dev)", raw)
	default:
		return fmt.Errorf("url %q must use https", raw)
	}
}

const fileHeader = `# Oka Cyber Agent configuration.
# Options: https://github.com/okanetsolutions/oka-cyber-agent#configuration
`

// Save writes the configuration atomically, readable by the service user.
func Save(dir string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, FileName), append([]byte(fileHeader), data...), 0o644)
}

// TokenPath returns where the agent token is read from. Under systemd the root owned token file is passed
// in with LoadCredential, so the unprivileged service user never needs read access to /etc/oka-cyber-agent/token.
func TokenPath(dir string) string {
	if credentials := os.Getenv("CREDENTIALS_DIRECTORY"); credentials != "" {
		path := filepath.Join(credentials, TokenFileName)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return filepath.Join(dir, TokenFileName)
}

func LoadToken(dir string) (string, error) {
	path := TokenPath(dir)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotEnrolled
	}
	if err != nil {
		return "", fmt.Errorf("read agent token %s: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("agent token %s is empty", path)
	}
	return token, nil
}

// SaveToken writes the agent token with mode 0600, owned by root when running as root.
func SaveToken(dir, token string) error {
	path := filepath.Join(dir, TokenFileName)
	if err := WriteFileAtomic(path, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return os.Chown(path, 0, 0)
	}
	return nil
}

func WriteFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
