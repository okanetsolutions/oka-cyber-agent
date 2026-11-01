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
	"strconv"
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
	return WriteFileAtomic(filepath.Join(dir, FileName), append([]byte(fileHeader), data...), 0o644, nil)
}

// TokenPath returns where the agent token is read from. Under systemd 247 or newer the root owned token file is
// passed in with LoadCredential, so the unprivileged service user never needs read access to
// /etc/oka-cyber-agent/token. Older systemd ignores LoadCredential and the service reads the file (see TokenAccessFor).
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

// MinCredentialsSystemdVersion is the first systemd release that supports LoadCredential.
const MinCredentialsSystemdVersion = 247

// TokenAccess is the owner and mode SaveToken gives the agent token file.
type TokenAccess struct {
	Owner *Owner
	Mode  fs.FileMode
}

// TokenAccessFor returns the owner and mode of the agent token written by a process with effective user euid.
// Root keeps the token root only (0600) and systemd hands it to the service with LoadCredential. systemd older
// than 247 (the RHEL 8 family) ignores LoadCredential, so there the service user reads the file itself and the
// token becomes readable by the service group serviceGID only (0640), never by other users. systemdVersion is 0
// when unknown and serviceGID is -1 when the group does not exist; both keep the token root only.
func TokenAccessFor(euid, systemdVersion, serviceGID int) TokenAccess {
	switch {
	case euid != 0:
		return TokenAccess{Mode: 0o600}
	case systemdVersion > 0 && systemdVersion < MinCredentialsSystemdVersion && serviceGID > 0:
		return TokenAccess{Owner: &Owner{UID: 0, GID: serviceGID}, Mode: 0o640}
	default:
		return TokenAccess{Owner: &Owner{UID: 0, GID: 0}, Mode: 0o600}
	}
}

// ParseSystemdVersion reads the version from the first line of "systemctl --version", for example
// "systemd 239 (239-82.el8)". It returns 0 when the output has no version.
func ParseSystemdVersion(out string) int {
	first, _, _ := strings.Cut(out, "\n")
	fields := strings.Fields(first)
	if len(fields) < 2 || fields[0] != "systemd" {
		return 0
	}
	version, err := strconv.Atoi(fields[1])
	if err != nil || version < 0 {
		return 0
	}
	return version
}

// SaveToken writes the agent token with the owner and mode of access.
func SaveToken(dir, token string, access TokenAccess) error {
	return WriteFileAtomic(filepath.Join(dir, TokenFileName), []byte(token+"\n"), access.Mode, access.Owner)
}

// CheckWritable fails when the agent token and configuration could not be saved in dir, so enroll stops
// before it spends an enrollment token. It creates dir when missing, then creates and removes a probe file.
func CheckWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".write-check.*")
	if err != nil {
		return err
	}
	if err := probe.Close(); err != nil {
		os.Remove(probe.Name())
		return err
	}
	return os.Remove(probe.Name())
}

// Owner is the owner WriteFileAtomic gives a file.
type Owner struct{ UID, GID int }

// WriteFileAtomic replaces path with a new file that has data, mode and, when owner is not nil, that owner.
// The owner and mode are set through the open temporary file before it is renamed over path, never on path
// itself: when root writes into a directory another user can write to, that user could swap path for a
// symlink, and a chown or chmod by name would then follow it to any file on the host.
func WriteFileAtomic(path string, data []byte, mode fs.FileMode, owner *Owner) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if owner != nil {
		if err := tmp.Chown(owner.UID, owner.GID); err != nil {
			tmp.Close()
			return err
		}
	}
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
