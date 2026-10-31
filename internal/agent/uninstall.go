package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const ServiceName = "oka-cyber-agent.service"

type Uninstaller struct {
	ConfigDir  string
	StateDir   string
	UnitPath   string
	BinaryPath string
	Systemctl  func(ctx context.Context, args ...string) error
}

// Uninstall stops the service and removes everything the installer and the agent created. Missing pieces are
// skipped, so it can be rerun after a partial uninstall.
func (u Uninstaller) Uninstall(ctx context.Context) ([]string, error) {
	for _, path := range []string{u.ConfigDir, u.StateDir, u.UnitPath, u.BinaryPath} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) == "/") {
			return nil, fmt.Errorf("refusing to remove %q", path)
		}
	}
	var removed []string
	var errs []error
	if u.UnitPath != "" && exists(u.UnitPath) {
		if u.Systemctl != nil {
			if err := u.Systemctl(ctx, "disable", "--now", ServiceName); err != nil {
				errs = append(errs, fmt.Errorf("stop %s: %w", ServiceName, err))
			}
		}
		if err := os.Remove(u.UnitPath); err != nil {
			errs = append(errs, err)
		} else {
			removed = append(removed, u.UnitPath)
		}
		if u.Systemctl != nil {
			if err := u.Systemctl(ctx, "daemon-reload"); err != nil {
				errs = append(errs, fmt.Errorf("systemctl daemon-reload: %w", err))
			}
		}
	}
	for _, path := range []string{u.ConfigDir, u.StateDir, u.BinaryPath} {
		if path == "" || !exists(path) {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, path)
	}
	return removed, errors.Join(errs...)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
