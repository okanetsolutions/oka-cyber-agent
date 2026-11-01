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

// ErrServiceNotStopped means uninstall removed nothing because the service could not be stopped: deleting the
// configuration under a running agent would leave it reporting with the token it holds in memory.
var ErrServiceNotStopped = errors.New("the agent service could not be stopped, so nothing was removed")

type Uninstaller struct {
	ConfigDir  string
	StateDir   string
	UnitPath   string
	BinaryPath string
	User       string
	// Systemctl runs systemctl with args and returns an error for a non zero exit. It is nil when systemd is not
	// running, in which case no service can be running either.
	Systemctl  func(ctx context.Context, args ...string) error
	UserExists func(name string) bool
	DeleteUser func(ctx context.Context, name string) error
}

// Uninstall stops the service and removes everything the installer and the agent created. Missing pieces are
// skipped, so it can be rerun after a partial uninstall.
func (u Uninstaller) Uninstall(ctx context.Context) ([]string, error) {
	for _, path := range []string{u.ConfigDir, u.StateDir, u.UnitPath, u.BinaryPath} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) == "/") {
			return nil, fmt.Errorf("refusing to remove %q", path)
		}
	}
	if err := u.stopService(ctx); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrServiceNotStopped, err)
	}
	var removed []string
	var errs []error
	if u.UnitPath != "" && exists(u.UnitPath) {
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
	if u.User != "" && u.UserExists != nil && u.DeleteUser != nil && u.UserExists(u.User) {
		if err := u.DeleteUser(ctx, u.User); err != nil {
			errs = append(errs, fmt.Errorf("delete user %s: %w", u.User, err))
		} else {
			removed = append(removed, "user "+u.User)
		}
	}
	return removed, errors.Join(errs...)
}

// stopService disables and stops the unit wherever its file is (a package installs it under /usr/lib, not at
// UnitPath), and stops a unit that still runs after its file was deleted.
func (u Uninstaller) stopService(ctx context.Context) error {
	if u.Systemctl == nil {
		return nil
	}
	if (u.UnitPath != "" && exists(u.UnitPath)) || u.Systemctl(ctx, "cat", ServiceName) == nil {
		if err := u.Systemctl(ctx, "disable", "--now", ServiceName); err != nil {
			return fmt.Errorf("systemctl disable --now %s: %w", ServiceName, err)
		}
		return nil
	}
	if u.Systemctl(ctx, "is-active", "--quiet", ServiceName) == nil {
		if err := u.Systemctl(ctx, "stop", ServiceName); err != nil {
			return fmt.Errorf("systemctl stop %s: %w", ServiceName, err)
		}
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
