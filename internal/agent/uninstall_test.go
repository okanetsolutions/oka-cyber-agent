package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// installedTree installs every piece under a temporary root, with a fake systemctl that records its calls and
// fails the commands listed in failing.
func installedTree(t *testing.T, failing ...string) (Uninstaller, *[]string) {
	t.Helper()
	root := t.TempDir()
	u := Uninstaller{
		ConfigDir:  filepath.Join(root, "etc", "oka-cyber-agent"),
		StateDir:   filepath.Join(root, "var", "lib", "oka-cyber-agent"),
		UnitPath:   filepath.Join(root, "etc", "systemd", "system", ServiceName),
		BinaryPath: filepath.Join(root, "usr", "local", "bin", "oka-cyber-agent"),
	}
	for _, file := range []string{filepath.Join(u.ConfigDir, "token"), filepath.Join(u.StateDir, "state.json"), u.UnitPath, u.BinaryPath} {
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	u.Systemctl = func(_ context.Context, args ...string) error {
		call := strings.Join(args, " ")
		calls = append(calls, call)
		if slices.Contains(failing, call) {
			return errors.New("exit status 1")
		}
		return nil
	}
	users := map[string]bool{"oka-cyber": true}
	u.User = "oka-cyber"
	u.UserExists = func(name string) bool { return users[name] }
	u.DeleteUser = func(_ context.Context, name string) error {
		delete(users, name)
		return nil
	}
	return u, &calls
}

func TestUninstallStopsServiceAndRemovesEverything(t *testing.T) {
	u, calls := installedTree(t)
	removed, err := u.Uninstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*calls, []string{"disable --now " + ServiceName, "daemon-reload"}) {
		t.Fatalf("systemctl calls = %v", *calls)
	}
	for _, path := range []string{u.ConfigDir, u.StateDir, u.UnitPath, u.BinaryPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists", path)
		}
		if !slices.Contains(removed, path) {
			t.Fatalf("removed = %v, missing %s", removed, path)
		}
	}
	if !slices.Contains(removed, "user oka-cyber") || u.UserExists("oka-cyber") {
		t.Fatalf("removed = %v, want the service user deleted", removed)
	}

	*calls = nil
	u.Systemctl = func(_ context.Context, args ...string) error {
		*calls = append(*calls, strings.Join(args, " "))
		return errors.New("exit status 1")
	}
	removed, err = u.Uninstall(context.Background())
	if err != nil || len(removed) != 0 {
		t.Fatalf("rerun: removed = %v, err = %v; want a no op", removed, err)
	}
	if !slices.Equal(*calls, []string{"cat " + ServiceName, "is-active --quiet " + ServiceName}) {
		t.Fatalf("rerun systemctl calls = %v, want only queries", *calls)
	}
}

func TestUninstallStopsAUnitInstalledElsewhere(t *testing.T) {
	u, calls := installedTree(t)
	if err := os.Remove(u.UnitPath); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*calls, []string{"cat " + ServiceName, "disable --now " + ServiceName}) {
		t.Fatalf("systemctl calls = %v, want the unit systemd knows disabled and stopped", *calls)
	}
	assertRemoved(t, u.ConfigDir, u.StateDir)
}

func TestUninstallStopsARunningUnitWhoseFileIsGone(t *testing.T) {
	u, calls := installedTree(t, "cat "+ServiceName)
	if err := os.Remove(u.UnitPath); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"cat " + ServiceName, "is-active --quiet " + ServiceName, "stop " + ServiceName}
	if !slices.Equal(*calls, want) {
		t.Fatalf("systemctl calls = %v, want %v", *calls, want)
	}
	assertRemoved(t, u.ConfigDir, u.StateDir)
}

func TestUninstallRemovesNothingWhenTheServiceDoesNotStop(t *testing.T) {
	tests := map[string]struct {
		removeUnit bool
		failing    []string
	}{
		"disable fails":         {failing: []string{"disable --now " + ServiceName}},
		"unit elsewhere":        {removeUnit: true, failing: []string{"disable --now " + ServiceName}},
		"stop of orphaned unit": {removeUnit: true, failing: []string{"cat " + ServiceName, "stop " + ServiceName}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			u, _ := installedTree(t, tt.failing...)
			if tt.removeUnit {
				if err := os.Remove(u.UnitPath); err != nil {
					t.Fatal(err)
				}
			}
			removed, err := u.Uninstall(context.Background())
			if !errors.Is(err, ErrServiceNotStopped) {
				t.Fatalf("err = %v, want ErrServiceNotStopped", err)
			}
			if len(removed) != 0 {
				t.Fatalf("removed = %v, want nothing", removed)
			}
			paths := []string{u.ConfigDir, u.StateDir, u.BinaryPath}
			if !tt.removeUnit {
				paths = append(paths, u.UnitPath)
			}
			for _, path := range paths {
				if _, err := os.Lstat(path); err != nil {
					t.Fatalf("%s: %v, want it kept", path, err)
				}
			}
			if !u.UserExists(u.User) {
				t.Fatal("the service user was deleted, want it kept")
			}
		})
	}
}

func TestUninstallWithoutSystemd(t *testing.T) {
	u, _ := installedTree(t)
	u.Systemctl = nil
	if _, err := u.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRemoved(t, u.ConfigDir, u.StateDir, u.UnitPath, u.BinaryPath)
}

func assertRemoved(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists", path)
		}
	}
}

func TestUninstallRefusesDangerousPaths(t *testing.T) {
	for _, path := range []string{"/", "relative/dir", "/etc/.."} {
		u := Uninstaller{ConfigDir: path}
		if _, err := u.Uninstall(context.Background()); err == nil {
			t.Errorf("Uninstall with ConfigDir %q must refuse", path)
		}
	}
}
