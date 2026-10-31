package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func installedTree(t *testing.T) (Uninstaller, *[]string) {
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
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	users := map[string]bool{"oka-cyber": true}
	u.User = "oka-cyber"
	u.UserExists = func(name string) bool { return users[name] }
	u.DeleteUser = func(_ context.Context, name string) error {
		calls = append(calls, "userdel "+name)
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
	if !slices.Equal(*calls, []string{"disable --now " + ServiceName, "daemon-reload", "userdel oka-cyber"}) {
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
	if !slices.Contains(removed, "user oka-cyber") {
		t.Fatalf("removed = %v, missing the service user", removed)
	}

	*calls = nil
	removed, err = u.Uninstall(context.Background())
	if err != nil || len(removed) != 0 || len(*calls) != 0 {
		t.Fatalf("rerun: removed = %v, calls = %v, err = %v; want a no op", removed, *calls, err)
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
