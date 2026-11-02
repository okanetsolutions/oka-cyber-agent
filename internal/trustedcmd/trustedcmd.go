// Package trustedcmd finds the system commands the agent runs (rpm, journalctl) in fixed system directories.
package trustedcmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Dirs are the only directories commands are run from. The agent's own PATH is never searched, since it can
// run as root and a PATH kept by sudo can contain a directory other users can write to.
var Dirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

// Look returns the absolute path of the executable name in the first of Dirs that has it. Pass that path to
// exec.Command: a bare name would be looked up in the agent's own PATH.
func Look(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("command %q: %w", name, exec.ErrNotFound)
	}
	for _, dir := range Dirs {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s in %s: %w", name, strings.Join(Dirs, ":"), exec.ErrNotFound)
}

// Env is the environment a command runs with: the C locale and a PATH of Dirs only, plus extra.
func Env(extra ...string) []string {
	return append([]string{"LC_ALL=C", "PATH=" + strings.Join(Dirs, ":")}, extra...)
}
