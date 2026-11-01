package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Watcher tells a running agent that enroll --force or an edit replaced the configuration or the agent token.
// It only stats the two files: under systemd the service user cannot read the root owned token, and the token
// it uses is the copy systemd made at start (LoadCredential), so the agent has to be restarted to use a new one.
type Watcher struct {
	dir  string
	seen [2]fs.FileInfo
}

func NewWatcher(dir string) *Watcher {
	w := &Watcher{dir: dir}
	w.seen = w.stat()
	return w
}

// Changed reports whether either file was replaced or edited since the last call, and the new configuration
// loads and the token file exists. When they do not, it returns false and an error once for that change, so
// a half finished edit does not stop an agent that still works with the settings it started with.
func (w *Watcher) Changed() (bool, error) {
	current := w.stat()
	if sameFile(w.seen[0], current[0]) && sameFile(w.seen[1], current[1]) {
		return false, nil
	}
	w.seen = current
	if _, err := Load(w.dir); err != nil {
		return false, err
	}
	if current[1] == nil {
		return false, fmt.Errorf("agent token %s is missing", filepath.Join(w.dir, TokenFileName))
	}
	return true, nil
}

func (w *Watcher) stat() [2]fs.FileInfo {
	var infos [2]fs.FileInfo
	for i, name := range []string{FileName, TokenFileName} {
		if info, err := os.Stat(filepath.Join(w.dir, name)); err == nil {
			infos[i] = info
		}
	}
	return infos
}

func sameFile(a, b fs.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}
