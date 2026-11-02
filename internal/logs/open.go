package logs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/okanetsolutions/oka-cyber-agent/internal/safeopen"
)

var (
	errSymlink    = errors.New("symlink")
	errNotRegular = errors.New("not a regular file")
)

// openLogFile opens the log file at path for reading. pattern is the glob pattern the path was found by, or ""
// for a path named in full (both with Options.Root). A directory written literally in the configured path may
// be a symlink, since the admin chose it (deploy tools link current/ and storage/). A name a wildcard matched
// and the log file itself are never followed through a symlink: whoever can write to their directory could
// otherwise point the agent at any file it can read. Every name after the literal start of the path is opened
// relative to its parent directory, so a symlink swapped in after the plan is refused as well. O_NONBLOCK keeps
// a FIFO from blocking the open, and anything but a regular file is refused.
func openLogFile(path, pattern string) (*os.File, error) {
	names := splitPath(path)
	wildcard := make([]bool, len(names))
	if pattern != "" {
		patternNames := splitPath(pattern)
		offset := len(names) - len(patternNames)
		for i, name := range patternNames {
			if offset+i >= 0 && hasGlobMeta(name) {
				wildcard[offset+i] = true
			}
		}
	}
	last := len(names) - 1
	start := slices.Index(wildcard[:last], true)
	if start < 0 {
		start = last
	}
	dir, err := os.OpenFile("/"+filepath.Join(names[:start]...), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	for i := start; i < last; i++ {
		var next *os.File
		if wildcard[i] {
			next, err = openNoFollow(dir, names[i], true)
		} else {
			next, err = safeopen.FollowAt(dir, names[i], os.O_RDONLY|syscall.O_DIRECTORY)
		}
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = next
	}
	defer dir.Close()
	return openNoFollow(dir, names[last], false)
}

// openNoFollow opens name in dir without following a symlink, and returns the file only when it is a
// directory (wantDir) or a regular file.
func openNoFollow(dir *os.File, name string, wantDir bool) (*os.File, error) {
	f, err := safeopen.OpenAt(dir, name, os.O_RDONLY)
	if errors.Is(err, syscall.ELOOP) {
		return nil, &fs.PathError{Op: "open", Path: filepath.Join(dir.Name(), name), Err: errSymlink}
	}
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && (wantDir && !info.IsDir() || !wantDir && !info.Mode().IsRegular()) {
		err = &fs.PathError{Op: "open", Path: f.Name(), Err: errNotRegular}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func splitPath(path string) []string {
	return strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
}

func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// skipReason is the reason a log file that could not be opened is listed as skipped.
func skipReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermissionDenied
	case errors.Is(err, errSymlink):
		return ReasonSymlink
	case errors.Is(err, errNotRegular):
		return ReasonNotRegularFile
	default:
		return ReasonNotFound
	}
}
