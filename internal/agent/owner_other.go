//go:build !linux

package agent

import "io/fs"

func fileOwner(fs.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}
