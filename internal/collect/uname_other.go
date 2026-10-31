//go:build !linux

package collect

import (
	"os"
	"runtime"
)

func systemUname() (Uname, error) {
	hostname, err := os.Hostname()
	return Uname{Nodename: hostname, Machine: runtime.GOARCH}, err
}
