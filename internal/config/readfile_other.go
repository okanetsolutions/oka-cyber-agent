//go:build !linux

package config

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func openRegular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegularFile)
	}
	return os.Open(path)
}

func openDir(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "open", Path: path, Err: syscall.ENOTDIR}
	}
	return os.Open(path)
}
