package config

import (
	"errors"
	"fmt"
	"io"
)

var ErrNotRegularFile = errors.New("not a regular file")

// ReadRegularFile reads a file of at most maxSize bytes that is a regular file at path itself, not through a
// symlink. It is for files in directories the unprivileged service user can write to, which root also reads.
func ReadRegularFile(path string, maxSize int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegularFile)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxSize)
	}
	return data, nil
}
