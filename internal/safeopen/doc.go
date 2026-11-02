// Package safeopen opens files and directories one path component at a time, relative to an open parent
// directory, without following symlinks other local users may plant and without blocking on a FIFO.
package safeopen
