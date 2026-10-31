package collect

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// packageDatabase reports whether a package collector applies. It does not when the database is absent or
// belongs to a package manager that is not the system's own (rpm installed on Debian), and it records a
// skipped file when the database exists on a distribution OSV.dev has no ecosystem for.
func packageDatabase(root, path, family string, inv *Inventory) (bool, error) {
	_, err := os.Stat(filepath.Join(root, path))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	if inv.OS.Family != family && slices.Contains([]string{FamilyDebian, FamilyRHEL, FamilyAlpine}, inv.OS.Family) {
		return false, nil
	}
	if inv.OS.Family != family || inv.OS.OSVEcosystem == "" {
		inv.Skip(path, ReasonUnsupportedDistribution)
		return false, nil
	}
	return true, nil
}
