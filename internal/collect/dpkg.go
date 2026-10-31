package collect

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const dpkgStatusPath = "/var/lib/dpkg/status"

type DpkgCollector struct {
	Root string
}

func (DpkgCollector) Name() string { return "dpkg" }

func (c DpkgCollector) Collect(_ context.Context, inv *Inventory) error {
	ok, err := packageDatabase(c.Root, dpkgStatusPath, FamilyDebian, inv)
	if !ok || err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(c.Root, dpkgStatusPath))
	if err != nil {
		return fmt.Errorf("dpkg status: %w", err)
	}
	defer f.Close()
	packages, err := ParseDpkgStatus(f, inv.OS.OSVEcosystem)
	if err != nil {
		return fmt.Errorf("dpkg status: %w", err)
	}
	inv.Packages = append(inv.Packages, packages...)
	return nil
}

// ParseDpkgStatus returns the installed packages of a dpkg status file. Removed packages that only left
// their configuration files behind are not installed and are left out.
func ParseDpkgStatus(r io.Reader, ecosystem string) ([]Package, error) {
	var packages []Package
	err := readStanzas(r, ":", keepKeys("Package", "Status", "Version", "Architecture", "Source"), func(s map[string]string) {
		status := strings.Fields(s["Status"])
		if len(status) != 3 || status[2] != "installed" || s["Package"] == "" || s["Version"] == "" {
			return
		}
		sourceName, sourceVersion := s["Package"], s["Version"]
		if source := s["Source"]; source != "" {
			name, version, hasVersion := strings.Cut(source, " ")
			sourceName = name
			if hasVersion {
				sourceVersion = strings.Trim(strings.TrimSpace(version), "()")
			}
		}
		packages = append(packages, Package{
			Ecosystem:     ecosystem,
			Name:          s["Package"],
			Version:       s["Version"],
			Architecture:  s["Architecture"],
			SourcePackage: sourceName,
			SourceVersion: sourceVersion,
		})
	})
	return packages, err
}
