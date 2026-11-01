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

// ParseDpkgStatus returns the packages of a dpkg status file whose files are on disk. That includes the states
// of an upgrade in progress or an interrupted dpkg run (unpacked, half-installed, half-configured, triggers-awaited,
// triggers-pending): leaving them out would make the server delete them and close their findings. Packages that
// are not installed, or removed with only their configuration files left, are left out.
func ParseDpkgStatus(r io.Reader, ecosystem string) ([]Package, error) {
	var packages []Package
	err := readStanzas(r, ":", keepKeys("Package", "Status", "Version", "Architecture", "Source"), func(s map[string]string) {
		status := strings.Fields(s["Status"])
		if len(status) != 3 || !dpkgFilesOnDisk(status[2]) || s["Package"] == "" || s["Version"] == "" {
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

// dpkgFilesOnDisk reports whether a package in this dpkg state (the third word of Status, see dpkg(1)) has its
// files installed. An unknown state is left out, as dpkg itself refuses a status file with one.
func dpkgFilesOnDisk(state string) bool {
	switch state {
	case "installed", "triggers-pending", "triggers-awaited", "half-configured", "unpacked", "half-installed":
		return true
	}
	return false
}
