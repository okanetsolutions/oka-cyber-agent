package collect

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const apkInstalledPath = "/lib/apk/db/installed"

type APKCollector struct {
	Root string
}

func (APKCollector) Name() string { return "apk" }

func (c APKCollector) Collect(_ context.Context, inv *Inventory) error {
	ok, err := packageDatabase(c.Root, apkInstalledPath, FamilyAlpine, inv)
	if !ok || err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(c.Root, apkInstalledPath))
	if err != nil {
		return fmt.Errorf("apk database: %w", err)
	}
	defer f.Close()
	packages, err := ParseAPKInstalled(f, inv.OS.OSVEcosystem)
	if err != nil {
		return fmt.Errorf("apk database: %w", err)
	}
	inv.Packages = append(inv.Packages, packages...)
	return nil
}

// ParseAPKInstalled reads the apk installed database, where P is the package, V the version, A the architecture
// and o the origin (source) package.
func ParseAPKInstalled(r io.Reader, ecosystem string) ([]Package, error) {
	var packages []Package
	err := readStanzas(r, ":", keepKeys("P", "V", "A", "o"), func(s map[string]string) {
		if s["P"] == "" || s["V"] == "" {
			return
		}
		origin := s["o"]
		if origin == "" {
			origin = s["P"]
		}
		packages = append(packages, Package{
			Ecosystem:     ecosystem,
			Name:          s["P"],
			Version:       s["V"],
			Architecture:  s["A"],
			SourcePackage: origin,
			SourceVersion: s["V"],
		})
	})
	return packages, err
}
