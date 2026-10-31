package collect

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	FamilyDebian = "debian"
	FamilyRHEL   = "rhel"
	FamilyAlpine = "alpine"
)

type Uname struct {
	Nodename string
	Release  string
	Machine  string
}

type OSCollector struct {
	Root  string
	Uname func() (Uname, error)
}

func (OSCollector) Name() string { return "os" }

func (c OSCollector) Collect(_ context.Context, inv *Inventory) error {
	uname := c.Uname
	if uname == nil {
		uname = systemUname
	}
	u, err := uname()
	if err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	release, err := c.readOSRelease()
	if err != nil {
		return err
	}
	inv.OS = OS{
		Hostname:     u.Nodename,
		Family:       osFamily(release["ID"], strings.Fields(release["ID_LIKE"])),
		Name:         release["NAME"],
		Version:      release["VERSION_ID"],
		Kernel:       u.Release,
		Architecture: u.Machine,
		OSVEcosystem: OSVEcosystem(release["ID"], release["VERSION_ID"]),
	}
	return nil
}

func (c OSCollector) readOSRelease() (map[string]string, error) {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		f, err := os.Open(filepath.Join(c.Root, path))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("os-release: %w", err)
		}
		defer f.Close()
		return ParseOSRelease(f)
	}
	return map[string]string{}, nil
}

func ParseOSRelease(r io.Reader) (map[string]string, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = unquoteOSReleaseValue(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("os-release: %w", err)
	}
	return values, nil
}

func unquoteOSReleaseValue(value string) string {
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1]
	}
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return strings.Trim(value, `"`)
}

func osFamily(id string, idLike []string) string {
	for _, candidate := range append([]string{id}, idLike...) {
		switch candidate {
		case "debian", "ubuntu":
			return FamilyDebian
		case "rhel", "centos", "fedora", "rocky", "almalinux":
			return FamilyRHEL
		case "alpine":
			return FamilyAlpine
		}
	}
	return id
}

// OSVEcosystem returns the OSV.dev ecosystem of the distribution's packages, or "" when OSV has no data for it.
func OSVEcosystem(id, versionID string) string {
	if versionID == "" {
		return ""
	}
	parts := strings.Split(versionID, ".")
	major := parts[0]
	switch id {
	case "debian":
		return "Debian:" + major
	case "ubuntu":
		return "Ubuntu:" + versionID
	case "alpine":
		if len(parts) < 2 {
			return ""
		}
		return "Alpine:v" + major + "." + parts[1]
	case "rocky":
		return "Rocky Linux:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	case "rhel":
		return "Red Hat:" + major
	}
	return ""
}
