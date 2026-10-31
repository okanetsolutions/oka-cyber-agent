package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const rpmQueryFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{INSTALLTIME}\n`

var rpmDatabasePaths = []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"}

type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type RPMCollector struct {
	Root string
	Run  CommandRunner
}

func (RPMCollector) Name() string { return "rpm" }

func (c RPMCollector) Collect(ctx context.Context, inv *Inventory) error {
	var found bool
	for _, path := range rpmDatabasePaths {
		if _, err := os.Stat(filepath.Join(c.Root, path)); err == nil {
			ok, err := packageDatabase(c.Root, path, FamilyRHEL, inv)
			if err != nil {
				return err
			}
			found = ok
			break
		}
	}
	if !found {
		return nil
	}
	run := c.Run
	if run == nil {
		run = runCommand
	}
	output, err := run(ctx, "rpm", "--root", c.Root, "-qa", "--queryformat", rpmQueryFormat)
	if err != nil {
		return fmt.Errorf("rpm -qa: %w", err)
	}
	packages, err := ParseRPMQuery(bytes.NewReader(output), inv.OS.OSVEcosystem)
	if err != nil {
		return fmt.Errorf("rpm -qa: %w", err)
	}
	inv.Packages = append(inv.Packages, packages...)
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}

// ParseRPMQuery parses the output of rpm -qa with rpmQueryFormat. Versions are [epoch:]version-release, as in
// OSV.dev's RPM ecosystems. When several versions of one name and architecture are installed (kernels), the
// most recently installed one is kept, since the server accepts one package per name and architecture.
func ParseRPMQuery(r io.Reader, ecosystem string) ([]Package, error) {
	type installed struct {
		pkg  Package
		time int64
	}
	var order []packageIdentity
	latest := map[packageIdentity]installed{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxLineBytes)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 7 {
			continue
		}
		name, epoch, version, release, arch, sourceRPM := fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
		if name == "" || version == "" || arch == "(none)" {
			continue
		}
		pkg := Package{
			Ecosystem:    ecosystem,
			Name:         name,
			Version:      withEpoch(epoch, version+"-"+release),
			Architecture: arch,
		}
		if sourceName, sourceVersion, ok := parseSourceRPM(sourceRPM); ok {
			pkg.SourcePackage = sourceName
			pkg.SourceVersion = withEpoch(epoch, sourceVersion)
		}
		installTime, _ := strconv.ParseInt(fields[6], 10, 64)
		id := pkg.identity()
		previous, seen := latest[id]
		if !seen {
			order = append(order, id)
		}
		if !seen || installTime > previous.time || (installTime == previous.time && pkg.Version > previous.pkg.Version) {
			latest[id] = installed{pkg, installTime}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	packages := make([]Package, 0, len(order))
	for _, id := range order {
		packages = append(packages, latest[id].pkg)
	}
	return packages, nil
}

func withEpoch(epoch, version string) string {
	if epoch == "" || epoch == "0" || epoch == "(none)" {
		return version
	}
	return epoch + ":" + version
}

// parseSourceRPM splits "openssl-3.0.7-27.el9.src.rpm" into "openssl" and "3.0.7-27.el9".
func parseSourceRPM(file string) (string, string, bool) {
	base, ok := strings.CutSuffix(file, ".rpm")
	if !ok {
		return "", "", false
	}
	if dot := strings.LastIndexByte(base, '.'); dot > 0 {
		base = base[:dot]
	}
	releaseDash := strings.LastIndexByte(base, '-')
	if releaseDash <= 0 {
		return "", "", false
	}
	versionDash := strings.LastIndexByte(base[:releaseDash], '-')
	if versionDash <= 0 {
		return "", "", false
	}
	return base[:versionDash], base[versionDash+1:], true
}
