package collect

import (
	"context"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/okanetsolutions/oka-cyber-agent/internal/sqlite"
)

const dnfHistoryPath = "/var/lib/dnf/history.sqlite"

// Actions that record the old side of a change (downgraded, obsoleted, upgraded, reinstalled). libdnf skips them
// when it looks up the repository an installed package came from.
var dnfReplacedActions = []int64{3, 5, 7, 10}

// rpmNEVRA identifies an installed rpm; version is [epoch:]version-release, as in Package.Version.
type rpmNEVRA struct {
	name, version, arch string
}

// dnfRepositories maps every package in the dnf history database to the id of the repository its latest
// transaction installed it from, as `dnf repoquery --installed --qf %{from_repo}` does (libdnf
// Swdb::getRPMRepo). It reads the rpm, trans_item and repo tables only, never the recorded command lines or
// console output.
func dnfRepositories(ctx context.Context, root string) (map[rpmNEVRA]string, error) {
	db, err := sqlite.Open(filepath.Join(root, dnfHistoryPath))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	repos := map[int64]string{}
	err = db.Scan(ctx, "repo", []string{"id", "repoid"}, func(row []any) error {
		id, idOK := row[0].(int64)
		repoid, repoOK := row[1].(string)
		if idOK && repoOK {
			repos[id] = repoid
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	rpms := map[int64]rpmNEVRA{}
	err = db.Scan(ctx, "rpm", []string{"item_id", "name", "epoch", "version", "release", "arch"}, func(row []any) error {
		item, itemOK := row[0].(int64)
		name, nameOK := row[1].(string)
		epoch, epochOK := row[2].(int64)
		version, versionOK := row[3].(string)
		release, releaseOK := row[4].(string)
		arch, archOK := row[5].(string)
		if itemOK && nameOK && epochOK && versionOK && releaseOK && archOK {
			rpms[item] = rpmNEVRA{name, withEpoch(strconv.FormatInt(epoch, 10), version+"-"+release), arch}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	type installed struct {
		transItem int64
		repoid    string
	}
	latest := map[rpmNEVRA]installed{}
	err = db.Scan(ctx, "trans_item", []string{"id", "item_id", "repo_id", "action"}, func(row []any) error {
		id, _ := row[0].(int64)
		item, _ := row[1].(int64)
		repo, _ := row[2].(int64)
		action, _ := row[3].(int64)
		nevra, isRPM := rpms[item]
		repoid, hasRepo := repos[repo]
		if !isRPM || !hasRepo || slices.Contains(dnfReplacedActions, action) {
			return nil
		}
		if previous, seen := latest[nevra]; !seen || id > previous.transItem {
			latest[nevra] = installed{id, repoid}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	repositories := make(map[rpmNEVRA]string, len(latest))
	for nevra, item := range latest {
		repositories[nevra] = item.repoid
	}
	return repositories, nil
}

// assignRedHatEcosystems gives each package the OSV.dev ecosystem of the repository it was installed from. The
// history database only refines the OS ecosystem every package already has, so when it is missing or unreadable,
// or a package is not in it (installed with rpm -i or by an image builder) or comes from a repository without an
// OSV ecosystem, the package keeps the OS ecosystem: BaseOS on RHEL 8 and 9, where the base system comes from.
func assignRedHatEcosystems(ctx context.Context, root, versionID string, packages []Package) error {
	repositories, err := dnfRepositories(ctx, root)
	if err != nil {
		return ctx.Err()
	}
	for i, p := range packages {
		if ecosystem := redHatPackageEcosystem(versionID, repositories[rpmNEVRA{p.Name, p.Version, p.Architecture}]); ecosystem != "" {
			packages[i].Ecosystem = ecosystem
		}
	}
	return nil
}

// redHatPackageEcosystem returns the OSV.dev ecosystem of a package from the repository repoid on a RHEL host
// with os-release VERSION_ID versionID, or "" when the repository has none. Red Hat publishes RHEL 8 and 9
// advisories per repository stream ("Red Hat:enterprise_linux:9::appstream") and per extended support channel
// ("Red Hat:rhel_eus:9.4::baseos"), and RHEL 10 advisories per minor release ("Red Hat:enterprise_linux:10.1",
// the OS ecosystem) with a few exceptions.
func redHatPackageEcosystem(versionID, repoid string) string {
	stream, channel := redHatRepository(repoid)
	major, minor, _ := strings.Cut(versionID, ".")
	var ecosystem string
	switch {
	case stream == "":
	case major == "8" || major == "9":
		ecosystem = "Red Hat:enterprise_linux:" + major + "::" + stream
		if channel != "" && minor != "" {
			ecosystem = "Red Hat:rhel_" + channel + ":" + versionID + "::" + stream
		}
	case redHatMajor(major) >= 10:
		if stream == "fastdatapath" {
			ecosystem = "Red Hat:enterprise_linux:" + major + "::fastdatapath"
		} else if channel == "eus" && minor != "" {
			ecosystem = "Red Hat:enterprise_linux_eus:" + versionID
		}
	}
	if !validOSVEcosystem(ecosystem) {
		return ""
	}
	return ecosystem
}

// redHatRepository reads the stream and the extended support channel from a repository id. Ids differ between the
// CDN ("rhel-9-for-x86_64-appstream-rpms", "codeready-builder-for-rhel-9-x86_64-rpms"), RHUI on cloud providers
// ("rhui-rhel-9-for-x86_64-baseos-rhui-rpms"), UBI ("ubi-9-appstream-rpms") and extended support
// ("rhel-9-for-x86_64-baseos-eus-rpms"), so they are matched by word.
func redHatRepository(repoid string) (stream, channel string) {
	words := strings.FieldsFunc(strings.ToLower(repoid), func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	has := func(word string) bool { return slices.Contains(words, word) }
	for _, c := range []string{"eus", "e4s", "aus", "tus"} {
		if has(c) {
			channel = c
		}
	}
	switch {
	case has("baseos"):
		stream = "baseos"
	case has("appstream"):
		stream = "appstream"
	case has("codeready") || has("crb"):
		stream = "crb"
	case has("highavailability"):
		stream = "highavailability"
	case has("resilientstorage"):
		stream = "resilientstorage"
	case has("rt") || has("realtime"):
		stream = "realtime"
	case has("nfv"):
		stream = "nfv"
	case has("supplementary"):
		stream = "supplementary"
	case has("sap") && has("netweaver"):
		stream = "sap"
	case has("sap") && has("solutions"):
		stream = "sap_hana"
	case has("fast") && has("datapath"):
		stream = "fastdatapath"
	}
	return stream, channel
}

func redHatMajor(major string) int {
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return n
}
