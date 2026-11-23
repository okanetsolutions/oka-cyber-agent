package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	looseCommit    = "321ce7d78ac13e18930bda718f9bc1e605c45abd"
	packedCommit   = "c62705d07318abe1f3116e40b3419c8b4ba99f1e"
	detachedCommit = "4b5e7496a25c895d276231f9c2bd22af3dd90b73"
	sha256Commit   = "b8fd2fbe15fc4f08fe4b985340715a89234e1dc01dc09c721d73e345585db5d2"
)

func applicationFixture(name string) string {
	return filepath.Join("testdata", "applications", name)
}

// git copies the files of a real .git directory, kept under testdata as a plain directory because git does not
// store one, to the .git of hostDir: HEAD, config, the ref files and packed-refs, as git 2.53 wrote them.
func (tr tree) git(fixture, hostDir string) {
	tr.t.Helper()
	source := applicationFixture(filepath.Join("git", fixture))
	err := filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		tr.copy(p, filepath.Join(hostDir, ".git", rel))
		return nil
	})
	if err != nil {
		tr.t.Fatal(err)
	}
}

func (tr tree) mkdir(hostPath string) {
	tr.t.Helper()
	if err := os.MkdirAll(filepath.Join(tr.root, hostPath), 0o755); err != nil {
		tr.t.Fatal(err)
	}
}

func collectApplications(t *testing.T, tr tree, options DependencyOptions) *Inventory {
	t.Helper()
	options.ApplicationDetails = true
	inv, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func checkApplications(t *testing.T, got, want []Application) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applications = %+v\nwant %+v", got, want)
	}
}

// One application per directory with a parsed lock file, sorted by path: the name comes from composer.json, then
// from package.json, and is left out when neither has one. A directory whose lock file was not parsed, a manifest
// without a lock file and a Go executable are no application.
func TestApplicationNamesAndRuntimes(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("composer/composer.lock"), "/var/www/shop/composer.lock")
	tr.copy(applicationFixture("composer.json"), "/var/www/shop/composer.json")
	tr.copy(lockFixture("npm-v3/package-lock.json"), "/var/www/shop/package-lock.json")
	tr.copy(applicationFixture("package.json"), "/var/www/shop/package.json")
	tr.copy(lockFixture("npm-v3/package-lock.json"), "/var/www/storefront/package-lock.json")
	tr.copy(applicationFixture("package.json"), "/var/www/storefront/package.json")
	tr.copy(lockFixture("npm-v3/package-lock.json"), "/var/www/unnamed/package-lock.json")
	tr.copy(applicationFixture("package-unnamed.json"), "/var/www/unnamed/package.json")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/rust/Cargo.lock")
	tr.write("/srv/broken/composer.lock", "{not json")
	tr.copy(applicationFixture("composer.json"), "/srv/broken/composer.json")
	tr.copy(applicationFixture("package.json"), "/srv/nolock/package.json")
	tr.copy(self, "/srv/bin/tool")
	if err := os.Chmod(filepath.Join(tr.root, "/srv/bin/tool"), 0o755); err != nil {
		t.Fatal(err)
	}

	inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/var/www", "/srv", "/var/www/shop"}, GoBinaries: true})
	checkApplications(t, inv.Applications, []Application{
		{Path: "/srv/rust"},
		{Path: "/var/www/shop", Name: "acme/shop", Runtimes: []Runtime{{"php", "^8.3"}, {"node", ">=24"}}},
		{Path: "/var/www/storefront", Name: "@acme/storefront", Runtimes: []Runtime{{"node", ">=24"}}},
		{Path: "/var/www/unnamed"},
	})
}

// The repository is the origin remote without the user and password it carries, the branch and commit are what
// HEAD names. The fixtures are the .git files of repositories made with git: a branch with a loose ref file, a
// branch whose ref git packed (git pack-refs --all leaves the empty refs/heads behind), a detached HEAD, a
// remote git wrote quoted because the password has a ";", a remote whose password has an unescaped "/" and a
// SHA-256 repository.
func TestApplicationRepositoryBranchAndCommit(t *testing.T) {
	tests := []struct {
		fixture string
		want    Application
	}{
		{"loose", Application{Repository: "https://github.com/acme/shop.git", Branch: "main", Commit: looseCommit}},
		{"packed", Application{Repository: "ssh://git.acme.example:2222/acme/api.git", Branch: "release/2026.11", Commit: packedCommit}},
		{"detached", Application{Repository: "git@github.com:acme/storefront.git", Commit: detachedCommit}},
		{"quoted", Application{Repository: "https://git.acme.example/acme/billing.git", Branch: "main", Commit: "2b9874c71f65e5f938c4392832378841d17f348e"}},
		{"malformed", Application{Branch: "main", Commit: "cab4a8ed3de7eb0161cead7d5791e3eaec94355b"}},
		{"sha256", Application{Repository: "https://github.com/acme/ledger.git", Branch: "main", Commit: sha256Commit}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			tr := tree{t, t.TempDir()}
			tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/app/Cargo.lock")
			tr.git(tt.fixture, "/srv/app")
			tr.mkdir("/srv/app/.git/refs/heads")
			inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/srv"}})
			tt.want.Path = "/srv/app"
			checkApplications(t, inv.Applications, []Application{tt.want})
			raw, err := json.Marshal(inv)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"deploy-token", "hunter2", "se;cret", "to/ken"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("the snapshot carries the credential %q", secret)
				}
			}
		})
	}
}

// A loose ref file wins over packed-refs, as in git: after a commit git writes the ref file and leaves the old
// line in packed-refs. A branch without any commit yet has a name and no commit.
func TestApplicationCommitPrefersTheLooseRef(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/app/Cargo.lock")
	tr.git("packed", "/srv/app")
	tr.copy(applicationFixture("git/loose/refs/heads/main"), "/srv/app/.git/refs/heads/release/2026.11")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/unborn/Cargo.lock")
	tr.copy(applicationFixture("git/loose/HEAD"), "/srv/unborn/.git/HEAD")

	inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/srv"}})
	checkApplications(t, inv.Applications, []Application{
		{Path: "/srv/app", Repository: "ssh://git.acme.example:2222/acme/api.git", Branch: "release/2026.11", Commit: looseCommit},
		{Path: "/srv/unborn", Branch: "main"},
	})
}

// The live release of a deployment folder reports its details under the current path, like its packages, so a
// deploy changes the commit and not the path. The other releases are not read.
func TestApplicationDetailsOfADeploymentFolderUseTheCurrentPath(t *testing.T) {
	tr := tree{t, t.TempDir()}
	for release, fixture := range map[string]string{"20261107": "loose", "20261108": "packed"} {
		dir := "/home/forge/okastore.app/releases/" + release
		tr.copy(lockFixture("composer/composer.lock"), dir+"/composer.lock")
		tr.copy(applicationFixture("composer.json"), dir+"/composer.json")
		tr.git(fixture, dir)
	}
	tr.symlink("/home/forge/okastore.app/releases/20261108", "/home/forge/okastore.app/current")

	inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/home"}})
	checkApplications(t, inv.Applications, []Application{{
		Path:       "/home/forge/okastore.app/current",
		Name:       "acme/shop",
		Repository: "ssh://git.acme.example:2222/acme/api.git",
		Branch:     "release/2026.11",
		Commit:     packedCommit,
		Runtimes:   []Runtime{{"php", "^8.3"}},
	}})
	if want := map[string]int{"/home/forge/okastore.app/current/composer.lock": 7}; !mapsEqual(manifests(inv), want) {
		t.Fatalf("manifests = %v, want %v", manifests(inv), want)
	}
}

// .git is read only when it is a real directory. A symlink to one and a gitfile (what a worktree or a submodule
// has) are skipped, and so are a symlinked HEAD, config, ref directory and manifest inside a real one.
func TestApplicationDetailsNeverFollowSymlinks(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.git("loose", "/outside/repo")
	tr.copy(applicationFixture("composer.json"), "/outside/composer.json")

	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/linked/Cargo.lock")
	tr.symlink("../../outside/repo/.git", "/srv/linked/.git")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/worktree/Cargo.lock")
	tr.write("/srv/worktree/.git", "gitdir: /outside/repo/.git/worktrees/worktree\n")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/inside/Cargo.lock")
	tr.symlink("../../../outside/repo/.git/HEAD", "/srv/inside/.git/HEAD")
	tr.symlink("../../../outside/repo/.git/config", "/srv/inside/.git/config")
	tr.symlink("../../outside/composer.json", "/srv/inside/composer.json")
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/refs/Cargo.lock")
	tr.copy(applicationFixture("git/loose/HEAD"), "/srv/refs/.git/HEAD")
	tr.symlink("../../../outside/repo/.git/refs", "/srv/refs/.git/refs")

	inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/srv"}})
	checkApplications(t, inv.Applications, []Application{
		{Path: "/srv/inside"},
		{Path: "/srv/linked"},
		{Path: "/srv/refs", Branch: "main"},
		{Path: "/srv/worktree"},
	})
}

// A file that is too large, is not what it should be or names something the server would reject only leaves its
// fields out. The inventory, its packages and the other fields are still reported.
func TestApplicationDetailsOmitWhatCannotBeRead(t *testing.T) {
	padding := strings.Repeat(" ", 4096)
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/oversized/Cargo.lock")
	tr.write("/srv/oversized/composer.json", `{"name": "acme/oversized", "require": {"php": "^8.3"}}`+padding)
	tr.copy(applicationFixture("package.json"), "/srv/oversized/package.json")
	tr.git("loose", "/srv/oversized")
	tr.write("/srv/oversized/.git/config", "[remote \"origin\"]\n\turl = https://github.com/acme/oversized.git\n"+padding)

	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/unparsable/Cargo.lock")
	tr.write("/srv/unparsable/composer.json", "{not json")
	tr.write("/srv/unparsable/package.json", `{"name": ["acme"], "engines": {"node": 24}}`)
	tr.write("/srv/unparsable/.git/HEAD", "ref: refs/heads/../../../../etc/passwd\n")
	tr.write("/srv/unparsable/.git/config", "[remote \"origin\"\n\turl = \"https://github.com/acme/app.git\n")

	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/rejected/Cargo.lock")
	tr.write("/srv/rejected/composer.json", fmt.Sprintf(`{"name": %q, "require": []}`, strings.Repeat("a", MaxApplicationFieldLength+1)))
	tr.write("/srv/rejected/package.json", fmt.Sprintf(`{"name": "acme/rejected", "engines": {"node": %q}}`, strings.Repeat("1", MaxApplicationFieldLength+1)))
	tr.write("/srv/rejected/.git/HEAD", "ref: refs/heads/"+strings.Repeat("b", MaxApplicationFieldLength+1)+"\n")
	tr.write("/srv/rejected/.git/config", "[remote \"origin\"]\n\turl = https://github.com/acme/"+strings.Repeat("c", MaxRepositoryLength)+".git\n")

	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/padded/Cargo.lock")
	tr.write("/srv/padded/.git/HEAD", "ref: refs/heads/"+strings.Repeat("\u00a0", MaxApplicationFieldLength)+"main\n")

	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/garbage/Cargo.lock")
	tr.write("/srv/garbage/.git/HEAD", "ref: refs/heads/main\n")
	tr.write("/srv/garbage/.git/refs/heads/main", "not a commit\n")
	tr.write("/srv/garbage/.git/packed-refs", looseCommit+" refs/heads/main\n")
	tr.mkdir("/srv/garbage/.git/config")

	inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/srv"}, MaxFileSize: 4096})
	checkApplications(t, inv.Applications, []Application{
		{Path: "/srv/garbage", Branch: "main"},
		{Path: "/srv/oversized", Name: "@acme/storefront", Branch: "main", Commit: looseCommit, Runtimes: []Runtime{{"node", ">=24"}}},
		{Path: "/srv/padded"},
		{Path: "/srv/rejected", Name: "acme/rejected"},
		{Path: "/srv/unparsable"},
	})
	want := map[string]int{"/srv/garbage/Cargo.lock": 9, "/srv/oversized/Cargo.lock": 9, "/srv/padded/Cargo.lock": 9, "/srv/rejected/Cargo.lock": 9, "/srv/unparsable/Cargo.lock": 9}
	if !mapsEqual(manifests(inv), want) {
		t.Fatalf("manifests = %v, want %v", manifests(inv), want)
	}
	// The manifests are listed for having no lock file of their own, never for what reading them gave.
	for _, f := range inv.SkippedFiles {
		if f.Reason != ReasonNoLockFile {
			t.Fatalf("skipped = %v, want no record for a file read for the details", inv.SkippedFiles)
		}
	}
}

// exclude_paths applies to the files read for the details as it does to lock files, written with the path the
// application is reported under or, for a deployment folder, with the path of the release.
func TestApplicationDetailsHonourExcludePaths(t *testing.T) {
	for _, excluded := range [][]string{
		{"/srv/app/current/.git", "/srv/app/current/composer.json"},
		{"/srv/app/releases/2/.git", "/srv/app/releases/2/composer.json"},
		{"/srv/app/current/.git/config", "/srv/app/current/.git/HEAD", "/srv/app/current/composer.json"},
		{"/srv/app/releases/2/.git/config", "/srv/app/releases/2/.git/HEAD", "/srv/app/releases/2/composer.json"},
	} {
		tr := tree{t, t.TempDir()}
		tr.copy(lockFixture("composer/composer.lock"), "/srv/app/releases/2/composer.lock")
		tr.copy(applicationFixture("composer.json"), "/srv/app/releases/2/composer.json")
		tr.copy(applicationFixture("package.json"), "/srv/app/releases/2/package.json")
		tr.git("loose", "/srv/app/releases/2")
		tr.symlink("releases/2", "/srv/app/current")
		inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/srv"}, ExcludePaths: excluded})
		want := []Application{{Path: "/srv/app/current", Name: "@acme/storefront", Runtimes: []Runtime{{"node", ">=24"}}}}
		if !reflect.DeepEqual(inv.Applications, want) {
			t.Errorf("exclude %v: applications = %+v\nwant %+v", excluded, inv.Applications, want)
		}
	}
}

// Excluding only the ref file HEAD names keeps the branch and leaves the commit out, even when packed-refs has
// an older commit for it.
func TestApplicationDetailsDoNotReadAnExcludedRefFile(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("cargo/Cargo.lock"), "/srv/app/Cargo.lock")
	tr.git("loose", "/srv/app")
	tr.write("/srv/app/.git/packed-refs", packedCommit+" refs/heads/main\n")
	for _, excluded := range []string{"/srv/app/.git/refs/heads/main", "/srv/app/.git/refs"} {
		inv := collectApplications(t, tr, DependencyOptions{ScanPaths: []string{"/srv"}, ExcludePaths: []string{excluded}})
		checkApplications(t, inv.Applications, []Application{{Path: "/srv/app", Repository: "https://github.com/acme/shop.git", Branch: "main"}})
	}
}

// Without ApplicationDetails (collect_application_details: false) nothing is read for the details and the snapshot
// has no applications key, like the snapshot of an agent older than it.
func TestApplicationDetailsOnlyWhenEnabled(t *testing.T) {
	tr := tree{t, t.TempDir()}
	tr.copy(lockFixture("composer/composer.lock"), "/srv/app/composer.lock")
	tr.copy(applicationFixture("composer.json"), "/srv/app/composer.json")
	tr.git("loose", "/srv/app")
	options := DependencyOptions{ScanPaths: []string{"/srv"}}

	keys := func(inv *Inventory) map[string]json.RawMessage {
		data, err := inv.Marshal(1<<20, nil)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot map[string]json.RawMessage
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	off, err := Run(context.Background(), DependencyCollector{Root: tr.root, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if _, sent := keys(off)["applications"]; sent || len(off.Applications) != 0 || len(off.Packages) != 7 {
		t.Fatalf("applications = %+v with %d packages, want no applications key and the 7 packages", off.Applications, len(off.Packages))
	}

	on := keys(collectApplications(t, tr, options))
	want := `[{"path":"/srv/app","name":"acme/shop","repository":"https://github.com/acme/shop.git","branch":"main","commit":"` + looseCommit + `","runtimes":[{"name":"php","constraint":"^8.3"}]}]`
	if string(on["applications"]) != want {
		t.Fatalf("applications = %s\nwant %s", on["applications"], want)
	}
}

func TestNormalizeSortsDedupesAndCapsApplications(t *testing.T) {
	runtimes := make([]Runtime, MaxApplicationRuntimes+1)
	for i := range runtimes {
		runtimes[i] = Runtime{Name: fmt.Sprintf("runtime-%02d", i), Constraint: "*"}
	}
	inv := &Inventory{Applications: []Application{
		{Path: "/srv/b", Runtimes: runtimes},
		{Path: "relative/path", Name: "relative"},
		{Path: "/srv/a", Name: "first"},
		{Path: "/srv/a", Name: "second"},
		{Path: "/srv/" + strings.Repeat("c", 1024)},
	}}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	checkApplications(t, inv.Applications, []Application{
		{Path: "/srv/a", Name: "first"},
		{Path: "/srv/b", Runtimes: runtimes[:MaxApplicationRuntimes]},
	})

	inv = &Inventory{}
	for i := range MaxApplications + 5 {
		inv.Applications = append(inv.Applications, Application{Path: fmt.Sprintf("/srv/app-%04d", MaxApplications+5-i)})
	}
	if err := inv.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(inv.Applications) != MaxApplications || inv.Applications[0].Path != "/srv/app-0001" || inv.Applications[MaxApplications-1].Path != "/srv/app-1000" {
		t.Fatalf("%d applications from %s to %s, want the first %d by path", len(inv.Applications), inv.Applications[0].Path, inv.Applications[len(inv.Applications)-1].Path, MaxApplications)
	}
}

// A remote is sent only when no user or password can be left in it.
func TestRepositoryURLIsSentOnlyWithoutCredentials(t *testing.T) {
	for remote, want := range map[string]string{
		"https://github.com/acme/shop.git":                       "https://github.com/acme/shop.git",
		"https://token@github.com/acme/shop.git":                 "https://github.com/acme/shop.git",
		"https://user:pass@github.com/acme/shop.git":             "https://github.com/acme/shop.git",
		"https://user:p%40ss@github.com/acme/shop.git":           "https://github.com/acme/shop.git",
		"http://user:pass@git.acme.example:8080/acme/shop.git":   "http://git.acme.example:8080/acme/shop.git",
		"ssh://git@github.com/acme/shop.git":                     "ssh://github.com/acme/shop.git",
		"ssh://deploy:pass@git.acme.example:2222/acme/shop.git":  "ssh://git.acme.example:2222/acme/shop.git",
		"git://git.acme.example/acme/shop.git":                   "git://git.acme.example/acme/shop.git",
		"git@github.com:acme/shop.git":                           "git@github.com:acme/shop.git",
		"git.acme.example:/srv/git/shop.git":                     "git.acme.example:/srv/git/shop.git",
		"https://user:pa/ss@github.com/acme/shop.git":            "",
		"https://user:12/34@github.com/acme/shop.git":            "",
		"https://user:pa?ss@github.com/acme/shop.git":            "",
		"https://user:pa#ss@github.com/acme/shop.git":            "",
		"https://user:pa ss@github.com/acme/shop.git":            "",
		"https://github.com/acme/shop.git?access_token=secret":   "",
		"https://github.com/acme/shop.git#secret":                "",
		"https://github.com/acme/shop.git user:pass":             "",
		"https://user:pass@/acme/shop.git":                       "",
		"user:pass@github.com:acme/shop.git":                     "",
		"git@github.com:acme/shop.git?token=secret":              "",
		"ext::ssh -i /home/forge/.ssh/id_ed25519 git@github.com": "",
		"ftp://user:pass@ftp.acme.example/shop.git":              "",
		"file:///srv/git/shop.git":                               "",
		"/srv/git/shop.git":                                      "",
		"../shop.git":                                            "",
		"":                                                       "",
	} {
		if got := repositoryURL(remote); got != want {
			t.Errorf("repositoryURL(%q) = %q, want %q", remote, got, want)
		}
	}
}

// The url of [remote "origin"] is read as git reads it, or not at all.
func TestOriginURLReadsOnlyWhatGitWouldRead(t *testing.T) {
	for config, want := range map[string]string{
		"[remote \"origin\"]\n\turl = https://github.com/acme/shop.git\n":                                  "https://github.com/acme/shop.git",
		"[REMOTE \"origin\"]\n\tURL=https://github.com/acme/shop.git\r\n":                                  "https://github.com/acme/shop.git",
		"[remote \"origin\"] url = https://github.com/acme/shop.git\n":                                     "https://github.com/acme/shop.git",
		"[remote \"origin\"]\n\turl = \"https://github.com/acme/shop.git\"\n":                              "https://github.com/acme/shop.git",
		"[remote \"origin\"]\n\turl = https://github.com/acme/a.git\n\turl = https://github.com/acme/b\n":  "https://github.com/acme/a.git",
		"[remote \"upstream\"]\n\turl = https://github.com/acme/shop.git\n":                                "",
		"[remote \"Origin\"]\n\turl = https://github.com/acme/shop.git\n":                                  "",
		"[remote \"origin\"]\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[core]\n\turl = https://x\n":  "",
		"[remote \"origin\"]\n\turl = https://github.com/acme/shop.git # https://user:pass@github.com\n":   "",
		"[remote \"origin\"]\n\turl = https://github.com/acme/shop.git ; note\n":                           "",
		"[remote \"origin\"]\n\turl = \"https://github.com/acme/\\\"shop.git\"\n":                          "",
		"[remote \"origin\"]\n\turl = https://github.com/acme/\\\n\tshop.git\n":                            "",
		"[remote \"origin\"]\n\turl = \"https://github.com/acme/shop.git\" \"https://user:pass@x.test\"\n": "",
		"[remote \"origin\"]\n\turl\n": "",
		"":                             "",
	} {
		if got := originURL([]byte(config)); got != want {
			t.Errorf("originURL(%q) = %q, want %q", config, got, want)
		}
	}
}
