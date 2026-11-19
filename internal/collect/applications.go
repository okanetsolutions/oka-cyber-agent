package collect

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/okanetsolutions/oka-cyber-agent/internal/safeopen"
)

const (
	gitBranchPrefix = "refs/heads/"

	// reasonExcluded is what detailFile answers for a file exclude_paths names. It is never sent.
	reasonExcluded = "excluded"
)

var (
	errExcluded = errors.New("excluded")

	// A remote helper or an unknown transport (ext::, a custom scheme) can carry anything in its address, so only
	// the transports whose address is a plain URL are reported.
	repositorySchemes = []string{"http", "https", "ssh", "git"}

	// scpLikeRepository is the [user@]host:path form of an SSH remote, which has no place for a password. The
	// strict character set keeps out anything that could hide one, such as a second "@" or ":".
	scpLikeRepository = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9.-]+:[A-Za-z0-9._~/+-]+$`)
)

// application records what the directory dir, reported at hostDir, says about the application the agent parsed a
// lock file of: the name and runtime requirements its composer.json and package.json declare, and the origin
// remote, branch and commit of its .git directory. It opens those two manifests and, under .git, only HEAD,
// config, the one ref file HEAD names and packed-refs. Each is opened like a lock file (see read), an excluded one
// is never opened, and one that is missing, too large or unreadable only leaves its fields out.
func (s *scan) application(dir *os.File, hostDir string) {
	composer, node := s.manifest(dir, hostDir, "composer.json"), s.manifest(dir, hostDir, "package.json")
	app := Application{Path: hostDir, Name: cmp.Or(detail(text(composer.Name), MaxApplicationFieldLength), detail(text(node.Name), MaxApplicationFieldLength))}
	for _, runtime := range []Runtime{{"php", text(composer.Require["php"])}, {"node", text(node.Engines["node"])}} {
		if runtime.Constraint = detail(runtime.Constraint, MaxApplicationFieldLength); runtime.Constraint != "" {
			app.Runtimes = append(app.Runtimes, runtime)
		}
	}
	gitPath := path.Join(hostDir, ".git")
	// O_DIRECTORY and safeopen.OpenAt's O_NOFOLLOW refuse a .git that is a symlink or a gitfile (a worktree or a
	// submodule): the repository they point to lies somewhere the walk did not reach.
	if git, err := s.detailDirectory(dir, gitPath, ".git"); err == nil {
		defer git.Close()
		config, _ := s.detailFile(git, gitPath, "config")
		app.Repository = repositoryURL(originURL(config))
		app.Branch, app.Commit = s.gitHead(git, gitPath)
	}
	s.inv.Applications = append(s.inv.Applications, app)
}

// detailFile reads the file name of dir, a directory reported at hostDir, with the checks of a lock file, unless
// exclude_paths names it. The reason is empty when it was read (see read).
func (s *scan) detailFile(dir *os.File, hostDir, name string) ([]byte, string) {
	if isExcluded(path.Join(hostDir, name), s.options.ExcludePaths) || s.isExcludedName(dir, name) {
		return nil, reasonExcluded
	}
	return s.read(dir, name)
}

// detailDirectory opens the directory name of parent, reported at hostPath, without following a symlink and
// unless exclude_paths names it. It is only used for .git and the directories of the ref file HEAD names, which
// are never listed.
func (s *scan) detailDirectory(parent *os.File, hostPath, name string) (*os.File, error) {
	if isExcluded(hostPath, s.options.ExcludePaths) || s.isExcludedName(parent, name) {
		return nil, errExcluded
	}
	dir, err := safeopen.OpenAt(parent, name, os.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	if info, err := dir.Stat(); err != nil || s.isExcludedFile(info) {
		dir.Close()
		return nil, errExcluded
	}
	return dir, nil
}

// isExcludedName tells whether name in dir is one of the excluded files or directories, looking it up without
// opening it, as isExcludedEntry does for an entry the walk listed.
func (s *scan) isExcludedName(dir *os.File, name string) bool {
	if len(s.excluded) == 0 {
		return false
	}
	info, err := os.Lstat(filepath.Join(dir.Name(), name))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return err != nil || s.isExcludedFile(info)
}

// manifest is what the agent reads of a composer.json or package.json: the declared name and the runtime
// requirement (require.php in composer.json, engines.node in package.json).
type manifest struct {
	Name    any            `json:"name"`
	Require map[string]any `json:"require"`
	Engines map[string]any `json:"engines"`
}

// manifest reads the manifest name of dir. One that is missing or is not JSON gives nothing, and a key of another
// type than expected (PHP writes an empty require as []) is left out without losing the others.
func (s *scan) manifest(dir *os.File, hostDir, name string) manifest {
	data, _ := s.detailFile(dir, hostDir, name)
	var m manifest
	var wrongType *json.UnmarshalTypeError
	if err := json.Unmarshal(data, &m); err != nil && !errors.As(err, &wrongType) {
		return manifest{}
	}
	return m
}

func text(value any) string {
	s, _ := value.(string)
	return s
}

// detail returns a value read from a file of the application when the server accepts it. A longer one is left out
// rather than cut, because a cut repository, branch or version constraint would name something else.
func detail(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return ""
	}
	return value
}

// originURL finds the url of [remote "origin"] in a git config file, the first one as git fetches from it. It
// accepts a value written plainly or as one quoted string, which is how git itself writes them. A value with an
// escape, a comment or a quote elsewhere gives nothing: reading it differently from git could leave a credential
// where repositoryURL does not look for it.
func originURL(config []byte) string {
	inOrigin := false
	for line := range strings.Lines(string(config)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			header, rest, _ := strings.Cut(line[1:], "]")
			section := strings.Fields(header)
			inOrigin = len(section) == 2 && strings.EqualFold(section[0], "remote") && section[1] == `"origin"`
			line = strings.TrimSpace(rest)
		}
		key, value, hasValue := strings.Cut(line, "=")
		if !inOrigin || !hasValue || !strings.EqualFold(strings.TrimSpace(key), "url") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		} else if strings.ContainsAny(value, "#;") {
			return ""
		}
		if strings.ContainsAny(value, `"\`) {
			return ""
		}
		return value
	}
	return ""
}

// repositoryURL returns the remote URL without the user and password it may carry, or nothing when it cannot be
// sure it removed them. An http, https, ssh or git URL loses its user information, and is not sent when it has a
// query or a fragment, or when an "@" is left after that: a password with an unescaped "/", "?" or "#" ends the
// host early and leaves the rest of the credentials in the path. The scp form of an SSH remote
// (git@host:org/repo.git) is sent as it is. Anything else, a local path included, is not sent.
func repositoryURL(remote string) string {
	if !strings.Contains(remote, "://") {
		if !scpLikeRepository.MatchString(remote) {
			return ""
		}
		return detail(remote, MaxRepositoryLength)
	}
	u, err := url.Parse(remote)
	if err != nil || strings.ContainsFunc(remote, unicode.IsSpace) || !slices.Contains(repositorySchemes, u.Scheme) || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return ""
	}
	u.User = nil
	clean := u.String()
	if strings.Contains(clean, "@") {
		return ""
	}
	return detail(clean, MaxRepositoryLength)
}

// gitHead reads the branch and the commit HEAD names in the open .git directory git, reported at gitPath. HEAD
// holds either a commit (a detached HEAD, which has no branch) or the name of a branch ref, whose commit is in
// the ref file of that name or, once git packed the refs, in packed-refs.
func (s *scan) gitHead(git *os.File, gitPath string) (branch, commit string) {
	data, _ := s.detailFile(git, gitPath, "HEAD")
	head := strings.TrimSpace(string(data))
	ref, isRef := strings.CutPrefix(head, "ref:")
	if !isRef {
		return "", commitID(head)
	}
	ref = strings.TrimSpace(ref)
	branch, isBranch := strings.CutPrefix(ref, gitBranchPrefix)
	if !isBranch || !validRef(ref) || detail(branch, MaxApplicationFieldLength) == "" {
		return "", ""
	}
	commit, missing := s.looseRef(git, gitPath, ref)
	if missing {
		packed, _ := s.detailFile(git, gitPath, "packed-refs")
		commit = packedRef(packed, ref)
	}
	return branch, commit
}

// validRef accepts a ref name whose path stays inside .git: no empty, "." or ".." component (git allows none
// that starts with a dot), and none of the characters git forbids in every ref name.
func validRef(ref string) bool {
	for name := range strings.SplitSeq(ref, "/") {
		if name == "" || strings.HasPrefix(name, ".") {
			return false
		}
	}
	return !strings.ContainsFunc(ref, func(r rune) bool { return r <= 0x20 || r == 0x7f || r == '\\' })
}

// looseRef reads the commit in the ref file HEAD names. It opens each directory of the ref name relative to its
// parent without following a symlink and never lists one. missing is true when there is no such file, which is
// when git reads the ref from packed-refs instead.
func (s *scan) looseRef(git *os.File, gitPath, ref string) (commit string, missing bool) {
	directories, file := path.Split(ref)
	dir, hostPath := git, gitPath
	defer func() {
		if dir != git {
			dir.Close()
		}
	}()
	for name := range strings.SplitSeq(strings.TrimSuffix(directories, "/"), "/") {
		hostPath = path.Join(hostPath, name)
		next, err := s.detailDirectory(dir, hostPath, name)
		if err != nil {
			return "", errors.Is(err, fs.ErrNotExist)
		}
		if dir != git {
			dir.Close()
		}
		dir = next
	}
	data, reason := s.detailFile(dir, hostPath, file)
	if reason != "" {
		return "", reason == ReasonNotFound
	}
	return commitID(strings.TrimSpace(string(data))), false
}

// packedRef finds the commit of ref in a packed-refs file, whose lines are "<commit> <ref name>".
func packedRef(packed []byte, ref string) string {
	for line := range bytes.Lines(packed) {
		id, name, found := bytes.Cut(bytes.TrimSpace(line), []byte(" "))
		if found && string(name) == ref {
			return commitID(string(id))
		}
	}
	return ""
}

// commitID accepts an object name as git writes it: 40 hexadecimal characters, or 64 in a SHA-256 repository.
func commitID(id string) string {
	if len(id) != 40 && len(id) != 64 {
		return ""
	}
	for _, c := range []byte(id) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return id
}
