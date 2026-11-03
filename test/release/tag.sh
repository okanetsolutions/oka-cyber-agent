#!/bin/sh
# Tests .github/workflows/tag.sh against a scratch repository and a stub gh.
set -eu

script="$(cd "$(dirname "$0")/../.." && pwd)/.github/workflows/tag.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git init -q --bare "$work/remote.git"
git init -q "$work/repo"
cd "$work/repo"
git config user.email test@example.invalid
git config user.name test
git remote add origin "$work/remote.git"

cat > "$work/gh" <<'STUB'
#!/bin/sh
echo "$*" >> "$GH_LOG"
STUB
chmod +x "$work/gh"
export GH="$work/gh" GH_LOG="$work/gh.log"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

commit() {
	git commit -q --allow-empty -m "$1"
	git rev-parse HEAD
}

expect_tag() {
	got=$(git ls-remote --tags origin "refs/tags/$1" | cut -f 1)
	[ "$got" = "$2" ] || fail "expected $1 at $2 on the remote, got '$got'"
	tail -n 1 "$GH_LOG" | grep -qx "workflow run release.yml --ref $1" || fail "release.yml not dispatched on $1"
}

first=$(commit first)
sh "$script" "$first" >/dev/null
expect_tag v0.1.0 "$first"

second=$(commit second)
sh "$script" "$second" >/dev/null
expect_tag v0.1.1 "$second"

# A commit already contained in the latest tag is not released again.
calls=$(wc -l < "$GH_LOG")
sh "$script" "$first" >/dev/null
sh "$script" "$second" >/dev/null
[ "$(wc -l < "$GH_LOG")" = "$calls" ] || fail "an already released commit was released again"
[ "$(git tag | wc -l)" -eq 2 ] || fail "an already released commit was tagged again"

# Versions compare numerically, a hand made minor release is continued and other tags are ignored.
git tag v0.1.9 "$second"
git tag v0.1.10 "$second"
third=$(commit third)
git tag v0.2.0 "$third"
git tag v0.3.0-rc1 "$third"
git tag latest "$third"
fourth=$(commit fourth)
sh "$script" "$fourth" >/dev/null
expect_tag v0.2.1 "$fourth"

# A commit that is not in any tag but older than one is released on top of the latest version.
git checkout -q -b side "$first"
side=$(commit side)
sh "$script" "$side" >/dev/null
expect_tag v0.2.2 "$side"

echo "tag.sh: all tests passed"
