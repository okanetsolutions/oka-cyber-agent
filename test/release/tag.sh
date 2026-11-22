#!/bin/sh
# Tests .github/workflows/tag.sh against a scratch repository.
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

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

commit() {
	git commit -q --allow-empty -m "$1"
	git rev-parse HEAD
}

merge_to_main() {
	git push -q origin "$1:refs/heads/main"
	git fetch -q origin
}

remote_tags() {
	git ls-remote --tags origin
}

expect_tag() {
	got=$(git ls-remote --tags origin "refs/tags/$1" | cut -f 1)
	[ "$got" = "$2" ] || fail "expected $1 at $2 on the remote, got '$got'"
}

first=$(commit first)
merge_to_main "$first"
sh "$script" "$first" >/dev/null
expect_tag v0.1.0 "$first"

second=$(commit second)
merge_to_main "$second"
sh "$script" "$second" >/dev/null
expect_tag v0.1.1 "$second"

# A commit already contained in the latest tag is not released again.
before=$(remote_tags)
sh "$script" "$first" >/dev/null
sh "$script" "$second" >/dev/null
[ "$(remote_tags)" = "$before" ] || fail "an already released commit was released again"
[ "$(git tag | wc -l)" -eq 2 ] || fail "an already released commit was tagged again"

# Versions compare numerically, an existing minor release is continued and other tags are ignored.
git tag v0.1.9 "$second"
git tag v0.1.10 "$second"
third=$(commit third)
merge_to_main "$third"
git tag v0.2.0 "$third"
git tag v0.3.0-rc1 "$third"
git tag latest "$third"
fourth=$(commit fourth)
merge_to_main "$fourth"
sh "$script" "$fourth" >/dev/null
expect_tag v0.2.1 "$fourth"

# A commit of main whose CI finishes after main moved on is still released.
fifth=$(commit fifth)
sixth=$(commit sixth)
merge_to_main "$sixth"
sh "$script" "$fifth" >/dev/null
expect_tag v0.2.2 "$fifth"

# A commit outside main is never released, whatever its branch is called or the bump is.
git checkout -q -b side "$first"
side=$(commit side)
git push -q origin "$side:refs/heads/side"
before=$(remote_tags)
for bump in patch minor major; do
	if sh "$script" "$side" "$bump" >/dev/null 2>&1; then
		fail "a commit outside main was released ($bump)"
	fi
done
if sh "$script" "$sixth" 1.2.3 >/dev/null 2>&1; then
	fail "an unknown bump was accepted"
fi
[ "$(remote_tags)" = "$before" ] || fail "a refused release left a tag"

# A minor or major release by hand takes the head of main, also when it is the latest patch release.
sh "$script" "$sixth" minor >/dev/null
expect_tag v0.3.0 "$sixth"
sh "$script" "$sixth" major >/dev/null
expect_tag v1.0.0 "$sixth"

# A bump never releases a commit older than the latest release.
before=$(remote_tags)
sh "$script" "$fifth" minor >/dev/null
[ "$(remote_tags)" = "$before" ] || fail "an older commit was promoted"

echo "tag.sh: all tests passed"
