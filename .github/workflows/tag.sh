#!/bin/sh
# Tags a commit of main with the next patch version and starts release.yml on that tag.
# Usage: tag.sh <commit sha>. GH overrides the gh command (tests pass a stub).
set -eu

sha="$1"
gh_cmd="${GH:-gh}"

git cat-file -e "$sha^{commit}"

latest=$(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t . -k 1.2,1n -k 2,2n -k 3,3n | tail -n 1 || true)

if [ -n "$latest" ] && git merge-base --is-ancestor "$sha" "$latest"; then
	echo "$sha is already in $latest, nothing to release"
	exit 0
fi

if [ -z "$latest" ]; then
	next="v0.1.0"
else
	major=$(echo "$latest" | cut -d . -f 1)
	minor=$(echo "$latest" | cut -d . -f 2)
	patch=$(echo "$latest" | cut -d . -f 3)
	next="$major.$minor.$((patch + 1))"
fi

git tag "$next" "$sha"
git push origin "refs/tags/$next"
echo "tagged $sha as $next"

"$gh_cmd" workflow run release.yml --ref "$next"
echo "started release.yml on $next"
