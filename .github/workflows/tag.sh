#!/bin/sh
# Tags a commit of main with the next version. The tag push starts release.yml.
# Usage: tag.sh <commit sha> [patch|minor|major]
set -eu

sha="$1"
bump="${2:-patch}"

case "$bump" in
patch | minor | major) ;;
*)
	echo "unknown version bump: $bump" >&2
	exit 1
	;;
esac

git cat-file -e "$sha^{commit}"

# workflow_run filters on the name of a ref, which is no proof that the commit was merged.
if ! git merge-base --is-ancestor "$sha" refs/remotes/origin/main; then
	echo "$sha is not on main, refusing to release it" >&2
	exit 1
fi

latest=$(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t . -k 1.2,1n -k 2,2n -k 3,3n | tail -n 1 || true)

if [ -n "$latest" ] && git merge-base --is-ancestor "$sha" "$latest"; then
	# A minor or major release may promote the commit of the latest patch, never an older one.
	if [ "$bump" = patch ] || [ "$(git rev-parse "$sha^{commit}")" != "$(git rev-parse "$latest^{commit}")" ]; then
		echo "$sha is already in $latest, nothing to release"
		exit 0
	fi
fi

if [ -z "$latest" ]; then
	next="v0.1.0"
else
	major=$(echo "${latest#v}" | cut -d . -f 1)
	minor=$(echo "$latest" | cut -d . -f 2)
	patch=$(echo "$latest" | cut -d . -f 3)
	case "$bump" in
	patch) next="v$major.$minor.$((patch + 1))" ;;
	minor) next="v$major.$((minor + 1)).0" ;;
	major) next="v$((major + 1)).0.0" ;;
	esac
fi

git tag "$next" "$sha"
git push origin "refs/tags/$next"
echo "tagged $sha as $next"
