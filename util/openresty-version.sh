#!/usr/bin/env bash

set -euo pipefail

dockerfile="${1:-Dockerfile}"

read_arg() {
    local name="$1"

    sed -n "s/^ARG ${name}=\"\([^\"]*\)\"[[:space:]]*$/\1/p" \
        "$dockerfile" | head -n 1
}

# Keep compatibility with older revisions so CI can compare a migration
# commit with a parent that still pinned RESTY_VERSION directly.
version="$(read_arg RESTY_VERSION)"
if [[ -n "$version" ]]; then
    printf '%s\n' "$version"
    exit 0
fi

git_mirror="$(read_arg RESTY_GIT_MIRROR)"
repository="$(read_arg RESTY_REPOSITORY)"
commit="$(read_arg RESTY_COMMIT)"

if [[ -z "$repository" || -z "$commit" ]]; then
    echo "Failed to read the pinned OpenResty repository and commit from $dockerfile" >&2
    exit 1
fi

if [[ "$repository" == *'${RESTY_GIT_MIRROR}'* ]]; then
    if [[ -z "$git_mirror" ]]; then
        echo "Failed to read RESTY_GIT_MIRROR from $dockerfile" >&2
        exit 1
    fi

    repository="${repository//'${RESTY_GIT_MIRROR}'/$git_mirror}"
fi

if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Invalid OpenResty commit in $dockerfile: $commit" >&2
    exit 1
fi

checkout="$(mktemp -d)"
trap 'rm -rf "$checkout"' EXIT

git -C "$checkout" init --quiet
git -C "$checkout" remote add origin "$repository"
git -C "$checkout" fetch --quiet --depth=1 origin "$commit"

resolved="$(git -C "$checkout" rev-parse FETCH_HEAD)"
if [[ "$resolved" != "$commit" ]]; then
    echo "Resolved OpenResty commit $resolved does not match $commit" >&2
    exit 1
fi

git -C "$checkout" show "${resolved}:util/ver" > "$checkout/ver"
version="$(bash "$checkout/ver")"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid version from OpenResty util/ver: $version" >&2
    exit 1
fi

printf '%s\n' "$version"
