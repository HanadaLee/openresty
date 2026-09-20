#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
dockerfile="${1:-$repository_root/Dockerfile}"
event_name="${EVENT_NAME:-}"
before_sha="${BEFORE_SHA:-}"
remote="${GIT_REMOTE:-origin}"
zero_sha="0000000000000000000000000000000000000000"

read_release() {
    sed -n 's/^ARG RESTY_RELEASE="\([^"]*\)"[[:space:]]*$/\1/p' "$1" |
        head -n 1
}

read_version_at() {
    local ref="$1"
    local historical_dockerfile
    local resty_version
    local resty_release

    historical_dockerfile="$(mktemp)"
    if ! git -C "$repository_root" show "${ref}:Dockerfile" > "$historical_dockerfile"; then
        rm -f "$historical_dockerfile"
        return 1
    fi

    if ! resty_version="$(bash "$script_dir/../openresty-version.sh" \
        "$historical_dockerfile")"; then
        rm -f "$historical_dockerfile"
        return 1
    fi

    resty_release="$(read_release "$historical_dockerfile")"
    rm -f "$historical_dockerfile"

    if [[ -z "$resty_version" || -z "$resty_release" ]]; then
        echo "Failed to read version from ${ref}:Dockerfile" >&2
        return 1
    fi

    printf '%s.%s\n' "$resty_version" "$resty_release"
}

resty_version="$(bash "$script_dir/../openresty-version.sh" "$dockerfile")"
resty_release="$(read_release "$dockerfile")"
version="${resty_version}.${resty_release}"

if [[ -z "$resty_version" || -z "$resty_release" ]]; then
    echo "Failed to resolve RESTY_VERSION or RESTY_RELEASE" >&2
    exit 1
fi

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid resolved version: $version" >&2
    exit 1
fi

release_needed=false
git -C "$repository_root" fetch --force --tags "$remote"

if git -C "$repository_root" rev-parse -q \
    --verify "refs/tags/${version}" >/dev/null; then
    echo "Version ${version} is already tagged; running tests only." >&2
elif [[ "$event_name" == "push" &&
        -n "$before_sha" &&
        "$before_sha" != "$zero_sha" ]]; then
    if ! git -C "$repository_root" cat-file -e \
        "${before_sha}^{commit}" 2>/dev/null; then
        git -C "$repository_root" fetch --no-tags "$remote" "$before_sha"
    fi

    previous_version="$(read_version_at "$before_sha")"
    if [[ "$version" != "$previous_version" ]]; then
        release_needed=true
    else
        echo "Version remains ${version}; running tests only." >&2
    fi
else
    release_needed=true
fi

printf 'RESTY_VERSION=%s\n' "$resty_version"
printf 'RESTY_RELEASE=%s\n' "$resty_release"
printf 'VERSION=%s\n' "$version"
printf 'RELEASE_NEEDED=%s\n' "$release_needed"
