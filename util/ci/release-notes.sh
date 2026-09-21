#!/usr/bin/env bash

set -euo pipefail

commit="${1:-}"
version="${2:-}"
output="${3:-release-notes.md}"
github_repository="${GITHUB_REPOSITORY:-HanadaLee/openresty}"
harbor_image="${HARBOR_IMAGE:-registry.hanada.info/openresty/openresty}"
dockerhub_image="${DOCKERHUB_IMAGE:-docker.io/hanadalee/openresty}"
ghcr_image="${GHCR_IMAGE:-ghcr.io/hanadalee/openresty}"

if [[ -z "$commit" || -z "$version" ]]; then
    echo "Usage: $0 <commit> <version> [output]" >&2
    exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
previous_tag="$(
    git -C "$repository_root" tag --merged "$commit" --sort=-version:refname |
        grep -Fvx "$version" | head -n 1 || true
)"

{
    echo "## What's Changed"
    echo

    if [[ -n "$previous_tag" ]]; then
        git -C "$repository_root" log --no-merges \
            --pretty=format:'- %s (`%h`)' "${previous_tag}..${commit}"
        echo
        echo
        echo "**Full Changelog**: https://github.com/${github_repository}/compare/${previous_tag}...${version}"
    else
        git -C "$repository_root" log --no-merges \
            --pretty=format:'- %s (`%h`)' "$commit"
        echo
        echo
        echo "**Full Changelog**: https://github.com/${github_repository}/commits/${version}"
    fi

    echo
    echo "## Container Images"
    echo
    echo "- \`${harbor_image}:${version}\`"
    echo "- \`${dockerhub_image}:${version}\`"
    echo "- \`${ghcr_image}:${version}\`"
} > "$output"
