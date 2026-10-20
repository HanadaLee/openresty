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
commit="$(git -C "$repository_root" rev-parse --verify "${commit}^{commit}")"
tags="$(git -C "$repository_root" tag --merged "$commit" --sort=-version:refname)"
previous_tag=""
while IFS= read -r tag; do
    [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    [[ "$tag" != "$version" ]] || continue
    if [[ "$(printf '%s\n%s\n' "$tag" "$version" | sort -V | tail -n 1)" == "$version" ]]; then
        previous_tag="$tag"
        break
    fi
done <<< "$tags"

module_changes="$(python3 "$script_dir/module-versions.py" \
    "$repository_root" "$previous_tag" "$commit")"

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
    if [[ -n "$module_changes" ]]; then
        printf '%s\n\n' "$module_changes"
    fi
    echo "## Container Images"
    echo
    echo "- \`${harbor_image}:${version}\`"
    echo "- \`${dockerhub_image}:${version}\`"
    echo "- \`${ghcr_image}:${version}\`"
} > "$output"
