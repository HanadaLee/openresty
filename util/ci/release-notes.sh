#!/usr/bin/env bash

set -euo pipefail

commit="${1:-}"
version="${2:-}"
output="${3:-release-notes.md}"

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

if [[ -n "$previous_tag" ]]; then
    {
        echo "Changes since \`${previous_tag}\`:"
        echo
        git -C "$repository_root" log --no-merges \
            --pretty=format:'- %s (`%h`)' "${previous_tag}..${commit}"
        echo
    } > "$output"
else
    {
        echo "Changes through \`${commit}\`:"
        echo
        git -C "$repository_root" log --no-merges \
            --pretty=format:'- %s (`%h`)' "$commit"
        echo
    } > "$output"
fi
