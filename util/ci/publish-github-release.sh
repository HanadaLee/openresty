#!/usr/bin/env bash

set -euo pipefail

version="${1:?Usage: $0 <version> <commit> [notes-file]}"
commit="${2:?Usage: $0 <version> <commit> [notes-file]}"
notes_file="${3:-release-notes.md}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

state="$(bash "$script_dir/github-release-state.sh" "$version")"
case "$state" in
    published)
        echo "GitHub release ${version} already published; leaving it unchanged"
        ;;
    draft)
        gh release edit "$version" --repo "$GITHUB_REPOSITORY" \
            --verify-tag --draft=false --title "$version" --notes-file "$notes_file"
        ;;
    missing)
        gh release create "$version" --repo "$GITHUB_REPOSITORY" \
            --verify-tag --target "$commit" --title "$version" --notes-file "$notes_file"
        ;;
esac
