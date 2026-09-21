#!/usr/bin/env bash

set -euo pipefail

commit="${1:-}"
version="${2:-}"
gitlab_repository="${GITLAB_REPOSITORY:-https://git.hanada.info/hanada/openresty.git}"
gitlab_push_username="${GITLAB_PUSH_USERNAME:-oauth2}"
gitlab_push_token="${GITLAB_PUSH_TOKEN:-}"

if [[ -z "$commit" || -z "$version" ]]; then
    echo "Usage: $0 <commit> <version>" >&2
    exit 2
fi

if [[ -z "$gitlab_push_token" ]]; then
    echo "GITLAB_PUSH_TOKEN is required" >&2
    exit 2
fi

if ! git check-ref-format "refs/tags/${version}"; then
    echo "Invalid release tag: ${version}" >&2
    exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
commit="$(git -C "$repository_root" rev-parse --verify "${commit}^{commit}")"

# GitLab is the canonical repository for release tags. Fetching its tags also
# ensures release notes use the canonical previous version even if the GitHub
# mirror has not synchronized yet.
git -C "$repository_root" fetch --force --tags "$gitlab_repository"

local_tag="$({
    git -C "$repository_root" rev-parse -q --verify \
        "refs/tags/${version}^{}" || true
} | head -n 1)"

if [[ -n "$local_tag" && "$local_tag" != "$commit" ]]; then
    echo "Local tag ${version} points to ${local_tag}, expected ${commit}" >&2
    exit 1
fi

if [[ -z "$local_tag" ]]; then
    git -C "$repository_root" tag "$version" "$commit"
fi

remote_tag="$({
    git ls-remote "$gitlab_repository" \
        "refs/tags/${version}" "refs/tags/${version}^{}" || true
} | awk '
    $2 ~ /\^\{\}$/ { peeled = $1 }
    $2 !~ /\^\{\}$/ { direct = $1 }
    END { print peeled != "" ? peeled : direct }
')"

if [[ -n "$remote_tag" ]]; then
    if [[ "$remote_tag" != "$commit" ]]; then
        echo "GitLab tag ${version} points to ${remote_tag}, expected ${commit}" >&2
        exit 1
    fi

    echo "GitLab tag ${version} already points to ${commit}"
    exit 0
fi

umask 077
askpass="$(mktemp)"
trap 'rm -f "$askpass"' EXIT

cat > "$askpass" <<'EOF'
#!/bin/sh

case "$1" in
    *Username*) printf '%s\n' "$GITLAB_PUSH_USERNAME" ;;
    *Password*) printf '%s\n' "$GITLAB_PUSH_TOKEN" ;;
    *) exit 1 ;;
esac
EOF
chmod 700 "$askpass"

export GITLAB_PUSH_TOKEN
export GITLAB_PUSH_USERNAME="$gitlab_push_username"
GIT_ASKPASS="$askpass" GIT_TERMINAL_PROMPT=0 \
    git -C "$repository_root" push "$gitlab_repository" \
        "refs/tags/${version}:refs/tags/${version}"

echo "Published GitLab tag ${version} at ${commit}"
