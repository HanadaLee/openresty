#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
dockerfile="${1:-$repository_root/Dockerfile}"
remote="${GIT_REMOTE:-origin}"
gitlab_repository="${GITLAB_REPOSITORY:-https://git.hanada.info/hanada/openresty.git}"

read_release() {
    sed -n 's/^ARG RESTY_RELEASE="\([^"]*\)"[[:space:]]*$/\1/p' "$1" |
        head -n 1
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
publish_images=false
release_commit="$(git -C "$repository_root" rev-parse --verify HEAD)"
git -C "$repository_root" fetch --force --tags "$remote"

tag_commit="$(git -C "$repository_root" rev-parse -q \
    --verify "refs/tags/${version}^{commit}" || true)"

if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    # GitLab's tag may exist before the GitHub mirror has synchronized it.
    gitlab_refs="$(git ls-remote "$gitlab_repository" \
        "refs/tags/${version}" "refs/tags/${version}^{}")"
    gitlab_commit="$(awk '
        $2 ~ /\^\{\}$/ { peeled = $1 }
        $2 !~ /\^\{\}$/ { direct = $1 }
        END { print peeled != "" ? peeled : direct }
    ' <<< "$gitlab_refs")"

    if [[ -n "$tag_commit" && -n "$gitlab_commit" &&
          "$tag_commit" != "$gitlab_commit" ]]; then
        echo "GitHub and GitLab tags disagree for ${version}; refusing to publish." >&2
        exit 1
    fi
    tag_commit="${tag_commit:-$gitlab_commit}"
    release_state="$(bash "$script_dir/github-release-state.sh" "$version")"
elif [[ -n "$tag_commit" ]]; then
    # Preserve tag-based operation for callers outside GitHub Actions.
    release_state=published
else
    release_state=missing
fi

if [[ "$release_state" == published ]]; then
    echo "Version ${version} is already published; running tests only." >&2
elif [[ -n "$tag_commit" ]]; then
    # Tags are created only after manifests. Resume metadata publication at
    # the original commit without moving the tag or rebuilding its images.
    release_needed=true
    release_commit="$tag_commit"
    echo "Version ${version} is tagged but not published; repairing releases at ${release_commit}." >&2
else
    release_needed=true
    publish_images=true
    echo "Version ${version} is not tagged; building and publishing it, including same-version retries." >&2
fi

printf 'RESTY_VERSION=%s\n' "$resty_version"
printf 'RESTY_RELEASE=%s\n' "$resty_release"
printf 'VERSION=%s\n' "$version"
printf 'RELEASE_NEEDED=%s\n' "$release_needed"
printf 'PUBLISH_IMAGES=%s\n' "$publish_images"
printf 'RELEASE_COMMIT=%s\n' "$release_commit"
