#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Only the Git and GitHub boundary is mocked. No image build, remote mutation,
# or live credentials are needed to exercise release recovery decisions.
mkdir "$work/bin"
cp "$script_dir/fixtures/git.sh" "$work/bin/git"
cp "$script_dir/fixtures/gh.sh" "$work/bin/gh"
chmod +x "$work/bin/git" "$work/bin/gh"
export PATH="$work/bin:$PATH"
export GITHUB_REPOSITORY=example/openresty
export GITLAB_REPOSITORY=https://gitlab.invalid/example/openresty.git
export MOCK_HEAD=1111111111111111111111111111111111111111
tag_commit=2222222222222222222222222222222222222222
export MOCK_GH_CALLS="$work/gh-calls"
printf 'ARG RESTY_VERSION="1.31.6.1"\nARG RESTY_RELEASE="384"\n' > "$work/Dockerfile"
printf 'Release notes\n' > "$work/notes.md"

reset_state() {
    export MOCK_GITHUB_TAG= MOCK_GITLAB_TAG= MOCK_GITLAB_PEELED=
    export MOCK_GH_STATUS=0 MOCK_FETCH_STATUS=0 MOCK_GITLAB_STATUS=0
    export MOCK_GH_RESPONSE='{"data":{"repository":{"release":null}}}'
    export EVENT_NAME=push BEFORE_SHA=3333333333333333333333333333333333333333
    : > "$MOCK_GH_CALLS"
}

resolve() {
    bash "$repository_root/util/ci/resolve-version.sh" "$work/Dockerfile"
}

check_decision() {
    local name="$1" release="$2" images="$3" commit="$4" output
    output="$(resolve)"
    for expected in RESTY_RELEASE=384 VERSION=1.31.6.1.384 \
        "RELEASE_NEEDED=$release" "PUBLISH_IMAGES=$images" "RELEASE_COMMIT=$commit"; do
        if ! grep -Fxq "$expected" <<< "$output"; then
            printf 'FAIL: %s; missing %s\n%s\n' "$name" "$expected" "$output" >&2
            exit 1
        fi
    done
    echo "PASS: $name"
}

check_failure() {
    local name="$1"
    shift
    if "$@" > "$work/output" 2> "$work/error"; then
        echo "FAIL: $name unexpectedly succeeded" >&2
        exit 1
    fi
    if grep -q '^RELEASE_NEEDED=' "$work/output" || [[ -s "$MOCK_GH_CALLS" ]]; then
        echo "FAIL: $name allowed publication after an error" >&2
        exit 1
    fi
    echo "PASS: $name"
}

publish() {
    bash "$repository_root/util/ci/publish-github-release.sh" \
        1.31.6.1.384 "$tag_commit" "$work/notes.md"
}

reset_state
check_decision 'same-version push retries an untagged release' true true "$MOCK_HEAD"
EVENT_NAME=workflow_dispatch
check_decision 'manual CI also requests image and manifest publication' true true "$MOCK_HEAD"

reset_state
MOCK_GITHUB_TAG="$tag_commit"
MOCK_GITLAB_TAG="$tag_commit"
check_decision 'tag-only failure repairs metadata at the original commit' true false "$tag_commit"
MOCK_GH_RESPONSE='{"data":{"repository":{"release":{"isDraft":true}}}}'
check_decision 'a draft is not a completed release' true false "$tag_commit"
MOCK_GH_RESPONSE='{"data":{"repository":{"release":{"isDraft":false}}}}'
check_decision 'a published version runs tests only' false false "$MOCK_HEAD"

reset_state
MOCK_GH_RESPONSE='{"data":{"repository":{"release":{"isDraft":true}}}}'
check_decision 'an untagged draft still needs production images' true true "$MOCK_HEAD"

reset_state
MOCK_GITLAB_TAG="$tag_commit"
check_decision 'a GitLab-only tag prevents rebuilding published images' true false "$tag_commit"
MOCK_GITLAB_TAG=4444444444444444444444444444444444444444
MOCK_GITLAB_PEELED="$tag_commit"
check_decision 'an annotated GitLab tag resolves to its commit' true false "$tag_commit"
MOCK_GITHUB_TAG="$MOCK_HEAD"
check_failure 'conflicting tags stop publication' resolve

reset_state
MOCK_GH_STATUS=1
check_failure 'GitHub network or authorization failure is not an absent release' resolve
reset_state
MOCK_GH_RESPONSE='{"errors":[{"message":"query failed"}],"data":{"repository":null}}'
check_failure 'GraphQL errors stop publication' resolve
reset_state
MOCK_GH_RESPONSE='{"data":{"repository":{}}}'
check_failure 'missing response fields stop publication' resolve
reset_state
MOCK_GH_RESPONSE='invalid json'
check_failure 'invalid JSON stops publication' resolve
reset_state
MOCK_FETCH_STATUS=128
check_failure 'tag fetch failure stops publication' resolve
reset_state
MOCK_GITLAB_STATUS=128
check_failure 'GitLab network failure stops publication' resolve

reset_state
publish
grep -q '^release create 1.31.6.1.384 .*--verify-tag' "$MOCK_GH_CALLS"
echo 'PASS: a missing release is created against an existing tag'
reset_state
MOCK_GH_RESPONSE='{"data":{"repository":{"release":{"isDraft":true}}}}'
publish
grep -q '^release edit 1.31.6.1.384 .*--draft=false' "$MOCK_GH_CALLS"
echo 'PASS: a draft is published'
reset_state
MOCK_GH_RESPONSE='{"data":{"repository":{"release":{"isDraft":false}}}}'
publish
[[ ! -s "$MOCK_GH_CALLS" ]]
echo 'PASS: an existing published release is not edited'
reset_state
MOCK_GH_STATUS=1
check_failure 'release publication fails closed on API errors' publish
