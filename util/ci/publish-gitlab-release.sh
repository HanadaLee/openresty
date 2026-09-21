#!/usr/bin/env bash

set -euo pipefail

version="${1:-}"
notes_file="${2:-release-notes.md}"
gitlab_api_url="${GITLAB_API_URL:-https://git.hanada.info/api/v4}"
gitlab_project_id="${GITLAB_PROJECT_ID:-22}"
gitlab_push_token="${GITLAB_PUSH_TOKEN:-}"

if [[ -z "$version" ]]; then
    echo "Usage: $0 <version> [notes-file]" >&2
    exit 2
fi

if [[ -z "$gitlab_push_token" ]]; then
    echo "GITLAB_PUSH_TOKEN is required" >&2
    exit 2
fi

if [[ ! -f "$notes_file" ]]; then
    echo "Release notes file not found: ${notes_file}" >&2
    exit 2
fi

release_url="${gitlab_api_url}/projects/${gitlab_project_id}/releases/${version}"
release_status="$(
    curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --header "PRIVATE-TOKEN: ${gitlab_push_token}" \
        "$release_url"
)"

case "$release_status" in
    200)
        curl --fail-with-body --silent --show-error \
            --request PUT \
            --header "PRIVATE-TOKEN: ${gitlab_push_token}" \
            --data-urlencode "name=${version}" \
            --data-urlencode "description@${notes_file}" \
            "$release_url" >/dev/null
        echo "Updated GitLab release ${version}"
        ;;

    404)
        curl --fail-with-body --silent --show-error \
            --request POST \
            --header "PRIVATE-TOKEN: ${gitlab_push_token}" \
            --data-urlencode "name=${version}" \
            --data-urlencode "tag_name=${version}" \
            --data-urlencode "description@${notes_file}" \
            "${gitlab_api_url}/projects/${gitlab_project_id}/releases" \
            >/dev/null
        echo "Published GitLab release ${version}"
        ;;

    *)
        echo "Failed to query GitLab release ${version}: HTTP ${release_status}" >&2
        exit 1
        ;;
esac
