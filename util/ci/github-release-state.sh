#!/usr/bin/env bash

set -euo pipefail

version="${1:?Usage: $0 <version>}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must identify the GitHub repository}"

# GraphQL finds drafts by tag as well as published releases. API/authentication
# failures must fail the job, not be interpreted as a missing release.
response="$(gh api graphql \
    -f owner="${GITHUB_REPOSITORY%%/*}" \
    -f name="${GITHUB_REPOSITORY#*/}" \
    -f tag="$version" \
    -f query='query($owner: String!, $name: String!, $tag: String!) {
        repository(owner: $owner, name: $name) {
            release(tagName: $tag) { isDraft }
        }
    }')"

jq -er '
    if (.errors | length) > 0 or (.data.repository | type) != "object" then
        error("Failed to query GitHub release state")
    elif (.data.repository | has("release") | not) then
        error("Missing GitHub release state")
    elif .data.repository.release == null then "missing"
    elif .data.repository.release.isDraft == true then "draft"
    elif .data.repository.release.isDraft == false then "published"
    else error("Invalid GitHub release state")
    end
' <<< "$response"
