#!/usr/bin/env bash

set -euo pipefail

case "$1 $2" in
    'api graphql')
        if [[ "${MOCK_GH_STATUS:-0}" != 0 ]]; then
            echo 'GitHub API request failed' >&2
            exit "$MOCK_GH_STATUS"
        fi
        printf '%s\n' "$MOCK_GH_RESPONSE"
        ;;
    'release create'|'release edit')
        printf '%s\n' "$*" >> "$MOCK_GH_CALLS"
        ;;
    *)
        echo "Unexpected gh command: $*" >&2
        exit 99
        ;;
esac
