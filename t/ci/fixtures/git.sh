#!/usr/bin/env bash

set -euo pipefail

if [[ "${1:-}" == -C ]]; then
    shift 2
fi

case "$1" in
    fetch)
        exit "${MOCK_FETCH_STATUS:-0}"
        ;;
    rev-parse)
        if [[ "${*: -1}" == HEAD ]]; then
            printf '%s\n' "$MOCK_HEAD"
        else
            [[ -n "${MOCK_GITHUB_TAG:-}" ]] || exit 1
            printf '%s\n' "$MOCK_GITHUB_TAG"
        fi
        ;;
    ls-remote)
        if [[ "${MOCK_GITLAB_STATUS:-0}" != 0 ]]; then
            exit "$MOCK_GITLAB_STATUS"
        fi
        if [[ -n "${MOCK_GITLAB_TAG:-}" ]]; then
            printf '%s\trefs/tags/1.31.6.1.384\n' "$MOCK_GITLAB_TAG"
        fi
        if [[ -n "${MOCK_GITLAB_PEELED:-}" ]]; then
            printf '%s\trefs/tags/1.31.6.1.384^{}\n' "$MOCK_GITLAB_PEELED"
        fi
        ;;
    *)
        echo "Unexpected git command: $*" >&2
        exit 99
        ;;
esac
