#!/usr/bin/env bash

set -euo pipefail

mode="${1:-}"
image="${2:-}"

if [[ "$mode" != "debug" && "$mode" != "production" ]] || [[ -z "$image" ]]; then
    echo "Usage: $0 <debug|production> <image>" >&2
    exit 2
fi

nginx_version="$(
    docker run --rm "$image" /usr/local/openresty/sbin/nginx -V 2>&1
)"
printf '%s\n' "$nginx_version"

if [[ "$mode" == "debug" ]]; then
    if ! grep -Fq -- '--with-debug' <<< "$nginx_version"; then
        echo "Debug image does not contain --with-debug" >&2
        exit 1
    fi
elif grep -Fq -- '--with-debug' <<< "$nginx_version"; then
    echo "Production image unexpectedly contains --with-debug" >&2
    exit 1
fi
