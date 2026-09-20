#!/usr/bin/env bash

set -euo pipefail

version="${1:-}"
architecture="${2:-}"

if [[ -z "$version" || -z "$architecture" ]]; then
    echo "Usage: $0 <version> <architecture>" >&2
    exit 2
fi

: "${HARBOR_IMAGE:?HARBOR_IMAGE is required}"
: "${DOCKERHUB_IMAGE:?DOCKERHUB_IMAGE is required}"
: "${GHCR_IMAGE:?GHCR_IMAGE is required}"

for image in "$HARBOR_IMAGE" "$DOCKERHUB_IMAGE" "$GHCR_IMAGE"; do
    docker push "${image}:${version}-${architecture}"
done
