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

vips_dependencies="$(
    docker run --rm "$image" \
        sh -c 'ldd /usr/local/openresty/lib/libvips.so.42'
)"
printf '%s\n' "$vips_dependencies"

if grep -Fq 'not found' <<< "$vips_dependencies"; then
    echo "libvips has unresolved runtime dependencies" >&2
    exit 1
fi

for dependency in \
    libMagickCore-7.Q16.so.10 \
    libOpenEXR-3_1.so.30 \
    libheif.so.1 \
    libhwy.so.1 \
    libjxl.so.0.11 \
    libpoppler-glib.so.8 \
    librsvg-2.so.2 \
    libspng.so.0
do
    if ! grep -Fq "$dependency =>" <<< "$vips_dependencies"; then
        echo "libvips is missing expected dependency: $dependency" >&2
        exit 1
    fi
done

if [[ "$mode" == "debug" ]]; then
    if ! grep -Fq -- '--with-debug' <<< "$nginx_version"; then
        echo "Debug image does not contain --with-debug" >&2
        exit 1
    fi
elif grep -Fq -- '--with-debug' <<< "$nginx_version"; then
    echo "Production image unexpectedly contains --with-debug" >&2
    exit 1
fi
