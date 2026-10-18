#!/usr/bin/env bash

set -euo pipefail

mode="${1:-}"
image="${2:-}"

if [[ "$mode" != "debug" && "$mode" != "production" ]] || [[ -z "$image" ]]; then
    echo "Usage: $0 <debug|production> <image>" >&2
    exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
source "$script_dir/test-run.sh"
init_test_run "verify-$mode"
run_test_phase nginx-version docker run --rm "$image" /usr/local/openresty/sbin/nginx -V
nginx_version="$(cat "$test_output/nginx-version.log")"

run_test_phase runtime-libraries docker run --rm "$image" \
    sh -c 'ldd /usr/local/openresty/lib/libvips.so.42'
vips_dependencies="$(cat "$test_output/runtime-libraries.log")"

validate_image() {
    if grep -Fq 'not found' <<< "$vips_dependencies"; then
        echo "libvips has unresolved runtime dependencies" >&2
        return 1
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
            return 1
        fi
    done

    if [[ "$mode" == "debug" ]]; then
        if ! grep -Fq -- '--with-debug' <<< "$nginx_version"; then
            echo "Debug image does not contain --with-debug" >&2
            return 1
        fi
    elif grep -Fq -- '--with-debug' <<< "$nginx_version"; then
        echo "Production image unexpectedly contains --with-debug" >&2
        return 1
    fi
}
run_test_phase validate-image validate_image
run_test_phase default-config docker run --rm "$image" /usr/local/openresty/sbin/nginx -t
