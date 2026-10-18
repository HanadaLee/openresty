#!/usr/bin/env bash

set -euo pipefail

test_image="${1:?Usage: run-module-tests.sh <builder-image>}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
git_mirror="${RESTY_GIT_MIRROR:-github.com}"
harness_root="$(mktemp -d)"
trap 'rm -rf "$harness_root"' EXIT

git clone --depth=1 "https://${git_mirror}/openresty/test-nginx.git" \
    "$harness_root/test-nginx"
git clone --depth=1 "https://${git_mirror}/nginx/nginx-tests.git" \
    "$harness_root/nginx-tests"

# Use the builder's installed binary and original module checkouts, not another
# clone of their moving branches. Test dependencies never enter release images.
docker run --rm --init \
    --volume "$repository_root/util/run-module-tests.sh:/input/run-module-tests.sh:ro" \
    --volume "$harness_root:/input/harnesses:ro" \
    "$test_image" \
    bash -c '
        set -euo pipefail
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            perl \
            brotli \
            zstd \
            libtest-base-perl \
            libtext-diff-perl \
            libtest-longstring-perl \
            libwww-perl \
            libipc-run-perl \
            libio-socket-ssl-perl \
            liburi-perl \
            liblist-moreutils-perl \
            libnet-dns-perl \
            libimage-magick-perl \
            libbarcode-zbar-perl

        resty_version="$(cat /build/openresty-version)"
        export NGINX_SOURCE="/build/openresty-${resty_version}/build/nginx-${resty_version%.*}"
        export NGINX_BUILD_DIR="$NGINX_SOURCE/objs"

        TEST_NGINX_BINARY=/usr/local/openresty/sbin/nginx \
            TEST_NGINX_ROOT=/input/harnesses/test-nginx \
            NGINX_TESTS_ROOT=/input/harnesses/nginx-tests \
            bash /input/run-module-tests.sh /build/modules
    '
