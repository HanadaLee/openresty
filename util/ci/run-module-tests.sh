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

weighttp_revision=7eb9b9cd125eaf505bfbc1c8ba1c5dafed1092e0
git clone "https://${git_mirror}/lighttpd/weighttp.git" "$harness_root/weighttp"
git -C "$harness_root/weighttp" checkout --detach "$weighttp_revision"

# Use the builder's installed binary and original module checkouts, not another
# clone of their moving branches. Test dependencies never enter release images.
docker run --rm --init \
    --env http_proxy --env https_proxy --env no_proxy \
    --env HTTP_PROXY --env HTTPS_PROXY --env NO_PROXY \
    --volume "$repository_root/util/run-module-tests.sh:/input/run-module-tests.sh:ro" \
    --volume "$harness_root:/input/harnesses:ro" \
    --volume "$repository_root/t/patches:/input/test-patches:ro" \
    "$test_image" \
    bash -c '
        set -euo pipefail
        apt-get -o APT::Update::Error-Mode=any update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            perl brotli zstd meson ninja-build libev-dev libcryptx-perl \
            libtest-base-perl libtext-diff-perl libtest-longstring-perl \
            libwww-perl libipc-run-perl libio-socket-ssl-perl liburi-perl \
            liblist-moreutils-perl libnet-dns-perl \
            libimage-magick-perl libbarcode-zbar-perl
        meson setup /test-weighttp-build /input/harnesses/weighttp
        meson compile -C /test-weighttp-build -j 2
        export PATH="/test-weighttp-build/src:$PATH"
        command -v weighttp
        perl -MCrypt::Misc -e '\''die "CryptX 0.067 or newer is required\n" if $Crypt::Misc::VERSION < 0.067'\''

        resty_version="$(cat /build/openresty-version)"
        export NGINX_SOURCE="/build/openresty-${resty_version}/build/nginx-${resty_version%.*}"
        export NGINX_BUILD_DIR="$NGINX_SOURCE/objs"

        patch --batch --forward --fuzz=0 -p1 -d /build/modules/ngx_lua_resty_lmdb_module \
            < /input/test-patches/lua-resty-lmdb-prefix-tests.patch
        unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
        export NO_PROXY="*" no_proxy="*"
        TEST_NGINX_BINARY=/usr/local/openresty/sbin/nginx \
            TEST_NGINX_ROOT=/input/harnesses/test-nginx \
            NGINX_TESTS_ROOT=/input/harnesses/nginx-tests \
            bash /input/run-module-tests.sh /build/modules
    '
