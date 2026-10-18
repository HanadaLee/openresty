#!/usr/bin/env bash

set -euo pipefail

test_image="${1:?Usage: run-module-tests.sh <builder-image>}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
source "$script_dir/test-run.sh"
init_test_run modules

# A read-only bind does not freeze files being edited on the host.
cp "$repository_root/util/run-module-tests.sh" "$test_snapshot/"
cp -a "$repository_root/t/patches" "$test_snapshot/test-patches"
mkdir -p "$test_snapshot/harnesses"
git_mirror="${RESTY_GIT_MIRROR:-github.com}"
weighttp_revision=7eb9b9cd125eaf505bfbc1c8ba1c5dafed1092e0
run_test_phase fetch-test-nginx git clone --depth=1 \
    "https://${git_mirror}/openresty/test-nginx.git" "$test_snapshot/harnesses/test-nginx"
run_test_phase fetch-nginx-tests git clone --depth=1 \
    "https://${git_mirror}/nginx/nginx-tests.git" "$test_snapshot/harnesses/nginx-tests"
run_test_phase fetch-weighttp git clone \
    "https://${git_mirror}/lighttpd/weighttp.git" "$test_snapshot/weighttp"
git -C "$test_snapshot/weighttp" checkout --detach "$weighttp_revision"
for dependency in harnesses/test-nginx harnesses/nginx-tests weighttp; do
    printf '%s %s\n' "$dependency" "$(git -C "$test_snapshot/$dependency" rev-parse HEAD)"
done > "$test_output/dependency-revisions.txt"
bash -n "$test_snapshot/run-module-tests.sh"
record_test_inputs

run_test_phase module-regressions docker run --rm --init \
    --env http_proxy --env https_proxy --env no_proxy \
    --env HTTP_PROXY --env HTTPS_PROXY --env NO_PROXY \
    --volume "$test_snapshot:/input:ro" \
    --volume "$test_output:/results" \
    "$test_image" bash -c '
        set -euo pipefail
        trap '\''rc=$?; chmod -R a+rX /results; exit "$rc"'\'' EXIT
        (cd /input && sha256sum -c /results/inputs.sha256) > /results/input-verification.log
        apt-get -o APT::Update::Error-Mode=any update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            perl brotli zstd meson ninja-build libev-dev libcryptx-perl \
            libtest-base-perl libtext-diff-perl libtest-longstring-perl \
            libwww-perl libipc-run-perl libio-socket-ssl-perl liburi-perl \
            liblist-moreutils-perl libnet-dns-perl \
            libimage-magick-perl libbarcode-zbar-perl
        meson setup /test-weighttp-build /input/weighttp
        meson compile -C /test-weighttp-build -j 2
        export PATH="/test-weighttp-build/src:$PATH"
        command -v weighttp
        perl -MCrypt::Misc -e '\''die "CryptX 0.067 or newer is required\n" if $Crypt::Misc::VERSION < 0.067'\''

        resty_version="$(cat /build/openresty-version)"
        export NGINX_SOURCE="/build/openresty-${resty_version}/build/nginx-${resty_version%.*}"
        export NGINX_BUILD_DIR="$NGINX_SOURCE/objs"
        /usr/local/openresty/sbin/nginx -V > /results/nginx-build.txt 2>&1
        sha256sum /usr/local/openresty/sbin/nginx > /results/nginx.sha256
        for module in /build/modules/*; do
            if [[ -e "$module/.git" ]]; then
                printf "%s %s\n" "${module##*/}" "$(git -C "$module" rev-parse HEAD)"
            fi
        done > /results/module-revisions.txt
        patch --batch --forward --fuzz=0 -p1 -d /build/modules/ngx_lua_resty_lmdb_module \
            < /input/test-patches/lua-resty-lmdb-prefix-tests.patch
        unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
        export NO_PROXY="*" no_proxy="*"
        export TEST_MODULE_OUTPUT=/results/suites
        TEST_NGINX_BINARY=/usr/local/openresty/sbin/nginx \
            TEST_NGINX_ROOT=/input/harnesses/test-nginx \
            NGINX_TESTS_ROOT=/input/harnesses/nginx-tests \
            bash /input/run-module-tests.sh /build/modules
    '
