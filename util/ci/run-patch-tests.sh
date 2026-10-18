#!/usr/bin/env bash

set -euo pipefail

test_image="${1:?Usage: run-patch-tests.sh <test-image>}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
source "$script_dir/test-run.sh"
init_test_run patches
cp -a "$repository_root/t" "$test_snapshot/tests"
cp "$repository_root/util/run-tests.sh" "$test_snapshot/run-tests.sh"
git_mirror="${RESTY_GIT_MIRROR:-github.com}"
mkdir -p "$test_snapshot/harnesses"
for dependency in test-nginx nginx-tests; do
    owner=openresty
    [[ "$dependency" != nginx-tests ]] || owner=nginx
    run_test_phase "fetch-$dependency" git clone --depth=1 \
        "https://${git_mirror}/$owner/$dependency.git" "$test_snapshot/harnesses/$dependency"
    printf '%s %s\n' "$dependency" "$(git -C "$test_snapshot/harnesses/$dependency" rev-parse HEAD)" \
        >> "$test_output/dependency-revisions.txt"
done
bash -n "$test_snapshot/run-tests.sh"
record_test_inputs
run_test_phase patch-regressions docker run --rm --init \
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
            perl libtest-base-perl libtext-diff-perl libtest-longstring-perl \
            libwww-perl libipc-run-perl libio-socket-ssl-perl liburi-perl \
            liblist-moreutils-perl
        mkdir -p /test-work/tests /test-work/harnesses /results/tmp
        cp -a /input/tests/. /test-work/tests/
        cp -a /input/harnesses/. /test-work/harnesses/
        unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
        export NO_PROXY="*" no_proxy="*"
        export TMPDIR=/results/tmp TEST_NGINX_LEAVE=1
        TEST_NGINX_BINARY=/usr/local/openresty/sbin/nginx \
            TEST_NGINX_ROOT=/test-work/harnesses/test-nginx \
            NGINX_TESTS_ROOT=/test-work/harnesses/nginx-tests \
            TEST_ROOT=/test-work/tests TEST_PATCH_OUTPUT=/results \
            bash /input/run-tests.sh
    '
