#!/usr/bin/env bash

set -euo pipefail

test_image="${1:-}"
if [[ -z "$test_image" ]]; then
    echo "Usage: $0 <test-image>" >&2
    exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
git_mirror="${RESTY_GIT_MIRROR:-github.com}"
harness_root="$(mktemp -d)"
trap 'rm -rf "$harness_root"' EXIT

git clone --depth=1 \
    "https://${git_mirror}/openresty/test-nginx.git" \
    "$harness_root/test-nginx"
git clone --depth=1 \
    "https://${git_mirror}/nginx/nginx-tests.git" \
    "$harness_root/nginx-tests"

docker run --rm \
    --volume "$repository_root/t:/input/tests:ro" \
    --volume "$repository_root/util/run-tests.sh:/input/run-tests.sh:ro" \
    --volume "$harness_root/test-nginx:/input/test-nginx:ro" \
    --volume "$harness_root/nginx-tests:/input/nginx-tests:ro" \
    "$test_image" \
    bash -c '
        set -euo pipefail

        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            --no-install-recommends \
            perl \
            libtest-base-perl \
            libtext-diff-perl \
            libtest-longstring-perl \
            libwww-perl \
            libipc-run-perl \
            liburi-perl \
            liblist-moreutils-perl

        mkdir -p /test-work/tests /test-work/harnesses
        cp -a /input/tests/. /test-work/tests/
        cp -a /input/test-nginx /test-work/harnesses/test-nginx
        cp -a /input/nginx-tests /test-work/harnesses/nginx-tests

        TEST_NGINX_BINARY=/usr/local/openresty/sbin/nginx \
            TEST_NGINX_ROOT=/test-work/harnesses/test-nginx \
            NGINX_TESTS_ROOT=/test-work/harnesses/nginx-tests \
            TEST_ROOT=/test-work/tests \
            bash /input/run-tests.sh
    '
