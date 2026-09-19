#!/bin/bash

set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)

: "${TEST_NGINX_BINARY:?TEST_NGINX_BINARY must point to the patched nginx binary}"
: "${TEST_NGINX_ROOT:?TEST_NGINX_ROOT must point to the test-nginx checkout}"
: "${NGINX_TESTS_ROOT:?NGINX_TESTS_ROOT must point to the nginx-tests checkout}"

export TEST_NGINX_BINARY
export TEST_NGINX_RESTY_LUALIB="${TEST_NGINX_RESTY_LUALIB:-/usr/local/openresty/lualib}"

(
    cd "$root/nginx-tests"

    if [ "$(id -u)" -eq 0 ]; then
        export TEST_NGINX_GLOBALS="${TEST_NGINX_GLOBALS:-user root;}"
    fi

    PERL5LIB="$NGINX_TESTS_ROOT/lib${PERL5LIB:+:$PERL5LIB}" \
        prove -v ./*.t
)

(
    cd "$root/test-nginx"
    PERL5LIB="$TEST_NGINX_ROOT/lib${PERL5LIB:+:$PERL5LIB}" \
        prove -v -r .
)
