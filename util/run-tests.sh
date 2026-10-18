#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/.." && pwd)"
test_root="${TEST_ROOT:-$repository_root/t}"

: "${TEST_NGINX_BINARY:?TEST_NGINX_BINARY must point to the patched nginx binary}"
: "${TEST_NGINX_ROOT:?TEST_NGINX_ROOT must point to the test-nginx checkout}"
: "${NGINX_TESTS_ROOT:?NGINX_TESTS_ROOT must point to the nginx-tests checkout}"

export TEST_NGINX_BINARY
export TEST_NGINX_RESTY_LUALIB="${TEST_NGINX_RESTY_LUALIB:-/usr/local/openresty/lualib}"
output="${TEST_PATCH_OUTPUT:-$(mktemp -d)}"
mkdir -p "$output"
printf 'framework\texit_code\n' > "$output/framework-results.tsv"
status=0

if (
    cd "$test_root/nginx-tests"

    if [ "$(id -u)" -eq 0 ]; then
        export TEST_NGINX_GLOBALS="${TEST_NGINX_GLOBALS:-user root;}"
    fi

    PERL5LIB="$NGINX_TESTS_ROOT/lib${PERL5LIB:+:$PERL5LIB}" \
        prove -v ./*.t
) 2>&1 | tee "$output/nginx-tests.log"; then
    printf 'nginx-tests\t0\n' >> "$output/framework-results.tsv"
else
    suite_codes=("${PIPESTATUS[@]}")
    suite_rc="${suite_codes[0]}"
    if ((suite_rc == 0)); then suite_rc="${suite_codes[1]}"; fi
    printf 'nginx-tests\t%s\n' "$suite_rc" >> "$output/framework-results.tsv"
    status=1
fi

if (
    cd "$test_root/test-nginx"

    # Test::Nginx defaults its server root to t/servroot.
    mkdir -p t

    PERL5LIB="$TEST_NGINX_ROOT/lib${PERL5LIB:+:$PERL5LIB}" \
        prove -v -r .
) 2>&1 | tee "$output/test-nginx.log"; then
    printf 'test-nginx\t0\n' >> "$output/framework-results.tsv"
else
    suite_codes=("${PIPESTATUS[@]}")
    suite_rc="${suite_codes[0]}"
    if ((suite_rc == 0)); then suite_rc="${suite_codes[1]}"; fi
    printf 'test-nginx\t%s\n' "$suite_rc" >> "$output/framework-results.tsv"
    status=1
fi
if [[ -d "$test_root/test-nginx/t/servroot" ]]; then
    cp -a "$test_root/test-nginx/t/servroot" "$output/servroot"
fi
exit "$status"
