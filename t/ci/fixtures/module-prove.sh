#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -v ]]
shift
[[ -f t/fixtures/marker ]]
[[ "${TEST_NGINX_EXPR:-}" == "${MOCK_EXPECT_EXPR:-0}" ]]
[[ "${NGX_STAT_CONDITION:-}" == "${MOCK_EXPECT_EXPR:-0}" ]]
if [[ "$(id -u)" == 0 ]]; then
    [[ "${TEST_NGINX_GLOBALS:-}" == "${MOCK_EXPECT_GLOBALS:-user root;}" ]]
fi
if [[ -n "${MOCK_EXPECT_INCLUDES:-}" ]]; then
    [[ "$C_INCLUDE_PATH" == "$MOCK_EXPECT_INCLUDES" ]]
fi
for test in "$@"; do
    if grep -q 'Test::Nginx::Socket' "$test"; then
        [[ "$PERL5LIB" == "$TEST_NGINX_ROOT/lib:"* ]]
        [[ "$PERL5LIB" != *"$NGINX_TESTS_ROOT/lib"* ]]
    else
        [[ "$PERL5LIB" == "$NGINX_TESTS_ROOT/lib:"* ]]
        [[ "$PERL5LIB" != *"$TEST_NGINX_ROOT/lib"* ]]
    fi
    printf '%s|%s\n' "$(basename "$PWD")" "$(basename "$test")" >> "$MOCK_MODULE_CALLS"
done
if [[ "${MOCK_FAIL_MODULE:-}" == "$(basename "$PWD")" ]]; then
    exit "${MOCK_FAIL_CODE:-1}"
fi
