#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/official/lib" "$work/openresty/lib"
export MOCK_MODULE_ROOT="$work/modules with spaces"
export MOCK_MODULE_CALLS="$work/calls"
export TEST_MODULE_OUTPUT="$work/reports"
export NGINX_TESTS_ROOT="$work/official"
export TEST_NGINX_ROOT="$work/openresty"
export TEST_NGINX_BINARY="$work/bin/nginx"
export PATH="$work/bin:$PATH"
cp "$script_dir/fixtures/module-nginx.sh" "$TEST_NGINX_BINARY"
cp "$script_dir/fixtures/module-prove.sh" "$work/bin/prove"
chmod +x "$TEST_NGINX_BINARY" "$work/bin/prove"
for module in a b unbuilt; do
    mkdir -p "$MOCK_MODULE_ROOT/$module/t/fixtures"
    touch "$MOCK_MODULE_ROOT/$module/t/fixtures/marker"
    printf 'use Test::Nginx;\n' > "$MOCK_MODULE_ROOT/$module/t/official.t"
done
mkdir -p "$MOCK_MODULE_ROOT/a/t/nested" "$MOCK_MODULE_ROOT/empty"
printf 'use Test::Nginx::Socket::Lua;\n' > "$MOCK_MODULE_ROOT/a/t/nested/socket.t"

run() {
    : > "$MOCK_MODULE_CALLS"
    bash "$repository_root/util/run-module-tests.sh" "$MOCK_MODULE_ROOT" \
        > "$work/output" 2>&1
}

run
grep -Fxq 'Module tests: 3 suites, 3 files' "$work/output"
[[ "$(wc -l < "$MOCK_MODULE_CALLS")" -eq 3 ]]
! grep -q '^unbuilt|' "$MOCK_MODULE_CALLS"
echo 'PASS: built modules, nested tests, fixtures and separate Perl harnesses'

for module in ngx_http_grpc_filter_module ngx_http_proxy_filter_module; do
    mkdir -p "$MOCK_MODULE_ROOT/$module/t/fixtures"
    touch "$MOCK_MODULE_ROOT/$module/t/fixtures/marker"
    printf 'use Test::Nginx;\n' > "$MOCK_MODULE_ROOT/$module/t/filter.t"
done
export MOCK_FILTER_MODULES=1
run
grep -Fxq 'Module tests: 3 suites, 3 files' "$work/output"
for module in ngx_http_grpc_filter_module ngx_http_proxy_filter_module; do
    grep -Fxq "SKIP: $module (tested by its own GitHub Actions workflow)" "$work/output"
    ! grep -q "^$module|" "$MOCK_MODULE_CALLS"
done
echo 'PASS: filter framework tests run only in their own repository CI'
unset MOCK_FILTER_MODULES

module=ngx_http_headers_control_module
mkdir -p "$MOCK_MODULE_ROOT/$module/t/fixtures"
touch "$MOCK_MODULE_ROOT/$module/t/fixtures/marker"
for test in eval sanity; do
    printf 'use Test::Nginx::Socket;\n' > "$MOCK_MODULE_ROOT/$module/t/$test.t"
done
export MOCK_HEADERS_MODULE=1
run
grep -Fxq 'Module tests: 4 suites, 4 files' "$work/output"
grep -Fxq "$module|sanity.t" "$MOCK_MODULE_CALLS"
! grep -Fxq "$module|eval.t" "$MOCK_MODULE_CALLS"
grep -Fxq "SKIP: $module/t/eval.t (requires nginx-eval-module, tested by its own GitHub Actions workflow)" "$work/output"
echo 'PASS: tests requiring extra nginx modules are excluded without skipping compatible tests'
unset MOCK_HEADERS_MODULE

export MOCK_EXPR=1 MOCK_EXPECT_EXPR=1
run
echo 'PASS: both harnesses select expr tests from the built nginx configuration'
unset MOCK_EXPR MOCK_EXPECT_EXPR
export TEST_NGINX_EXPR=1 NGX_STAT_CONDITION=1
run
echo 'PASS: a non-expr binary does not inherit expr test flags from the caller'
unset TEST_NGINX_EXPR NGX_STAT_CONDITION

module=ngx_stream_log_set_module
mkdir -p "$MOCK_MODULE_ROOT/$module/t/fixtures"
touch "$MOCK_MODULE_ROOT/$module/t/fixtures/marker"
for test in log_set log_set_legacy; do
    printf 'use Test::Nginx;\n' > "$MOCK_MODULE_ROOT/$module/t/$test.t"
done
export MOCK_LEGACY_MODULES=1 MOCK_EXPR=1 MOCK_EXPECT_EXPR=1
run
grep -Fxq 'Module tests: 4 suites, 4 files' "$work/output"
grep -Fxq "$module|log_set.t" "$MOCK_MODULE_CALLS"
! grep -Fxq "$module|log_set_legacy.t" "$MOCK_MODULE_CALLS"
grep -Fxq "SKIP: $module/t/log_set_legacy.t (requires a build without ngx_expr_module)" "$work/output"
unset MOCK_EXPR MOCK_EXPECT_EXPR
run
grep -Fxq 'Module tests: 4 suites, 5 files' "$work/output"
grep -Fxq "$module|log_set_legacy.t" "$MOCK_MODULE_CALLS"
echo 'PASS: legacy-only suites are selected according to the built nginx configuration'
unset MOCK_LEGACY_MODULES

export MOCK_FAIL_MODULE=a MOCK_FAIL_CODE=17
if run; then
    echo 'FAIL: a failed module suite was accepted' >&2
    exit 1
fi
grep -Fxq 'b|official.t' "$MOCK_MODULE_CALLS"
grep -Fxq 'a|socket.t' "$MOCK_MODULE_CALLS"
grep -Fxq $'a\tofficial\t1\t17' "$TEST_MODULE_OUTPUT/results.tsv"
echo 'PASS: failures propagate without skipping later suites'
unset MOCK_FAIL_MODULE MOCK_FAIL_CODE

export MOCK_MISSING_MODULE=1
if run; then
    echo 'FAIL: missing built module sources were accepted' >&2
    exit 1
fi
grep -q 'Missing built module source:' "$work/output"
echo 'PASS: missing source checkout fails'
unset MOCK_MISSING_MODULE

export MOCK_NO_MODULES=1
if run; then
    echo 'FAIL: zero discovered tests was accepted' >&2
    exit 1
fi
grep -q 'No module tests were found' "$work/output"
echo 'PASS: an empty test selection fails'
unset MOCK_NO_MODULES

export NGINX_SOURCE="$work/nginx source"
mkdir -p "$NGINX_SOURCE/objs" "$NGINX_SOURCE/src/core" "$work/extension headers"
printf 'ALL_INCS = -I src/core \\\n\t-I "%s"\n\n' "$work/extension headers" \
    > "$NGINX_SOURCE/objs/Makefile"
export MOCK_EXPECT_INCLUDES="$NGINX_SOURCE/src/core:$work/extension headers"
run
echo 'PASS: native fixtures use the configured build header paths'
