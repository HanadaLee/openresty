#!/usr/bin/env bash

# Run against a configured, built nginx source tree; no installation is needed.
set -euo pipefail

source_dir="${1:?Usage: test-module-abi.sh <nginx-source> [fixtures]}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="${2:-$script_dir/../../t/module-abi}"
source_dir="$(cd "$source_dir" && pwd)"
fixtures="$(cd "$fixtures" && pwd)"
nginx="$source_dir/objs/nginx"
test_root="$(mktemp -d /tmp/resty-abi.XXXXXX)"
nginx_pid=""

cleanup() {
    if [[ -n "$nginx_pid" ]]; then
        kill -QUIT "$nginx_pid" 2>/dev/null || true
        wait "$nginx_pid" 2>/dev/null || true
    fi
    if [[ "${RESTY_ABI_KEEP_FILES:-0}" == 1 ]]; then
        echo "ABI test files: $test_root"
    else
        rm -rf -- "$test_root"
    fi
}
trap cleanup EXIT

fail() {
    echo "ABI test failed: $*" >&2
    exit 1
}

compile() {
    local output="$1" flags="$2" link="$3"
    shift 3
    : > "$test_root/test_config.h"
    local setting name value
    for setting in "$@"; do
        name="${setting%%=*}"
        value="${setting#*=}"
        printf '#undef %s\n#define %s %s\n' "$name" "$name" "$value" \
            >> "$test_root/test_config.h"
    done
    if ! make -s -C "$source_dir" -f objs/Makefile -f "$fixtures/Makefile" \
        abi-fixture ABI_TMP="$test_root" ABI_FLAGS="$flags" \
        ABI_SOURCE="$fixtures/ngx_http_abi_test_module.c" \
        ABI_LINK="$link" ABI_OUTPUT="$output" > "$test_root/compile.log" 2>&1; then
        cat "$test_root/compile.log" >&2
        fail "compiling $output"
    fi
}

# Check both compatibility modes without modifying the configured source tree.
# With EXT disabled, the signature must remain exactly the legacy signature.
for compat in 0 1; do
    for ssl in 0 1; do
        compile "$test_root/signature" \
            '-DRESTY_ABI_TEST_PRINT=1 -DRESTY_ABI_TEST_LEGACY=1' '' \
            "NGX_COMPAT=$compat" "NGX_HTTP_SSL=$ssl" NGX_RESTY_EXT=0
        legacy="$("$test_root/signature")"
        for expr in 0 1; do
            for proxy_filter in 0 1; do
                for grpc_filter in 0 1; do
                    for ext in 0 1; do
                        compile "$test_root/signature" '-DRESTY_ABI_TEST_PRINT=1' '' \
                            "NGX_COMPAT=$compat" "NGX_HTTP_SSL=$ssl" \
                            "NGX_RESTY_EXT=$ext" "NGX_EXPR=$expr" \
                            "NGX_HTTP_PROXY_FILTER=$proxy_filter" \
                            "NGX_HTTP_GRPC_FILTER=$grpc_filter"
                        expected="$legacy"
                        if [[ "$ext" == 1 ]]; then
                            expected+=",resty,1,$expr$proxy_filter$grpc_filter$ssl"
                        fi
                        [[ "$("$test_root/signature")" == "$expected" ]] || \
                            fail "signature: compat=$compat ssl=$ssl ext=$ext expr=$expr proxy_filter=$proxy_filter grpc_filter=$grpc_filter"
                    done
                done
            done
        done
    done
done
echo 'ABI signature matrix: 64 combinations passed'

mkdir -p "$test_root/logs" "$test_root/html"
printf 'abi body\n' > "$test_root/html/body"

# Only Unix sockets in our temporary directory: no production ports or prefix.
write_config() {
    cat > "$test_root/nginx.conf" <<EOF
load_module $test_root/$1.so;
pid $test_root/nginx.pid;
error_log $test_root/error.log notice;
events {}
http {
    access_log off;
    client_body_temp_path $test_root/client_body;
    proxy_temp_path $test_root/proxy_temp;
    fastcgi_temp_path $test_root/fastcgi_temp;
    scgi_temp_path $test_root/scgi_temp;
    uwsgi_temp_path $test_root/uwsgi_temp;
    server {
        listen unix:$test_root/front.sock;
        location /probe {
            proxy_pass http://unix:$test_root/back.sock:/body;
        }
    }
    server {
        listen unix:$test_root/back.sock;
        root $test_root/html;
    }
}
EOF
}

compile "$test_root/matching.so" '' '-shared'
write_config matching
if ! "$nginx" -e stderr -p "$test_root/" -c nginx.conf -t > "$test_root/matching.log" 2>&1; then
    cat "$test_root/matching.log" >&2
    fail 'matching module rejected'
fi
grep -q 'abi_test configuration reached' "$test_root/matching.log" || \
    fail 'matching module configuration hook not called'
echo 'ABI loader: matching module accepted'

for variant in legacy no-ext expr proxy-filter grpc-filter http-ssl revision; do
    settings=()
    flags=''
    case "$variant" in
        legacy) flags='-DRESTY_ABI_TEST_LEGACY=1' ;;
        no-ext) settings=(NGX_RESTY_EXT=0) ;;
        revision) flags='-DRESTY_ABI_TEST_REVISION=1' ;;
        *)
            case "$variant" in
                expr) macro=NGX_EXPR ;;
                proxy-filter) macro=NGX_HTTP_PROXY_FILTER ;;
                grpc-filter) macro=NGX_HTTP_GRPC_FILTER ;;
                http-ssl) macro=NGX_HTTP_SSL ;;
            esac
            value=1
            if grep -Eq "^#define $macro +1$" "$source_dir/objs/ngx_auto_config.h"; then
                value=0
            fi
            settings=("$macro=$value")
            ;;
    esac
    compile "$test_root/$variant.so" "$flags" '-shared' "${settings[@]}"
    write_config "$variant"
    if "$nginx" -e stderr -p "$test_root/" -c nginx.conf -t > "$test_root/$variant.log" 2>&1; then
        fail "incompatible $variant module accepted"
    fi
    grep -q 'is not binary compatible' "$test_root/$variant.log" || {
        cat "$test_root/$variant.log" >&2
        fail "$variant rejected for a different reason"
    }
    if grep -q 'abi_test configuration reached' "$test_root/$variant.log"; then
        fail "$variant configuration hook called before ABI rejection"
    fi
    echo "ABI loader: $variant module rejected before configuration"
done

write_config matching
"$nginx" -e stderr -p "$test_root/" -c nginx.conf -g 'daemon off; master_process off;' \
    > "$test_root/run.log" 2>&1 &
nginx_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -S "$test_root/front.sock" ]] && break
    kill -0 "$nginx_pid" 2>/dev/null || {
        cat "$test_root/run.log" >&2
        fail 'test nginx exited before listening'
    }
    sleep 0.05
done
curl --silent --show-error --fail --noproxy '*' --max-time 5 \
    --unix-socket "$test_root/front.sock" http://localhost/probe \
    > "$test_root/response"
cmp "$test_root/html/body" "$test_root/response"
kill -QUIT "$nginx_pid"
wait "$nginx_pid"
nginx_pid=''
grep -Eq 'abi_test uri=/probe status=200 length=9 peer=unix:.* request_length=[1-9][0-9]*' \
    "$test_root/error.log" || {
        cat "$test_root/error.log" >&2
        fail 'request/upstream fields do not match'
    }
if grep -Eq '\[(emerg|alert|crit|error)\]' "$test_root/error.log"; then
    cat "$test_root/error.log" >&2
    fail 'runtime error in matching module'
fi
echo 'ABI runtime: matching module read request and upstream fields correctly'
