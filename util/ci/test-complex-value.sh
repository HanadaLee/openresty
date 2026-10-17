#!/usr/bin/env bash

# Exercise the real setters and runtime getter against a built nginx tree.
set -euo pipefail

source_dir="${1:?Usage: test-complex-value.sh <nginx-source> [fixtures]}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="${2:-$script_dir/../../t/complex-value}"
source_dir="$(cd "$source_dir" && pwd)"
fixtures="$(cd "$fixtures" && pwd)"
nginx="$source_dir/objs/nginx"
test_root="$(mktemp -d /tmp/resty-complex.XXXXXX)"
nginx_pid=''

cleanup() {
    if [[ -n "$nginx_pid" ]]; then
        kill -QUIT "$nginx_pid" 2>/dev/null || true
        wait "$nginx_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT

fail() {
    echo "Complex-value test failed: $*" >&2
    for log in "$test_root"/*.log; do
        [[ ! -f "$log" ]] || cat "$log" >&2
    done
    exit 1
}

make -s -C "$source_dir" -f objs/Makefile -f "$fixtures/Makefile" \
    complex-value-fixture \
    FIXTURE_SOURCE="$fixtures/ngx_http_complex_value_test_module.c" \
    FIXTURE_OUTPUT="$test_root/fixture.so"

mkdir -p "$test_root/logs"
cat > "$test_root/nginx.conf" <<EOF
load_module $test_root/fixture.so;
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
        listen unix:$test_root/test.sock;
        include $test_root/locations.conf;
    }
}
EOF

valid=('0' '0ms' '1' '1s' '100ms' '1m' '1h' '1m 2s 3ms')
expected=(0 0 1000 1000 100 60000 3600000 62003)
invalid=('' 'invalid' '1xs' '-1s' '1y' '1M' '999999999999999999999ms')

# Invalid constants must be rejected just like the native millisecond setter.
for value in "${invalid[@]}"; do
    for directive in test_complex_msec test_reference_msec; do
        printf 'location / { %s "%s"; }\n' "$directive" "$value" \
            > "$test_root/locations.conf"
        if "$nginx" -e stderr -p "$test_root/" -c nginx.conf -t \
            > "$test_root/config.log" 2>&1; then
            fail "$directive accepted invalid value: $value"
        fi
        grep -Fq "\"$directive\" directive invalid value" "$test_root/config.log" || \
            fail "$directive rejected $value for an unexpected reason"
    done
done

: > "$test_root/locations.conf"
for i in "${!valid[@]}"; do
    cat >> "$test_root/locations.conf" <<EOF
location /constant-$i {
    test_reference_msec "${valid[$i]}";
    test_complex_msec "${valid[$i]}";
}
location /variable-$i {
    test_reference_msec "${valid[$i]}";
    test_complex_msec \$http_x_test_time;
}
EOF
done
cat >> "$test_root/locations.conf" <<'EOF'
location /unset {
    test_reference_msec 17ms;
}
location /invalid {
    test_reference_msec 17ms;
    test_complex_msec $http_x_test_time;
}
EOF

"$nginx" -e stderr -p "$test_root/" -c nginx.conf -t \
    > "$test_root/config.log" 2>&1 || fail 'valid configuration rejected'
"$nginx" -e stderr -p "$test_root/" -c nginx.conf \
    -g 'daemon off; master_process off;' > "$test_root/run.log" 2>&1 &
nginx_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -S "$test_root/test.sock" ]] && break
    kill -0 "$nginx_pid" 2>/dev/null || fail 'nginx exited before listening'
    sleep 0.05
done
[[ -S "$test_root/test.sock" ]] || fail 'nginx did not start listening'

check() {
    local path="$1" value="$2" expected_value="$3" response
    response="$(curl --silent --show-error --fail --noproxy '*' --max-time 5 \
        --unix-socket "$test_root/test.sock" \
        -H "X-Test-Time: $value" "http://localhost/$path")" || fail "$path request"
    [[ "$response" == "$expected_value $expected_value" ]] || \
        fail "$path ($value): expected $expected_value, got $response"
}

for i in "${!valid[@]}"; do
    check "constant-$i" '' "${expected[$i]}"
    check "variable-$i" "${valid[$i]}" "${expected[$i]}"
done
check unset '' 17
for value in "${invalid[@]}"; do
    check invalid "$value" 17
done

kill -QUIT "$nginx_pid"
wait "$nginx_pid"
nginx_pid=''

echo 'Complex-value milliseconds: constants, variables, native setter and fallback passed'
