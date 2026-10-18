#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -V ]]
echo 'nginx version: test'
printf 'configure arguments: '
if [[ "${MOCK_NO_MODULES:-0}" != 1 ]]; then
    printf -- "--add-module='%s/a' --add-dynamic-module='%s/b' " \
        "$MOCK_MODULE_ROOT" "$MOCK_MODULE_ROOT"
    printf -- "--add-module='%s/empty' " "$MOCK_MODULE_ROOT"
    if [[ "${MOCK_FILTER_MODULES:-0}" == 1 ]]; then
        printf -- "--add-module='%s/ngx_http_grpc_filter_module' " "$MOCK_MODULE_ROOT"
        printf -- "--add-module='%s/ngx_http_proxy_filter_module' " "$MOCK_MODULE_ROOT"
    fi
fi
if [[ "${MOCK_MISSING_MODULE:-0}" == 1 ]]; then
    printf -- "--add-module='%s/missing' " "$MOCK_MODULE_ROOT"
fi
echo
