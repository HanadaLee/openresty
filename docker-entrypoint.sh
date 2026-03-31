#!/bin/sh
set -e

rm -f /usr/local/openresty/var/run/*.sock
rm -f /usr/local/openresty/var/run/nginx.pid

exec "$@"
