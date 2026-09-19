# vim:set ft= ts=4 sw=4 et fdm=marker:

BEGIN {
    $ENV{TEST_NGINX_RESTY_LUALIB} ||= "/usr/local/openresty/lualib";
    $ENV{TEST_NGINX_INIT_BY_LUA} =
        "package.path = '$ENV{TEST_NGINX_RESTY_LUALIB}/?.lua;' "
        . ".. (package.path or ''); require 'resty.core'";
}

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);
plan tests => repeat_each() * blocks() * 4;

run_tests();

__DATA__

=== TEST 1: ngx.upstream reads configuration through the stream request API
--- stream_config
    upstream primary_patch_backend {
        server 127.0.0.1:9001 weight=2;
    }

    upstream secondary_patch_backend {
        server 127.0.0.1:9002;
    }
--- stream_server_config
    content_by_lua_block {
        local upstream = require("ngx.upstream")
        local names = upstream.get_upstreams()
        table.sort(names)

        local servers = assert(
            upstream.get_servers("primary_patch_backend"))

        ngx.say(table.concat(names, ","))
        ngx.say(servers[1].name, ":", servers[1].weight)
        ngx.log(ngx.INFO, "stream request API returned ", #names,
                " upstreams")
    }
--- stream_response
primary_patch_backend,secondary_patch_backend
127.0.0.1:9001:2
--- error_log
stream request API returned 2 upstreams
--- no_error_log
[error]
