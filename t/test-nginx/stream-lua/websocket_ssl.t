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

=== TEST 1: wss uses stream SSL socket support
--- stream_server_config
    content_by_lua_block {
        local websocket = require("resty.websocket.client")
        local wb = assert(websocket:new({ timeout = 100 }))
        local ok, err = wb:connect("wss://127.0.0.1:1/")

        if err == "ngx_lua 0.9.11+ required for SSL sockets" then
            ngx.say("stream SSL guard rejected wss")
        else
            ngx.say("stream SSL path enabled")
            ngx.log(ngx.INFO, "wss reached socket path: ",
                    ok or "nil", ":", err or "nil")
        end
    }
--- stream_response
stream SSL path enabled
--- error_log
wss reached socket path:
--- no_error_log
ngx_lua 0.9.11+ required for SSL sockets
