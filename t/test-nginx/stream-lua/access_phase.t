# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2);

run_tests();

__DATA__

=== TEST 1: get_phase in access_by_lua
--- stream_server_config
    access_by_lua_block {
        ngx.say(ngx.get_phase())
        ngx.exit(200)
    }
    content_by_lua_block {
        return;
    }
--- stream_response
access
