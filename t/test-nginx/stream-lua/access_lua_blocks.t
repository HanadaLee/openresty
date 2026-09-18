# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

no_long_string();
run_tests();

__DATA__

=== TEST 1: access and content Lua blocks preserve nested braces and context
--- stream_config
    init_by_lua_block {
        glob = "init by lua }here{"
    }

    init_worker_by_lua_block {
        glob = glob .. ", init worker }here{"
    }
--- stream_server_config
    access_by_lua_block {
        local s = '}access{\n'
        ngx.ctx.a = s
    }
    content_by_lua_block {
        local s = ngx.ctx.a .. [[}content{]]
        ngx.ctx.a = s
        ngx.say(s)
        ngx.say("glob: ", glob)
    }
    log_by_lua_block {
        print("log by lua running \"}{!\"")
    }
--- config
--- stream_response
}access{
}content{
glob: init by lua }here{, init worker }here{
--- error_log
log by lua running "}{!"
--- no_error_log
[error]
