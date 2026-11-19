BEGIN {
    $ENV{TEST_NGINX_RESTY_LUALIB} ||= "/usr/local/openresty/lualib";
    $ENV{TEST_NGINX_INIT_BY_LUA} =
        "package.path = '$ENV{TEST_NGINX_RESTY_LUALIB}/?.lua;' "
        . ".. (package.path or ''); require 'resty.core'";
}

use Test::Nginx::Socket::Lua::Stream 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: file tasks resume in Stream access, preread, and content
--- main_config
    thread_pool default_lua_io threads=2 max_queue=32;
--- stream_server_config
    access_by_lua_block {
        local path = ngx.config.prefix() .. "html/stream-file"
        assert(ngx.fs.append_file(path, "abcdef") == 6)
        ngx.ctx.path = path
    }

    preread_by_lua_block {
        ngx.ctx.initial = assert(ngx.fs.read_file(ngx.ctx.path, 6))
    }

    content_by_lua_block {
        local path = assert(ngx.ctx.path)
        assert(ngx.ctx.initial == "abcdef")
        local info = assert(ngx.fs.stat(path))
        assert(info.is_file and info.size == 6)

        local file = assert(ngx.fs.open(path, "r+"))
        assert(file:read(2, 1) == "bc")
        assert(file:write("XY", 2) == 2)
        assert(file:close())
        ngx.say(assert(ngx.fs.read_file(path, 6)))
    }
--- stream_response
abXYef
--- no_error_log
[error]

=== TEST 2: Stream timers can use ngx.fs after a cancelled operation
--- main_config
    thread_pool stream_io threads=2 max_queue=32;
--- stream_server_config
    content_by_lua_block {
        local path = ngx.config.prefix() .. "html/stream-timer-file"
        assert(ngx.fs.append_file(path, "ready", "stream_io") == 5)
        local worker = ngx.thread.spawn(function()
            return ngx.fs.read_file(path, 5, "stream_io")
        end)
        assert(ngx.thread.kill(worker))

        local sem = assert(require("ngx.semaphore").new())
        local data, err

        assert(ngx.timer.at(0, function(premature)
            if not premature then
                data, err = ngx.fs.read_file(path, 5, "stream_io")
            end
            sem:post()
        end))

        assert(sem:wait(2))
        assert(data == "ready", err)
        ngx.say(data)
    }
--- stream_response
ready
--- no_error_log
[error]
