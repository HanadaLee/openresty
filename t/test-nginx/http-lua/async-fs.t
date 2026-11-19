use Test::Nginx::Socket::Lua 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: a whole-file read enforces its byte limit
--- main_config
    thread_pool default_lua_io threads=2 max_queue=32;
--- config
    location /t {
        content_by_lua_block {
            local path = ngx.config.prefix() .. "html/whole-file"
            assert(ngx.fs.append_file(path, "abcdef") == 6)
            assert(ngx.fs.read_file(path, 6) == "abcdef")
            assert(ngx.fs.read_file(path, nil) == "abcdef")
            local data, err = ngx.fs.read_file(path, 5)
            assert(not data and err:find("maximum size 5", 1, true), err)
            assert(ngx.fs.read_file(path .. "-missing", 4) == nil)
            assert(ngx.fs.read_file(ngx.config.prefix(), 4) == nil)
            assert(ngx.fs.append_file(path .. "-empty", "") == 0)
            assert(ngx.fs.read_file(path .. "-empty", 0) == "")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: batches and append handles write at the end of the file
--- main_config
    thread_pool file_io threads=2 max_queue=32;
--- config
    location /t {
        content_by_lua_block {
            local path = ngx.config.prefix() .. "html/append-file"
            assert(ngx.fs.append_file(path, "one\ntwo\n", "file_io") == 8)
            local handle = assert(ngx.fs.open(path, "a", "file_io"))
            assert(handle:write("three\n", 0) == 6)
            assert(handle:close())
            handle = assert(ngx.fs.open(path, "r", "file_io"))
            assert(handle:read(4) == "one\n")
            assert(handle:read(4, 4) == "two\n")
            assert(handle:read(6, 8) == "three\n")
            assert(handle:read(1, 14) == "")
            assert(handle:close())
            local n, err = ngx.fs.append_file(path, "lost", "missing")
            assert(not n and err:find("thread pool", 1, true), err)
            assert(ngx.fs.read_file(path, 14, "file_io") == "one\ntwo\nthree\n")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: queued reads resume in preaccess
--- main_config
    thread_pool default_lua_io threads=2 max_queue=32;
--- config
    location /t {
        preaccess_by_lua_block {
            local path = ngx.config.prefix() .. "html/preaccess-file"
            assert(ngx.fs.append_file(path, "hello") == 5)
            ngx.ctx.file_data = assert(ngx.fs.read_file(path, 5))
        }

        content_by_lua_block {
            ngx.say(ngx.ctx.file_data)
        }
    }
--- request
GET /t
--- response_body
hello
--- no_error_log
[error]

=== TEST 4: cancelling a read leaves subsequent tasks usable
--- main_config
    thread_pool default_lua_io threads=2 max_queue=32;
--- config
    location /t {
        content_by_lua_block {
            local path = ngx.config.prefix() .. "html/cancel-file"
            assert(ngx.fs.append_file(path, "ok") == 2)
            for _ = 1, 10 do
                local thread = ngx.thread.spawn(function()
                    return ngx.fs.read_file(path, 2)
                end)
                assert(ngx.thread.kill(thread))
            end
            ngx.say(assert(ngx.fs.read_file(path, 2)))
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]


=== TEST 5: finalized handles remain safe during and after pending operations
--- main_config
    thread_pool default_lua_io threads=2 max_queue=32;
--- config
    location /t {
        content_by_lua_block {
            local path = ngx.config.prefix() .. "html/finalized-file"
            assert(ngx.fs.append_file(path, "hello") == 5)
            for _ = 1, 20 do
                local file = assert(ngx.fs.open(path))
                local finalize = getmetatable(file).__gc
                local thread = ngx.thread.spawn(function()
                    return file:read(5)
                end)
                finalize(file)
                local ok, data = ngx.thread.wait(thread)
                assert(ok and data == "hello", data)
                assert(not pcall(file.read, file, 1))
                assert(not pcall(file.write, file, "x"))
                assert(file:close() == false)
                assert(tostring(file) == "file (closed)")
                finalize(file)
            end
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: reject invalid sizes, offsets, modes, and pool names before posting
--- main_config
    thread_pool default_lua_io threads=2 max_queue=32;
--- config
    location /t {
        content_by_lua_block {
            local path = ngx.config.prefix() .. "html/invalid-arguments"
            assert(ngx.fs.append_file(path, "hello") == 5)
            local file = assert(ngx.fs.open(path, "r+"))
            for _, n in ipairs({-1, 0 / 0, math.huge, 1.5, 2^63}) do
                assert(not pcall(file.read, file, n))
                assert(not pcall(file.read, file, 1, n))
                assert(not pcall(file.write, file, "", n))
                assert(not pcall(ngx.fs.read_file, path, n))
            end
            assert(not pcall(file.read, file, 0x7fffff00))
            assert(not pcall(ngx.fs.open, path, "r\0ignored"))
            local pool = "default_lua_io\0ignored"
            assert(not pcall(ngx.fs.open, path, "r", pool))
            assert(not pcall(ngx.fs.stat, path, pool))
            assert(not pcall(ngx.fs.read_file, path, 5, pool))
            assert(not pcall(ngx.fs.append_file, path, "x", pool))
            assert(not pcall(ngx.fs.open, path, "r", ("x"):rep(64)))
            assert(file:read(5) == "hello")
            assert(file:close())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: subrequests and timers resume their own file operations
--- main_config
    thread_pool default_lua_io threads=2 max_queue=32;
--- config
    location /file {
        internal;
        content_by_lua_block {
            local path = ngx.config.prefix() .. "html/context-file"
            ngx.print(assert(ngx.fs.read_file(path, 5)))
        }
    }
    location /t {
        content_by_lua_block {
            local path = ngx.config.prefix() .. "html/context-file"
            assert(ngx.fs.append_file(path, "hello") == 5)
            local result = ngx.location.capture("/file")
            assert(result.status == 200 and result.body == "hello")
            local sema = assert(require("ngx.semaphore").new())
            local value, timer_err
            assert(ngx.timer.at(0, function(premature)
                assert(not premature)
                value, timer_err = ngx.fs.read_file(path, 5)
                sema:post()
            end))
            assert(sema:wait(1))
            assert(value == "hello", timer_err)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
