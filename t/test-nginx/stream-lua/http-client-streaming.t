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

=== TEST 1: Stream Lua streams the HTTP request and response bodies
--- http_config
    server {
        server_name @echo;
        client;
        client_body_buffer_size 256k;
        location / {
            content_by_lua_block {
                ngx.req.read_body()
                local body = assert(ngx.req.get_body_data())
                ngx.header.content_length = #body
                ngx.print(body)
            }
        }
    }
--- stream_server_config
    content_by_lua_block {
        local n = 0
        local part = string.rep("abc", 8192)
        local res = assert(ngx.http.request("http://example.test/", {
            server = "@echo", method = "POST",
            body = function()
                n = n + 1
                if n <= 3 then
                    ngx.sleep(0.001)
                    return part
                end
            end,
        }))
        assert(res.status == 200)
        local chunks = {}
        while true do
            local chunk, err = res.body_reader(997)
            assert(not err, err)
            if not chunk then break end
            assert(#chunk <= 997)
            chunks[#chunks + 1] = chunk
        end
        assert(table.concat(chunks) == part:rep(3))
        ngx.say("ok")
    }
--- stream_response
ok
--- no_error_log
[alert]
[error]

=== TEST 2: closing a Stream Lua response wakes its pending reader
--- http_config
    server {
        server_name @delayed;
        client;
        location / {
            content_by_lua_block {
                ngx.send_headers()
                ngx.sleep(0.05)
                ngx.print("ok")
            }
        }
    }
--- stream_server_config
    content_by_lua_block {
        local function open()
            return assert(ngx.http.request("http://example.test/",
                                           { server = "@delayed" }))
        end
        local res = open()
        local reader = ngx.thread.spawn(function()
            local chunk, err = res.body_reader()
            assert(not chunk and err == "closed", err)
        end)
        local chunk, err = res.body_reader()
        assert(not chunk and err:find("busy", 1, true))
        assert(res:close())
        assert(ngx.thread.wait(reader))
        res = open()
        assert(res.body_reader() == "ok")
        chunk, err = res.body_reader()
        assert(not chunk and not err)
        ngx.say("ok")
    }
--- stream_response
ok
--- no_error_log
[alert]
[error]
