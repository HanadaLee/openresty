use Test::Nginx::Socket::Lua 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: read before the origin finishes and resume a slow consumer
--- http_config
    lua_shared_dict progress 64k;
--- config
    location = /source {
        content_by_lua_block {
            ngx.header.content_length = 5 + 64 * 8192
            ngx.print("first")
            ngx.flush(true)
            for i = 1, 200 do
                if ngx.shared.progress:get("read") then break end
                ngx.sleep(0.005)
            end
            assert(ngx.shared.progress:get("read"))
            for i = 1, 64 do
                ngx.print(string.rep(string.char(i), 8192))
                ngx.flush(true)
            end
        }
    }
    location = /t {
        content_by_lua_block {
            local res = assert(ngx.http.request("http://127.0.0.1:"
                                                .. ngx.var.server_port .. "/source"))
            assert(res.status == 200 and res.body == nil)
            assert(res.body_reader(5) == "first")
            ngx.shared.progress:set("read", true)
            ngx.sleep(0.03)
            local n = 0
            while true do
                local chunk, err = res.body_reader(509)
                assert(not err, err)
                if not chunk then break end
                assert(#chunk > 0 and #chunk <= 509)
                for j = 1, #chunk do
                    assert(chunk:byte(j) == math.floor((n + j - 1) / 8192) + 1)
                end
                n = n + #chunk
            end
            assert(n == 64 * 8192 and not res.body_reader())
            assert(res:close())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 2: request body iterators with proxy buffering enabled and disabled
--- http_config
    server {
        server_name @request_body;
        client;
        location /buffered {
            client_body_buffer_size 4k;
            proxy_buffering on;
            proxy_request_buffering on;
            proxy_pass http://127.0.0.1:$arg_port/origin;
        }
        location /unbuffered {
            client_body_buffer_size 32k;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_pass http://127.0.0.1:$arg_port/origin;
        }
    }
--- config
    location = /origin {
        client_body_buffer_size 256k;
        content_by_lua_block {
            ngx.req.read_body()
            ngx.print(ngx.md5(assert(ngx.req.get_body_data())))
        }
    }
    location = /t {
        content_by_lua_block {
            local part = string.rep("a" .. string.char(0) .. "b", 16384)
            for _, mode in ipairs({ "buffered", "unbuffered" }) do
                for _, known in ipairs({ true, false }) do
                    local n = 0
                    local res = assert(ngx.http.request_uri("http://example.test/"
                        .. mode .. "?port=" .. ngx.var.server_port, {
                        method = "POST", server = "@request_body",
                        headers = known and { ["Content-Length"] = #part * 4 } or {},
                        body = function(size)
                            assert(size > 0)
                            n = n + 1
                            if n <= 4 then
                                ngx.sleep(0.001)
                                return part
                            end
                        end,
                    }))
                    assert(res.status == 200 and res.body == ngx.md5(part:rep(4)))
                end
            end
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 3: EOF, limit errors and explicit close
--- http_config
    server {
        server_name @stream;
        client;
        location = /empty { return 204; }
        location = /known { return 200 "123456"; }
        location = /unknown {
            content_by_lua_block {
                ngx.print("abc")
                ngx.flush(true)
                ngx.sleep(0.02)
                ngx.print("def")
            }
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local function request(path, limit, method)
                return ngx.http.request("http://example.test/" .. path, {
                    server = "@stream", max_response_bytes = limit, method = method,
                })
            end
            local res, err = request("known", 4)
            assert(not res and err == "HTTP response exceeds maximum size", err)
            res = assert(request("unknown", 4))
            repeat
                local chunk
                chunk, err = res.body_reader(2)
                if not chunk then break end
            until false
            assert(err == "HTTP response exceeds maximum size", err)
            for _, res in ipairs({ assert(request("empty")), assert(request("known", 1, "HEAD")) }) do
                local chunk, err = res.body_reader()
                assert(chunk == nil and err == nil)
            end
            res = assert(request("unknown"))
            assert(res:close() and res:close())
            local chunk
            chunk, err = res.body_reader()
            assert(chunk == nil and err == "closed")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]

=== TEST 4: unbuffered proxy forwards the first request body chunk before EOF
--- http_config
    lua_shared_dict request_body_progress 64k;
    server {
        server_name @request_body;
        client;
        location / {
            proxy_http_version 1.1;
            proxy_request_buffering off;
            proxy_pass http://127.0.0.1:$arg_port/receive;
        }
    }
--- config
    location = /receive {
        content_by_lua_block {
            local socket = assert(ngx.req.socket())
            local part = string.rep("a", 32768)
            assert(socket:receive(#part) == part)
            ngx.shared.request_body_progress:set("first", true)
            assert(socket:receive(32769) == string.rep("z", 32769))
            ngx.print("received")
        }
    }
    location = /t {
        content_by_lua_block {
            local n = 0
            local res = assert(ngx.http.request_uri("http://example.test/?port="
                .. ngx.var.server_port, {
                server = "@request_body", method = "POST",
                headers = { ["Content-Length"] = 65537 },
                body = function()
                    n = n + 1
                    if n == 1 then
                        return string.rep("a", 32768) .. string.rep("z", 32768)
                    end
                    if n == 2 then
                        for i = 1, 200 do
                            if ngx.shared.request_body_progress:get("first") then break end
                            ngx.sleep(0.005)
                        end
                        assert(ngx.shared.request_body_progress:get("first"))
                        return "z"
                    end
                end,
            }))
            assert(res.status == 200 and res.body == "received" and n >= 2)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 5: close and kill while a reader is waiting
--- http_config
    server {
        server_name @delayed;
        client;
        location / {
            content_by_lua_block {
                ngx.send_headers()
                ngx.sleep(0.1)
                ngx.print("done")
            }
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local function open()
                return assert(ngx.http.request("http://example.test/",
                                               { server = "@delayed" }))
            end
            for _, kill in ipairs({ false, true }) do
                local res = open()
                local waiting
                local th = ngx.thread.spawn(function()
                    waiting = true
                    local chunk, err = res.body_reader()
                    assert(not chunk and err == "closed", err)
                end)
                assert(waiting)
                local chunk, err = res.body_reader()
                assert(not chunk and err:find("busy", 1, true))
                if kill then
                    assert(ngx.thread.kill(th))
                    chunk, err = res.body_reader()
                    assert(not chunk and err == "closed", err)
                else
                    assert(res:close())
                    assert(ngx.thread.wait(th))
                end
                assert(res:close())
            end
            local res = open()
            assert(res.body_reader() == "done")
            local chunk, err = res.body_reader()
            assert(not chunk and not err)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 6: buffered proxy streams a response larger than the buffered Lua limit
--- http_config
    server {
        server_name @large;
        client;
        location / {
            proxy_buffering on;
            proxy_pass http://127.0.0.1:$arg_port/large;
        }
    }
--- config
    location = /large {
        content_by_lua_block {
            local block = string.rep("0123456789abcdef", 1024)
            ngx.header.content_length = #block * 1088
            for i = 1, 1088 do
                ngx.print(block)
                if i % 8 == 0 then ngx.flush(true) end
            end
        }
    }
    location = /t {
        content_by_lua_block {
            local res = assert(ngx.http.request("http://example.test/?port="
                .. ngx.var.server_port, { server = "@large" }))
            assert(res.status == 200)
            local bytes = 0
            local digest = ngx.md5_bin(string.rep("0123456789abcdef", 1024))
            repeat
                local chunk, err = res.body_reader()
                assert(not err, err)
                if not chunk then break end
                assert(#chunk > 0 and #chunk <= 16384)
                if #chunk == 16384 and bytes % 16 == 0 then
                    assert(ngx.md5_bin(chunk) == digest)
                end
                bytes = bytes + #chunk
            until false
            assert(bytes == 17 * 1024 * 1024)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 7: body producer failures and an early final response
--- http_config
    server {
        server_name @body;
        client;
        location /reject { return 413; }
        location /read {
            content_by_lua_block {
                ngx.req.read_body()
                ngx.print("ok")
            }
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local function send_request(path, producer, length)
                return ngx.http.request("http://example.test/" .. path, {
                    method = "POST", server = "@body", body = producer,
                    headers = length and { ["Content-Length"] = length },
                })
            end
            for _, case in ipairs({
                { function() return nil, "stopped" end, nil, "stopped" },
                { function() error("stopped") end, nil, "stopped" },
                { function() return "" end, nil, "non-empty string" },
                { function() return nil end, 10, "Content-Length" },
                { function() return "abc" end, 2, "Content-Length" },
            }) do
                local res, err = send_request("read", case[1], case[2])
                assert(not res and err:find(case[3], 1, true), err)
            end
            local calls = 0
            local res = assert(send_request("reject", function()
                calls = calls + 1
                assert(calls < 3)
                return string.rep("a", 32768)
            end))
            assert(res.status == 413)
            assert(res:close())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]

=== TEST 8: a truncated upstream response fails after its headers
--- config
    location = /partial {
        content_by_lua_block {
            ngx.header.content_length = 100
            ngx.print("part")
            ngx.flush(true)
            ngx.sleep(0.02)
            ngx.exit(444)
        }
    }
    location = /t {
        content_by_lua_block {
            local res = assert(ngx.http.request("http://127.0.0.1:"
                .. ngx.var.server_port .. "/partial"))
            assert(res.status == 200)
            assert(res.body_reader(4) == "part")
            local chunk, err = res.body_reader()
            assert(not chunk and err, err)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]

=== TEST 9: streams are owned and cleaned up by the calling request
--- http_config
    server {
        server_name @owned;
        client;
        location / {
            content_by_lua_block {
                ngx.send_headers()
                ngx.sleep(0.05)
                ngx.print("done")
            }
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local function open()
                return assert(ngx.http.request("http://example.test/", { server = "@owned" }))
            end
            local res = open()
            local finished, abandoned
            assert(ngx.timer.at(0, function()
                local chunk, err = res.body_reader()
                assert(not chunk and err:find("another request", 1, true))
                local ok, err = res:close()
                assert(not ok and err:find("another request", 1, true))
                abandoned = open()
                finished = true
            end))
            for i = 1, 100 do
                if finished then break end
                ngx.sleep(0.005)
            end
            assert(finished and abandoned)
            abandoned = nil
            collectgarbage()
            assert(res.body_reader() == "done")
            local chunk, err = res.body_reader()
            assert(not chunk and not err)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 10: read local, file and proxy output through the write filter
--- http_config
    server {
        server_name @sized;
        client;

        location = /memory {
            output_buffers 3 256;
            return 200 $arg_text;
        }
        location = /asset.txt {
            root html;
            output_buffers 1 512;
        }
        location = /proxied {
            proxy_buffering off;
            proxy_pass http://127.0.0.1:$arg_port/source;
        }
    }
--- config
    location = /source {
        content_by_lua_block {
            ngx.print(string.rep("abcdef", 512))
        }
    }
    location = /t {
        content_by_lua_block {
            local body = string.rep("abcdef", 512)
            for _, path in ipairs({ "memory", "asset.txt", "proxied" }) do
                local res = assert(ngx.http.request("http://example.test/" .. path, {
                    server = "@sized", query = { text = body, port = ngx.var.server_port },
                }))
                assert(res.status == 200)
                local pos = 0
                while true do
                    local chunk, err = res.body_reader(8192)
                    assert(not err, err)
                    if not chunk then break end
                    if pos == 0 and path == "memory" then
                        assert(#chunk == #body)
                    end
                    assert(#chunk > 0 and #chunk <= 8192)
                    assert(chunk == body:sub(pos + 1, pos + #chunk))
                    pos = pos + #chunk
                end
                assert(pos == #body)
            end
            ngx.say("ok")
        }
    }
--- user_files eval
">>> asset.txt\n" . ("abcdef" x 512)
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 11: a local flush waits for the caller to consume its output
--- http_config
    lua_shared_dict drained 64k;
    server {
        server_name @flush;
        client;
        location / {
            content_by_lua_block {
                ngx.print("first")
                ngx.shared.drained:set("writing", true)
                assert(ngx.flush(true))
                ngx.shared.drained:set("flushed", true)
                ngx.print("last")
            }
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local res = assert(ngx.http.request("http://example.test/", { server = "@flush" }))
            assert(ngx.shared.drained:get("writing"))
            ngx.sleep(0.01)
            assert(not ngx.shared.drained:get("flushed"))
            assert(res.body_reader(3) == "fir")
            ngx.sleep(0.01)
            assert(not ngx.shared.drained:get("flushed"))
            assert(res.body_reader(2) == "st")
            assert(res.body_reader() == "last")
            assert(ngx.shared.drained:get("flushed"))
            local chunk, err = res.body_reader()
            assert(not chunk and not err)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 12: read across write rate delays and sendfile chunk limits
--- http_config
    server {
        server_name @paced;
        client;
        location / {
            limit_rate 16k;
            sendfile_max_chunk 1k;
            return 200 $arg_data;
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local data = string.rep("abcd", 1024)
            local res = assert(ngx.http.request("http://example.test/", {
                server = "@paced", query = { data = data },
            }))
            local n = 0
            local start = ngx.now()
            while true do
                local chunk, err = res.body_reader(1536)
                assert(not err, err)
                if not chunk then break end
                assert(#chunk > 0 and #chunk <= 1024)
                assert(chunk == data:sub(n + 1, n + #chunk))
                n = n + #chunk
            end
            assert(n == #data and ngx.now() - start >= 0.1)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]

=== TEST 13: cancel a partially consumed response while the producer is flushing
--- http_config
    lua_shared_dict producer 64k;
    server {
        server_name @cancel;
        client;
        location = /pending {
            content_by_lua_block {
                ngx.print(string.rep("a", 65536))
                assert(ngx.flush(true))
                ngx.shared.producer:incr("finished", 1, 0)
            }
        }
        location = /next { return 200 "ok"; }
    }
--- config
    location = /t {
        content_by_lua_block {
            local opt = { server = "@cancel" }
            for i = 1, 8 do
                local res = assert(ngx.http.request("http://example.test/pending", opt))
                assert(res.body_reader(17) == string.rep("a", 17))
                assert(res:close())
                local chunk, err = res.body_reader()
                assert(not chunk and err == "closed")
            end
            local res = assert(ngx.http.request_uri("http://example.test/next", opt))
            assert(res.body == "ok" and not ngx.shared.producer:get("finished"))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[alert]
[error]
