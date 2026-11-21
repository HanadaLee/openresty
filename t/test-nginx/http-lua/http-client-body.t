use Test::Nginx::Socket::Lua 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: collect successive body buffers and enforce the caller's limit
--- http_config
    server {
        server_name @body;
        client;

        location / {
            content_by_lua_block {
                ngx.header.content_length = tonumber(ngx.var.arg_length)
                ngx.print("abc")
                ngx.flush()
                ngx.print("def")
                ngx.flush()
                ngx.print("ghi")
            }
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local function request(query, limit)
                return ngx.http.request_uri("http://example.test/" .. query, {
                    server = "@body",
                    max_response_bytes = limit,
                })
            end

            for _, query in ipairs({ "?length=9", "", "?length=5", "?length=12" }) do
                local res = assert(request(query, 12))
                assert(res.status == 200 and res.body == "abcdefghi")
            end

            for _, query in ipairs({ "?length=9", "" }) do
                local res, err = request(query, 8)
                assert(res == nil and err == "HTTP response exceeds maximum size")
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
