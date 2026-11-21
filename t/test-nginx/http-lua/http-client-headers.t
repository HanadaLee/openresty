use Test::Nginx::Socket::Lua 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: static, partial and bodyless responses expose final headers
--- http_config
    server {
        server_name @response_headers;
        client;
        default_type text/plain;
        charset utf-8;
        charset_types text/plain;

        location / {
            root html;
            add_header X-Channel first;
            add_header X-Channel second;
        }

        location = /empty {
            add_header X-Channel empty always;
            return 204;
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local function request(path, method, headers)
                return assert(ngx.http.request_uri("http://example.test" .. path, {
                    server = "@response_headers",
                    method = method,
                    headers = headers,
                }))
            end

            local res = request("/asset.txt")
            assert(res.status == 200 and res.body:sub(1, 10) == "0123456789")
            assert(res.headers["Content-Type"] == "text/plain; charset=utf-8")
            assert(table.concat(res.headers["X-Channel"], ",") == "first,second")
            local length = tostring(#res.body)
            local modified = res.headers["Last-Modified"]
            assert(modified and ngx.parse_http_time(modified))
            assert(res.headers["Content-Length"] == length)

            res = request("/asset.txt", "HEAD")
            assert(res.status == 200 and res.body == "")
            assert(res.headers["Content-Length"] == length)
            assert(res.headers["Last-Modified"] == modified)

            res = request("/asset.txt", "GET", { Range = "bytes=2-4" })
            assert(res.status == 206 and res.body == "234")
            assert(res.headers["Content-Range"] == "bytes 2-4/" .. length)
            assert(res.headers["Content-Length"] == "3")
            assert(res.headers["Last-Modified"] == modified)

            res = request("/asset.txt", "GET", { ["If-Modified-Since"] = modified })
            assert(res.status == 304 and res.body == "")
            assert(res.headers["Last-Modified"] == modified)

            res = request("/empty")
            assert(res.status == 204 and res.body == "")
            assert(res.headers["X-Channel"] == "empty")
            assert(res.headers["Content-Length"] == nil)
            assert(res.headers["Content-Type"] == nil)
            ngx.say("ok")
        }
    }
--- user_files
>>> asset.txt
0123456789
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]


=== TEST 2: the captured body follows charset conversion without chunk framing
--- http_config
    charset_map windows-1252 utf-8 {
        E9 C3A9;
    }
    server {
        server_name @response_charset;
        client;

        location / {
            default_type text/plain;
            charset_types text/plain;
            source_charset windows-1252;
            charset utf-8;

            content_by_lua_block {
                ngx.print("caf", string.char(0xe9))
                ngx.print("!")
            }
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local res = assert(ngx.http.request_uri("http://example.test/", {
                server = "@response_charset",
            }))
            assert(res.status == 200)
            assert(res.headers["Content-Type"] == "text/plain; charset=utf-8")
            assert(res.headers["Transfer-Encoding"] == nil)
            assert(res.body == "caf" .. string.char(0xc3, 0xa9) .. "!")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]


=== TEST 3: buffered and unbuffered proxy responses preserve upstream metadata
--- http_config
    server {
        server_name @response_proxy;
        client;
        charset utf-8;
        charset_types text/plain;
        add_header X-Proxy filtered;

        location = /buffered {
            proxy_buffering on;
            proxy_pass http://127.0.0.1:$arg_port/origin;
        }

        location = /streamed {
            proxy_buffering off;
            proxy_pass http://127.0.0.1:$arg_port/origin;
        }
    }
--- config
    location = /origin {
        default_type text/plain;
        charset utf-8;
        charset_types text/plain;
        add_header Last-Modified "Mon, 28 Sep 1970 06:00:00 GMT";

        content_by_lua_block {
            ngx.print("from ")
            ngx.flush(true)
            ngx.print("origin")
        }
    }

    location = /t {
        content_by_lua_block {
            for _, path in ipairs({ "/buffered", "/streamed" }) do
                local res = assert(ngx.http.request_uri(
                    "http://example.test" .. path .. "?port=" .. ngx.var.server_port,
                    { server = "@response_proxy" }))
                assert(res.status == 200 and res.body == "from origin")
                assert(res.headers["Content-Type"] == "text/plain; charset=utf-8")
                assert(res.headers["Last-Modified"] == "Mon, 28 Sep 1970 06:00:00 GMT")
                assert(res.headers["X-Proxy"] == "filtered")
                assert(res.headers["Transfer-Encoding"] == nil)
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
