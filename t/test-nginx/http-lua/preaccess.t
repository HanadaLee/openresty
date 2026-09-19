# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';

repeat_each(2);

#log_level("info");
#no_long_string();

run_tests();

__DATA__

=== TEST 1: preaccess_by_lua_block basic test
--- config
    location /lua {
        preaccess_by_lua_block {
            ngx.log(ngx.INFO, "preaccess_by_lua_block executed")
        }
        content_by_lua_block {
            ngx.say("content phase executed")
        }
    }
--- request
GET /lua
--- response_body
content phase executed
--- error_log
preaccess_by_lua_block executed
--- no_error_log
[error]



=== TEST 2: preaccess_by_lua_no_postpone enabled
--- http_config
    preaccess_by_lua_no_postpone on;
--- config
    location /lua {
        preaccess_by_lua_block {
            ngx.log(ngx.INFO, "preaccess no postpone")
            ngx.say("preaccess response")
        }
        content_by_lua_block {
            ngx.say("content")
        }
    }
--- request
GET /lua
--- response_body
preaccess response
--- error_log
preaccess no postpone
--- no_error_log
[error]



=== TEST 3: preaccess_by_lua ngx.exit
--- config
    location /lua {
        preaccess_by_lua_block {
            ngx.exit(403)
        }
        content_by_lua_block {
            ngx.say("should not reach")
        }
    }
--- request
GET /lua
--- error_code: 403
--- response_body_like: .*
--- no_error_log
should not reach



=== TEST 4: preaccess_by_lua_file test
--- user_files
>>> preaccess.lua
ngx.log(ngx.INFO, "preaccess file loaded")
ngx.say("preaccess file")
--- config
    location /lua {
        preaccess_by_lua_file html/preaccess.lua;
        content_by_lua_block {
            ngx.say("content")
        }
    }
--- request
GET /lua
--- response_body
preaccess file
--- error_log
preaccess file loaded
--- no_error_log
[error]



=== TEST 5: multiple headers in preaccess
--- config
    location /lua {
        preaccess_by_lua_block {
            ngx.header["X-Preaccess"] = "1"
        }
        content_by_lua_block {
            ngx.say("content")
        }
    }
--- request
GET /lua
--- response_body
content
--- response_headers
X-Preaccess: 1
--- no_error_log
[error]



=== TEST 6: no_postpone does not block other preaccess handlers
--- http_config
    preaccess_by_lua_no_postpone on;
    limit_req_zone $binary_remote_addr zone=preaccess:10m rate=1r/s;
--- config
    location /lua {
        limit_req zone=preaccess burst=100 nodelay;
        preaccess_by_lua_block {
            ngx.log(ngx.INFO, "lua preaccess handler executed")
        }
        content_by_lua_block {
            ngx.say("limit status: ", ngx.var.limit_req_status or "not run")
        }
    }
--- request
GET /lua
--- response_body
limit status: PASSED
--- error_log
lua preaccess handler executed
--- no_error_log
[error]



=== TEST 7: async sleep in preaccess
--- http_config
    preaccess_by_lua_no_postpone on;
    limit_req_zone $binary_remote_addr zone=preaccess:10m rate=1r/s;
--- config
    location /lua {
        limit_req zone=preaccess burst=100 nodelay;
        preaccess_by_lua_block {
            ngx.log(ngx.INFO, "preaccess sleep begin")
            ngx.sleep(0.01)
            ngx.log(ngx.INFO, "preaccess sleep end")
        }
        content_by_lua_block {
            ngx.say("limit status: ", ngx.var.limit_req_status or "not run")
        }
    }
--- request
GET /lua
--- response_body
limit status: PASSED
--- error_log
preaccess sleep begin
preaccess sleep end
--- no_error_log
[error]



=== TEST 8: ngx.req.read_body in preaccess
--- config
    location /lua {
        lua_need_request_body on;
        preaccess_by_lua_block {
            ngx.req.read_body()
            local data = ngx.req.get_body_data()
            ngx.log(ngx.INFO, "body read: ", data)
        }
        content_by_lua_block {
            ngx.say("ok")
        }
    }
--- request
POST /lua
hello body
--- response_body
ok
--- error_log
body read: hello body
--- no_error_log
[error]



=== TEST 9: ngx.exec in preaccess (internal redirect)
--- config
    location /lua {
        preaccess_by_lua_block {
            ngx.exec("/bar")
        }
        content_by_lua_block {
            ngx.say("should not reach")
        }
    }
    location /bar {
        content_by_lua_block {
            ngx.say("redirected")
        }
    }
--- request
GET /lua
--- response_body
redirected
--- no_error_log
[error]



=== TEST 10: subrequest in preaccess
--- config
    location /lua {
        preaccess_by_lua_block {
            local res = ngx.location.capture("/sub")
            ngx.log(ngx.INFO, "subrequest status: ", res.status)
            ngx.print("sub:" .. res.body)
        }
        content_by_lua_block {
            ngx.say("should not reach")
        }
    }
    location /sub {
        content_by_lua_block {
            ngx.say("subresponse")
        }
    }
--- request
GET /lua
--- response_body
sub:subresponse
--- error_log
subrequest status: 200
--- no_error_log
[error]



=== TEST 11: ngx.get_phase reports preaccess
--- config
    location /lua {
        set $preaccess_phase "not-run";
        preaccess_by_lua_block {
            ngx.var.preaccess_phase = ngx.get_phase()
            ngx.log(ngx.INFO, "phase observed: ", ngx.get_phase())
        }
        content_by_lua_block {
            ngx.say("phase: ", ngx.var.preaccess_phase)
        }
    }
--- request
GET /lua
--- response_body
phase: preaccess
--- error_log
phase observed: preaccess
--- no_error_log
[error]



=== TEST 12: TCP cosocket can yield in preaccess
--- config
    location = /lua {
        preaccess_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)

            local ok, err = sock:connect("127.0.0.1", ngx.var.server_port)
            assert(ok, err)

            local bytes
            bytes, err = sock:send(
                "GET /socket-backend HTTP/1.0\r\n"
                .. "Host: localhost\r\n\r\n")
            assert(bytes, err)

            local status
            status, err = sock:receive("*l")
            assert(status, err)
            assert(sock:close())

            ngx.ctx.backend_status = status
            ngx.log(ngx.INFO, "preaccess cosocket status: ", status)
        }
        content_by_lua_block {
            ngx.say(ngx.ctx.backend_status)
        }
    }

    location = /socket-backend {
        return 204;
    }
--- request
GET /lua
--- response_body
HTTP/1.1 204 No Content
--- error_log
preaccess cosocket status: HTTP/1.1 204 No Content
--- no_error_log
[error]



=== TEST 13: send headers flush and eof in preaccess
--- config
    location = /lua {
        preaccess_by_lua_block {
            ngx.header["X-Preaccess-Output"] = "sent"
            assert(ngx.send_headers())
            assert(ngx.print("preaccess output\n"))
            assert(ngx.flush(true))
            assert(ngx.eof())
            ngx.log(ngx.INFO, "preaccess output finalized")
        }
        content_by_lua_block {
            ngx.say("should not reach")
        }
    }
--- request
GET /lua
--- response_body
preaccess output
--- response_headers
X-Preaccess-Output: sent
--- error_log
preaccess output finalized
--- no_error_log
[error]



=== TEST 14: raw request socket in preaccess
--- config
    location = /lua {
        preaccess_by_lua_block {
            ngx.status = 200
            ngx.header.content_length = 16
            assert(ngx.send_headers())
            assert(ngx.flush(true))

            local sock, err = ngx.req.socket(true)
            assert(sock, err)

            local data
            data, err = sock:receive(5)
            assert(data, err)

            local bytes
            bytes, err = sock:send("raw body: " .. data .. "\n")
            assert(bytes, err)
            ngx.log(ngx.INFO, "preaccess raw body: ", data)
        }
        content_by_lua_block {
            ngx.say("should not reach")
        }
    }
--- raw_request eval
"GET /lua HTTP/1.1\r
Host: localhost\r
Connection: close\r
\r
hello"
--- response_body
raw body: hello
--- error_log
preaccess raw body: hello
--- no_error_log
[error]



=== TEST 15: ngx.redirect in preaccess
--- config
    location = /lua {
        preaccess_by_lua_block {
            ngx.log(ngx.INFO, "preaccess redirect")
            return ngx.redirect("/redirect-target")
        }
        content_by_lua_block {
            ngx.say("should not reach")
        }
    }

    location = /redirect-target {
        return 204;
    }
--- request
GET /lua
--- error_code: 302
--- response_body_like: 302 Found
--- response_headers_like
Location: /redirect-target
--- error_log
preaccess redirect
--- no_error_log
[error]
