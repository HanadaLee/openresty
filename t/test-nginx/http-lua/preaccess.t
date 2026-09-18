# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 3);

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
            ngx.say("sub:" .. res.body)
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
