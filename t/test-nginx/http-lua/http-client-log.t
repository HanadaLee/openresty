use Test::Nginx::Socket::Lua 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: connection failures identify the internal request and its upstream
--- http_config
    server {
        server_name @client_log;
        client;

        location / {
            proxy_pass http://unix:/dev/null:;
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local res, err = ngx.http.request_uri("http://origin.test/probe?tag=log", {
                server = "@client_log",
                headers = { Host = "origin.test" },
            })
            assert(not res and err == "HTTP request failed", err)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log eval
qr/while connecting to upstream, .*?server: \@client_log, request: "GET \/probe\?tag=log HTTP\/1\.1", upstream: "http:\/\/unix:\/dev\/null:\/probe\?tag=log", host: "origin\.test"/
--- no_error_log
[alert]

=== TEST 2: an internal client can read and write indexed variables through the log phase
--- http_config
    lua_load_var_index $client_result;
    init_by_lua_block { require("resty.var").load_indexes() }

    server {
        server_name @client_index;
        client;

        location = /probe {
            set $client_result initial;
            precontent_by_lua_block {
                local var = require "resty.var"
                assert(var.get("client_result") == "initial")
                var.set("client_result", "updated")
            }
            content_by_lua_block {
                ngx.print(ngx.var.client_result)
            }
            log_by_lua_block {
                ngx.log(ngx.NOTICE, "client result: ", require("resty.var").get("client_result"))
            }
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local res = assert(ngx.http.request_uri("http://origin.test/probe", {
                server = "@client_index",
            }))
            ngx.say(res.body)
        }
    }
--- request
GET /t
--- response_body
updated
--- error_log
client result: updated
--- no_error_log
[error]
