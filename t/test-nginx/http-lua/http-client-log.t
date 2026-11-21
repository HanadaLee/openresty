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
