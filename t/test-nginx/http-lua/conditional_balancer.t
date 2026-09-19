# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(2);
plan('no_plan');

run_tests();

__DATA__

=== TEST 1: balancer sees fallback proxy_next_upstream_tries
--- http_config
    upstream conditional_balancer_backend {
        server 127.0.0.1:1;

        balancer_by_lua_block {
            local balancer = require("ngx.balancer")

            if not ngx.ctx.more_tries_set then
                ngx.ctx.more_tries_set = true
                local ok, warning = balancer.set_more_tries(2)
                assert(ok)
                ngx.log(ngx.INFO, "conditional tries warning: ",
                        warning or "none")
            end

            assert(balancer.set_current_peer("127.0.0.1", 1))
        }
    }
--- config
    condition enabled str_in $http_x_case enabled;

    location = /t {
        proxy_connect_timeout 100ms;
        proxy_next_upstream error;

        when enabled {
            proxy_next_upstream_tries 3;
        }

        proxy_next_upstream_tries 1;
        proxy_pass http://conditional_balancer_backend;
    }
--- request
GET /t
--- error_code: 502
--- error_log
conditional tries warning: reduced tries due to limit
--- no_error_log
[alert]



=== TEST 2: balancer sees matched proxy_next_upstream_tries
--- http_config
    upstream conditional_balancer_backend {
        server 127.0.0.1:1;

        balancer_by_lua_block {
            local balancer = require("ngx.balancer")

            if not ngx.ctx.more_tries_set then
                ngx.ctx.more_tries_set = true
                local ok, warning = balancer.set_more_tries(2)
                assert(ok)
                ngx.log(ngx.INFO, "conditional tries warning: ",
                        warning or "none")
            end

            assert(balancer.set_current_peer("127.0.0.1", 1))
        }
    }
--- config
    condition enabled str_in $http_x_case enabled;

    location = /t {
        proxy_connect_timeout 100ms;
        proxy_next_upstream error;

        when enabled {
            proxy_next_upstream_tries 3;
        }

        proxy_next_upstream_tries 1;
        proxy_pass http://conditional_balancer_backend;
    }
--- request
GET /t
X-Case: enabled
--- error_code: 502
--- error_log
conditional tries warning: none
--- no_error_log
conditional tries warning: reduced tries due to limit
[alert]
