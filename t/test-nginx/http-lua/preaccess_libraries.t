# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(2);
plan('no_plan');

run_tests();

__DATA__

=== TEST 1: dns client waits for a synchronized query in preaccess
--- config
    location = /t {
        preaccess_by_lua_block {
            local client = require("resty.dns.client")
            assert(client.init({
                hosts = {},
                resolvConf = {},
                nameservers = { { "127.0.0.1", 1 } },
                timeout = 10,
                retrans = 1,
                search = {},
            }))

            local answers, err = client.resolve(
                "preaccess.invalid.", { qtype = client.TYPE_A })

            ngx.ctx.dns_answers_type = type(answers)
            ngx.ctx.dns_waited = answers == nil
                and type(err) == "string"
                and err:find("dns lookup pool exceeded retries", 1, true)
                    ~= nil

            ngx.log(ngx.INFO, "dns preaccess result: ",
                    ngx.ctx.dns_answers_type, ":", ngx.ctx.dns_waited)
        }

        content_by_lua_block {
            ngx.say("phase: ", ngx.get_phase())
            ngx.say("answers: ", ngx.ctx.dns_answers_type)
            ngx.say("waited: ", ngx.ctx.dns_waited)
        }
    }
--- request
GET /t
--- response_body
phase: content
answers: nil
waited: true
--- error_log
dns preaccess result: nil:true
--- no_error_log
API disabled in the context of preaccess_by_lua
