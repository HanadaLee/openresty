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



=== TEST 2: lmdb prefix iterator yields between pages in preaccess
--- main_config
    lmdb_environment_path /tmp/openresty-preaccess-test.mdb;
    lmdb_map_size 16m;
--- http_config
    lua_shared_dict preaccess_phase_state 1m;
--- config
    location = /t {
        preaccess_by_lua_block {
            local lmdb = require("resty.lmdb")
            local transaction = require("resty.lmdb.transaction")
            local state = ngx.shared.preaccess_phase_state

            assert(lmdb.set("preaccess:setup", "value"))
            assert(lmdb.db_drop(false))

            local txn = transaction.begin(520)
            for i = 1, 520 do
                txn:set(string.format("preaccess:%04d", i), "value")
            end
            assert(txn:commit())

            state:delete("timer-ran")
            assert(ngx.timer.at(0, function()
                state:set("timer-ran", true)
            end))

            local count = 0
            for key, value in lmdb.prefix("preaccess:") do
                assert(key and value)
                count = count + 1
            end

            ngx.ctx.phase = ngx.get_phase()
            ngx.ctx.count = count
            ngx.ctx.yielded = state:get("timer-ran") == true
            ngx.log(ngx.INFO, "lmdb preaccess page yield: ",
                    ngx.ctx.phase, ":", ngx.ctx.count, ":",
                    ngx.ctx.yielded)
        }

        content_by_lua_block {
            ngx.say("phase: ", ngx.ctx.phase)
            ngx.say("count: ", ngx.ctx.count)
            ngx.say("yielded: ", ngx.ctx.yielded)
        }
    }
--- request
GET /t
--- response_body
phase: preaccess
count: 520
yielded: true
--- error_log
lmdb preaccess page yield: preaccess:520:true
--- no_error_log
[error]
[warn]
[crit]
