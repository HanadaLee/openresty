# Copyright (C) Hanada

import http.client
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
from collections import Counter
from ipaddress import ip_address
from pathlib import Path

from common import check_logs


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode()
                    for label in name.split(".")) + b"\0"


def dns_answer(qtype, value):
    return struct.pack("!HHHIH", 0xC00C, qtype, 1, 30, len(value)) + value


def dns_server(sock, index):
    while True:
        data, peer = sock.recvfrom(65535)
        position, labels = 12, []
        while data[position]:
            length = data[position]
            labels.append(data[position + 1:position + 1 + length].decode())
            position += length + 1
        position += 1
        host = ".".join(labels)
        qtype = int.from_bytes(data[position:position + 2], "big")
        with lock:
            queries[index, host, qtype] += 1

        if host in ("timeout.example", ip_address("192.0.2.4").reverse_pointer):
            continue

        code, answers = 0, []
        if qtype == 12:
            if host == ip_address("192.0.2.3").reverse_pointer:
                code = 3
            elif host == ip_address("192.0.2.5").reverse_pointer and index == 0:
                code = 2
            else:
                answers = [dns_answer(12, dns_name("ptr.example"))]
        elif host == "missing.example":
            code = 3
        elif host == "backup.example" and index == 0:
            code = 2
        elif host == "alias.example":
            answers = [dns_answer(5, dns_name("target.example"))]
        elif qtype == 1:
            addresses = {
                "target.example": ["127.0.0.2", "127.0.0.3"],
                "different.example": ["127.0.0.4"],
            }.get(host, ["127.0.0.1"])
            answers = [dns_answer(1, socket.inet_aton(ip)) for ip in addresses]
        elif qtype == 28 and host not in ("cached.example", "only-v4.example"):
            answers = [dns_answer(28, socket.inet_pton(socket.AF_INET6, "::1"))]

        reply = (
            struct.pack("!HHHHHH", int.from_bytes(data[:2], "big"),
                        0x8180 | code, 1, len(answers), 0, 0)
            + data[12:position + 4]
            + b"".join(answers)
        )
        sock.sendto(reply, peer)


def http_request(path, listen_port):
    conn = http.client.HTTPConnection("127.0.0.1", listen_port, timeout=4)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        assert response.status == 200, (path, response.status)
        return response.read().decode().strip()
    finally:
        conn.close()


def wait_for_nginx(proc, listen_port):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            return http_request("/origin", listen_port)
        except OSError:
            time.sleep(0.02)
    raise AssertionError("nginx did not start")


http_port, no_dns_port, stream_port = (port() for _ in range(3))
queries, lock = Counter(), threading.Lock()
dns_ports = []
for i in range(2):
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.bind(("127.0.0.1", 0))
    dns_ports.append(dns_sock.getsockname()[1])
    threading.Thread(target=dns_server, args=(dns_sock, i), daemon=True).start()

with tempfile.TemporaryDirectory(prefix="resolver-lua-api-") as tmp:
    directory = Path(tmp)
    (directory / "logs").mkdir()
    (directory / "resolve-format.lua").write_text("""
local function lookup(host, family)
    local addrs, err = ngx.resolve(host, family)
    if not addrs then
        return err
    end
    if family == "ptr" then
        return addrs
    end
    local result = {}
    for i, addr in ipairs(addrs) do
        result[i] = addr.type .. "/" .. addr.addr
    end
    table.sort(result)
    return table.concat(result, ",")
end

return lookup
""")
    config = directory / "nginx.conf"
    config.write_text(f"""daemon off;
master_process off;
error_log {directory}/error.log debug;
pid {directory}/nginx.pid;
events {{}}
http {{
    init_by_lua_block {{
        package.loaded.resolve_format = dofile("{directory}/resolve-format.lua")
    }}
    nameserver dns {{
        server 127.0.0.1:{dns_ports[0]};
        server 127.0.0.1:{dns_ports[1]} level=2;
    }}
    upstream proxy_test {{
        server 0.0.0.1:1;
        balancer_by_lua_block {{
            local addrs, err = ngx.resolve("127.0.0.1")
            assert(not addrs and err:find("balancer", 1, true), err)
            assert(require("ngx.balancer").set_current_peer("127.0.0.1", {http_port}))
        }}
    }}
    server {{
        listen 127.0.0.1:{http_port};
        resolver dns negative_valid=10s;
        resolver_timeout 250ms;
        resolver_next_nameserver rcode_servfail;

        location = /origin {{ return 200 ok; }}
        location = /balanced {{ proxy_pass http://proxy_test/origin; }}
        location = /resolve {{
            precontent_by_lua_block {{
                local lookup = require "resolve_format"
                ngx.ctx.answer = lookup(ngx.var.arg_host, ngx.var.arg_family)
            }}
            content_by_lua_block {{ ngx.say(ngx.ctx.answer) }}
        }}
        location = /preaccess {{
            preaccess_by_lua_block {{
                ngx.ctx.answer = require("resolve_format")("preaccess.example", "ipv4")
            }}
            content_by_lua_block {{ ngx.say(ngx.ctx.answer) }}
        }}
        location = /ipv4-only {{
            resolver 127.0.0.1:{dns_ports[0]} ipv6=off;
            content_by_lua_block {{
                ngx.say(require("resolve_format")("only-v4.example", "ipv6"))
            }}
        }}
        location = /parallel {{
            content_by_lua_block {{
                local lookup = require "resolve_format"
                local a = ngx.thread.spawn(lookup, "coalesced.example", "ipv4")
                local b = ngx.thread.spawn(lookup, "coalesced.example", "ipv6")
                local c = ngx.thread.spawn(lookup, "different.example", "ipv4")
                local ok, result = ngx.thread.wait(a)
                assert(ok, result)
                ngx.say(result)
                ok, result = ngx.thread.wait(b)
                assert(ok, result)
                ngx.say(result)
                ok, result = ngx.thread.wait(c)
                assert(ok, result)
                ngx.say(result)
            }}
        }}
        location = /cancel {{
            content_by_lua_block {{
                local lookup = require "resolve_format"
                local thread = ngx.thread.spawn(lookup, "cancel.example")
                assert(ngx.thread.kill(thread))
                ngx.say(lookup("cancel.example", "ipv4"))
            }}
        }}
        location = /ptr-parallel {{
            content_by_lua_block {{
                local lookup = require "resolve_format"
                local a = ngx.thread.spawn(lookup, "192.0.2.2", "ptr")
                local b = ngx.thread.spawn(lookup, "192.0.2.2", "ptr")
                assert(ngx.thread.kill(a))
                local ok, name = ngx.thread.wait(b)
                assert(ok, name)
                ngx.say(name)
            }}
        }}
        location = /cosocket {{
            content_by_lua_block {{
                local sock = ngx.socket.tcp()
                assert(sock:connect("cached.example", {http_port}))
                assert(sock:close())
                ngx.say("connected")
            }}
        }}
        location = /timer {{
            content_by_lua_block {{
                local sem = assert(require("ngx.semaphore").new())
                local result
                assert(ngx.timer.at(0, function(premature)
                    assert(not premature)
                    result = require("resolve_format")("timer.example", "ipv4")
                    sem:post()
                end))
                assert(sem:wait(1))
                ngx.say(result)
            }}
        }}
    }}
    server {{
        listen 127.0.0.1:{no_dns_port};
        location / {{
            content_by_lua_block {{
                ngx.say(require("resolve_format")(ngx.var.arg_host, ngx.var.arg_family))
            }}
        }}
    }}
}}
stream {{
    init_by_lua_block {{
        package.loaded.resolve_format = dofile("{directory}/resolve-format.lua")
    }}
    server {{
        listen 127.0.0.1:{stream_port};
        resolver 127.0.0.1:{dns_ports[0]} ipv6=off;
        resolver_timeout 250ms;
        preread_by_lua_block {{
            local lookup = require "resolve_format"
            ngx.ctx.answer = lookup("stream.example", "ipv4")
            ngx.ctx.ptr4 = lookup("192.0.2.1", "ptr")
            ngx.ctx.ptr6 = lookup("2001:db8::1", "ptr")
        }}
        content_by_lua_block {{
            ngx.say(ngx.ctx.answer)
            ngx.say(ngx.ctx.ptr4, " ", ngx.ctx.ptr6)
        }}
    }}
}}
""")
    binary = os.environ["TEST_NGINX_BINARY"]
    with (directory / "stderr.log").open("w") as log:
        nginx = subprocess.Popen(
            [binary, "-p", tmp, "-c", str(config)], stderr=log
        )
        try:
            assert wait_for_nginx(nginx, http_port) == "ok"

            def request(path):
                return http_request(path, http_port)

            assert request("/resolve?host=ALIAS.example.") == (
                "4/127.0.0.2,4/127.0.0.3,6/::1"
            )
            assert request("/resolve?host=alias.example&family=ipv6") == "6/::1"
            assert queries[0, "alias.example", 1] == 1, queries
            print("PASS HTTP precontent resolves CNAME and all A/AAAA addresses")

            assert request("/preaccess") == "4/127.0.0.1"
            assert queries[0, "preaccess.example", 1] == 1, queries
            print("PASS HTTP preaccess can wait for a DNS response")

            assert request("/parallel") == "4/127.0.0.1\n6/::1\n4/127.0.0.4"
            assert queries[0, "coalesced.example", 1] == 1, queries
            assert queries[0, "coalesced.example", 28] == 1, queries
            assert request("/cancel") == "4/127.0.0.1"
            print("PASS concurrent coroutines coalesce queries and cancel independently")

            assert request("/resolve?host=cached.example&family=ipv4") == "4/127.0.0.1"
            assert request("/cosocket") == "connected"
            assert queries[0, "cached.example", 1] == 1, queries
            assert request("/resolve?host=backup.example&family=ipv4") == "4/127.0.0.1"
            assert queries[1, "backup.example", 1] == 1, queries
            print("PASS FFI shares the native cache and uses nameserver failover")

            assert "Host not found" in request("/resolve?host=missing.example")
            assert "timed out" in request("/resolve?host=timeout.example").lower()
            assert request("/ipv4-only") == "no addresses for the requested family"
            assert queries[0, "only-v4.example", 28] == 0, queries
            assert http_request("/?host=without.example", no_dns_port) == "no resolver defined"
            assert http_request("/?host=::1", no_dns_port) == "6/::1"
            print("PASS DNS errors, family filtering and IP literals")

            for addr in ("192.0.2.1", "2001:db8::1"):
                path = f"/resolve?host={addr}&family=ptr"
                assert request(path) == "ptr.example"
                assert request(path) == "ptr.example"
                assert queries[0, ip_address(addr).reverse_pointer, 12] == 1, queries
            assert request("/resolve?host=invalid.example&family=ptr") == "invalid IP address"
            assert "Host not found" in request("/resolve?host=192.0.2.3&family=ptr")
            assert "timed out" in request("/resolve?host=192.0.2.4&family=ptr").lower()
            assert request("/resolve?host=192.0.2.5&family=ptr") == "ptr.example"
            assert queries[1, ip_address("192.0.2.5").reverse_pointer, 12] == 1, queries
            assert http_request("/?host=192.0.2.1&family=ptr", no_dns_port) == "no resolver defined"
            assert request("/ptr-parallel") == "ptr.example"
            assert queries[0, ip_address("192.0.2.2").reverse_pointer, 12] == 1, queries
            print("PASS IPv4/IPv6 PTR, cache, failover, errors and coroutine cancellation")

            with socket.create_connection(("127.0.0.1", stream_port), 5) as sock:
                sock.sendall(b"x")
                output = b"4/127.0.0.1\nptr.example ptr.example\n"
                assert sock.makefile("rb").read(len(output)) == output
            assert request("/timer") == "4/127.0.0.1"
            assert request("/balanced") == "ok"
            print("PASS Stream preread, HTTP timers and balancer context checks")
        except BaseException:
            for name in ("stderr.log", "error.log"):
                path = directory / name
                if path.exists():
                    print(path.read_text(errors="replace")[-6000:])
            raise
        finally:
            nginx.terminate()
            nginx.wait(timeout=5)
    check_logs(directory)
    assert nginx.returncode == 0, nginx.returncode
