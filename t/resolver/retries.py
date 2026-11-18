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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import check_logs

binary = Path(os.environ["TEST_NGINX_BINARY"]).resolve()
root = Path(tempfile.gettempdir())
directory = Path(tempfile.mkdtemp(prefix="resolver-retry-", dir=root))
(directory / "logs").mkdir()
counts = Counter()
attempts = {}
lock = threading.Lock()
sockets = []
ports = []
for _ in range(3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
    ports.append(sock.getsockname()[1])


def dns_server(index):
    sock = sockets[index]
    while True:
        data, peer = sock.recvfrom(65535)
        pos, labels = 12, []
        while data[pos]:
            length = data[pos]
            labels.append(data[pos + 1 : pos + 1 + length].decode())
            pos += length + 1
        pos += 1
        name = ".".join(labels)
        qtype, _qclass = struct.unpack("!HH", data[pos : pos + 4])
        with lock:
            counts[name, index, qtype] += 1
            attempts.setdefault(name, []).append(index)
        if name.startswith("health_drop."):
            continue
        if name.startswith(("drop.", "shared.")) and index == 0:
            continue
        code = 2 if index == 0 else 0
        if name == "window_shared.example":
            time.sleep(0.08)
        if name.startswith("active."):
            time.sleep(0.3)
            code = 0
        if name.startswith("slow."):
            time.sleep(5.3)
            code = 0
        if index == 0 and name.startswith("shortformerr."):
            sock.sendto(
                struct.pack(
                    "!HHHHHH", int.from_bytes(data[:2], "big"), 0x8001, 0, 0, 0, 0
                ),
                peer,
            )
            continue
        if index == 0 and name.startswith("formerr."):
            code = 1
        if index == 0 and name.startswith("rcode6."):
            code = 6
        if index == 0 and name.startswith(("invalid.", "loop.", "edns.")):
            code = 0
        if name.startswith(("all.", "health.")) or (
            name == "priority.example" and index != 2
        ):
            code = 2
        if name.startswith("empty.") and index == 0:
            code = 0
        if name.startswith("fresh."):
            code = 0
        answer = b""
        if code == 0 and not (name.startswith("empty.") and index == 0) and qtype == 1:
            answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 30, 4) + socket.inet_aton(
                "127.0.0.1"
            )
        reply = (
            struct.pack(
                "!HHHHHH",
                struct.unpack("!H", data[:2])[0],
                0x8180 | code,
                1,
                bool(answer),
                0,
                0,
            )
            + data[12 : pos + 4]
            + answer
        )
        if index == 0 and name.startswith("invalid."):
            reply = reply[:2] + b"\0\0" + reply[4:]
        if index == 0 and name.startswith("loop."):
            offset = pos + 4 + 12
            answer = struct.pack("!HHHIHH", 0xC00C, 5, 1, 30, 2, 0xC000 | offset)
            reply = (
                struct.pack(
                    "!HHHHHH", int.from_bytes(data[:2], "big"), 0x8180, 1, 1, 0, 0
                )
                + data[12 : pos + 4]
                + answer
            )
        if index == 0 and name.startswith("edns."):
            reply = (
                reply[:10]
                + b"\0\1"
                + reply[12:]
                + b"\0"
                + struct.pack("!HHIH", 41, 1232, 1 << 24, 0)
            )
        sock.sendto(reply, peer)


for i in range(3):
    threading.Thread(target=dns_server, args=(i,), daemon=True).start()

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

config = f"""
daemon off;
master_process off;
error_log {directory}/error.log debug;
pid {directory}/nginx.pid;
events {{}}
http {{
    access_log off;
    nameserver levels {{ server 127.0.0.1:{ports[1]} level=2; server 127.0.0.1:{ports[0]}; }}
    nameserver priority {{ server 127.0.0.1:{ports[2]} level=20; server 127.0.0.1:{ports[0]} level=5; server 127.0.0.1:{ports[1]} level=5; }}
    nameserver health {{ server 127.0.0.1:{ports[0]} max_fails=1; server 127.0.0.1:{ports[1]} level=2 max_fails=1; }}
    resolver 127.0.0.1:{ports[0]} 127.0.0.1:{ports[1]} ipv6=off;
    server {{
        listen 127.0.0.1:{port};
        resolver_timeout 7s;
        location = /origin {{ return 200 "ok"; }}
        location /default {{ resolver 127.0.0.1:{ports[0]} 127.0.0.1:{ports[1]} ipv6=off; proxy_pass http://$arg_name:{port}/origin; }}
        location /invalid {{ resolver 127.0.0.1:{ports[0]} 127.0.0.1:{ports[1]} ipv6=off; resolver_next_nameserver invalid_response rcode_formerr; proxy_pass http://$arg_name:{port}/origin; }}
        location /retry {{ resolver 127.0.0.1:{ports[0]} 127.0.0.1:{ports[1]} ipv6=off; resolver_next_nameserver rcode_servfail; proxy_pass http://$arg_name:{port}/origin; }}
        location /levels {{ resolver levels ipv6=off; resolver_next_nameserver error timeout rcode_servfail; proxy_pass http://$arg_name:{port}/origin; }}
        location /levels_cache {{ resolver levels ipv6=off error_valid=10s; resolver_next_nameserver rcode_servfail; resolver_next_nameserver_tries 2; proxy_pass http://$arg_name:{port}/origin; }}
        location /priority {{ resolver priority ipv6=off; resolver_next_nameserver rcode_servfail; proxy_pass http://$arg_name:{port}/origin; }}
        location /shared_window {{
            resolver 127.0.0.1:{ports[0]} ipv6=off;
            resolver_next_nameserver rcode_servfail;
            location /shared_window/short {{ resolver_next_nameserver_timeout 100ms; proxy_pass http://$arg_name:{port}/origin; }}
            location /shared_window/long {{ resolver_next_nameserver_timeout 300ms; proxy_pass http://$arg_name:{port}/origin; }}
        }}
        location /transport {{
            resolver health ipv6=off;
            resolver_timeout 300ms;
            location /transport/warm {{ proxy_pass http://$arg_name:{port}/origin; }}
            location /transport/off {{ resolver_next_nameserver off; proxy_pass http://$arg_name:{port}/origin; }}
        }}
        location /health {{ resolver health ipv6=off; resolver_next_nameserver error timeout rcode_servfail; resolver_next_nameserver_tries 2; proxy_pass http://$arg_name:{port}/origin; }}
        location /one {{ resolver 127.0.0.1:{ports[0]} 127.0.0.1:{ports[1]} ipv6=off; resolver_next_nameserver rcode_servfail; resolver_next_nameserver_tries 1; proxy_pass http://$arg_name:{port}/origin; }}
        location /off_wait {{ resolver 127.0.0.1:{ports[0]} ipv6=off; resolver_next_nameserver error timeout; resolver_next_nameserver OFF; resolver_timeout 8s; proxy_pass http://$arg_name:{port}/origin; }}
        location /off {{ resolver_next_nameserver off; proxy_pass http://$arg_name:{port}/origin; }}
        location /long {{ resolver_next_nameserver_tries 2; proxy_pass http://$arg_name:{port}/origin; }}
        location /short {{ resolver_next_nameserver_tries 1; proxy_pass http://$arg_name:{port}/origin; }}
        location /empty {{ resolver 127.0.0.1:{ports[0]} 127.0.0.1:{ports[1]} ipv6=off; resolver_next_nameserver nodata; proxy_pass http://$arg_name:{port}/origin; }}
        location /window {{ resolver 127.0.0.1:{ports[0]} ipv6=off; resolver_next_nameserver rcode_servfail; resolver_next_nameserver_timeout 100ms; proxy_pass http://$arg_name:{port}/origin; }}
        location /active {{ resolver 127.0.0.1:{ports[0]} ipv6=off; resolver_next_nameserver_timeout 100ms; proxy_pass http://$arg_name:{port}/origin; }}
        location /round {{ resolver 127.0.0.1:{ports[0]} 127.0.0.1:{ports[1]} ipv6=off; resolver_next_nameserver rcode_servfail; resolver_next_nameserver_tries 4; proxy_pass http://$arg_name:{port}/origin; }}
    }}
}}
"""
(directory / "nginx.conf").write_text(config)
log = (directory / "stderr.log").open("w")
proc = subprocess.Popen(
    [str(binary), "-p", str(directory), "-c", str(directory / "nginx.conf")], stderr=log
)


def request(path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path)
        res = conn.getresponse()
        res.read()
        return res.status
    finally:
        conn.close()


results = []


def check(path, status):
    actual = request(path)
    assert actual == status, (path, actual, status, directory)
    results.append(f"PASS {path}: {actual}")


try:
    for _ in range(100):
        try:
            request("/origin")
            break
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError((directory / "stderr.log").read_text())
            time.sleep(0.02)
    check("/off_wait?name=slow.example", 200)
    assert counts["slow.example", 0, 1] == 1, dict(counts)
    results.append(
        "PASS off overrides merged conditions and keeps waiting without retransmitting"
    )
    started = time.monotonic()
    check("/window?name=window.example", 502)
    assert time.monotonic() - started < 1, directory
    assert counts["window.example", 0, 1] == 1, dict(counts)
    assert (
        "window.example could not be resolved (2: Server failure)"
        in (directory / "error.log").read_text()
    ), directory
    check("/active?name=active.example", 200)
    results.append(
        "PASS retry window bounds backoff but does not interrupt an active attempt"
    )
    check("/default?name=default.example", 502)
    assert counts["default.example", 1, 1] == 0
    check("/retry?name=retry.example", 200)
    check("/levels?name=level.example", 200)
    check("/levels?name=level.example", 200)
    assert attempts["level.example"] == [0, 1], dict(attempts)
    results.append("PASS backup success is cached with error caching disabled")
    check("/priority?name=priority.example", 200)
    assert attempts["priority.example"] == [0, 1, 2], dict(attempts)
    results.append("PASS priority orders attempts before trying the backup")
    check("/levels_cache?name=all.levels.example", 502)
    check("/levels_cache?name=all.levels.example", 502)
    assert attempts["all.levels.example"] == [0, 1], dict(attempts)
    results.append("PASS final failure is cached after trying primary and backup")
    started = time.monotonic()
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(request, "/shared_window/short?name=window_shared.example")
        time.sleep(0.02)
        second = pool.submit(request, "/shared_window/long?name=window_shared.example")
        assert (first.result(), second.result()) == (502, 502), directory
    assert counts["window_shared.example", 0, 1] == 1, dict(counts)
    assert 0.25 <= time.monotonic() - started < 1, directory
    results.append("PASS coalesced waiters retain independent retry windows")
    check("/one?name=one.example", 502)
    assert counts["one.example", 1, 1] == 0
    check("/empty?name=empty.example", 200)
    for prefix in ("formerr", "shortformerr", "rcode6", "invalid", "loop", "edns"):
        check(f"/invalid?name={prefix}.example", 200)
        assert (
            counts[prefix + ".example", 0, 1] == 1
            and counts[prefix + ".example", 1, 1] == 1
        ), (prefix, dict(counts), directory)
        check(f"/invalid?name=fresh.{prefix}.example", 200)
    results.append("PASS FORMERR, malformed replies and extended RCODE retries")
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(request, "/short?name=shared.example")
        time.sleep(0.1)
        second = pool.submit(request, "/long?name=shared.example")
        assert (first.result(), second.result()) == (502, 200), directory
    results.append("PASS shared query: independent attempt limits")
    assert counts["shared.example", 0, 1] == 1 and counts["shared.example", 1, 1] == 1
    started = time.monotonic()
    check("/round?name=all.example", 502)
    elapsed = time.monotonic() - started
    assert elapsed >= 4.5, (elapsed, directory)
    assert counts["all.example", 0, 1] == 2 and counts["all.example", 1, 1] == 2
    for i in range(3):
        check(f"/health?name=health.{i}.example", 502)
    results.append("PASS RCODE errors remain eligible for later queries")
    check("/transport/warm?name=health_drop.0.example", 502)
    check("/transport/off?name=health_good.example", 200)
    assert (
        counts["health_good.example", 0, 1] == 0
        and counts["health_good.example", 1, 1] == 1
    ), dict(counts)
    check("/transport/warm?name=health_drop.1.example", 502)
    check("/transport/warm?name=health_drop.2.example", 502)
    assert counts["health_drop.0.example", 0, 1] == 1, dict(counts)
    assert counts["health_drop.1.example", 1, 1] == 1, dict(counts)
    assert counts["health_drop.2.example", 0, 1] == 1, dict(counts)
    results.append(
        "PASS transport health, initial health filtering with off, and all-failed fallback"
    )
finally:
    proc.terminate()
    proc.wait(timeout=5)
    log.close()
    check_logs(directory)
    assert proc.returncode == 0, (
        proc.returncode,
        (directory / "stderr.log").read_text(),
        directory,
    )
    (directory / "results.log").write_text(
        "\n".join(results) + "\n" + repr(dict(counts)) + "\n" + str(directory)
    )
print("\n".join(results))
