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
directory = Path(tempfile.mkdtemp(prefix="resolver-stale-", dir=root))
(directory / "logs").mkdir()
counts = Counter()
refresh_ready = threading.Event()
refresh_release = threading.Event()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
dns_port = sock.getsockname()[1]
lock = threading.Lock()


def reply(data, peer):
    p, labels = 12, []
    while data[p]:
        size = data[p]
        labels.append(data[p + 1 : p + size + 1].decode())
        p += size + 1
    p += 1
    name = ".".join(labels)
    with lock:
        counts[name] += 1
        count = counts[name]
    code = 0
    if count > 1:
        if name.startswith("drop."):
            return
        if name.startswith("error."):
            code = 2
        elif name.startswith("negative."):
            code = 3
        else:
            if name == "refresh.example":
                refresh_ready.set()
                refresh_release.wait(3)
            else:
                time.sleep(0.4)
    addr = "127.0.0.1" if count == 1 else "127.0.0.2"
    ttl = 1 if count == 1 else 30
    answer = (
        b""
        if code
        else struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + socket.inet_aton(addr)
    )
    msg = (
        struct.pack(
            "!HHHHHH",
            int.from_bytes(data[:2], "big"),
            0x8180 | code,
            1,
            bool(answer),
            0,
            0,
        )
        + data[12 : p + 4]
        + answer
    )
    sock.sendto(msg, peer)


def server():
    while True:
        data, peer = sock.recvfrom(65535)
        threading.Thread(target=reply, args=(data, peer), daemon=True).start()


threading.Thread(target=server, daemon=True).start()
with socket.socket() as temp:
    temp.bind(("127.0.0.1", 0))
    port = temp.getsockname()[1]
conf = f"""daemon off; master_process off; error_log {directory}/error.log debug; pid {directory}/nginx.pid;
events {{}}
http {{ access_log off;
server {{ listen {port}; resolver_timeout 700ms;
location = /origin {{ return 200 $server_addr; }}
location /stale {{ resolver 127.0.0.1:{dns_port} ipv6=off stale_valid=3s; proxy_pass http://$arg_name:{port}/origin; }}
location /long {{ resolver 127.0.0.1:{dns_port} ipv6=off stale_valid=60s; proxy_pass http://$arg_name:{port}/origin; }}
}} }}"""
(directory / "nginx.conf").write_text(conf)
log = (directory / "stderr.log").open("w")
proc = subprocess.Popen(
    [str(binary), "-p", str(directory), "-c", str(directory / "nginx.conf")], stderr=log
)


def get(path, status=200, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
    try:
        conn.request("GET", path)
        res = conn.getresponse()
        actual = res.read()
        assert res.status == status, (path, res.status, status, directory)
        if body is not None:
            assert actual == body, (path, actual, body, directory)
        return actual
    finally:
        conn.close()


results = []
try:
    for _ in range(100):
        try:
            get("/origin")
            break
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError((directory / "stderr.log").read_text())
            time.sleep(0.02)
    get("/long?name=drop.idle.example", body=b"127.0.0.1")
    idle_started = time.monotonic()
    for name in ("refresh", "error", "negative", "drop"):
        get("/stale?name=" + name + ".example", body=b"127.0.0.1")
    initial = time.monotonic()
    time.sleep(2.1)
    with ThreadPoolExecutor(6) as pool:
        list(
            pool.map(
                lambda _: get("/stale?name=refresh.example", body=b"127.0.0.1"),
                range(6),
            )
        )
    assert refresh_ready.wait(1), directory
    assert counts["refresh.example"] == 2, (dict(counts), directory)
    refresh_release.set()
    time.sleep(0.2)
    get("/stale?name=refresh.example", body=b"127.0.0.2")
    results.append(
        "PASS stale returns immediately; refresh is single-flight and installs new value"
    )
    get("/stale?name=error.example", body=b"127.0.0.1")
    time.sleep(0.05)
    get("/stale?name=error.example", body=b"127.0.0.1")
    assert counts["error.example"] == 2, (dict(counts), directory)
    results.append("PASS failed refresh retains original positive value")
    get("/stale?name=negative.example", body=b"127.0.0.1")
    time.sleep(0.05)
    get("/stale?name=negative.example", 502)
    results.append("PASS negative refresh invalidates stale positive value")
    get("/stale?name=drop.example", body=b"127.0.0.1")
    time.sleep(max(0, 5.2 - (time.monotonic() - initial)))
    get("/stale?name=drop.example", 502)
    results.append("PASS stale lifetime is not renewed by cache hits or failed refresh")
    time.sleep(max(0, 32 - (time.monotonic() - idle_started)))
    get("/long?name=fresh.trigger.example", body=b"127.0.0.1")
    get("/long?name=drop.idle.example", body=b"127.0.0.1")
    results.append(
        "PASS stale cache survives the native 30-second idle eviction deadline"
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
