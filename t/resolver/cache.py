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
from pathlib import Path

from common import check_logs

binary = Path(os.environ["TEST_NGINX_BINARY"]).resolve()
root = Path(tempfile.gettempdir())
directory = Path(tempfile.mkdtemp(prefix="resolver-cache-", dir=root))
(directory / "logs").mkdir()
counts = Counter()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
dns_port = sock.getsockname()[1]


def server():
    while True:
        data, peer = sock.recvfrom(65535)
        p, labels = 12, []
        while data[p]:
            size = data[p]
            labels.append(data[p + 1 : p + size + 1].decode())
            p += size + 1
        p += 1
        name = ".".join(labels)
        counts[name] += 1
        if name.startswith("silent."):
            continue
        rcode = (
            0 if name.startswith("empty.") else 2 if name.startswith("error.") else 3
        )
        authority = b""
        if name.startswith(("soa.", "minimum.", "zero.")):
            ttl = 1 if name.startswith("soa.") else 30
            minimum = (
                1
                if name.startswith("minimum.")
                else 0
                if name.startswith("zero.")
                else 30
            )
            rdata = b"\0\0" + struct.pack("!IIIII", 1, 2, 3, 4, minimum)
            authority = struct.pack("!HHHIH", 0xC00C, 6, 1, ttl, len(rdata)) + rdata
        reply = (
            struct.pack(
                "!HHHHHH",
                int.from_bytes(data[:2], "big"),
                0x8180 | rcode,
                1,
                0,
                bool(authority),
                0,
            )
            + data[12 : p + 4]
            + authority
        )
        sock.sendto(reply, peer)


threading.Thread(target=server, daemon=True).start()
with socket.socket() as temp:
    temp.bind(("127.0.0.1", 0))
    port = temp.getsockname()[1]
conf = f"""daemon off; master_process off; error_log {directory}/error.log debug; pid {directory}/nginx.pid;
events {{}}
http {{ access_log off;
nameserver dns {{ server 127.0.0.1:{dns_port}; }}
server {{ listen 127.0.0.1:{port}; resolver_timeout 2s;
location = /origin {{ return 200 ok; }}
location /negative {{ resolver 127.0.0.1:{dns_port} ipv6=off negative_valid=30s; proxy_pass http://$arg_name:{port}/origin; }}
location /group {{ resolver dns ipv6=off negative_valid=30s; proxy_pass http://$arg_name:{port}/origin; }}
location /error {{ resolver 127.0.0.1:{dns_port} ipv6=off error_valid=30s; proxy_pass http://$arg_name:{port}/origin; }}
location /valid {{ resolver 127.0.0.1:{dns_port} ipv6=off negative_valid=30s valid=1s; proxy_pass http://$arg_name:{port}/origin; }}
location /silent {{ resolver 127.0.0.1:{dns_port} ipv6=off error_valid=1s; resolver_timeout 100ms; proxy_pass http://$arg_name:{port}/origin; }}
location /default {{ resolver 127.0.0.1:{dns_port} ipv6=off; proxy_pass http://$arg_name:{port}/origin; }}
}} }}"""
(directory / "nginx.conf").write_text(conf)
log = (directory / "stderr.log").open("w")
proc = subprocess.Popen(
    [str(binary), "-p", str(directory), "-c", str(directory / "nginx.conf")], stderr=log
)


def get(path, status=502):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
    try:
        conn.request("GET", path)
        res = conn.getresponse()
        res.read()
        assert res.status == status, (path, res.status, status, directory)
    finally:
        conn.close()


results = []
try:
    for _ in range(100):
        try:
            get("/origin", 200)
            break
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError((directory / "stderr.log").read_text())
            time.sleep(0.02)
    for path, name, expected in [
        ("/negative", "nx.example", 1),
        ("/negative", "empty.example", 1),
        ("/error", "error.example", 1),
        ("/negative", "error.unconfigured", 2),
        ("/default", "nx.default", 2),
        ("/negative", "zero.example", 2),
    ]:
        for _ in range(2):
            get(f"{path}?name={name}")
        assert counts[name] == expected, (name, dict(counts), directory)
        results.append(f"PASS {name}: {expected} queries")
    get("/silent?name=silent.example")
    get("/silent?name=silent.example")
    assert counts["silent.example"] == 1, (dict(counts), directory)
    results.append("PASS timeout error cache suppresses a repeated query")
    for path, name in [
        ("/negative", "soa.example"),
        ("/group", "soa.group.example"),
        ("/negative", "minimum.example"),
        ("/valid", "valid.example"),
    ]:
        get(f"{path}?name={name}")
        get(f"{path}?name={name}")
        assert counts[name] == 1, (name, dict(counts), directory)
    time.sleep(2.1)
    for path, name in [
        ("/negative", "soa.example"),
        ("/group", "soa.group.example"),
        ("/negative", "minimum.example"),
        ("/valid", "valid.example"),
    ]:
        get(f"{path}?name={name}")
        assert counts[name] == 2, (name, dict(counts), directory)
        results.append(f"PASS {name}: cache TTL capped")
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
