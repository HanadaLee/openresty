# Copyright (C) Hanada

import errno
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
directory = Path(tempfile.mkdtemp(prefix="resolver-ttl-", dir=root))
(directory / "logs").mkdir()
counts = Counter()
lock = threading.Lock()

# TCP and UDP allocate ephemeral ports independently.
for _ in range(10):
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    address = tcp.getsockname()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.bind(address)
    except OSError as exc:
        udp.close()
        tcp.close()
        if exc.errno != errno.EADDRINUSE:
            raise
    else:
        tcp.listen()
        dns_port = address[1]
        break
else:
    raise RuntimeError("could not bind UDP and TCP on the same DNS port")


def response(data, protocol):
    ident = struct.unpack("!H", data[:2])[0]
    pos = 12
    labels = []
    while data[pos]:
        size = data[pos]
        labels.append(data[pos + 1 : pos + 1 + size].decode())
        pos += size + 1
    pos += 1
    qtype, qclass = struct.unpack("!HH", data[pos : pos + 4])
    name = ".".join(labels)
    with lock:
        counts[name, protocol] += 1
    if protocol == "udp" and name.startswith("truncated."):
        return struct.pack("!HHHHHH", ident, 0x8380, 1, 0, 0, 0) + data[12 : pos + 4]

    ttl = 0 if name.startswith(("min.", "default.")) else 30
    answer = b""
    if qtype == 1:
        answer = struct.pack("!HHHIH", 0xC00C, 1, qclass, ttl, 4) + socket.inet_aton(
            "127.0.0.1"
        )
    return (
        struct.pack("!HHHHHH", ident, 0x8180, 1, int(bool(answer)), 0, 0)
        + data[12 : pos + 4]
        + answer
    )


def udp_server(sock, label):
    while True:
        data, peer = sock.recvfrom(65535)
        sock.sendto(response(data, label), peer)


def tcp_client(conn):
    with conn:
        pending = b""
        while True:
            data = conn.recv(65535)
            if not data:
                return
            pending += data
            while len(pending) >= 2:
                size = struct.unpack("!H", pending[:2])[0]
                if len(pending) < size + 2:
                    break
                reply = response(pending[2 : 2 + size], "tcp")
                pending = pending[2 + size :]
                conn.sendall(struct.pack("!H", len(reply)) + reply)


def tcp_server():
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=tcp_client, args=(conn,), daemon=True).start()


udp2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp2.bind(("127.0.0.1", 0))
dns_port2 = udp2.getsockname()[1]
threading.Thread(target=udp_server, args=(udp, "udp"), daemon=True).start()
threading.Thread(target=udp_server, args=(udp2, "udp2"), daemon=True).start()
threading.Thread(target=tcp_server, daemon=True).start()
with socket.socket() as port_socket:
    port_socket.bind(("127.0.0.1", 0))
    http_port = port_socket.getsockname()[1]

config = f"""
daemon off;
master_process off;
error_log {directory}/error.log debug;
pid {directory}/nginx.pid;
events {{}}
http {{
    access_log off;
    nameserver dns {{ server 127.0.0.1:{dns_port}; }}
    nameserver weighted {{ server 127.0.0.1:{dns_port} weight=3; server 127.0.0.1:{dns_port2} weight=1; }}
    server {{
        listen 127.0.0.1:{http_port};
        resolver_timeout 2s;
        location = /origin {{ return 200 "ok"; }}
        location /min {{ resolver 127.0.0.1:{dns_port} ipv6=off min_ttl=5s; proxy_pass http://$arg_name:{http_port}/origin; }}
        location /max {{ resolver 127.0.0.1:{dns_port} ipv6=off max_ttl=1s; proxy_pass http://$arg_name:{http_port}/origin; }}
        location /default {{ resolver 127.0.0.1:{dns_port} ipv6=off; proxy_pass http://$arg_name:{http_port}/origin; }}
        location /fallback {{
            resolver dns ipv6=off;
            resolver_next_nameserver_tries 1;
            proxy_pass http://$arg_name:{http_port}/origin;
        }}
        location /weighted {{ resolver weighted ipv6=off; proxy_pass http://$arg_name:{http_port}/origin; }}
    }}
}}
"""
(directory / "nginx.conf").write_text(config)
stderr = (directory / "stderr.log").open("w")
proc = subprocess.Popen(
    [str(binary), "-p", str(directory), "-c", str(directory / "nginx.conf")],
    stderr=stderr,
)


def request(path):
    connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
    try:
        connection.request("GET", path)
        reply = connection.getresponse()
        body = reply.read()
        assert reply.status == 200 and body == b"ok", (path, reply.status, body)
    finally:
        connection.close()


results = []
try:
    for _ in range(100):
        try:
            request("/origin")
            break
        except (ConnectionError, OSError):
            if proc.poll() is not None:
                raise RuntimeError((directory / "stderr.log").read_text())
            time.sleep(0.02)
    else:
        raise RuntimeError("nginx did not start")
    for kind in ("min", "max", "default"):
        request(f"/{kind}?name={kind}.example")
    time.sleep(2.1)
    for kind, expected in (("min", 1), ("max", 2), ("default", 2)):
        request(f"/{kind}?name={kind}.example")
        assert counts[kind + ".example", "udp"] == expected, dict(counts)
        results.append(f"PASS {kind}: {expected} DNS queries")
    request("/fallback?name=truncated.example")
    assert counts["truncated.example", "udp"] == 1, dict(counts)
    assert counts["truncated.example", "tcp"] == 1, dict(counts)
    results.append("PASS truncated UDP response falls back to TCP in one attempt")
    for i in range(20):
        request(f"/weighted?name=weight{i}.example")
    total1 = sum(
        value
        for (name, protocol), value in counts.items()
        if name.startswith("weight") and protocol == "udp"
    )
    total2 = sum(
        value
        for (name, protocol), value in counts.items()
        if name.startswith("weight") and protocol == "udp2"
    )
    assert (total1, total2) == (15, 5), dict(counts)
    results.append("PASS weighted round robin: 15/5 queries for weights 3/1")
finally:
    proc.terminate()
    proc.wait(timeout=5)
    stderr.close()
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
