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

from common import check_logs, has_module

binary = Path(os.environ["TEST_NGINX_BINARY"]).resolve()
root = Path(tempfile.gettempdir())
stream = has_module("stream")
mail = has_module("mail")
directory = Path(tempfile.mkdtemp(prefix="resolver-protocols-", dir=root))
(directory / "logs").mkdir()
counts = Counter()
lock = threading.Lock()
sockets = []
dns_ports = []
for _ in range(3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
    dns_ports.append(sock.getsockname()[1])


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


http_port, stream_port, stream_up_port, mail_port, mail_off_port = [
    port() for _ in range(5)
]


def encode(name):
    return (
        b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
        + b"\0"
    )


def dns_server(index):
    sock = sockets[index]
    while True:
        data, peer = sock.recvfrom(65535)
        p, labels = 12, []
        while data[p]:
            length = data[p]
            labels.append(data[p + 1 : p + length + 1].decode())
            p += length + 1
        p += 1
        name = ".".join(labels)
        typ, cls = struct.unpack("!HH", data[p : p + 4])
        with lock:
            counts[index, name, typ] += 1
        if name.startswith("alias-window."):
            time.sleep(0.2)
        if typ == 12:
            rdata = encode("client.example")
        elif typ == 33:
            rdata = struct.pack("!HHH", 0, 1, http_port) + encode("srv-target.example")
        elif name.startswith("alias"):
            typ = 5
            rdata = encode(
                "window-target.example"
                if name.startswith("alias-window.")
                else "target.example"
            )
        else:
            rdata = socket.inet_aton("127.0.0.1")
        answer = struct.pack("!HHHIH", 0xC00C, typ, cls, 30, len(rdata)) + rdata
        reply = (
            struct.pack("!HHHHHH", int.from_bytes(data[:2], "big"), 0x8180, 1, 1, 0, 0)
            + data[12 : p + 4]
            + answer
        )
        sock.sendto(reply, peer)


for i in range(3):
    threading.Thread(target=dns_server, args=(i,), daemon=True).start()

conf = f"""daemon off; master_process off; error_log {directory}/error.log debug; pid {directory}/nginx.pid;
events {{}}
http {{ access_log off;
resolver localhost ipv6=off;
resolver_next_nameserver_tries 3;
upstream dynamic {{ zone dynamic 64k; server dynamic.example:{http_port} resolve; }}
upstream service1 {{ zone service1 64k; server srv1.example service=_web._tcp resolve; resolver_next_nameserver_tries 1; }}
upstream service2 {{ zone service2 64k; server srv2.example service=_web._tcp resolve; resolver_next_nameserver_tries 2; }}
server {{ listen 127.0.0.1:{http_port}; resolver_timeout 1s;
location = /origin {{ return 200 ok; }}
location /http {{ proxy_pass http://http.example:{http_port}/origin; proxy_pass_request_headers off; }}
location /variable {{ proxy_pass http://$arg_name:{http_port}/origin; }}
location /dynamic {{ proxy_pass http://dynamic/origin; }}
location /srv1 {{ proxy_pass http://service1/origin; }}
location /srv2 {{ proxy_pass http://service2/origin; }}
location /one {{ resolver localhost ipv6=off; resolver_next_nameserver_tries 1; proxy_pass http://$arg_name:{http_port}/origin; }}
location /window {{ resolver localhost ipv6=off; resolver_next_nameserver_timeout 100ms; proxy_pass http://$arg_name:{http_port}/origin; }}
location /two {{ resolver localhost ipv6=off; resolver_next_nameserver_tries 2; proxy_pass http://$arg_name:{http_port}/origin; }}
}}
nameserver localhost {{ server 127.0.0.1:{dns_ports[0]}; }}
}}
stream {{
resolver dns.invalid ipv6=off;
resolver_timeout 1s;
resolver_next_nameserver_tries 2;
upstream dynamic {{ zone stream_dynamic 64k; server stream-dynamic.example:{http_port} resolve; }}
server {{ listen 127.0.0.1:{stream_port}; set $target stream.example:{http_port}; proxy_pass $target; }}
server {{ listen 127.0.0.1:{stream_up_port}; proxy_pass dynamic; }}
nameserver dns.invalid {{ server 127.0.0.1:{dns_ports[1]}; }}
}}
mail {{
resolver dns.invalid ipv6=off;
resolver_timeout 1s;
resolver_next_nameserver_tries 2;
auth_http 127.0.0.1:{http_port}/auth;
smtp_auth none;
server_name fixture.example;
server {{ listen 127.0.0.1:{mail_port}; protocol smtp; }}
server {{ listen 127.0.0.1:{mail_off_port}; protocol smtp; resolver off; }}
nameserver dns.invalid {{ server 127.0.0.1:{dns_ports[2]}; }}
}}
"""
if not mail:
    conf = conf[: conf.index("\nmail {")]
if not stream:
    start = conf.index("\nstream {")
    end = conf.index("\nmail {") if mail else len(conf)
    conf = conf[:start] + conf[end:]

# The literal host is intentionally used through a variable below; a static
# proxy_pass host would invoke the operating-system resolver during loading.
conf = conf.replace(
    "proxy_pass http://http.example:",
    "set $http_target http.example; proxy_pass http://$http_target:",
)
(directory / "nginx.conf").write_text(conf)
log = (directory / "stderr.log").open("w")
proc = subprocess.Popen(
    [str(binary), "-p", str(directory), "-c", str(directory / "nginx.conf")], stderr=log
)


def get(path, listen=http_port):
    conn = http.client.HTTPConnection("127.0.0.1", listen, timeout=3)
    try:
        conn.request("GET", path)
        res = conn.getresponse()
        body = res.read()
        return res.status, body
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
    for path in ("/http", "/variable?name=variable.example", "/dynamic", "/srv2"):
        for _ in range(100):
            status, body = get(path)
            if status == 200:
                break
            time.sleep(0.02)
        assert status == 200 and body == b"ok", (path, status, body, directory)
    assert get("/srv1")[0] == 502, directory
    assert get("/one?name=alias1.example")[0] == 502, directory
    assert get("/two?name=alias2.example") == (200, b"ok"), directory
    results.append("PASS HTTP core/upstream inheritance and CNAME/SRV attempt budgets")
    assert get("/window?name=alias-window.example")[0] == 502, directory
    assert counts[0, "window-target.example", 1] == 0, dict(counts)
    results.append("PASS CNAME follow-up does not restart the retry window")

    if stream:
        for listen in (stream_port, stream_up_port):
            assert get("/origin", listen) == (200, b"ok"), directory
        results.append("PASS Stream variable proxy and dynamic upstream")
    if mail:
        for listen in (mail_port, mail_off_port):
            with socket.create_connection(("127.0.0.1", listen), timeout=3) as conn:
                greeting = conn.recv(1024)
                assert greeting.startswith(b"220"), (listen, greeting, directory)
        results.append("PASS Mail reverse/forward lookup and resolver off")
    assert counts[0, "http.example", 1] == 1, dict(counts)
    if stream:
        assert counts[1, "stream.example", 1] == 1, dict(counts)
    if mail:
        assert counts[2, "1.0.0.127.in-addr.arpa", 12] == 1, dict(counts)
        assert counts[2, "client.example", 1] == 1, dict(counts)
        assert not any(
            (i == 2 and name not in ("client.example", "1.0.0.127.in-addr.arpa"))
            for i, name, typ in counts
        ), dict(counts)
    results.append("PASS nameserver namespace isolation across enabled protocols")
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
