# Copyright (C) Hanada

import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from common import check_logs

binary = Path(os.environ["TEST_NGINX_BINARY"]).resolve()
directory = Path(tempfile.mkdtemp(prefix="resolver-lifecycle-"))
(directory / "logs").mkdir()
waiting = threading.Event()
single = len(sys.argv) > 1 and sys.argv[1] == "single"
sockets = []
for _ in range(2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)


def dns_server(index):
    sock = sockets[index]
    while True:
        data, peer = sock.recvfrom(65535)
        position = 12
        while data[position]:
            position += data[position] + 1
        position += 1
        qtype = int.from_bytes(data[position : position + 2], "big")
        if index == 0 and qtype == 1:
            waiting.set()
            continue

        code = 2
        answer = b""
        if (single or index == 1) and qtype == 33:
            code = 0
            target = b"\x0bcycle-child\x07example\0"
            value = struct.pack("!HHH", 0, 1, 80) + target
            answer = struct.pack("!HHHIH", 0xC00C, 33, 1, 1, len(value)) + value
        header = struct.pack(
            "!HHHHHH",
            int.from_bytes(data[:2], "big"),
            0x8180 | code,
            1,
            bool(answer),
            0,
            0,
        )
        sock.sendto(header + data[12 : position + 4] + answer, peer)


for index in range(2):
    threading.Thread(target=dns_server, args=(index,), daemon=True).start()

config = directory / "nginx.conf"
second = "" if single else f"server 127.0.0.1:{sockets[1].getsockname()[1]} level=2;"
config.write_text(f"""daemon off; master_process off;
error_log {directory}/error.log debug; pid {directory}/pid;
events {{}}
http {{
    nameserver dns {{
        server 127.0.0.1:{sockets[0].getsockname()[1]};
        {second}
    }}
    resolver dns ipv6=off;
    resolver_timeout 30s;
    resolver_next_nameserver error timeout rcode_servfail;
    upstream background {{
        zone background 64k;
        server cycle.example service=_web._tcp resolve;
    }}
}}""")
with (directory / "stderr.log").open("w") as log:
    proc = subprocess.Popen(
        [str(binary), "-p", str(directory), "-c", str(config)], stderr=log
    )
    try:
        deadline = time.monotonic() + 10
        while not waiting.wait(0.05) and time.monotonic() < deadline:
            if proc.poll() is not None:
                break
        assert waiting.is_set(), directory
    finally:
        proc.terminate()
        proc.wait(timeout=5)
check_logs(directory)
assert proc.returncode == 0, (proc.returncode, directory)
print(
    "PASS shutdown cleans active SRV target queries"
    if single
    else "PASS shutdown cleans an SRV target query after its parent used a backup"
)
if not single:
    subprocess.run([sys.executable, __file__, "single"], check=True)
