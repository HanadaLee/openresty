# Copyright (C) Hanada

import os
import subprocess
import tempfile
from pathlib import Path

from common import has_module

binary = Path(os.environ["TEST_NGINX_BINARY"]).resolve()
root = Path(tempfile.gettempdir())

directory = Path(tempfile.mkdtemp(prefix="resolver-config-", dir=root))
(directory / "logs").mkdir()
(directory / "resolv.conf").write_text("# test\nnameserver 127.0.0.1\nnameserver ::1")
protocols = ["http"] + [p for p in ("stream", "mail") if has_module(p)]

good = [
    *(
        (
            f"{p}-forward",
            f"{p} {{ resolver dns.invalid; nameserver dns.invalid {{ server 127.0.0.1; }} }}",
        )
        for p in protocols
    ),
    (
        "namespaces",
        " ".join(
            f"{p} {{ nameserver dns {{ server 127.0.0.1; }} resolver dns; }}"
            for p in protocols
        ),
    ),
    (
        "mail-off",
        "mail { nameserver off { server 127.0.0.1; } resolver off; resolver_next_nameserver rcode_refused; }",
    ),
    (
        "local",
        f"http {{ nameserver dns {{ local {directory}/resolv.conf level=2 weight=3 max_fails=2 fail_timeout=7s; }} resolver dns; }}",
    ),
    ("hostname-fallback", "http { resolver localhost; }"),
    (
        "options",
        "http { resolver 127.0.0.1 ipv4=on ipv6=off min_ttl=1s max_ttl=1m negative_valid=10s error_valid=1s stale_valid=5m; resolver_next_nameserver error timeout rcode_servfail; resolver_next_nameserver_tries 3; resolver_next_nameserver_timeout 2s; }",
    ),
    (
        "http-upstream",
        "http { upstream u { zone u 64k; resolver dns.invalid; resolver_next_nameserver off; server localhost:80 resolve; } nameserver dns.invalid { server 127.0.0.1; } }",
    ),
    (
        "stream-upstream",
        "stream { upstream u { zone u 64k; resolver dns.invalid; resolver_next_nameserver_tries 2; server localhost:80 resolve; } nameserver dns.invalid { server 127.0.0.1; } }",
    ),
    (
        "off-condition",
        "http { resolver_next_nameserver off error; }",
    ),
]
bad = [
    (
        "unknown-nameserver",
        "http { resolver dns.invalid; }",
        "host not found",
    ),
    (
        "duplicate-group",
        "http { nameserver dns { server 127.0.0.1; } nameserver dns { server 127.0.0.1; } }",
        "duplicate nameserver",
    ),
    ("empty-group", "http { nameserver dns { } }", "no servers"),
    (
        "bootstrap",
        "stream { nameserver dns { server 127.0.0.1 bootstrap=127.0.0.2; } }",
        "invalid parameter",
    ),
    (
        "server-protocol",
        "http { nameserver dns { server 127.0.0.1 protocol=tcp; } }",
        'invalid parameter "protocol=tcp"',
    ),
    (
        "local-protocol",
        f"http {{ nameserver dns {{ local {directory}/resolv.conf protocol=udp; }} }}",
        'invalid parameter "protocol=udp"',
    ),
    (
        "tls",
        "mail { nameserver dns { server 127.0.0.1 protocol=tls; } }",
        "invalid parameter",
    ),
    ("valid-ttl", "http { resolver 127.0.0.1 valid=0 min_ttl=1s; }", "cannot be used"),
    (
        "min-max",
        "http { resolver 127.0.0.1 min_ttl=10s max_ttl=5s; }",
        "must not exceed",
    ),
    (
        "unprefixed-rcode",
        "stream { resolver_next_nameserver servfail; }",
        "invalid value",
    ),
    ("option-only", "http { resolver stale_valid=1m; }", "no name servers"),
]

results = []
environment = dict(os.environ)
if "ASAN_OPTIONS" in environment:
    # nginx -t exits without running the normal cycle cleanup.
    environment["ASAN_OPTIONS"] += ":detect_leaks=0"

for name, body, expected in [(n, b, None) for n, b in good] + bad:
    if body.split()[0] not in protocols:
        continue
    path = directory / (name + ".conf")
    path.write_text("error_log stderr;\nevents {}\n" + body + "\n")
    proc = subprocess.run(
        [str(binary), "-t", "-p", str(directory), "-c", str(path)],
        text=True,
        capture_output=True,
        env=environment,
        check=False,
    )
    passed = (
        proc.returncode == 0
        if expected is None
        else proc.returncode != 0 and expected in proc.stderr
    )
    results.append(
        f"{'PASS' if passed else 'FAIL'} {name}\n{proc.stderr if not passed else ''}"
    )
(directory / "results.log").write_text("\n".join(results))
print("\n".join(results))
assert all(line.startswith("PASS") for line in results)
