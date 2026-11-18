# Copyright (C) Hanada

import os
import re
import subprocess


def has_module(name):
    version = subprocess.run(
        [os.environ["TEST_NGINX_BINARY"], "-V"],
        capture_output=True,
        text=True,
        check=True,
    )
    return (
        re.search(r"(?:^|\s)--with-" + re.escape(name) + r"(?:\s|$)", version.stderr)
        is not None
    )


def check_logs(directory):
    for name in ("error.log", "stderr.log"):
        path = directory / name
        if not path.exists():
            continue

        text = path.read_text(errors="replace")
        failures = re.findall(
            r"^.*(?:\[(?:alert|crit)\]|AddressSanitizer|LeakSanitizer|"
            r"UndefinedBehaviorSanitizer|runtime error:).*$",
            text,
            re.MULTILINE,
        )
        assert not failures, (str(path), failures)
