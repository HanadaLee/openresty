#!/usr/bin/env python3

"""Compare nginx and Lua module pins in two release Dockerfiles."""

import re
import shlex
import subprocess
import sys
from pathlib import PurePosixPath


def modules(dockerfile):
    dockerfile = re.sub(r"\\\r?\n", " ", dockerfile)
    arguments = {}
    for line in dockerfile.splitlines():
        if line.startswith("ARG ") and "=" in line:
            name, value = line[4:].split("=", 1)
            arguments[name] = shlex.split(value)[0] if value.strip() else ""

    def expand(value):
        for _ in range(len(arguments) + 1):
            expanded = re.sub(
                r"\$\{(\w+)\}|\$(\w+)",
                lambda match: arguments.get(
                    match[1] or match[2], match[0]
                ),
                value,
            )
            if expanded == value:
                break
            value = expanded
        if "$" in value:
            raise ValueError(f"Unresolved module version: {value}")
        return value

    # Match configured modules, including modules copied out of a larger tree.
    nginx = {}
    for path in re.findall(r"--add-(?:dynamic-)?module=/build/modules/([^\s\"']+)",
                           dockerfile):
        parts = PurePosixPath(path).parts
        nginx.setdefault(parts[0], []).append(parts[-1])

    result = {}
    sources = {}
    for line in dockerfile.splitlines():
        if not line.startswith("RUN "):
            continue
        directory = ""
        for command in re.split(r"\s+&&\s+", line[4:]):
            command = command.strip()
            if not re.match(r"(?:cd |git |mv |cp |\S*luarocks install )", command):
                continue
            tokens = shlex.split(command)
            if tokens[0] == "cd":
                directory = tokens[1].rstrip("/")
                continue
            if tokens[0] in ("mv", "cp"):
                paths = [token for token in tokens[1:] if not token.startswith("-")]
                if directory == "/build/modules" and len(paths) == 2:
                    source = PurePosixPath(paths[0]).parts[0]
                    if source in sources:
                        for module in nginx.get(paths[1], []):
                            result[("nginx", module)] = sources[source]
                continue
            if PurePosixPath(tokens[0]).name == "luarocks":
                name = tokens[2]
                ref = expand(tokens[3]) if len(tokens) > 3 else ""
                result[("Lua", name)] = ("LuaRocks", ref)
                continue

            ref = ""
            if tokens[:2] == ["git", "clone"]:
                url_index = next((i for i, token in enumerate(tokens)
                                  if "://" in token or token.startswith("git@")),
                                 None)
                if url_index is None:
                    raise ValueError(f"Unrecognized module clone: {command}")
                name = (tokens[url_index + 1] if len(tokens) > url_index + 1
                        else PurePosixPath(tokens[url_index]).stem)
                for i, token in enumerate(tokens[2:url_index], 2):
                    if token in ("--branch", "-b"):
                        ref = tokens[i + 1]
                    elif token.startswith("--branch="):
                        ref = token.split("=", 1)[1]
            elif tokens[:2] == ["git", "-C"] and tokens[3] == "fetch":
                name = tokens[2]
                ref = tokens[-1]
            else:
                continue

            if directory == "/build/modules":
                sources[name] = ("Git", expand(ref))
                for module in nginx.get(name, []):
                    result[("nginx", module)] = sources[name]
            elif directory == "/build/lualib":
                result[("Lua", name)] = ("Git", expand(ref))
    return result


def describe(pin):
    if pin is None:
        return "Not included"
    source, version = pin
    if not version:
        return f"{source} (unpinned)"
    version = version.replace("&", "&amp;").replace("|", "&#124;").replace("`", "&#96;")
    return f"{source} `{version}`"


def changes(repository, previous, commit):
    def read(ref):
        dockerfile = subprocess.check_output(
            ["git", "-C", repository, "show", f"{ref}:Dockerfile"],
            text=True,
        )
        return modules(dockerfile)

    before = read(previous) if previous else {}
    after = read(commit)
    rows = []
    for kind, name in sorted(before.keys() | after.keys()):
        key = (kind, name)
        if before.get(key) != after.get(key):
            rows.append(f"| {kind} | `{name}` | {describe(before.get(key))} "
                        f"| {describe(after.get(key))} |")
    if rows:
        print("## Module Changes\n")
        print("| Type | Module | Previous | Current |")
        print("| --- | --- | --- | --- |")
        print("\n".join(rows))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(f"Usage: {sys.argv[0]} <repository> <previous-ref> <commit>")
    changes(*sys.argv[1:])
