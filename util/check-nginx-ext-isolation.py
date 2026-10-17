#!/usr/bin/env python3
"""Compare extension-disabled source with the base, preserving all other #ifs.

Only empty/whitespace-only lines and CRLF versus LF are ignored.  Indentation,
comments, declarations and non-extension preprocessor branches remain exact.
This is a source audit, not a replacement for compilation or runtime tests.
"""

import argparse
import difflib
import json
from pathlib import Path
import re
import subprocess


EXT = "NGX_RESTY_EXT"
DIRECTIVE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
TOKEN = re.compile(r"defined|[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|[0-9]+|&&|\|\||!|\(|\)")
LITERAL = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|/\*.*?\*/|//[^\n]*''', re.S)


def condition(kind, expression, undefined=False):
    if EXT not in expression:
        return None
    expression = re.sub(r"/\*.*?\*/|//.*", "", expression).strip()
    if kind in ("ifdef", "ifndef"):
        if expression != EXT:
            raise ValueError(f"unsupported directive: #{kind} {expression}")
        value = not undefined
        return not value if kind == "ifndef" else value
    tokens = TOKEN.findall(expression)
    if re.sub(r"\s+", "", expression) != "".join(tokens):
        raise ValueError(f"unsupported extension expression: {expression}")
    pos = 0

    def atom():
        nonlocal pos
        token = tokens[pos]
        pos += 1
        if token == "!":
            value = atom()
            return None if value is None else not value
        if token == "(":
            value = either()
            if tokens[pos] != ")":
                raise ValueError(expression)
            pos += 1
            return value
        if token == "defined":
            parenthesized = tokens[pos] == "("
            pos += int(parenthesized)
            name = tokens[pos]
            pos += 1
            if parenthesized:
                if tokens[pos] != ")":
                    raise ValueError(expression)
                pos += 1
            return not undefined if name == EXT else None
        if token == EXT:
            return False
        if token[0].isdigit():
            return bool(int(token, 0))
        return None

    def both():
        nonlocal pos
        value = atom()
        while pos < len(tokens) and tokens[pos] == "&&":
            pos += 1
            right = atom()
            value = False if value is False or right is False else (
                True if value is True and right is True else None)
        return value

    def either():
        nonlocal pos
        value = both()
        while pos < len(tokens) and tokens[pos] == "||":
            pos += 1
            right = both()
            value = True if value is True or right is True else (
                False if value is False and right is False else None)
        return value

    value = either()
    if pos != len(tokens):
        raise ValueError(f"extension expression cannot be parsed: {expression}")
    return value


def project(text, undefined=False):
    lines = text.splitlines()
    # Comments and literals can contain text that looks like a directive.
    masked = LITERAL.sub(lambda m: re.sub(r"[^\n]", " ", m[0]), text)
    directives = {i: DIRECTIVE.match(line)
                  for i, line in enumerate(masked.splitlines())}
    index = 0

    def sequence():
        nonlocal index
        result = []
        while index < len(lines):
            line = lines[index]
            match = directives[index]
            if match and match[1] in ("elif", "else", "endif"):
                break
            if not match:
                result.append((line, index + 1))
                index += 1
                continue
            branches = []
            while True:
                head = (lines[index], index + 1)
                match = directives[index]
                kind, expression = match.groups()
                index += 1
                branches.append((head, kind, expression, sequence()))
                if index >= len(lines):
                    raise ValueError(f"unterminated #if at {head[1]}")
                tail = directives[index]
                if tail[1] == "endif":
                    end = (lines[index], index + 1)
                    index += 1
                    break
            # Untouched conditions stay symbolic: retain all their branches.
            active_unknown = False
            for head, kind, expression, children in branches:
                value = True if kind == "else" else condition(kind, expression, undefined)
                if value is False:
                    continue
                if value is True:
                    if active_unknown:
                        result.append(head if kind == "else" else ("#else", head[1]))
                    result.extend(children)
                    break
                if active_unknown:
                    result.append(head)
                else:
                    result.append((re.sub(r"#\s*elif\b", "#if", head[0]), head[1]))
                    active_unknown = True
                result.extend(children)
            if active_unknown:
                result.append(end)
        return result

    result = sequence()
    if index != len(lines):
        raise ValueError(f"unexpected preprocessor branch at {index + 1}")
    return [(line, number) for line, number in result if line.strip()]


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def tree(repo, ref):
    result = {}
    for record in git(repo, "ls-tree", "-r", "-z", ref).split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        path = name.decode()
        if path.endswith((".c", ".h")):
            result[path] = meta.split()[2].decode()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("--base", default="base/1.31.7")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--undefined", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repository.resolve()
    subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                    args.base, "HEAD"], check=True)
    base = git(repo, "rev-parse", args.base).decode().strip()
    bases = tree(repo, base)
    batch = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    texts, projections = {}, {}

    def blob(sha):
        if sha not in texts:
            batch.stdin.write((sha + "\n").encode())
            batch.stdin.flush()
            header = batch.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob":
                raise ValueError(f"invalid blob {sha}")
            texts[sha] = batch.stdout.read(int(header[2])).decode("utf-8")
            if batch.stdout.read(1) != b"\n":
                raise ValueError("invalid batch boundary")
        return texts[sha]

    base_lines = {path: [line for line in blob(sha).splitlines() if line.strip()]
                  for path, sha in bases.items()}

    def inspect(path, text, key):
        if key not in projections:
            projections[key] = project(text, args.undefined)
        projected = projections[key]
        expected = base_lines.get(path, [])
        actual = [line for line, _ in projected]
        if expected == actual:
            return None
        hunks = []
        for tag, a, b, c, d in difflib.SequenceMatcher(
                None, expected, actual, autojunk=False).get_opcodes():
            if tag == "equal":
                continue
            hunks.append({"kind": tag, "base": expected[a:b], "actual": actual[c:d],
                          "line": projected[c][1] if c < len(projected) else len(text.splitlines()) + 1,
                          "end": projected[d - 1][1] if d > c else None})
        return {"path": path, "hunks": hunks,
                "diff": "\n".join(difflib.unified_diff(expected, actual,
                    fromfile="base/" + path, tofile="disabled/" + path, lineterm=""))}

    history = []
    if args.history:
        for sha in git(repo, "rev-list", "--reverse", base + "..HEAD").decode().splitlines():
            entries = tree(repo, sha)
            failures = []
            for path in sorted(bases.keys() | entries.keys()):
                if bases.get(path) == entries.get(path):
                    continue
                content = blob(entries[path]) if path in entries else ""
                failure = inspect(path, content, entries.get(path, "missing:" + path))
                if failure:
                    failures.append(failure)
            subject = git(repo, "show", "-s", "--format=%s", sha).decode().strip()
            history.append({"commit": sha, "subject": subject, "failures": failures})
            print(f"{sha[:9]}: {len(failures)} file(s)", flush=True)

    current = []
    paths = bases.keys() | tree(repo, "HEAD").keys()
    for path in sorted(paths):
        file = repo / path
        text = file.read_text(encoding="utf-8") if file.exists() else ""
        failure = inspect(path, text, "worktree:" + path)
        if failure:
            current.append(failure)
    batch.stdin.close()
    batch.stdout.close()
    batch.wait()
    report = {"repository": str(repo), "base": base,
              "mode": "undefined" if args.undefined else "defined-zero",
              "source_files": len(paths), "commits": history, "worktree": current}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"WORKTREE: {len(current)} differing file(s), checked {len(paths)} C/H files")
    raise SystemExit(bool(current or any(item["failures"] for item in history)))


if __name__ == "__main__":
    main()
