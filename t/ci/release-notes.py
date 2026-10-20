#!/usr/bin/env python3

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OLD_VERSION = "1.31.7.1.385"
NEW_VERSION = "1.31.7.1.386"

DOCKERFILE = """\
ARG RESTY_NGX_EXAMPLE_MODULE_VERSION="1.0.0"
ARG RESTY_LUA_RESTY_MLCACHE_VERSION="2.7.0"
ARG RESTY_HTTP_VERSION="0.17.0-1"
ARG RESTY_OPENSSL_VERSION="3.5.8"
ARG RESTY_RUST_VERSION="1.88.0"
FROM debian AS build
ARG RESTY_NGX_EXAMPLE_MODULE_VERSION
ARG RESTY_LUA_RESTY_MLCACHE_VERSION
ARG OPTIONS="--add-module=/build/modules/ngx_example_module"
RUN mkdir -p /build/lib && cd /build/lib \\
    && git clone --branch 1.0 https://example.invalid/native.git native
RUN mkdir -p /build/modules && cd /build/modules \\
    && git clone --branch "${RESTY_NGX_EXAMPLE_MODULE_VERSION}" https://example.invalid/module.git ngx_example_module
RUN mkdir -p /build/lualib && cd /build/lualib \\
    && git clone --branch ${RESTY_LUA_RESTY_MLCACHE_VERSION} https://example.invalid/lua-resty-mlcache.git lua-resty-mlcache
RUN /usr/local/bin/luarocks install lua-resty-http "${RESTY_HTTP_VERSION}"
FROM debian AS runtime
ARG RESTY_NGX_EXAMPLE_MODULE_VERSION
"""


class ReleaseNotes(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="release-notes-")
        self.addCleanup(self.work.cleanup)
        self.repo = Path(self.work.name)
        self.env = dict(os.environ, GITHUB_REPOSITORY="example/openresty")
        self.git("init", "-q")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        scripts = self.repo / "util/ci"
        scripts.mkdir(parents=True)
        for name in ("release-notes.sh", "module-versions.py"):
            # Windows checkouts may contain CRLF; CI executes LF sources.
            (scripts / name).write_text((ROOT / "util/ci" / name).read_text())
        self.old = self.commit(DOCKERFILE, "Initial modules")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args], text=True, env=self.env
        ).strip()

    def commit(self, text, subject="Update modules"):
        (self.repo / "Dockerfile").write_text(text)
        self.git("add", "Dockerfile", "util")
        self.git("commit", "-qm", subject)
        return self.git("rev-parse", "HEAD")

    def notes(self, commit="HEAD", version=NEW_VERSION):
        path = self.repo / "notes.md"
        subprocess.run(
            ["bash", str(self.repo / "util/ci/release-notes.sh"),
             commit, version, str(path)],
            check=True, env=self.env, capture_output=True, text=True,
        )
        return path.read_text()

    def tag_previous(self):
        self.git("tag", "-a", OLD_VERSION, "-m", "Previous release", self.old)

    def test_nginx_and_lua_changes_exclude_native_libraries(self):
        self.tag_previous()
        self.commit(DOCKERFILE.replace('"1.0.0"', '"1.1.0"')
                    .replace('"2.7.0"', '"2.7.1"')
                    .replace('"0.17.0-1"', '"0.18.0-0"')
                    .replace('"3.5.8"', '"3.5.9"')
                    .replace('"1.88.0"', '"1.89.0"')
                    .replace("--branch 1.0 ", "--branch 2.0 "))
        notes = self.notes()
        self.assertIn("| nginx | `ngx_example_module` | Git `1.0.0` | Git `1.1.0` |", notes)
        self.assertIn("| Lua | `lua-resty-mlcache` | Git `2.7.0` | Git `2.7.1` |", notes)
        self.assertIn("| Lua | `lua-resty-http` | LuaRocks `0.17.0-1` | LuaRocks `0.18.0-0` |", notes)
        for text in ("openssl", "rust", "native", "3.5.9", "1.89.0"):
            self.assertNotIn(text, notes)
        self.assertIn("- Update modules (`", notes)
        self.assertIn(f"/compare/{OLD_VERSION}...{NEW_VERSION}", notes)
        self.assertIn("## Container Images", notes)

    def test_git_to_luarocks_and_unpinned_versions(self):
        old = DOCKERFILE.replace("--branch ${RESTY_LUA_RESTY_MLCACHE_VERSION} ", "")
        self.old = self.commit(old)
        self.tag_previous()
        self.commit(old.replace(
            "git clone https://example.invalid/lua-resty-mlcache.git lua-resty-mlcache",
            "luarocks install lua-resty-mlcache 2.7.1-1"))
        notes = self.notes()
        self.assertIn("| `lua-resty-mlcache` | Git (unpinned) | LuaRocks `2.7.1-1` |", notes)
        self.assertEqual(notes.count("| `lua-resty-mlcache` |"), 1)
        self.assertNotIn("| `lua-resty-http` |", notes)

    def test_commit_pin_can_change_to_tag(self):
        sha = "a" * 40
        old = DOCKERFILE.replace("VERSION=\"1.0.0\"", f"COMMIT=\"{sha}\"")
        old = old.replace(
            'git clone --branch "${RESTY_NGX_EXAMPLE_MODULE_VERSION}" https://example.invalid/module.git ngx_example_module',
            'git init ngx_example_module && git -C ngx_example_module fetch --depth=1 origin "${RESTY_NGX_EXAMPLE_MODULE_COMMIT}"')
        self.old = self.commit(old)
        self.tag_previous()
        self.commit(DOCKERFILE)
        self.assertIn(f"| `ngx_example_module` | Git `{sha}` | Git `1.0.0` |", self.notes())

    def test_initial_release_and_added_removed_modules(self):
        notes = self.notes(self.old)
        self.assertIn("| `ngx_example_module` | Not included | Git `1.0.0` |", notes)
        self.assertIn(f"/commits/{NEW_VERSION}", notes)
        self.tag_previous()
        new = DOCKERFILE.replace("luarocks install lua-resty-http", "luarocks install lua-resty-new")
        self.commit(new)
        notes = self.notes()
        self.assertIn("| `lua-resty-http` | LuaRocks `0.17.0-1` | Not included |", notes)
        self.assertIn("| `lua-resty-new` | Not included | LuaRocks `0.17.0-1` |", notes)

    def test_no_module_changes_omits_section(self):
        self.tag_previous()
        self.commit(DOCKERFILE.replace('"3.5.8"', '"3.5.9"') + "# comment\n")
        self.assertNotIn("## Module Changes", self.notes())

    def test_release_commit_is_used_instead_of_checkout(self):
        self.tag_previous()
        release = self.commit(DOCKERFILE.replace('"2.7.0"', '"2.7.1"'))
        self.git("tag", NEW_VERSION)
        self.commit(DOCKERFILE.replace('"2.7.0"', '"9.0.0"'))
        (self.repo / "Dockerfile").write_text("invalid working copy\n")
        notes = self.notes(release)
        self.assertIn("Git `2.7.0` | Git `2.7.1`", notes)
        self.assertNotIn("9.0.0", notes)
        self.assertIn(f"/compare/{OLD_VERSION}...{NEW_VERSION}", notes)

    def test_only_previous_reachable_image_tag_is_used(self):
        self.tag_previous()
        self.git("tag", "unrelated-tag")
        self.git("tag", "9.99.9.9.999")
        branch = self.git("branch", "--show-current")
        self.git("checkout", "-qb", "unmerged")
        self.commit(DOCKERFILE + "# another branch\n")
        self.git("tag", "1.31.7.1.390")
        self.git("checkout", "-q", branch)
        self.commit(DOCKERFILE.replace('"2.7.0"', '"2.7.1"'))
        self.assertIn(f"/compare/{OLD_VERSION}...1.31.7.1.400",
                      self.notes(version="1.31.7.1.400"))

    def test_legacy_nested_module_and_literal_tag(self):
        old = DOCKERFILE.replace("/build/modules/ngx_example_module",
                                 "/build/modules/tengine/modules/ngx_example_module")
        old = old.replace('"${RESTY_NGX_EXAMPLE_MODULE_VERSION}"', '"legacy-tag"')
        old = old.replace("module.git ngx_example_module", "module.git tengine")
        self.old = self.commit(old)
        self.tag_previous()
        self.commit(DOCKERFILE)
        self.assertIn("| `ngx_example_module` | Git `legacy-tag` | Git `1.0.0` |", self.notes())

    def test_module_moved_from_unpinned_source_tree(self):
        old = DOCKERFILE.replace(
            'git clone --branch "${RESTY_NGX_EXAMPLE_MODULE_VERSION}" https://example.invalid/module.git ngx_example_module',
            'git clone https://example.invalid/tengine.git tengine')
        old += "RUN cd /build/modules && mv tengine/modules/ngx_example_module ngx_example_module\n"
        self.old = self.commit(old)
        self.tag_previous()
        self.commit(DOCKERFILE)
        self.assertIn("| `ngx_example_module` | Git (unpinned) | Git `1.0.0` |", self.notes())

    def test_implicit_clone_directory_and_branch_equals(self):
        old = DOCKERFILE.replace("--branch ${RESTY_LUA_RESTY_MLCACHE_VERSION}", "--branch=v2.7.0")
        old = old.replace("mlcache.git lua-resty-mlcache", "mlcache.git")
        self.old = self.commit(old)
        self.tag_previous()
        self.commit(old.replace("--branch=v2.7.0", "-b v2.7.1"))
        self.assertIn("| `lua-resty-mlcache` | Git `v2.7.0` | Git `v2.7.1` |", self.notes())

    def test_invalid_commit_and_unresolved_pin_fail(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.notes("does-not-exist")
        self.commit(DOCKERFILE.replace("${RESTY_HTTP_VERSION}", "${UNKNOWN_VERSION}"))
        with self.assertRaises(subprocess.CalledProcessError):
            self.notes()


if __name__ == "__main__":
    unittest.main(verbosity=2)
