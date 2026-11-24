#!/usr/bin/env bash

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/overlays" "$work/source/bundle/nginx-1.2.3/src/core"

source="$work/source/bundle/nginx-1.2.3"
cat > "$source/src/core/nginx.h" <<'HEADER'
#define nginx_version      1002003
#define NGINX_VERSION      "1.2.3"
#define NGINX_VER          "openresty/" NGINX_VERSION ".1"
HEADER
printf 'bundle component\n' > "$work/source/bundle/component"
cat > "$work/source/bundle/nginx-no_pool.patch" <<'PATCH'
--- nginx-1.2.3/src/core/nginx.h
+++ nginx-1.2.3-patched/src/core/nginx.h
@@ -1,3 +1,3 @@
 #define nginx_version      1002003
 #define NGINX_VERSION      "1.2.3"
-#define NGINX_VER          "openresty/" NGINX_VERSION ".1"
+#define NGINX_VER          "openresty/" NGINX_VERSION ".1 (no pool)"
PATCH
cat > "$work/overlays/1.2.3-to-1.2.4.patch" <<'PATCH'
--- a/src/core/nginx.h
+++ b/src/core/nginx.h
@@ -1,3 +1,3 @@
-#define nginx_version      1002003
-#define NGINX_VERSION      "1.2.3"
+#define nginx_version      1002004
+#define NGINX_VERSION      "1.2.4"
 #define NGINX_VER          "openresty/" NGINX_VERSION ".1"
PATCH

run() {
    bash "$repo/util/nginx-overlay.sh" "$@" "$work/overlays"
}

expect_failure() {
    if "$@" > "$work/output" 2> "$work/error"; then
        printf 'Unexpected success: %s\n' "$*" >&2
        exit 1
    fi
    test ! -s "$work/output"
}

cp -R "$work/source" "$work/original"
test "$(run apply "$work/source" 1.2.3.1 '')" = 1.2.3.1
diff -r "$work/original" "$work/source"
echo 'PASS: disabling the overlay leaves the bundle unchanged'

expect_failure run version 1.2.3.1 'bad/path'
expect_failure run version 1.2.4.1 1.2.4
expect_failure run version 1.2.5.1 1.2.4
cp -R "$work/source" "$work/mismatch"
sed -i 's/"1.2.3"/"1.2.2"/' "$work/mismatch/bundle/nginx-1.2.3/src/core/nginx.h"
expect_failure run apply "$work/mismatch" 1.2.3.1 1.2.4
cp -R "$work/source" "$work/drift"
sed -i 's/\.1"$/.0"/' "$work/drift/bundle/nginx-1.2.3/src/core/nginx.h"
expect_failure run apply "$work/drift" 1.2.3.1 1.2.4
test ! -e "$work/drift/bundle/nginx-1.2.4"
echo 'PASS: invalid, stale, unsupported and incompatible overlays are rejected'

test "$(run version 1.2.3.1 1.2.4)" = 1.2.4.1
test "$(run apply "$work/source" 1.2.3.1 1.2.4)" = 1.2.4.1
test ! -e "$source"
header="$work/source/bundle/nginx-1.2.4/src/core/nginx.h"
grep -Fqx '#define nginx_version      1002004' "$header"
grep -Fqx '#define NGINX_VER          "openresty/" NGINX_VERSION ".1"' "$header"
cmp "$work/original/bundle/component" "$work/source/bundle/component"
(
    cd "$work/source/bundle"
    patch --batch --fuzz=0 -p0 < nginx-no_pool.patch
)
grep -Fqx '#define NGINX_VER          "openresty/" NGINX_VERSION ".1 (no pool)"' "$header"
echo 'PASS: switching nginx preserves other components and the no-pool patch'

printf 'ARG RESTY_VERSION="1.31.9.1"\nARG RESTY_NGINX_OVERRIDE="1.31.10"\n' > "$work/Dockerfile"
test "$(bash "$repo/util/openresty-version.sh" "$work/Dockerfile")" = 1.31.10.1
test "$(RESTY_NGINX_OVERRIDE= bash "$repo/util/openresty-version.sh" "$work/Dockerfile")" = 1.31.9.1
echo 'PASS: CI version resolution matches the configured overlay'
