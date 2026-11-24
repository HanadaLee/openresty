#!/usr/bin/env bash

set -euo pipefail

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

resolve_version() {
    local upstream="$1" override="$2" source
    [[ "$upstream" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || fail "Invalid upstream OpenResty version: $upstream"
    if [[ -z "$override" ]]; then
        printf '%s\n' "$upstream"
        return
    fi

    source="${upstream%.*}"
    [[ "$override" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || fail "Invalid nginx override: $override"
    [[ "$source" != "$override" ]] \
        || fail "OpenResty already bundles nginx $override; clear RESTY_NGINX_OVERRIDE"
    [[ -s "$patch_dir/$source-to-$override.patch" ]] \
        || fail "No nginx overlay for $source -> $override in $patch_dir"
    printf '%s.%s\n' "$override" "${upstream##*.}"
}

check_header() {
    local header="$1" want="$2" actual
    actual="$(sed -n 's/^#define[[:space:]]*NGINX_VERSION[[:space:]]*"\([0-9.]*\)"$/\1/p' "$header")"
    [[ "$actual" == "$want" ]] \
        || fail "Expected nginx $want in $header (found ${actual:-none})"
    actual="$(awk '$1 == "#define" && $2 == "nginx_version" { print $3 }' "$header")"
    [[ "$actual" == "$(version_id "$want")" ]] \
        || fail "Unexpected nginx_version in $header (found ${actual:-none})"
}

version_id() {
    local major minor patch
    IFS=. read -r major minor patch <<< "$1"
    printf '%s\n' "$((10#$major * 1000000 + 10#$minor * 1000 + 10#$patch))"
}

apply_overlay() {
    local bundle="$1" upstream="$2" override="$3"
    local effective source src dst no_pool source_id target_id
    effective="$(resolve_version "$upstream" "$override")"
    source="${upstream%.*}"
    src="$bundle/bundle/nginx-$source"
    check_header "$src/src/core/nginx.h" "$source"
    if [[ -z "$override" ]]; then
        printf '%s\n' "$effective"
        return
    fi

    dst="$bundle/bundle/nginx-$override"
    [[ ! -e "$dst" ]] || fail "Nginx overlay target already exists: $dst"
    patch --directory="$src" --batch --forward --fuzz=0 -p1 \
        < "$patch_dir/$source-to-$override.patch" >&2
    check_header "$src/src/core/nginx.h" "$override"
    mv -- "$src" "$dst"

    # OpenResty's optional configure switch applies this patch at -p0.
    no_pool="$bundle/bundle/nginx-no_pool.patch"
    if [[ -f "$no_pool" ]]; then
        source_id="$(version_id "$source")"
        target_id="$(version_id "$override")"
        sed -i -E "s@(nginx-)${source//./\\.}([-/])@\\1$override\\2@g; \
            s/(^ #define[[:space:]]+NGINX_VERSION[[:space:]]+\")${source//./\\.}(\")$/\\1$override\\2/; \
            s/(^ #define[[:space:]]+nginx_version[[:space:]]+)${source_id}$/\\1$target_id/" \
            "$no_pool"
    fi
    printf '%s\n' "$effective"
}

case "${1-}" in
    version)
        [[ $# == 4 ]] || fail 'Usage: nginx-overlay.sh version <upstream-version> <override> <patch-dir>'
        patch_dir="$4"
        resolve_version "$2" "$3"
        ;;
    apply)
        [[ $# == 5 ]] || fail 'Usage: nginx-overlay.sh apply <bundle> <upstream-version> <override> <patch-dir>'
        patch_dir="$5"
        apply_overlay "$2" "$3" "$4"
        ;;
    *)
        fail 'Expected nginx-overlay.sh version or apply'
        ;;
esac
