#!/usr/bin/env bash

set -euo pipefail

source_file="${1:-}"
git_mirror="${2:-github.com}"

if [[ -z "$source_file" ]]; then
    echo "Usage: $0 <mirror-tarballs> [git-mirror]" >&2
    exit 2
fi

if [[ "$git_mirror" == "github.com" ]]; then
    exit 0
fi

GIT_MIRROR="$git_mirror" perl -0pi -e '
    my $mirror = $ENV{GIT_MIRROR};

    s{https://github\.com/([^/]+)/([^/]+)/tarball/([^"\s]+)}
     {"https://$mirror/$1/$2/legacy.tar.gz/$3"}ge;

    s{https://github\.com/([^/]+)/([^/]+)/archive/(refs/tags/)?([^"\s]+)\.tar\.gz}
     {"https://$mirror/$1/$2/tar.gz/" . ($3 // "") . $4}ge;

    s{https://github\.com/}{"https://$mirror/"}ge;
' "$source_file"
