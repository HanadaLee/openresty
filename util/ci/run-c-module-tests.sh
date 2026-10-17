#!/usr/bin/env bash

set -euo pipefail

test_image="${1:?Usage: run-c-module-tests.sh <builder-image>}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"

docker run --rm --network none \
    --volume "$repository_root/t:/input/tests:ro" \
    --volume "$script_dir:/input/ci:ro" \
    "$test_image" \
    bash -c '
        set -euo pipefail

        resty_version="$(cat /build/openresty-version)"
        nginx_version="${resty_version%.*}"
        source_dir="/build/openresty-${resty_version}/build/nginx-${nginx_version}"

        bash /input/ci/test-module-abi.sh "$source_dir" /input/tests/module-abi
        bash /input/ci/test-complex-value.sh "$source_dir" /input/tests/complex-value
    '
