#!/usr/bin/env bash

set -euo pipefail

test_image="${1:?Usage: run-c-module-tests.sh <builder-image>}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
source "$script_dir/test-run.sh"
init_test_run c-modules
cp -a "$repository_root/t" "$test_snapshot/tests"
cp -a "$script_dir" "$test_snapshot/ci"
record_test_inputs

run_test_phase c-regressions docker run --rm --network none \
    --volume "$test_snapshot:/input:ro" \
    --volume "$test_output:/results" \
    "$test_image" \
    bash -c '
        set -euo pipefail
        (cd /input && sha256sum -c /results/inputs.sha256) > /results/input-verification.log

        resty_version="$(cat /build/openresty-version)"
        nginx_version="${resty_version%.*}"
        source_dir="/build/openresty-${resty_version}/build/nginx-${nginx_version}"

        bash /input/ci/test-module-abi.sh "$source_dir" /input/tests/module-abi
        bash /input/ci/test-complex-value.sh "$source_dir" /input/tests/complex-value
    '
