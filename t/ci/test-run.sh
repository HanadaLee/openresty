#!/usr/bin/env bash

set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repository_root/util/ci/test-run.sh"
root="$(mktemp -d)"
export TEST_OUTPUT_ROOT="$root"
init_test_run fixture
trap 'rm -rf "$test_snapshot" "$root"' EXIT

printf 'fixed input\n' > "$test_snapshot/input.sh"
record_test_inputs
(cd "$test_snapshot" && sha256sum -c "$test_output/inputs.sha256")
run_test_phase passed bash -c 'echo successful'
if run_test_phase rejected bash -c 'echo deliberate failure; exit 17'; then
    echo 'A failing command was accepted' >&2
    exit 1
else
    [[ "$?" == 17 ]]
fi
grep -q $'^rejected\t17\t' "$test_output/results.tsv"
run_test_phase after-failure true
grep -q $'^after-failure\t0\t' "$test_output/results.tsv"
[[ "$(wc -l < "$test_output/results.tsv")" == 4 ]]
printf 'changed\n' > "$test_snapshot/input.sh"
if (cd "$test_snapshot" && sha256sum -c "$test_output/inputs.sha256"); then
    echo 'Changed test inputs were accepted' >&2
    exit 1
fi
echo 'PASS: stage failures, separate results and input checksums'
