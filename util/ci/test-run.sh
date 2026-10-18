#!/usr/bin/env bash

# Shared bookkeeping for disposable CI test containers.
init_test_run() {
    local name="$1"
    mkdir -p "${TEST_OUTPUT_ROOT:-$repository_root/.ci/test-output}"
    test_output="$(mktemp -d "${TEST_OUTPUT_ROOT:-$repository_root/.ci/test-output}/$name.XXXXXX")"
    test_snapshot="$(mktemp -d)"
    export test_output test_snapshot
    printf 'phase\texit_code\tstarted_at\tfinished_at\n' > "$test_output/results.tsv"
    printf 'Test results: %s\n' "$test_output"
    trap 'rm -rf "$test_snapshot"' EXIT
}

record_test_inputs() {
    (cd "$test_snapshot" && find . -type f ! -path '*/.git/*' -print0 |
        sort -z | xargs -0 -r sha256sum) > "$test_output/inputs.sha256"
}

run_test_phase() {
    local phase="$1" started rc=0 code
    local -a codes
    shift
    started="$(date -u +%FT%TZ)"
    printf 'START %s %s\n' "$phase" "$started"
    if "$@" 2>&1 | tee "$test_output/$phase.log"; then
        codes=("${PIPESTATUS[@]}")
    else
        codes=("${PIPESTATUS[@]}")
    fi
    for code in "${codes[@]}"; do
        if ((code != 0 && rc == 0)); then rc="$code"; fi
    done
    printf '%s\t%s\t%s\t%s\n' "$phase" "$rc" "$started" "$(date -u +%FT%TZ)" \
        >> "$test_output/results.tsv"
    printf 'END %s exit=%s\n' "$phase" "$rc"
    return "$rc"
}
