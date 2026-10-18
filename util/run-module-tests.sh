#!/usr/bin/env bash

set -euo pipefail

: "${TEST_NGINX_BINARY:?TEST_NGINX_BINARY must point to the built nginx binary}"
: "${TEST_NGINX_ROOT:?TEST_NGINX_ROOT must point to the test-nginx checkout}"
: "${NGINX_TESTS_ROOT:?NGINX_TESTS_ROOT must point to the nginx-tests checkout}"

module_root="$(cd "${1:-/build/modules}" && pwd)"
export TEST_NGINX_BINARY
export TEST_NGINX_RESTY_LUALIB="${TEST_NGINX_RESTY_LUALIB:-/usr/local/openresty/lualib}"
export PATH="$(dirname "$TEST_NGINX_BINARY"):/usr/local/openresty/bin:/usr/local/openresty/luajit/bin:$PATH"

if [[ -n "${NGINX_SOURCE:-}" ]]; then
    export NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-$NGINX_SOURCE/objs}"
    # Native .t tests compile small fixtures against the configured nginx tree.
    # Include extension headers from that build as well as the core headers.
    C_INCLUDE_PATH="$(perl -0777 -MText::ParseWords=shellwords -MCwd=abs_path -e '
        my ($source, $makefile) = @ARGV;
        open my $fh, "<", $makefile or die "$makefile: $!";
        my $text = <$fh>;
        my ($flags) = $text =~ /^ALL_INCS = (.*?)(?:\n\n|\z)/ms;
        die "ALL_INCS not found in $makefile" unless defined $flags;
        $flags =~ s/\\\n/ /g;
        my @args = shellwords($flags);
        my @paths;
        while (@args) {
            my $arg = shift @args;
            next unless $arg =~ s/^-I//;
            $arg = shift @args unless length $arg;
            next unless defined $arg;
            $arg =~ s/^-I//;
            $arg = "$source/$arg" unless $arg =~ m{^/};
            push @paths, abs_path($arg) if -d $arg;
        }
        print join ":", @paths;
    ' "$NGINX_SOURCE" "$NGINX_BUILD_DIR/Makefile")"
    export C_INCLUDE_PATH
fi

nginx_config="$("$TEST_NGINX_BINARY" -V 2>&1)"
# Parse quoted configure arguments without evaluating them as shell code.
module_list="$(printf '%s\n' "$nginx_config" | perl -MText::ParseWords=shellwords -ne '
    next unless s/^configure arguments: //;
    for (shellwords($_)) {
        print "$1\n" if /^--add-(?:dynamic-)?module=(.+)$/;
    }
' | sort -u)"

status=0
suites=0
files=0
while IFS= read -r module_dir; do
    # Bundled OpenResty modules and dependency submodules are not standalone
    # repositories under this root. Only test modules compiled into this image.
    [[ "$module_dir" == "$module_root/"* ]] || continue
    name="$(basename "$module_dir")"
    case "$name" in
        ngx_http_grpc_filter_module|ngx_http_proxy_filter_module)
            # Their repository CI builds the required test consumer modules.
            echo "SKIP: $name (tested by its own GitHub Actions workflow)"
            continue
            ;;
    esac
    if [[ ! -d "$module_dir" ]]; then
        echo "Missing built module source: $module_dir" >&2
        status=1
        continue
    fi
    if [[ ! -d "$module_dir/t" ]]; then
        echo "No t directory: $name"
        continue
    fi

    official=()
    openresty=()
    while IFS= read -r -d '' test; do
        if grep -Eq '^[[:space:]]*(use|require)[[:space:]]+Test::Nginx::(Socket|LWP)' "$test"; then
            openresty+=("$test")
        else
            official+=("$test")
        fi
    done < <(find "$module_dir/t" -type d -name servroot -prune -o \
        -type f -name '*.t' -print0 | sort -z)

    for framework in official openresty; do
        if [[ "$framework" == official ]]; then
            tests=("${official[@]}")
            harness="$NGINX_TESTS_ROOT"
        else
            tests=("${openresty[@]}")
            harness="$TEST_NGINX_ROOT"
        fi
        ((${#tests[@]})) || continue
        suites=$((suites + 1))
        files=$((files + ${#tests[@]}))
        echo "::group::$name ($framework, ${#tests[@]} files)"
        if (
            cd "$module_dir" || exit 1
            # Keep the repository, fixtures and helper libraries together.
            # The two incompatible Test::Nginx implementations stay isolated.
            export PERL5LIB="$harness/lib:$module_dir/t/lib:$module_dir/lib"
            if [[ "$framework" == official ]]; then
                export NGINX_TESTS="$NGINX_TESTS_ROOT"
                if [[ "$(id -u)" == 0 ]]; then
                    export TEST_NGINX_GLOBALS="${TEST_NGINX_GLOBALS:-user root;}"
                fi
                if [[ "$nginx_config" == *"/ngx_expr_module"* ]]; then
                    export NGX_STAT_CONDITION=1
                fi
            fi
            timeout "${TEST_MODULE_TIMEOUT:-600}" prove -v "${tests[@]}"
        ); then
            echo "PASS: $name ($framework)"
        else
            echo "FAIL: $name ($framework)" >&2
            status=1
        fi
        echo '::endgroup::'
    done
done <<< "$module_list"

echo "Module tests: $suites suites, $files files"
if ((suites == 0)); then
    echo 'No module tests were found for this binary' >&2
    exit 1
fi
exit "$status"
