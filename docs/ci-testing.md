# CI regression tests

GitHub Actions and GitLab run the C regression checks, standalone module suites,
and downstream patch suites before publishing architecture images. Standalone
module regressions also run when the version is unchanged.

The entry points are:

```sh
bash t/ci/release-state.sh
bash t/ci/module-tests.sh
bash t/ci/test-run.sh
bash util/ci/run-c-module-tests.sh <debug-builder-image>
bash util/ci/run-module-tests.sh <debug-builder-image>
bash util/ci/verify-image.sh debug <debug-runtime-image>
bash util/ci/run-patch-tests.sh <debug-runtime-image>
bash util/ci/verify-image.sh production <production-runtime-image>
```

Build the debug builder with Docker target `openresty-build` and
`RESTY_DEBUG_OPTIONS=--with-debug`. Build runtime images from the final target;
omit `RESTY_DEBUG_OPTIONS` for the production image. The scripts do not publish
images or releases.

Each container entry point creates a new directory under `.ci/test-output/`. Set
`TEST_OUTPUT_ROOT` to choose another directory. `results.tsv` records each phase,
its exit code and UTC start/end times; each phase also has its own log. Module
results retain each suite's exit code, including timeouts. A failed suite does
not prevent later module suites or the other patch test framework from running;
the overall command still fails. Never combine result files from different runs
to decide whether a pipeline succeeded.

Test scripts, fixtures and harness sources are copied before containers start.
`inputs.sha256` records the copied files, and `dependency-revisions.txt` records
the fetched harness revisions. Changing the host checkout after the copy does
not change the running container's inputs. CI archives results on success and
failure, including retained nginx test directories.

The standalone module container installs CryptX and builds the pinned weighttp
client used by the QR code memory test. Both are checked before running suites.
These tools are installed only in disposable test containers. The QR code memory
test observes RSS under repeated requests; successful execution alone is not a
proof that the module is free of memory leaks.

The suites requiring additional consumer modules, such as the generic proxy and
gRPC filter framework suites, remain in their module repositories' CI. Legacy
suites are selected only for builds without `ngx_expr_module`. The runner prints
these exclusions explicitly.
