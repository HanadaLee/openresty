# Name

OpenResty - A High Performance Web Server and CDN Cache Server Based on Nginx and LuaJIT

# Table of Contents

- [Name](#name)
- [Table of Contents](#table-of-contents)
- [Description](#description)
- [Building](#building)
- [Testing](#testing)
- [Components](#components)
  - [Components of official OpenResty bundle](#components-of-official-openresty-bundle)
  - [Components of this OpenResty bundle](#components-of-this-openresty-bundle)
  - [Components from LuaRocks](#components-from-luarocks)
- [Module Overview](#module-overview)
- [Additional Features](#additional-features)
  - [Resolver](#resolver)
    - [nameserver](#nameserver)
    - [resolver](#resolver-1)
    - [resolver\_next\_nameserver](#resolver_next_nameserver)
    - [resolver\_next\_nameserver\_timeout](#resolver_next_nameserver_timeout)
    - [resolver\_next\_nameserver\_tries](#resolver_next_nameserver_tries)
  - [lua-resty-core](#lua-resty-core)
    - [ngx.resolve](#ngxresolve)
    - [ngx.http](#ngxhttp)
  - [ngx\_http\_client\_module](#ngx_http_client_module)
    - [client](#client)
  - [ngx\_http\_lua\_module](#ngx_http_lua_module)
    - [balancer\_ssl\_session\_cache](#balancer_ssl_session_cache)
    - [ngx.fs](#ngxfs)
    - [preaccess\_by\_lua\_block](#preaccess_by_lua_block)
    - [preaccess\_by\_lua\_file](#preaccess_by_lua_file)
    - [preaccess\_by\_lua\_no\_postpone](#preaccess_by_lua_no_postpone)
  - [ngx\_http\_core\_module](#ngx_http_core_module)
    - [auto\_redirect](#auto_redirect)
    - [Support for https\_allow\_http in listen directive](#support-for-https_allow_http-in-listen-directive)
    - [Enhancement of unique request id](#enhancement-of-unique-request-id)
    - [Configurable default error pages](#configurable-default-error-pages)
    - [Support for ignoring invalid Range header](#support-for-ignoring-invalid-range-header)
    - [Conditional error\_page](#conditional-error_page)
    - [More directives for not modified checking](#more-directives-for-not-modified-checking)
  - [ngx\_http\_ssl\_module](#ngx_http_ssl_module)
    - [ssl\_certificate\_load](#ssl_certificate_load)
    - [ssl\_certificate\_compression](#ssl_certificate_compression)
    - [ssl\_ocsp\_http\_client](#ssl_ocsp_http_client)
    - [ssl\_stapling\_http\_client](#ssl_stapling_http_client)
    - [Conditional ssl\_reject\_handshake](#conditional-ssl_reject_handshake)
    - [ssl\_delay\_handshake](#ssl_delay_handshake)
    - [Optimizing TLS over TCP to reduce latency](#optimizing-tls-over-tcp-to-reduce-latency)
    - [Variables about SSL handshake timestamps and time spent](#variables-about-ssl-handshake-timestamps-and-time-spent)
  - [ngx\_http\_slice\_filter\_module](#ngx_http_slice_filter_module)
    - [slice](#slice)
    - [slice\_size](#slice_size)
    - [slice\_bypass](#slice_bypass)
    - [slice\_verify\_etag](#slice_verify_etag)
    - [slice\_verify\_last\_modified](#slice_verify_last_modified)
    - [$slice\_error](#slice_error)
  - [ngx\_http\_sub\_filter\_module](#ngx_http_sub_filter_module)
    - [Conditional sub\_filter](#conditional-sub_filter)
  - [ngx\_http\_proxy\_module and related modules](#ngx_http_proxy_module-and-related-modules)
    - [proxy\_ssl\_certificate\_load](#proxy_ssl_certificate_load)
    - [gRPC upstream request header variables](#grpc-upstream-request-header-variables)
    - [gRPC upstream URI](#grpc-upstream-uri)
    - [gRPC upstream method](#grpc-upstream-method)
    - [Conditional upstream directives](#conditional-upstream-directives)
    - [Support for inheritance in "proxy\_set\_header" and its friends](#support-for-inheritance-in-proxy_set_header-and-its-friends)
    - [Enhancement of upstream cookie handler](#enhancement-of-upstream-cookie-handler)
    - [proxy\_cache\_lock\_early\_read](#proxy_cache_lock_early_read)
    - [proxy\_cache\_lock\_expired](#proxy_cache_lock_expired)
    - [proxy\_cache\_lock\_poll\_interval](#proxy_cache_lock_poll_interval)
    - [Persistent cache zones](#persistent-cache-zones)
    - [Enhancement of upstream cache control](#enhancement-of-upstream-cache-control)
  - [ngx\_http\_upstream\_module](#ngx_http_upstream_module)
    - [Upstream errors](#upstream-errors)
  - [ngx\_http\_realip\_module](#ngx_http_realip_module)
    - [Configuring real client IP with multiple request headers](#configuring-real-client-ip-with-multiple-request-headers)
  - [ngx\_http\_rewrite\_module](#ngx_http_rewrite_module)
    - [Additional operators for the "if" directive](#additional-operators-for-the-if-directive)
    - ["if" with multiple conditions](#if-with-multiple-conditions)
    - [Support for "elif" and "else" directives](#support-for-elif-and-else-directives)
    - [Support for "goto" directive](#support-for-goto-directive)
  - [ngx\_http\_log\_module](#ngx_http_log_module)
    - [Conditional access\_log](#conditional-access_log)
  - [ngx\_http\_modsecurity\_module (3rd-party module)](#ngx_http_modsecurity_module-3rd-party-module)
    - [modsecurity\_bypass](#modsecurity_bypass)
  - [ngx\_stream\_lua\_module](#ngx_stream_lua_module)
    - [access\_by\_lua\_block](#access_by_lua_block)
    - [access\_by\_lua\_file](#access_by_lua_file)
    - [access\_by\_lua\_no\_postpone](#access_by_lua_no_postpone)
  - [ngx\_stream\_log\_module](#ngx_stream_log_module)
    - [Conditional access\_log](#conditional-access_log-1)
  - [ngx\_stream\_ssl\_module](#ngx_stream_ssl_module)
    - [ssl\_certificate\_load](#ssl_certificate_load-1)
    - [ssl\_certificate\_compression](#ssl_certificate_compression-1)
    - [ssl\_ocsp\_http\_client](#ssl_ocsp_http_client-1)
    - [ssl\_stapling\_http\_client](#ssl_stapling_http_client-1)
    - [ssl\_reject\_handshake](#ssl_reject_handshake)
    - [ssl\_delay\_handshake](#ssl_delay_handshake-1)
    - [Variables about SSL handshake timestamps and time spent](#variables-about-ssl-handshake-timestamps-and-time-spent-1)
  - [ngx\_stream\_proxy\_module](#ngx_stream_proxy_module)
    - [proxy\_ssl\_certificate\_load](#proxy_ssl_certificate_load-1)
  - [ngx\_stream\_upstream\_module](#ngx_stream_upstream_module)
    - [Extra variables for upstream information](#extra-variables-for-upstream-information)
- [LuaRocks](#luarocks)
- [Copyright \& License](#copyright--license)

# Description

OpenResty is a full-fledged web application server by bundling the standard nginx core, lots of 3rd-party nginx modules, as well as most of their external dependencies.

This customized OpenResty bundle is designed to serve as a full-featured CDN cache server while retaining OpenResty's capabilities as a high-performance dynamic web platform.

Based on the official OpenResty, this bundle includes LuaRocks, additional patches, 3rd-party nginx modules and lua libraries.

This bundle is maintained by Hanada (im@hanada.info).

The bundled software components are copyrighted by the respective copyright holders.

[Back to TOC](#table-of-contents)

# Building

Independent core patches are maintained and applied by their module repositories. Modules using these patches must be built statically.

Docker is the supported build environment. The Dockerfile pins a full commit
from the upstream [OpenResty repository](https://github.com/openresty/openresty)
instead of downloading a published bundle or following the moving `master`
branch. A dedicated build stage runs the upstream `make` target to create the
OpenResty bundle tarball, a second stage compiles and installs the patched
runtime, and the final stage starts from the same slim Debian base, installs
only the explicit runtime packages, and copies the cleaned
`/usr/local/openresty` tree. The bundle archive, compiler toolchain, and other
build-stage files are therefore not retained in the published image.

`RESTY_VERSION` is derived from `util/ver` at the pinned commit and the optional nginx overlay. `RESTY_RELEASE` remains a local, monotonically increasing bundle release. A local image can be built directly from the repository root:

```shell
docker build --tag openresty:local .
```

To build a versioned local image, resolve the pinned upstream version first:

```shell
resty_version="$(bash util/openresty-version.sh)"
resty_release="$(
    sed -n 's/^ARG RESTY_RELEASE="\([^"]*\)"[[:space:]]*$/\1/p' Dockerfile |
        head -n 1
)"

docker build \
    --build-arg RESTY_VERSION="$resty_version" \
    --build-arg RESTY_RELEASE="$resty_release" \
    --tag "openresty:${resty_version}.${resty_release}" \
    .
```

To follow a newer upstream revision, update `RESTY_COMMIT` to a full
commit hash and increment `RESTY_RELEASE`. Do not replace the pin with a branch
name. The patches in this repository target the bundle produced by the pinned
commit and must be regenerated or revalidated whenever that commit changes.
The default `RESTY_REPOSITORY` is derived from `RESTY_GIT_MIRROR`, so overriding
the mirror also applies to the pinned OpenResty source checkout.

`RESTY_NGINX_OVERRIDE` selects the nginx version in the bundle. The build applies `patches/nginx-overlay/<bundled-nginx>-to-<target-nginx>.patch` before the extension patches. Other components come from `RESTY_COMMIT`. The bundle version combines the target nginx version with the fourth component of the pinned OpenResty version.

Pass `--build-arg RESTY_NGINX_OVERRIDE=` to use the pinned OpenResty bundle without an overlay. Use `RESTY_NGINX_OVERRIDE= bash util/openresty-version.sh` to print the corresponding bundle version.

The patched nginx configure script accepts `--without-client` to disable the internal HTTP client and `--without-ext` to disable all nginx-ext features. Add-on modules can test `NGX_EXT` and `NGX_CLIENT` at compile time.

Dynamic modules must be built against the same patched source and configuration headers as the server. Module signatures include the extension ABI. Incompatible modules are rejected with `is not binary compatible`; `--with-compat` does not bypass these checks.

[Back to TOC](#table-of-contents)

# Testing

The patch regression suite requires a test image built with `--with-debug`.
It is not embedded in the runtime image and is not run by the Dockerfile.
To run the suite locally, use Docker, Git, and a POSIX-compatible shell:

```shell
docker build \
    --build-arg RESTY_DEBUG_OPTIONS=--with-debug \
    --tag openresty:test \
    .

bash util/ci/verify-image.sh debug openresty:test
bash util/ci/run-patch-tests.sh openresty:test
```

When testing an existing local installation instead, point the runner at the
patched nginx binary and the two test harness checkouts:

```shell
TEST_NGINX_BINARY=/path/to/nginx \
TEST_NGINX_ROOT=/path/to/test-nginx \
NGINX_TESTS_ROOT=/path/to/nginx-tests \
bash util/run-tests.sh
```

The `nginx-tests` suite includes cross-worker tests for [proxy_cache_lock_early_read](#proxy_cache_lock_early_read). HTTP/2 cancellation uses `IO::Socket::SSL` with ALPN; HTTP/3 cancellation uses `CryptX`.

[Back to TOC](#table-of-contents)

# Components

## Components of official OpenResty bundle

For details on OpenResty's bundled components and features, refer to [openresty.org](https://openresty.org/).

[Back to TOC](#table-of-contents)

## Components of this OpenResty bundle

The following components are additionally bundled with OpenResty, some of which are developed and maintained by Hanada.

See [Module Overview](#module-overview) for the additional nginx modules and their functions. Other bundled components include:

* [coreruleset](https://github.com/coreruleset/coreruleset)
* [uap-core](https://github.com/ua-parser/uap-core)
* [luarocks](https://luarocks.org/)
* [lua-resty-multipart-parser](https://github.com/agentzh/lua-resty-multipart-parser)
* [lua-resty-balancer](https://github.com/OpenResty/lua-resty-balancer)
* [lua-resty-mlcache](https://git.hanada.info/hanada/lua-resty-mlcache)
* [lua-lolhtml](https://git.hanada.info/hanada/lua-lolhtml)

## Components from LuaRocks
* binaryheap
* luafilesystem
* penlight
* net-url
* api7-dkjson
* lyaml
* lrandom
* luaxxhash
* xml2lua
* lua-ffi-zlib
* lua-resty-openssl
* lua-resty-http
* lua-resty-hmac-ffi
* lua-resty-ljsonschema
* lua-resty-jwt
* lua-resty-session
* lua-resty-openidc
* lua-resty-timer
* lua-resty-kafka
* lua-resty-template
* lua-resty-m3u8
* lua-resty-cookie
* lua-resty-worker-events
* lua-resty-healthcheck
* lua-resty-ipmatcher
* lua-resty-expr
* api7-lua-resty-redis-connector
* lua-resty-redis-cluster
* lua-resty-timer-ng
* lua-resty-maxminddb
* lua-resty-ctx
* lua-resty-gd
* lua-resty-captcha

[Back to TOC](#table-of-contents)

# Module Overview

The following nginx module projects are added to the official OpenResty bundle. Follow each project link for its directives, variables, and examples.

| Project | Function |
| --- | --- |
| [ngx_backtrace_module](https://git.hanada.info/hanada/ngx_backtrace_module) | Records stack traces when nginx processes terminate abnormally. |
| [ngx_expr_module](https://git.hanada.info/hanada/ngx_expr_module) | Defines named expressions and `when` blocks for conditional HTTP and Stream configuration. |
| [ngx_geoip2_module](https://git.hanada.info/hanada/ngx_geoip2_module) | Looks up geographic and network information in MaxMind databases for HTTP and Stream. |
| [ngx_http_access_control_module](https://git.hanada.info/hanada/ngx_http_access_control_module) | Applies variable-based access rules to HTTP requests. |
| [ngx_http_auth_internal_module](https://git.hanada.info/hanada/ngx_http_auth_internal_module) | Validates internal authentication fingerprints received in request headers. |
| [ngx_http_cache_dechunk_filter_module](https://git.hanada.info/hanada/ngx_http_cache_dechunk_filter_module) | Enables byte-range responses from cached content originally received with chunked transfer encoding. |
| [ngx_http_cache_purge_module](https://git.hanada.info/hanada/ngx_http_cache_purge_module) | Builds cache keys and a persistent RocksDB index; deletes or invalidates entries by URL, prefix, host, or tag, with background processing and parent propagation. |
| [ngx_http_compression_module](https://git.hanada.info/hanada/ngx_http_compression_module) | Provides gzip, Brotli, Zstd, and deflate compression and decompression, precompressed files, Accept-Encoding normalization, and Vary handling. |
| [ngx_http_cors_module](https://git.hanada.info/hanada/ngx_http_cors_module) | Configures Cross-Origin Resource Sharing response headers and preflight handling. |
| [ngx_http_delay_module](https://git.hanada.info/hanada/ngx_http_delay_module) | Delays HTTP request processing. |
| [ngx_http_error_log_write_module](https://git.hanada.info/hanada/ngx_http_error_log_write_module) | Writes configured messages to the error log during HTTP request processing. |
| [ngx_http_extra_variables_module](https://git.hanada.info/hanada/ngx_http_extra_variables_module) | Exposes request, response, cache, and upstream information, including request measurements and upstream timing. |
| [ngx_http_grpc_filter_module](https://git.hanada.info/hanada/ngx_http_grpc_filter_module) | Provides equivalent hooks for gRPC upstream requests and responses. |
| [ngx_http_grpc_headers_control_module](https://git.hanada.info/hanada/ngx_http_grpc_headers_control_module) | Modifies gRPC upstream request and response headers. |
| [ngx_http_grpc_set_module](https://git.hanada.info/hanada/ngx_http_grpc_set_module) | Assigns variables while processing gRPC upstream response headers. |
| [ngx_http_headers_control_module](https://git.hanada.info/hanada/ngx_http_headers_control_module) | Sets, removes, appends, and rewrites client request and response headers. |
| [ngx_http_internal_redirect_module](https://git.hanada.info/hanada/ngx_http_internal_redirect_module) | Performs internal redirects in configurable request phases and supports HTTP redirects. |
| [ngx_http_label_module](https://git.hanada.info/hanada/ngx_http_label_module) | Defines HTTP configuration labels exposed as variables. |
| [ngx_http_limit_traffic_rate_filter_module](https://git.hanada.info/hanada/ngx_http_limit_traffic_rate_filter_module) | Shares a download bandwidth limit among concurrent responses with the same key, across workers. |
| [ngx_http_log_set_module](https://git.hanada.info/hanada/ngx_http_log_set_module) | Assigns variables before HTTP access logs are written. |
| [ngx_http_loop_detect_module](https://git.hanada.info/hanada/ngx_http_loop_detect_module) | Detects forwarding loops using the `CDN-Loop` request header. |
| [ngx_http_modsecurity_module](https://github.com/owasp-modsecurity/ModSecurity-nginx) | Connects HTTP request processing to the ModSecurity v3 web application firewall. |
| [ngx_http_phase_control_module](https://git.hanada.info/hanada/ngx_http_phase_control_module) | Skips selected HTTP processing phases before their handlers run. |
| [ngx_http_proxy_args_control_module](https://git.hanada.info/hanada/ngx_http_proxy_args_control_module) | Modifies query arguments sent to HTTP upstreams. |
| [ngx_http_proxy_auth_aws_module](https://git.hanada.info/hanada/ngx_http_proxy_auth_aws_module) | Generates AWS Signature Version 4 authentication for S3 upstream requests. |
| [ngx_http_proxy_auth_basic_module](https://git.hanada.info/hanada/ngx_http_proxy_auth_basic_module) | Generates HTTP Basic authentication for upstream requests. |
| [ngx_http_proxy_auth_internal_module](https://git.hanada.info/hanada/ngx_http_proxy_auth_internal_module) | Generates internal authentication fingerprints for upstream requests. |
| [ngx_http_proxy_auth_netstorage_module](https://git.hanada.info/hanada/ngx_http_proxy_auth_netstorage_module) | Generates authentication headers for Akamai NetStorage upstream requests. |
| [ngx_http_proxy_filter_module](https://git.hanada.info/hanada/ngx_http_proxy_filter_module) | Provides hooks for proxy access checks, request headers, response headers and bodies, and request finalization. |
| [ngx_http_proxy_headers_control_module](https://git.hanada.info/hanada/ngx_http_proxy_headers_control_module) | Modifies HTTP upstream request and response headers. |
| [ngx_http_proxy_request_cookies_control_module](https://git.hanada.info/hanada/ngx_http_proxy_request_cookies_control_module) | Modifies cookies sent to HTTP upstreams. |
| [ngx_http_proxy_set_module](https://git.hanada.info/hanada/ngx_http_proxy_set_module) | Assigns variables while processing HTTP upstream response headers. |
| [ngx_http_qrcode_module](https://git.hanada.info/hanada/ngx_http_qrcode_module) | Generates and serves QR codes. |
| [ngx_http_replace_filter_module](https://github.com/openresty/replace-filter-nginx-module) | Replaces matching response body content using regular expressions. |
| [ngx_http_rewrite_status_filter_module](https://git.hanada.info/hanada/ngx_http_rewrite_status_filter_module) | Rewrites response status codes. |
| [ngx_http_secure_link_hash_module](https://git.hanada.info/hanada/ngx_http_secure_link_hash_module) | Verifies hash-signed requests with optional time limits. |
| [ngx_http_secure_link_hmac_module](https://git.hanada.info/hanada/ngx_http_secure_link_hmac_module) | Verifies HMAC-signed requests with optional time limits. |
| [ngx_http_secure_link_sign_module](https://git.hanada.info/hanada/ngx_http_secure_link_sign_module) | Verifies RSA, RSA-PSS, ECDSA, and Ed25519 signatures with optional time limits. |
| [ngx_http_security_headers_filter_module](https://git.hanada.info/hanada/ngx_http_security_headers_filter_module) | Adds security response headers, including HSTS. |
| [ngx_http_server_redirect_module](https://git.hanada.info/hanada/ngx_http_server_redirect_module) | Redirects request processing to another virtual server. |
| [ngx_http_sorted_args_module](https://git.hanada.info/hanada/ngx_http_sorted_args_module) | Sorts and filters query arguments for normalized URLs and cache keys. |
| [ngx_http_ssl_strict_server_name_module](https://git.hanada.info/hanada/ngx_http_ssl_strict_server_name_module) | Controls the check between negotiated TLS SNI and the HTTP request host, with conditional configuration. |
| [ngx_http_sysguard_module](https://git.hanada.info/hanada/ngx_http_sysguard_module) | Limits request processing according to system load, memory, CPU usage, and response time. |
| [ngx_http_trim_filter_module](https://git.hanada.info/hanada/ngx_http_trim_filter_module) | Removes unnecessary HTML comments and whitespace, with optional inline JavaScript and CSS trimming. |
| [ngx_http_ua_parser_module](https://git.hanada.info/hanada/ngx_http_ua_parser_module) | Parses User-Agent values into browser, operating system, and device information. |
| [ngx_http_upstream_log_module](https://git.hanada.info/hanada/ngx_http_upstream_log_module) | Writes a separate log entry for each upstream attempt, with conditional logging and sampling. |
| [ngx_http_weserv_module](https://github.com/weserv/images) | Resizes, transforms, and converts images using libvips. |
| [ngx_lua_config_module](https://git.hanada.info/hanada/ngx_lua_config_module) | Exposes HTTP and Stream configuration values and upstream definitions through Lua APIs and nginx variables. |
| [ngx_lua_events_module](https://github.com/Kong/lua-resty-events) | Supports publish/subscribe event delivery between nginx worker processes. |
| [ngx_lua_load_var_index_module](https://git.hanada.info/hanada/ngx_lua_load_var_index_module) | Enables indexed access to HTTP and Stream nginx variables from Lua. |
| [ngx_lua_upstream_state_module](https://git.hanada.info/hanada/ngx_lua_upstream_state_module) | Lets Lua populate HTTP and Stream upstream state, timing, and peer information. |
| [ngx_ssl_fingerprint_module](https://git.hanada.info/hanada/ngx_ssl_fingerprint_module) | Exposes JA3 and JA4 TLS client fingerprints for HTTP and Stream, including HTTP/3. |
| [ngx_stat_module](https://git.hanada.info/hanada/ngx_stat_module) | Aggregates configurable HTTP and Stream metrics by group and time window. |
| [ngx_stream_access_control_module](https://git.hanada.info/hanada/ngx_stream_access_control_module) | Applies variable-based access rules to Stream sessions. |
| [ngx_stream_error_log_write_module](https://git.hanada.info/hanada/ngx_stream_error_log_write_module) | Writes configured messages to the error log during Stream session processing. |
| [ngx_stream_extra_variables_module](https://git.hanada.info/hanada/ngx_stream_extra_variables_module) | Exposes connection, session, and upstream information, including per-attempt timing and byte counts. |
| [ngx_stream_label_module](https://git.hanada.info/hanada/ngx_stream_label_module) | Defines Stream configuration labels exposed as variables. |
| [ngx_stream_log_set_module](https://git.hanada.info/hanada/ngx_stream_log_set_module) | Assigns variables before Stream access logs are written. |
| [ngx_stream_lua_upstream_module](https://git.hanada.info/hanada/ngx_stream_lua_upstream_module) | Exposes Lua APIs for inspecting and changing Stream upstream peer state. |
| [ngx_tcp_fingerprint_module](https://git.hanada.info/hanada/ngx_tcp_fingerprint_module) | Exposes passive TCP client fingerprints for HTTP and Stream. RTT collection is disabled in this bundle. |
| [ngx_var_module](https://git.hanada.info/hanada/ngx_var_module) | Defines HTTP and Stream variables using string, number, encoding, cryptographic, time, and IP functions. |

[Back to TOC](#table-of-contents)

# Additional Features

The following sections describe extensions maintained in this bundle's patches.

[Back to TOC](#table-of-contents)

## Resolver

Resolver extensions apply to HTTP, Stream and Mail.

```nginx
http {
    nameserver dns {
        server 192.0.2.53 weight=2;
        server 192.0.2.54;
        local /etc/resolv.conf level=2;
        server 203.0.113.53 level=3;
    }

    resolver dns ipv6=off max_ttl=5m
                 negative_valid=10s error_valid=1s stale_valid=5m;
    resolver_timeout 5s;
    resolver_next_nameserver error timeout rcode_servfail;
}
```

### nameserver

* **Syntax:** `nameserver name { ... }`

* **Default:** —

* **Context:** `http`, `stream`, `mail`

Defines a group of DNS servers. Group names are local to their HTTP, Stream or Mail block. A `resolver` directive may reference a group before its definition.

The block accepts `server` and `local`:

```nginx
server address [level=number] [weight=number]
               [max_fails=number] [fail_timeout=time];
local file [level=number] [weight=number]
           [max_fails=number] [fail_timeout=time];
```

`local` reads nameserver addresses from a resolv.conf file when the configuration is loaded.

| Parameter | Default | Description |
| --- | --- | --- |
| `level` | `1` | Smaller levels are tried first on a cache miss. |
| `weight` | `1` | Weight for round-robin selection within a level. |
| `max_fails` | `0` | Transport failures before temporary exclusion; `0` disables exclusion. |
| `fail_timeout` | `10s` | Failure counting window and exclusion time. |

The default port is 53. Server hostnames are resolved when the configuration is loaded. If every server in the group is excluded, selection temporarily considers all servers available.

### resolver

Extends the [HTTP resolver](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver), [Stream resolver](https://nginx.org/en/docs/stream/ngx_stream_core_module.html#resolver) and [Mail resolver](https://nginx.org/en/docs/mail/ngx_mail_core_module.html#resolver) directives.

A single server argument selects a nameserver group in the current HTTP, Stream or Mail block. If no group matches, nginx parses the argument as an address or hostname. Multiple server arguments and `local=on` retain address-list processing. Mail retains `resolver off`.

The following optional parameters are added:

| Parameter | Default | Description |
| --- | --- | --- |
| `min_ttl=time` | `0` | Minimum positive-answer TTL. |
| `max_ttl=time` | `0` | Maximum positive-answer TTL; `0` adds no limit. |
| `negative_valid=time` | `0` | Maximum cache lifetime for NXDOMAIN and NODATA. |
| `error_valid=time` | `0` | Maximum cache lifetime for final lookup failures. |
| `stale_valid=time` | `0` | Additional time during which expired positive answers may be returned while refreshing in the background. |

`valid` cannot be used with `min_ttl` or `max_ttl`, including `valid=0`. Negative and failure lifetimes use the smallest applicable TTL, their configured limit and a nonzero `valid`. Negative TTLs use the smaller SOA TTL and MINIMUM value. A zero negative TTL is not cached.

Stale answers remain available until their original validity plus `stale_valid`; access and failed refreshes do not extend that deadline. A successful refresh replaces the cached answer, and a negative result invalidates the previous positive answer. All levels of a resolver share the same cache.

### resolver_next_nameserver

* **Syntax:** `resolver_next_nameserver condition ...;`

* **Syntax:** `resolver_next_nameserver off;`

* **Default:** `resolver_next_nameserver error timeout;`

* **Context:** HTTP `http`, `server`, `location`, `upstream`; Stream `stream`, `server`, `upstream`; Mail `mail`, `server`

Specifies when another DNS server may be tried. Conditions are `error`, `timeout`, `invalid_response`, `nodata`, `rcode_formerr`, `rcode_servfail`, `rcode_nxdomain`, `rcode_notimp` and `rcode_refused`. RCODEs greater than 5 use `invalid_response`.

`off` disables retries while allowing the current attempt to complete. It takes precedence over any other conditions set at the same configuration level. Truncation fallback to TCP uses the same attempt. Exhausting a round does not start another round until the resend timer expires.

### resolver_next_nameserver_timeout

* **Syntax:** `resolver_next_nameserver_timeout time;`

* **Default:** `resolver_next_nameserver_timeout 0;`

* **Context:** HTTP `http`, `server`, `location`, `upstream`; Stream `stream`, `server`, `upstream`; Mail `mail`, `server`

Limits the time during which another nameserver may be tried. `0` disables the limit. The window starts with the first attempt and is not restarted for another level, CNAME or SRV target. `resolver_timeout` retains its existing query timeout semantics.

### resolver_next_nameserver_tries

* **Syntax:** `resolver_next_nameserver_tries number;`

* **Default:** `resolver_next_nameserver_tries 0;`

* **Context:** HTTP `http`, `server`, `location`, `upstream`; Stream `stream`, `server`, `upstream`; Mail `mail`, `server`

Limits attempts, including the first attempt, retransmissions and CNAME/SRV follow-up queries. `0` disables the limit. Waiters sharing a query retain independent limits.

[Back to TOC](#table-of-contents)

## lua-resty-core

### ngx.resolve

```lua
local addrs, err = ngx.resolve("backend.example", "ipv4")
```

Returns the resolved addresses as an array of `{ addr = "...", type = 4 | 6 }` entries, or `nil, err` on lookup failure. The optional family is `ipv4`, `ipv6`, or `both` (the default). It filters the returned addresses. The active `resolver` configuration controls which DNS queries are sent.

```lua
local name, err = ngx.resolve("192.0.2.1", "ptr")
```

The `ptr` mode accepts an IPv4 or IPv6 address and returns its PTR hostname, or `nil, err` on lookup failure.

The API follows the [ngx.resolve proposal](https://github.com/openresty/lua-nginx-module/pull/1478). It uses the resolver and timeout of the current HTTP location or Stream server. Available in HTTP server rewrite, rewrite, preaccess, access, precontent, and content, in Stream access, preread, and content, and in timers in both subsystems. Resolve upstream names before entering the balancer phase.

[Back to TOC](#table-of-contents)

### ngx.http

Sends an HTTP or HTTPS request through a named [client server](#client). Available in HTTP server rewrite, rewrite, preaccess, access, precontent and content, in Stream access, preread and content, and in timers in both subsystems.

| Call | Result |
| --- | --- |
| `ngx.http.request_uri(url[, options])` | Waits for the complete response and returns `status`, `headers` and `body` in a table. The default body limit is 16 MiB. |
| `ngx.http.request(url[, options])` | Returns `status`, `headers` and `body_reader` when the response headers arrive. There is no default total body limit. |

```lua
local res, err = ngx.http.request_uri("https://example.org/status", {
    headers = { Host = "example.org" },
})
if not res then
    return nil, err
end
return res.status, res.body
```

The URL must be absolute. Options include `server` (default `@client`), `method` (default `GET`), `headers`, `query`, `body` and `max_response_bytes`. A query string or argument table replaces the URL query. Response header names are case-insensitive. Repeated fields are returned as an array.

Both calls accept a request body string or a function that receives a suggested chunk size and returns a nonempty string, `nil` at EOF, or `nil, err`. For streaming responses, `res.body_reader([size])` reads up to the requested number of bytes (default 16 KiB) and uses the same EOF and error conventions. Call `res:close()` when stopping early. Transport errors return `nil, err`. HTTP error responses retain their status and body.

[Back to TOC](#table-of-contents)

## ngx_http_client_module

### client

* **Syntax:** *client;*

* **Default:** —

* **Context:** *server*

Declares an HTTP server for internally generated requests. It takes one literal `server_name` beginning with `@` and does not accept a `listen` directive. If `@client` is not configured, nginx creates the following default server in the HTTP configuration.

```nginx
server {
    client;
    server_name @client;
    access_log off;

    location / {
        proxy_pass $scheme://$host$is_request_port$request_port;
        proxy_set_header Host $http_host;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_ssl_server_name on;
        proxy_ssl_name $http_host;
    }
}
```

The internal request implementation is adapted from [Angie’s HTTP client module](https://github.com/webserver-llc/angie/commit/d17c5df825f2afdd7f5134b668d35a0b0d546544).

The proxy destination uses the URL scheme and host. `$is_request_port$request_port` includes the colon and port only when the URL specifies a port. The caller supplies the HTTP `Host` header. Configure a `resolver` for destinations that require DNS.

[Back to TOC](#table-of-contents)

## ngx_http_lua_module

### balancer_ssl_session_cache

* **Syntax:** `balancer_ssl_session_cache number;`

* **Default:** `balancer_ssl_session_cache 256;`

* **Context:** *upstream*

Sets the maximum number of upstream TLS sessions each worker caches for peers selected by `ngx.balancer.set_current_peer()`. Entries are allocated on demand and the least recently used entry is evicted when the cache is full. A value of zero disables the cache. Upstream TLS session reuse must be enabled. Sessions are isolated by peer, TLS name, ALPN offer and configuration context. Connections using client certificates or Lua upstream certificate or verification callbacks perform a full handshake.

### ngx.fs

Available in HTTP and Stream Lua contexts that can yield, including timers. The optional pool name defaults to `default_lua_io`. Define it with [thread_pool](https://nginx.org/en/docs/ngx_core_module.html#thread_pool).

The API is adapted from the [lua-nginx-module asynchronous file I/O proposal](https://github.com/openresty/lua-nginx-module/pull/2489).

| Operation | Description |
| --- | --- |
| `ngx.fs.read_file(path, max_bytes[, pool])` | Reads a regular file in one thread-pool task. A `nil` limit uses the file size at open time. |
| `ngx.fs.append_file(path, data[, pool])` | Opens, appends, and closes in one thread-pool task. Returns the number of bytes written. |
| `ngx.fs.open(path[, mode[, pool]])` | Opens a file in mode `r`, `w`, `a`, `r+`, or `w+`. |
| `file:read(size[, offset])` | Reads up to `size` bytes from the given offset. Returns an empty string at EOF. |
| `file:write(data[, offset])` | Writes from the given offset and returns the number of bytes written. Append mode writes at the end. |
| `file:close()` | Closes the handle. |
| `ngx.fs.stat(path[, pool])` | Returns file metadata. For symbolic links, returns the link's metadata. |

Offsets default to zero. Read sizes and offsets must be integers. Reads return Lua strings up to the LuaJIT string-size limit. I/O failures return `nil, err`. Append and write return the byte count from a single write without fsync. `file:close()` runs synchronously and invalidates the handle even if the close reports an error.

### preaccess_by_lua_block

* **Syntax:** `preaccess_by_lua_block { lua-script }`

* **Default:** *-*

* **Context:** *http, server, location, location if*

* **Phase:** *preaccess*

Runs the inline Lua code for each request during nginx's preaccess phase, after
rewrite processing and before the access phase. This is useful for early
request filtering, authentication, request-body inspection, internal redirects,
and work that must happen before access handlers.

The preaccess Lua context is yieldable. APIs such as `ngx.sleep`, cosockets,
subrequests, and request-body APIs can therefore be used subject to their normal
OpenResty restrictions. `ngx.exit` and `ngx.exec` can terminate or redirect the
request before later phases run.

By default, the handler is postponed to the end of the preaccess phase. Use
`preaccess_by_lua_no_postpone` when it must run at its natural position among
other preaccess handlers.

```nginx
location /protected {
    preaccess_by_lua_block {
        if not ngx.req.get_headers()["authorization"] then
            return ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    }

    proxy_pass http://backend;
}
```

### preaccess_by_lua_file

* **Syntax:** *preaccess_by_lua_file path;*

* **Default:** *-*

* **Context:** *http, server, location, location if*

* **Phase:** *preaccess*

Equivalent to `preaccess_by_lua_block`, except that the Lua source or LuaJIT
bytecode is loaded from `path`. Nginx variables may be used in the path. A
relative path is resolved against nginx's server prefix.

With `lua_code_cache on`, the file is loaded on the first request and cached;
reload nginx after changing it. `lua_code_cache off` can be used temporarily
during development.

```nginx
location /protected {
    preaccess_by_lua_file conf/lua/preaccess.lua;
    proxy_pass http://backend;
}
```

### preaccess_by_lua_no_postpone

* **Syntax:** *preaccess_by_lua_no_postpone on | off;*

* **Default:** *preaccess_by_lua_no_postpone off;*

* **Context:** *http*

Controls whether `preaccess_by_lua_block` and `preaccess_by_lua_file` are
postponed to the end of the preaccess phase. The default `off` runs Lua after
the other preaccess handlers. When set to `on`, the Lua handler runs at its
natural registered position among handlers such as `limit_req` and
`limit_conn`; normal completion continues through the remaining handlers.

[Back to TOC](#table-of-contents)

## ngx_http_core_module

### auto_redirect

* **Syntax:** *auto_redirect on | off | default;*

* **Default:** *auto_redirect default;*

* **Context:** *http, server, location*

Controls the automatic permanent redirect for a prefix location whose name ends with `/` when the request URI matches the location name without the trailing slash. `on` enables the redirect, `off` disables it, and `default` preserves the behavior selected by directives such as `proxy_pass`.
This directive is ported from [Angie](https://github.com/webserver-llc/angie/commit/bdaded513096c1df359f8ab540f57139a858cdbe).

### Support for https_allow_http in listen directive

* **Syntax:** *listen address[:port] [ssl] **[https_allow_http]** ...;*

* **Default:** *listen *:80 | *:8000;*

* **Context:** *server*

Refer to [listen](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen) for the original directive behavior. Adds the `https_allow_http` parameter, which allows a listener configured with `ssl` to accept both HTTP and HTTPS. The extension is from [Tengine](https://github.com/alibaba/tengine).

### Enhancement of unique request id

Based on the original nginx built-in variable $request_id, it supports inheriting unique IDs from request headers or any variables. In addition to random hex id, unique ID generation also supports trace id based on request characteristics.

* **Syntax:** *request_id_algorithm hexid | traceid;*

* **Default:** *request_id_algorithm hexid;*

* **Context:** *http, server, location*

Specify the format of the request ID.

* **Syntax:** *request_id_header header_name;*

* **Default:** *-*

* **Context:** *http, server, location*

Specifies the request header from which to inherit the request ID. The first matching header is used. Its value must contain 1 to 1024 bytes, using only ASCII letters, digits, periods (`.`), hyphens (`-`), and underscores (`_`). If the header is not configured, is missing, or has an invalid value, a new ID is generated using `request_id_algorithm`.

### Configurable default error pages

Configure the representation and diagnostic fields of nginx's built-in error responses.

* **Syntax:** *error_page_format default | json | xml;*

* **Default:** *error_page_format default;*

* **Context:** *http, server, location*

Select the output format for built-in error pages. `default` uses the HTML response, while `json` and `xml` use structured responses with the `application/json` and `application/xml` content types. Structured responses always contain the status code, error reason, and error message.

* **Syntax:** *error_page_field name $variable;*

* **Default:** *-*

* **Context:** *http, server, location*

Add a field backed by an nginx variable to built-in 4xx/5xx error responses. HTML responses display configured fields in a table; JSON and XML responses add them to the structured body. Field values are resolved once per response and escaped for the selected format. A missing or empty variable is rendered as `-`.

Multiple `error_page_field` directives preserve declaration order. The complete field list is inherited from the previous configuration level only when the current level defines no fields. Field names must start with a letter or underscore; subsequent characters may also contain digits, hyphens, and periods.

`status`, `reason` and `message` are always included and cannot be overridden by `error_page_field`.

Configure the required diagnostic fields explicitly:

```nginx
error_page_format json;
error_page_field date $time_iso8601;
error_page_field ip $remote_addr;
error_page_field server $hostname;
error_page_field id $request_id;
```

### Support for ignoring invalid Range header

* **Syntax:** *ignore_invalid_range on | off;*

* **Default:** *ignore_invalid_range off;*

* **Context:** *http, server, location*

Specify whether to ignore an invalid range header. If enabled, invalid range headers are ignored, and the full content will be responded to the client. Otherwise, the client will receive a 416 status. The invalid range headers are not cleared, just ignored.

### Conditional error_page

* **Syntax:** *error_page code ... [=[response]] uri;*

* **Default:** *-*

* **Context:** *http, server, location, when*

Refer to [error_page](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page) for the original directive behavior.

Define conditions with `ngx_expr_module` and place each conditional error page in a `when` block. Multiple condition references in one `when` are ANDed; prefix a reference with `!` to negate it. Entries retain configuration order, so an earlier unconditional error page for the same status takes precedence over a later conditional entry.

```nginx
expr use_json_error str_eq $http_accept application/json;

when use_json_error {
    error_page 404 /404.json;
}
```

The previous configuration level is used when the current level has no entries or all of its `when` conditions are false. Any unconditional entry or matching condition selects the current level as a whole. If that level has no active mapping for the response status, no parent mapping is used. `no_error_pages` stops inheritance.

### More directives for not modified checking

* **Syntax:** *ignore_if_unmodified_since on | off;*

* **Default:** *ignore_if_unmodified_since off;*

* **Context:** *http, server, location*

Specify whether to ignore the `If-Unmodified-Since` request header. If enabled, the `If-Unmodified-Since` request header will be ignored. Otherwise, the `If-Unmodified-Since` request header will be checked.

* **Syntax:** *ignore_if_match on | off;*

* **Default:** *ignore_if_match off;*

* **Context:** *http, server, location*

Specify whether to ignore the `If-Match` request header. If enabled, the `If-Match` request header will be ignored. Otherwise, the `If-Match` request header will be checked.

* **Syntax:** *not_modified_check on | any | strict | prefer_if_none_match;*

* **Default:** *not_modified_check strict;*

* **Context:** *http, server, location*

Specifies how to check if the response is unmodified (304 Not Modified):

* `off`: Do not check if the response is unmodified. the response is always considered modified.
* `any`: Check if the response is unmodified **if either** `If-Modified-Since` **or** `If-None-Match` request headers are present. If **any of the headers' checks pass**, a 304 response is returned.
* `strict`:
  - If **only one header** (`If-Modified-Since` **or** `If-None-Match`) is present, check that header. If its condition is met, return 304 (Not Modified).  
  - If **both headers** are present, **both must pass their checks** to return 304 (Not Modified).  
  - If neither header is present, the response is considered modified.
* `prefer_if_none_match`:
  - If **only one header** (`If-Modified-Since` **or** `If-None-Match`) is present, check that header. If its condition is met, return 304 (Not Modified).
  - If **both headers** are present, **only the `If-None-Match` header's condition must be satisfied** to return 304 (Not Modified).
  - If neither header is present, the response is considered modified.

[Back to TOC](#table-of-contents)

## ngx_http_ssl_module

### ssl_certificate_load

* **Syntax:** *ssl_certificate_load default | runtime;*

* **Default:** *ssl_certificate_load default;*

* **Context:** *http, server*

Specifies when certificates and private keys configured by `ssl_certificate`
and `ssl_certificate_key` are loaded. In `default` mode, files specified by
constant paths are loaded during startup or reload. In `runtime` mode, these
files are loaded on demand during TLS handshakes, in the same way as files
specified by paths containing variables.

If either path contains variables, certificates and private keys are always
loaded on demand at runtime, regardless of the selected mode.
`ssl_certificate_cache` also applies to files loaded in `runtime` mode.
The setting is inherited unless overridden.

### ssl_certificate_compression

Extends the nginx [ssl_certificate_compression](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate_compression) directive to support runtime certificates and OCSP stapling with OpenSSL 3.2 or later.

When a compressed version of the current certificate chain and staple is unavailable, the server sends the ordinary TLS 1.3 Certificate message. Worker processes use the `default` thread pool to compress new entries in builds with thread support.

### ssl_ocsp_http_client

* **Syntax:** *ssl_ocsp_http_client @name;*

* **Default:** *ssl_ocsp_http_client @client;*

* **Context:** *http, server*

Selects the HTTP client server used to check the OCSP status of client certificates. The named server must declare [client](#client).

### ssl_stapling_http_client

* **Syntax:** *ssl_stapling_http_client @name;*

* **Default:** *ssl_stapling_http_client @client;*

* **Context:** *http, server*

Selects the HTTP client server used to fetch OCSP responses for stapling. Both directives accept the same named server. The OCSP client sends an HTTP GET to the responder.

```nginx
http {
    ssl_ocsp_http_client @ocsp;
    ssl_stapling_http_client @ocsp;

    server {
        client;
        server_name @ocsp;
        access_log off;

        location / {
            proxy_pass http://$host$is_request_port$request_port;
            proxy_set_header Host $http_host;
        }
    }
}
```

### Conditional ssl_reject_handshake

* **Syntax:** *ssl_reject_handshake on | off;*

* **Default:** *ssl_reject_handshake off;*

* **Context:** *http, server, when*

Refer to [ssl_reject_handshake](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_reject_handshake) for the original directive behavior.

Define conditions with `ngx_expr_module` and place conditional settings in `when` blocks.

### ssl_delay_handshake

* **Syntax:** *ssl_delay_handshake time;*

* **Default:** *ssl_delay_handshake 0;*

* **Context:** *http, server, when*

Delays the TLS handshake by the specified time. The value can contain variables. The zero value disables the delay.

The delay is applied before handshake rejection and counts toward the handshake timeout.

> The directive is supported when using OpenSSL 1.1.1 or later, BoringSSL, and AWS-LC.

```nginx
http {
    expr restricted str_eq $ssl_server_name restricted.example.com;
    var $handshake_delay set 250ms;

    when restricted {
        ssl_delay_handshake $handshake_delay;
        ssl_reject_handshake on;
    }
}
```

### Optimizing TLS over TCP to reduce latency

By initially sending small (1 TCP segment) sized records, we are able to avoid HoL blocking of the first byte. This means TTFB is sometime lower by a whole RTT.

By sending increasingly larger records later in the connection, when HoL is not a problem, we reduce the overhead of TLS record (29 bytes per record with GCM/CHACHA-POLY).

Start each connection with small records (1369 bytes by default, configurable with `ssl_dynamic_record_low_size`).

After a given number of records (40, configurable with `ssl_dynamic_record_threshold`), start sending larger records (4229 bytes, `ssl_dynamic_record_high_size`).

Eventually after the same number of records, start sending the largest records (ssl_buffer_size).

In case the connection idles for a given amount of time (1s, `ssl_dynamic_record_timeout`), the process repeats itself (i.e. begin sending small records again).

* **Syntax:** *ssl_dynamic_record on | off;*

* **Default:** *ssl_dynamic_record off;*

* **Context:** *http, server*

Enables dynamic TLS record sizing.

* **Syntax:** *ssl_dynamic_record_timeout time;*

* **Default:** *ssl_dynamic_record_timeout 1s;*

* **Context:** *http, server*

We want the initial records to fit into one TCP segment so we don't get TCP HoL blocking due to TCP Slow Start.

A connection always starts with small records, but after a certain number of records have been sent, we increase the record size to reduce header overhead.

After a connection has idled for the specified timeout, the process starts again with small records. A value of `0` disables dynamic TLS record sizing.

* **Syntax:** *ssl_dynamic_record_low_size size;*

* **Default:** *ssl_dynamic_record_low_size 1369;*

* **Context:** *http, server*

Sets the initial record size, also used after an idle timeout. The default accounts for the maximum TLS and IPv6 overhead in one TCP segment: 1369 = 1500 - 40 (IP) - 20 (TCP) - 10 (Time) - 61 (TLS overhead). The size is limited to `ssl_buffer_size`.

* **Syntax:** *ssl_dynamic_record_high_size size;*

* **Default:** *ssl_dynamic_record_high_size 4229;*

* **Context:** *http, server*

Sets the intermediate record size. The default accounts for three TCP segments: 4229 = (1500 - 40 - 20 - 10) * 3 - 61. The size is limited to `ssl_buffer_size`.

* **Syntax:** *ssl_dynamic_record_threshold number;*

* **Default:** *ssl_dynamic_record_threshold 40;*

* **Context:** *http, server*

Dynamic record sizing is based on [Vlad Krasnov’s patch for Cloudflare](https://github.com/cloudflare/sslconfig/tree/3e45b99/patches).

### Variables about SSL handshake timestamps and time spent

New variables are introduced to get the start timestamp, end timestamp, and time taken for the SSL handshake.

| Variable                          | Description |
| ---                               | ---         |
| **$ssl_handshake_start_msec**     | SSL handshake start timestamp in seconds with the milliseconds resolution.|
| **$ssl_handshake_end_msec**       | SSL handshake finish timestamp in seconds with the milliseconds resolution.|
| **$ssl_handshake_time**           | Keeps time spent on ssl handshaking in seconds with the milliseconds resolution.|

[Back to TOC](#table-of-contents)

## ngx_http_slice_filter_module

### slice

* **Syntax:** *slice on | off;*

* **Default:** *slice off;*

* **Context:** *http, server, location, when*

Refer to [slice](https://nginx.org/en/docs/http/ngx_http_slice_module.html#slice) for the original directive behavior. The original size argument is moved to `slice_size`. This directive accepts `on` or `off` and supports conditional configuration through `when`.

When slicing is enabled, multipart byte-range requests are supported, including reordered and overlapping ranges. Design references: [Jayce’s analysis of multi-range requests with slice](https://jayce.github.io/public/posts/nginx/multi-ranges-with-slice/) and [DenizUgur’s prototype](https://github.com/DenizUgur/nginx/tree/770ec4f193bd7e8f90ea6c2ccb05ccf78355acfa).

Background cache updates retain the range of the slice being refreshed. Based on a [patch by J Carter](https://mailman.nginx.org/pipermail/nginx-devel/2024-June/M4X5EZSRTQQ6HQ5BAOBFPM7DL5QWEAZ7.html).

### slice_size

* **Syntax:** *slice_size size;*

* **Default:** *slice_size 0;*

* **Context:** *http, server, location*

Sets the size of each slice, using the size syntax of the original [slice](https://nginx.org/en/docs/http/ngx_http_slice_module.html#slice) directive. A value of `0` disables slicing regardless of the selected `slice` value.

### slice_bypass

* **Syntax:** *slice_bypass $variable;*

* **Default:** *-*

* **Context:** *http, server, location*

Disables slicing for the current request when the configured complex value, usually a variable, evaluates to a nonempty value other than `0`.

### slice_verify_etag

* **Syntax:** *slice_verify_etag on | off;*

* **Default:** *slice_verify_etag on;*

* **Context:** *http, server, location*

Controls ETag consistency verification between slice responses. A mismatch terminates the request and records an error.

### slice_verify_last_modified

* **Syntax:** *slice_verify_last_modified on | off;*

* **Default:** *slice_verify_last_modified off;*

* **Context:** *http, server, location*

Controls Last-Modified consistency verification between slice responses. A mismatch terminates the request and records an error.

### $slice_error

The `$slice_error` variable reports the first error recorded by the slice
filter. The main request and its slice subrequests share this state, so the
value remains available in the main request's access log after a subrequest
fails. It returns `ERR_NONE` when no slice filter error was recorded and is
not found when slice processing was not entered.

| Value | Description |
| --- | --- |
| **ERR_NONE** | No slice filter error was recorded. |
| **ERR_UNEXPECTED_STATUS** | A slice subrequest returned a status other than `206`. |
| **ERR_ETAG_MISMATCH** | The ETag changed between slice responses. |
| **ERR_LAST_MODIFIED_MISMATCH** | The Last-Modified value changed between slice responses. |
| **ERR_INVALID_RANGE** | The slice response contained an invalid `Content-Range` header. |
| **ERR_NO_COMPLETE_LENGTH** | The `Content-Range` header did not include a complete response length. |
| **ERR_UNEXPECTED_RANGE** | The returned range did not match the requested slice. |
| **ERR_MISSING_RESPONSE** | The slice body completed without an active slice response. |
| **ERR_SUBREQUEST_FAILED** | Creating the next slice subrequest failed. |

[Back to TOC](#table-of-contents)

## ngx_http_sub_filter_module

### Conditional sub_filter

* **Syntax:** *sub_filter string replacement;*

* **Default:** *-*

* **Context:** *http, server, location, when*

Refer to [sub_filter](https://nginx.org/en/docs/http/ngx_http_sub_module.html#sub_filter) for the original directive behavior. Define conditions with `ngx_expr_module` and place conditional replacement pairs in `when` blocks.

```nginx
expr replace_origin str_eq $upstream_type origin;

when replace_origin {
    sub_filter http://origin.example https://www.example.com;
    sub_filter origin.example www.example.com;
}

sub_filter_once off;
```

The previous configuration level is used when the current level has no pairs or all of its `when` conditions are false. Otherwise, its unconditional pairs and pairs with matching conditions form the replacement set. A search string that is absent from the response or evaluates to an empty value does not cause a fallback to parent pairs; an empty replacement removes the matching text.

[Back to TOC](#table-of-contents)

## ngx_http_proxy_module and related modules

### proxy_ssl_certificate_load

* **Syntax:** *proxy_ssl_certificate_load default | runtime;*

* **Default:** *proxy_ssl_certificate_load default;*

* **Context:** *http, server, location*

Specifies when certificates and private keys configured by
`proxy_ssl_certificate` and `proxy_ssl_certificate_key` are loaded. In `default`
mode, files specified by constant paths are loaded during startup or reload.
In `runtime` mode, these files are loaded on demand when establishing upstream
TLS connections, in the same way as files specified by paths containing variables.

If either path contains variables, certificates and private keys are always
loaded on demand at runtime, regardless of the selected mode.
`proxy_ssl_certificate_cache` also applies to files loaded in `runtime` mode.
The setting is inherited unless overridden.

> `grpc_ssl_certificate_load` and `uwsgi_ssl_certificate_load` are also available with the same behavior.

### gRPC upstream request header variables

The `$grpc_http_<name>` variables expose the final request headers sent to a gRPC upstream after applying `grpc_set_header`, passed client headers, and gRPC request filters. Header names are converted to lowercase with dashes represented by underscores. Multiple values are joined with a comma and space. `$grpc_http_host` exposes the final `:authority` value.

### gRPC upstream URI

* **Syntax:** *grpc_pass grpc://address[uri] | grpcs://address[uri];*

* **Default:** *-*

* **Context:** *location, if in location*

Refer to [grpc_pass](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_pass) for the original directive behavior. Adds an optional upstream URI, with the URI replacement rules of [proxy_pass](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass). A value containing variables uses its evaluated URI directly.

```nginx
location /api/ {
    grpc_pass grpc://grpc_backend/package.Service/;
}
```

A request for `/api/Method?debug=1` is sent upstream with `:path` set to `/package.Service/Method?debug=1`.

### gRPC upstream method

* **Syntax:** *grpc_method string;*

* **Default:** *the client request method*

* **Context:** *http, server, location, when*

Specifies the method used for the gRPC upstream request. The value can contain variables. The evaluated value is used for both the gRPC `:method` pseudo-header and the upstream request method exposed to proxy filters. `grpc_set_header` cannot override `:method`.

```nginx
grpc_method POST;
```

### Conditional upstream directives

The upstream directives listed below support conditional configuration through `when` with `ngx_expr_module`. Refer to the linked nginx documentation for the original behavior of native directives. Conditional configuration does not change a directive's syntax or default value.

For directives that select one effective value, declarations are evaluated in configuration order: the first unconditional declaration or declaration with a matching condition wins. A conditional declaration does not take precedence merely because it has a condition, so put conditional cases before an unconditional fallback.

```nginx
expr long_read str_in $http_x_profile slow debug;

when long_read {
    proxy_read_timeout 120s;
}

proxy_read_timeout 30s;
```

For `proxy_redirect` and `proxy_cookie_domain`, `proxy_cookie_path`,
`proxy_cookie_flags`, `proxy_cookie_value`, and `proxy_cookie_max_age`, enabled
rules are checked in declaration order when processing the upstream response.
The previous configuration level is used only if no declaration at the current
level is enabled. A rule that does not match its target does not cause a fallback
to parent rules.

A matching `off` declaration stops subsequent rules of that directive without
changing the current target. It does not undo an earlier successful rewrite or
disable other cookie directives. Combining `off` and ordinary rules under the
same condition remains a configuration error, including across split blocks.
An explicit `proxy_redirect default` participates at its declaration position;
the implicit default is not an additional fallback after enabled rules miss.

The supported directives are listed explicitly below.

| HTTP proxy | Stream proxy | fastcgi | scgi | uwsgi | grpc | memcached | tunnel |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [proxy_buffering](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering) | — | [fastcgi_buffering](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_buffering) | [scgi_buffering](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_buffering) | [uwsgi_buffering](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_buffering) | — | — | — |
| [proxy_cache_background_update](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_background_update) | — | [fastcgi_cache_background_update](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_background_update) | [scgi_cache_background_update](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_background_update) | [uwsgi_cache_background_update](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_background_update) | — | — | — |
| `proxy_cache_hide_cookies` | — | `fastcgi_cache_hide_cookies` | `scgi_cache_hide_cookies` | `uwsgi_cache_hide_cookies` | — | — | — |
| [proxy_cache_lock](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock) | — | [fastcgi_cache_lock](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_lock) | [scgi_cache_lock](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_lock) | [uwsgi_cache_lock](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_lock) | — | — | — |
| [proxy_cache_lock_age](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock_age) | — | [fastcgi_cache_lock_age](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_lock_age) | [scgi_cache_lock_age](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_lock_age) | [uwsgi_cache_lock_age](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_lock_age) | — | — | — |
| [proxy_cache_lock_timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock_timeout) | — | [fastcgi_cache_lock_timeout](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_lock_timeout) | [scgi_cache_lock_timeout](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_lock_timeout) | [uwsgi_cache_lock_timeout](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_lock_timeout) | — | — | — |
| `proxy_cache_max_length` | — | `fastcgi_cache_max_length` | `scgi_cache_max_length` | `uwsgi_cache_max_length` | — | — | — |
| [proxy_cache_max_range_offset](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_max_range_offset) | — | [fastcgi_cache_max_range_offset](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_max_range_offset) | [scgi_cache_max_range_offset](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_max_range_offset) | [uwsgi_cache_max_range_offset](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_max_range_offset) | — | — | — |
| [proxy_cache_methods](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_methods) | — | [fastcgi_cache_methods](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_methods) | [scgi_cache_methods](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_methods) | [uwsgi_cache_methods](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_methods) | — | — | — |
| `proxy_cache_min_length` | — | `fastcgi_cache_min_length` | `scgi_cache_min_length` | `uwsgi_cache_min_length` | — | — | — |
| [proxy_cache_min_uses](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_min_uses) | — | [fastcgi_cache_min_uses](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_min_uses) | [scgi_cache_min_uses](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_min_uses) | [uwsgi_cache_min_uses](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_min_uses) | — | — | — |
| [proxy_cache_use_stale](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_use_stale) | — | [fastcgi_cache_use_stale](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_use_stale) | [scgi_cache_use_stale](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_use_stale) | [uwsgi_cache_use_stale](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_use_stale) | — | — | — |
| `proxy_cache_vary` | — | `fastcgi_cache_vary` | `scgi_cache_vary` | `uwsgi_cache_vary` | — | — | — |
| [proxy_connect_timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_connect_timeout) | [proxy_connect_timeout](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_connect_timeout) | [fastcgi_connect_timeout](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_connect_timeout) | [scgi_connect_timeout](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_connect_timeout) | [uwsgi_connect_timeout](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_connect_timeout) | [grpc_connect_timeout](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_connect_timeout) | [memcached_connect_timeout](https://nginx.org/en/docs/http/ngx_http_memcached_module.html#memcached_connect_timeout) | [tunnel_connect_timeout](https://nginx.org/en/docs/http/ngx_http_tunnel_module.html#tunnel_connect_timeout) |
| — | [proxy_timeout](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_timeout) | — | — | — | — | — | — |
| [proxy_cookie_domain](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_domain) | — | — | — | — | — | — | — |
| [proxy_cookie_flags](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_flags) | — | — | — | — | — | — | — |
| `proxy_cookie_max_age` | — | — | — | — | — | — | — |
| [proxy_cookie_path](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_path) | — | — | — | — | — | — | — |
| `proxy_cookie_value` | — | — | — | — | — | — | — |
| [proxy_force_ranges](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_force_ranges) | — | [fastcgi_force_ranges](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_force_ranges) | [scgi_force_ranges](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_force_ranges) | [uwsgi_force_ranges](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_force_ranges) | — | — | — |
| `proxy_hide_cookie` | — | `fastcgi_hide_cookie` | `scgi_hide_cookie` | `uwsgi_hide_cookie` | — | — | — |
| `proxy_ignore_cache_control` | — | `fastcgi_ignore_cache_control` | `scgi_ignore_cache_control` | `uwsgi_ignore_cache_control` | — | — | — |
| [proxy_ignore_client_abort](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ignore_client_abort) | — | [fastcgi_ignore_client_abort](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_ignore_client_abort) | [scgi_ignore_client_abort](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_ignore_client_abort) | [uwsgi_ignore_client_abort](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_ignore_client_abort) | — | — | — |
| [proxy_ignore_headers](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ignore_headers) | — | [fastcgi_ignore_headers](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_ignore_headers) | [scgi_ignore_headers](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_ignore_headers) | [uwsgi_ignore_headers](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_ignore_headers) | [grpc_ignore_headers](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_ignore_headers) | — | — |
| [proxy_limit_rate](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_limit_rate) | — | [fastcgi_limit_rate](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_limit_rate) | [scgi_limit_rate](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_limit_rate) | [uwsgi_limit_rate](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_limit_rate) | — | — | — |
| [proxy_next_upstream](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream) | [proxy_next_upstream](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_next_upstream) | [fastcgi_next_upstream](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_next_upstream) | [scgi_next_upstream](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_next_upstream) | [uwsgi_next_upstream](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_next_upstream) | [grpc_next_upstream](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_next_upstream) | [memcached_next_upstream](https://nginx.org/en/docs/http/ngx_http_memcached_module.html#memcached_next_upstream) | [tunnel_next_upstream](https://nginx.org/en/docs/http/ngx_http_tunnel_module.html#tunnel_next_upstream) |
| [proxy_next_upstream_timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream_timeout) | [proxy_next_upstream_timeout](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_next_upstream_timeout) | [fastcgi_next_upstream_timeout](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_next_upstream_timeout) | [scgi_next_upstream_timeout](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_next_upstream_timeout) | [uwsgi_next_upstream_timeout](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_next_upstream_timeout) | [grpc_next_upstream_timeout](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_next_upstream_timeout) | [memcached_next_upstream_timeout](https://nginx.org/en/docs/http/ngx_http_memcached_module.html#memcached_next_upstream_timeout) | [tunnel_next_upstream_timeout](https://nginx.org/en/docs/http/ngx_http_tunnel_module.html#tunnel_next_upstream_timeout) |
| [proxy_next_upstream_tries](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream_tries) | [proxy_next_upstream_tries](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_next_upstream_tries) | [fastcgi_next_upstream_tries](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_next_upstream_tries) | [scgi_next_upstream_tries](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_next_upstream_tries) | [uwsgi_next_upstream_tries](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_next_upstream_tries) | [grpc_next_upstream_tries](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_next_upstream_tries) | [memcached_next_upstream_tries](https://nginx.org/en/docs/http/ngx_http_memcached_module.html#memcached_next_upstream_tries) | [tunnel_next_upstream_tries](https://nginx.org/en/docs/http/ngx_http_tunnel_module.html#tunnel_next_upstream_tries) |
| [proxy_pass_request_body](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass_request_body) | — | [fastcgi_pass_request_body](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_pass_request_body) | [scgi_pass_request_body](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_pass_request_body) | [uwsgi_pass_request_body](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_pass_request_body) | — | — | — |
| [proxy_pass_request_headers](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass_request_headers) | — | [fastcgi_pass_request_headers](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_pass_request_headers) | [scgi_pass_request_headers](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_pass_request_headers) | [uwsgi_pass_request_headers](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_pass_request_headers) | — | — | — |
| [proxy_read_timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout) | — | [fastcgi_read_timeout](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_read_timeout) | [scgi_read_timeout](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_read_timeout) | [uwsgi_read_timeout](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_read_timeout) | [grpc_read_timeout](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_read_timeout) | [memcached_read_timeout](https://nginx.org/en/docs/http/ngx_http_memcached_module.html#memcached_read_timeout) | [tunnel_read_timeout](https://nginx.org/en/docs/http/ngx_http_tunnel_module.html#tunnel_read_timeout) |
| [proxy_request_buffering](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_request_buffering) | — | [fastcgi_request_buffering](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_request_buffering) | [scgi_request_buffering](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_request_buffering) | [uwsgi_request_buffering](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_request_buffering) | — | — | — |
| [proxy_send_timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_send_timeout) | — | [fastcgi_send_timeout](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_send_timeout) | [scgi_send_timeout](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_send_timeout) | [uwsgi_send_timeout](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_send_timeout) | [grpc_send_timeout](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_send_timeout) | [memcached_send_timeout](https://nginx.org/en/docs/http/ngx_http_memcached_module.html#memcached_send_timeout) | [tunnel_send_timeout](https://nginx.org/en/docs/http/ngx_http_tunnel_module.html#tunnel_send_timeout) |
| [proxy_http_version](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version) | — | — | — | — | — | — | — |
| [proxy_method](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_method) | — | — | — | — | `grpc_method` | — | — |
| [proxy_redirect](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_redirect) | — | — | — | — | — | — | — |
| [proxy_ssl_name](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_name) | [proxy_ssl_name](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl_name) | — | — | [uwsgi_ssl_name](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_ssl_name) | [grpc_ssl_name](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_ssl_name) | — | — |
| [proxy_ssl_server_name](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_server_name) | [proxy_ssl_server_name](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl_server_name) | — | — | [uwsgi_ssl_server_name](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_ssl_server_name) | [grpc_ssl_server_name](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_ssl_server_name) | — | — |

### Support for inheritance in "proxy_set_header" and its friends

Refer to [proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header), [grpc_set_header](https://nginx.org/en/docs/http/ngx_http_grpc_module.html#grpc_set_header), [fastcgi_param](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_param), [scgi_param](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_param), and [uwsgi_param](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_param) for the original directive behavior. The switches below allow declarations to be merged with those inherited from the previous configuration level.

The extension is based on [[PATCH] Added merge inheritance to proxy_set_header](https://mailman.nginx.org/pipermail/nginx-devel/2023-November/XUGFHDLSLRTFLWIBYPSE7LTXFJHNZE3E.html).

* **Syntax:** *proxy_set_header_inherit on | off;*

* **Default:** *proxy_set_header_inherit off;*

* **Context:** *http, server, location*

Allows the merge inheritance of proxy_set_header in receiving contexts.

> grpc_set_header_inherit is also available.

* **Syntax:** *fastcgi_param_inherit on | off;*

* **Default:** *fastcgi_param_inherit off;*

* **Context:** *http, server, location*

Allows the merge inheritance of fastcgi_param in receiving contexts.

> scgi_param_inherit and uwsgi_param_inherit are also available.

### Enhancement of upstream cookie handler

Refer to [proxy_cookie_domain](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_domain), [proxy_cookie_flags](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_flags), and [proxy_cookie_path](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_path) for the original directive behavior. The directives below add cookie value and expiration rewriting.

* **Syntax:** *proxy_cookie_value off;*

* **Syntax:** *proxy_cookie_value cookie value replacement;*

* **Default:** *proxy_cookie_value off;*

* **Context:** *http, server, location, when*

Rewrites the value of a cookie in a proxied response. Plain cookie names are matched case-insensitively and can contain variables. A cookie name starting with `~` is treated as a case-insensitive regular expression.

For a plain `value`, the matching prefix is replaced and the rest of the cookie value is preserved. A value starting with `~` uses a case-sensitive regular expression, while `~*` uses a case-insensitive regular expression. The `replacement` can contain variables and can reference captures from the value regular expression.

A bare value such as `sid` is a cookie with an empty name and the value `sid`.
It is distinct from `sid=`, which has the name `sid` and an empty value.
Use `""` as the cookie name to match nameless cookies consistently in
`proxy_hide_cookie`, `proxy_cookie_value`, `proxy_cookie_max_age`, and
`proxy_cookie_flags`. Rewriting retains the bare or `=value` form; an empty
name with an empty replacement value is serialized as `=`.

```nginx
proxy_cookie_value sessionid old- new-;
proxy_cookie_value ~^session_ ~*^old-(.+)$ new-$1;
```

Several `proxy_cookie_value` directives can be configured at the same level.
The first rule matching both the cookie name and value is selected. A value
mismatch continues to the next rule; a successful rewrite is not processed
again by subsequent rules. The `off` parameter cancels rules inherited from
the previous configuration level.

* **Syntax:** *proxy_cookie_max_age off;*

* **Syntax:** *proxy_cookie_max_age cookie time;*

* **Default:** *proxy_cookie_max_age off;*

* **Context:** *http, server, location, when*

Sets the expiration time of a cookie in a proxied response. Existing `Max-Age` and `Expires` attributes are rewritten; if neither attribute is present, a `Max-Age` attribute is added. The time supports nginx time units such as `30m` and `1h`.

Plain cookie names are matched case-insensitively and can contain variables. A cookie name starting with `~` is treated as a case-insensitive regular expression.

```nginx
proxy_cookie_max_age sessionid 1h;
proxy_cookie_max_age ~^session_ 30m;
```

Several `proxy_cookie_max_age` directives can be configured at the same level. The first rule with a matching cookie name is selected. The `off` parameter cancels rules inherited from the previous configuration level.

The cookie directives above, as well as the native proxy cookie directives, support conditional configuration through `when` as listed in the conditional upstream directive table.

This bundle also adds controls for hiding upstream cookies by name and suppressing cached `Set-Cookie` fields.

* **Syntax:** *proxy_hide_cookie cookie;*

* **Default:** *-*

* **Context:** *http, server, location, when*

Sets "Set-Cookie" fields that will not be passed by cookie name.

All unconditional declarations and declarations with matching `when` conditions
at the current level are checked in declaration order. Declarations from the
previous level are used only when none at the current level are enabled; a
cookie name mismatch does not cause a fallback to the previous level.

See also the [proxy_hide_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header) directive.

> fastcgi_hide_cookie, scgi_hide_cookie and uwsgi_hide_cookie directives are also available.

* **Syntax:** *proxy_cache_hide_cookies on | off;*

* **Default:** *proxy_cache_hide_cookies off;*

* **Context:** *http, server, location, when*

Prevents Set-Cookie headers from being passed when the response is served from cache.

> fastcgi_cache_hide_cookies, scgi_cache_hide_cookies and uwsgi_cache_hide_cookies directives are also available.

### proxy_cache_lock_early_read

**Syntax:** `proxy_cache_lock_early_read on | off;`\
**Default:** `proxy_cache_lock_early_read off;`\
**Context:** `http`, `server`, `location`, `when`

Allows a request waiting for [proxy_cache_lock](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock) to read a response while its cache file is being written, including across workers. Requires proxy buffering and `use_temp_path=off` on a local file system. The lock timeout applies until the reader joins the fill.

Eligible responses are fixed-length `200` and single-range `206` responses without `Vary`, `Set-Cookie`, or `Content-Encoding`. Cache partial responses under a key that distinguishes ranges. When using slice, include `$slice_range` in the key as described in the [slice module documentation](https://nginx.org/en/docs/http/ngx_http_slice_module.html#slice). Authenticated, cookie-bearing and conditional requests use the regular cache path. A reader that joins a fill reports `MISS`; a subsequent hit reports `HIT`.

The shared temporary file design is based on [CDN77’s patch series](https://mailman.nginx.org/pipermail/nginx-devel/2022-January/7L5VS5E2RS4GG3GQF3H24IKS7QLZYFVV.html) by Jiří Setnička and Jan Prachař.

Early reads with cache purge require support for in-flight invalidation. A URL or key purge fences in-flight reads for the corresponding namespace and URL. A broader purge, or a reader that falls outside the retained purge history, can interrupt other in-flight reads.

### proxy_cache_lock_expired

**Syntax:** `proxy_cache_lock_expired on | off;`\
**Default:** `proxy_cache_lock_expired off;`\
**Context:** `http`, `server`, `location`, `when`

Extends [proxy_cache_lock](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock) to expired responses. Requests that cannot use the stale response wait for the first request to refresh it. A request that times out is passed upstream without writing its response to the cache.

Based on a [patch by Elliot Thomas](https://mailman.nginx.org/pipermail/nginx-devel/2019-June/012302.html).

### proxy_cache_lock_poll_interval

**Syntax:** `proxy_cache_lock_poll_interval time;`\
**Default:** `proxy_cache_lock_poll_interval 500ms;`\
**Context:** `http`, `server`, `location`, `when`

Sets the maximum interval between checks of a cache lock or an in-progress cache file. The interval must be greater than zero. When early readers share a timer, the shortest interval applies.

Based on a [proposal by Nejc Lovrencic](https://mailman.nginx.org/pipermail/nginx-devel/2024-March/XZ77NIM4V27W44Z75PRHCR6OA56SYOFT.html).

### Persistent cache zones

Refer to [proxy_cache_path](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path), [fastcgi_cache_path](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_cache_path), [scgi_cache_path](https://nginx.org/en/docs/http/ngx_http_scgi_module.html#scgi_cache_path), and [uwsgi_cache_path](https://nginx.org/en/docs/http/ngx_http_uwsgi_module.html#uwsgi_cache_path) for the original directive behavior.

The added `keys_state=file` parameter saves the cache keys zone on graceful shutdown and restores it on the next startup:

```nginx
proxy_cache_path /var/cache/nginx/content
                 keys_zone=content:10m
                 keys_state=/var/lib/nginx/content.zone;
```

Use a separate state file for each zone and keep its configured size
unchanged when restoring it. The state directory must exist and be writable
by the nginx master process. A reload keeps the live zone; a graceful stop
such as `nginx -s quit` saves it. `SIGKILL` does not save a snapshot. An incompatible keys-zone snapshot is renamed with the `.old` suffix. Cached response files remain usable.

`fastcgi_cache_path`, `scgi_cache_path`, and `uwsgi_cache_path` support
the same parameter. Shared-memory persistence is ported from [Angie’s shared-zone snapshots](https://github.com/webserver-llc/angie/commit/09bd7dc6dc0c10f68713a1f9153ca92e2c91b257) and [cache zone restore](https://github.com/webserver-llc/angie/commit/4cebcf43a911eb4531f7365c3c23babfd99dd371) by Vladimir Khomutov.

### Enhancement of upstream cache control

Refer to [proxy_cache_valid](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid), [proxy_cache_use_stale](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_use_stale), and [proxy_ignore_headers](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ignore_headers) for the original cache behavior.

This bundle changes upstream Cache-Control handling as follows:

* `no-cache`, `max-age=0`, and `s-maxage=0` responses can be stored as immediately stale cache entries instead of being treated as uncacheable.
* `no-cache`, `s-maxage`, `must-revalidate`, and `proxy-revalidate` require revalidation before an expired cached response can be reused.
* `no-store` and `private` responses remain uncacheable unless the corresponding Cache-Control field is ignored.

* **Syntax:** *proxy_ignore_cache_control field ...;*

* **Default:** *-*

* **Context:** *http, server, location, when*

Disables processing of certain fields of Cache-Control header in the response from upstream. The following directives can be ignored:

* no-cache
* no-store
* private
* max-age
* s-maxage
* stale-while-revalidate
* stale-if-error
* must-revalidate
* proxy-revalidate

> fastcgi_ignore_cache_control, scgi_ignore_cache_control and uwsgi_ignore_cache_control directives are also available.

* **Syntax:** *proxy_cache_min_age time;*

* **Default:** *proxy_cache_min_age 0s;*

* **Context:** *http, server, location*

If the received max-age/s-maxage of Cache-Control header from upstream is less than the specified minimum age, the max-age/s-maxage value is set to the configured minimum age value. For example, if the max-age/s-maxage value in the received HTTP header is 100s and the configured minimum age value is 200s, the effective cache time will be 200s. This directive does not rewrite the Cache-Control header. The value of this directive supports variables.

> fastcgi_cache_min_age, scgi_cache_min_age and uwsgi_cache_min_age directives are also available.

* **Syntax:** *proxy_cache_stale_if_error time;*

* **Default:** *proxy_cache_stale_if_error 0s;*

* **Context:** *http, server, location*

The stale-if-error extension of the Cache-Control header field permits using a stale cached response in case of an error. When stale-if-error is missing from Cache-Control header, this directive will take effect instead of the stale-if-error extension of the Cache-Control header. This directive has lower priority than using the directive parameters of proxy_cache_use_stale. The value of this directive supports variables.

> fastcgi_cache_stale_if_error, scgi_cache_stale_if_error and uwsgi_cache_stale_if_error directives are also available.

* **Syntax:** *proxy_cache_stale_while_revalidate time;*

* **Default:** *proxy_cache_stale_while_revalidate 0s;*

* **Context:** *http, server, location*

The stale-while-revalidate extension of the Cache-Control header field permits using a stale cached response if it is currently being updated. When stale-while-revalidate is missing from Cache-Control header, this directive will take effect instead of the stale-while-revalidate extension of the Cache-Control header. This directive has lower priority than using the directive parameters of proxy_cache_use_stale. The value of this directive supports variables.

> fastcgi_cache_stale_while_revalidate, scgi_cache_stale_while_revalidate and uwsgi_cache_stale_while_revalidate directives are also available.

* **Syntax:** *proxy_cache_types mime-type ...;*

* **Default:** `proxy_cache_types *;`

* **Context:** *http, server, location*

Enables upstream cache with the specified MIME types in addition to “text/html”. The special value “*” matches any MIME type.

> fastcgi_cache_types, scgi_cache_types and uwsgi_cache_types directives are also available.

* **Syntax:** *proxy_cache_valid [code ...] time;*

* **Default:** *-*

* **Context:** *http, server, location*

Refer to [proxy_cache_valid](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid) for the original directive behavior. The `time` parameter can contain variables.

* **Syntax:** *proxy_cache_vary on | off | string;*

* **Default:** *proxy_cache_vary on;*

* **Context:** *http, server, location, when*

Enables or disables `Vary` header handling for upstream cache.

The string parameter can be used to explicitly specify one or more header names to vary on, instead of relying on the upstream response's `Vary` header. An empty string disables the `Vary` header handling. The parameter value can contain variables.

```nginx
proxy_cache_vary Test-Header;
```
The cache will be differentiated by the value of the `Test-Header` request header.

```nginx
proxy_cache_vary "Test-Header-A, Test-Header-B";
```
The cache will be differentiated based on the values of **both** `Test-Header-A` and `Test-Header-B`.

Note that this directive only affects upstream cache, not the response headers sent to the client. If you want to also modify the `Vary` response header, use the `proxy_hide_header` and `add_header` directives.

> fastcgi_cache_vary, scgi_cache_vary and uwsgi_cache_vary directives are also available.

* **Syntax:** *proxy_cache_min_length size;*

* **Default:** *proxy_cache_min_length 0;*

* **Context:** *http, server, location, when*

Specifies the minimum response length that can be cached. Only the size of Content-Length header is checked. This directive will be ignored for chunked responses or responses with neither Content-Length header nor Transfer-Encoding header.

> fastcgi_cache_min_length, scgi_cache_min_length, uwsgi_cache_min_length directives are also available.

* **Syntax:** *proxy_cache_max_length size;*

* **Default:** *proxy_cache_max_length 0;*

* **Context:** *http, server, location, when*

Specifies the maximun response length that can be cached. Only the size of Content-Length header is checked. This directive will be ignored for chunked responses or responses with neither Content-Length header nor Transfer-Encoding header. The zero value disables maximum cache size limiting.

> fastcgi_cache_max_length, scgi_cache_max_length, uwsgi_cache_max_length directives are also available.

[Back to TOC](#table-of-contents)

## ngx_http_upstream_module

### Upstream errors

The `$upstream_error` variable reports the result of every upstream attempt.
Its sequence is aligned with `$upstream_status`: commas separate attempts and
colons separate upstream groups. A successful attempt is represented by
`ERR_NONE`, so a failed retry followed by success can be reported as:

```text
$upstream_status: 502, 200
$upstream_error: ERR_CONNECT_FAILED, ERR_NONE
$upstream_last_error: ERR_NONE
```

The `$upstream_last_error` variable reports the last value in that sequence;
it does not maintain a separate error state. Failures that occur before an
upstream state is created are retained and included in the same sequence.

| Value | Description |
| --- | --- |
| **ERR_NONE** | No upstream error was recorded. The attempt completed successfully. |
| **ERR_UNDEFINED** | Missing upstream configuration. |
| **ERR_INVALID_URL** | The upstream URL, port, scheme, or request URI is invalid. |
| **ERR_NO_RESOLVER** | A hostname must be resolved at runtime, but no resolver is configured. |
| **ERR_SSL_CERT_LOAD_FAILED** | Loading the client SSL certificate or private key for the upstream connection failed. |
| **ERR_INVALID_PROTOCOL_PARAMETER** | A protocol parameter, method, URI, header, SSL name, or similar request value is invalid or too large. |
| **ERR_RESOLVE_TIMEOUT** | Resolving the upstream hostname timed out. |
| **ERR_RESOLVE_FAILED** | Resolving the upstream hostname failed for a reason other than a timeout. |
| **ERR_NO_LIVE_PEER** | No live peer is available in the selected upstream group. |
| **ERR_CONNECT_TIMEOUT** | Establishing a connection to the upstream server timed out. |
| **ERR_CONNECT_FAILED** | Establishing a connection to the upstream server failed. |
| **ERR_SSL_HANDSHAKE_TIMEOUT** | The SSL handshake with the upstream server timed out. |
| **ERR_SSL_HANDSHAKE_FAILED** | The SSL handshake with the upstream server failed for a reason other than a timeout or certificate validation error. |
| **ERR_SSL_INVALID_CERT** | The upstream SSL certificate failed verification or did not match the configured SSL name. |
| **ERR_WRITE_TIMEOUT** | Writing the request to the upstream server timed out. |
| **ERR_WRITE_FAILED** | Writing the request to the upstream server failed for a reason other than a timeout. |
| **ERR_READ_TIMEOUT** | Reading the response from the upstream server timed out. |
| **ERR_READ_FAILED** | Reading the response from the upstream server failed for a reason other than a timeout or connection reset. |
| **ERR_CONNECTION_RESET** | The upstream server reset or aborted the connection. |
| **ERR_PREMATURELY_CLOSED** | The upstream server closed the connection before sending a complete response. |
| **ERR_HEADER_TOO_LARGE** | The upstream response header exceeded the available header buffer size. |
| **ERR_INVALID_HEADER** | The upstream server returned a malformed or otherwise invalid response header, or a cached upstream response contains an invalid header. |
| **ERR_INVALID_RESPONSE** | The upstream server returned a malformed or incompatible protocol response. |
| **ERR_INTERNAL_ERROR** | An internal error occurred while creating or processing the upstream request. |

[Back to TOC](#table-of-contents)

## ngx_http_realip_module

### Configuring real client IP with multiple request headers

* **Syntax:** *real_ip_header field | X-Real-IP | X-Forwarded-For | proxy_protocol [...];*

* **Default:** *real_ip_header X-Real-IP;*

* **Context:** *http, server, location*

Refer to [real_ip_header](https://nginx.org/en/docs/http/ngx_http_realip_module.html#real_ip_header) for the original directive behavior. Adds support for multiple sources, checked in configuration order. The first source containing a valid address is used:

```nginx
real_ip_header X-Real-IP Cdn-Src-Ip X-Forwarded-For;
```
The connection peer must be trusted by [set_real_ip_from](https://nginx.org/en/docs/http/ngx_http_realip_module.html#set_real_ip_from). Comma-separated addresses in all header fields follow [real_ip_recursive](https://nginx.org/en/docs/http/ngx_http_realip_module.html#real_ip_recursive). Once an address is obtained, the remaining sources are not checked. `X-Forwarded-For` processes multiple header lines; other fields use the first matching line.

Repeated directives append sources in declaration order. Sources are inherited only when no `real_ip_header` directive is configured at the current level.

[Back to TOC](#table-of-contents)

## ngx_http_rewrite_module

The original work is from [SEnginx](https://github.com/NeusoftSecurity/SEnginx) and [nginx-if](https://github.com/pei-jikui/nginx-if).

Refer to [if](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#if) for the original directive behavior. The extensions below add operators, combined conditions, and control-flow directives.

### Additional operators for the "if" directive

Adds the following operators to [if](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#if):
* `<`
* `>`
* `==` (numeric equality)
* `!<` or `>=`
* `!>` or `<=`
* `^~` (starts with) or `!^~` (does not start with)
* `~$` (ends with) or `!~$` (does not end with)

The numeric comparison operators support decimals and negative numbers. Non-numeric input always evaluates to false.

### "if" with multiple conditions

* **Syntax:** `if (conditions) {...}`

* **Default:** *-*

* **Context:** *server, location*

Refer to [if](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#if) for the original directive behavior. Adds `&&`, `||`, and parentheses for combining conditions.

Example:
```nginx
if ($remote_addr = 192.168.1.1 && ($http_user_agent ~ Mozilla || $server_port > 808)) {
    return 404;
}
```

**Known limitations:**

1. All sub-conditions are evaluated first before calculating the expression result. This is different from the sub-condition processing logic of general programming languages.

2. Due to the limitations of nginx script engine, if you use regular capture, you will only get the capture group of the last matching regular expression.

### Support for "elif" and "else" directives

* **Syntax:** `elif (conditions) {...}`

* **Default:** *-*

* **Context:** *server, location*

Similar to if, but if this directive is not preceded by an if/elif directive, or the result of the leading if/elif directive is true, it will not take effect.

> This directive will create a new location just like if, please refer to [if is evil](https://web.archive.org/web/20231227223503/https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/)

* **Syntax:** `else {...}`

* **Default:** *-*

* **Context:** *server, location*

Similar to if and elif, but does not contain any conditional expressions, it is always true. If this directive is not preceded by an if/elif directive, or the result of the leading if/elif directive is true, it will not take effect.

> This directive will create a new location just like if, please refer to [if is evil](https://web.archive.org/web/20231227223503/https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/)

### Support for "goto" directive

The original work is from [Angie](https://github.com/webserver-llc/angie/commit/8b6489cbbe03dbcf8b99f996c785099fcfc2d922).

* **Syntax:** *goto @named_location;*

* **Default:** *-*

* **Context:** *server, if in server, location, if in location*

Performs an unconditional internal redirect to a named location without modifying the `$uri`. Unlike `rewrite`, the directive does not change `$uri`. The redirect consumes one `uri_changes` slot; a cycle is detected and results in a 500 error.

The directive provides a clean alternative to common workarounds used to jump to a named location from the rewrite phase, such as abusing `try_files` with a guaranteed-nonexistent path as a fallback, or triggering `error_page` with an otherwise-unused status code via `return`.

Example:
```nginx
location /one {
    goto @two;
}

location @two {
    return 200 "Hello from @two";
}
```

[Back to TOC](#table-of-contents)

## ngx_http_log_module

### Conditional access_log

* **Syntax:** *access_log path [format [buffer=size] [gzip[=level]] [flush=time] [if=condition] [sample=number]];*

* **Syntax:** *access_log off;*

* **Default:** *access_log logs/access.log combined;*

* **Context:** *http, server, location, if in location, limit_except, when*

Refer to [access_log](https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log) for the original directive behavior.

Define conditions with `ngx_expr_module` and place conditional log entries in `when` blocks. Matching entries are processed in configuration order. Use `when !condition_name` for the inverse case.

When both `when` and `if=` are specified, both must permit logging. The `if!=` parameter is not supported. This also applies to `upstream_log`.

An unconditional entry or a matching `when` selects the current level's log list. Otherwise, the nearest parent level with active entries is used. Parent and child lists are not combined. Inherited conditions use the current expression definitions.

The `if=` and `sample=` parameters filter entries in the selected list. A failed filter, a matching `off`, or a write failure does not select a parent list. `upstream_log` and `stat_log` use the same rules independently.

`sample=number` accepts integers from `0` to `2147483647`; the value can contain variables. `0` skips this destination. `1` (the default) logs every eligible request or session. `N > 1` logs each entry with probability `1/N`. Destinations are sampled independently. With `upstream_log`, each upstream attempt is sampled separately.

```nginx
map $host $access_sample {
    default 20;
    important.example.com 1;
}

access_log logs/access.log combined sample=$access_sample;
upstream_log logs/upstream.log upstream sample=20;
```

Sampling is applied after `when` and `if=` and does not require `ngx_expr_module`. Invalid literal values or repeated `sample=` parameters are configuration errors. Invalid variable values log an error and skip only that entry.

```nginx
expr loggable !str_eq $status 204;

when loggable {
    access_log logs/access.log combined;
}
```

A matching `off` stops subsequent `access_log` entries at the selected level.

[Back to TOC](#table-of-contents)

## ngx_http_modsecurity_module (3rd-party module)

Refer to [ngx_http_modsecurity_module](https://github.com/owasp-modsecurity/ModSecurity-nginx).

This module connects NGINX/OpenResty with libModSecurity v3. This bundle applies a ModSecurity connector patch that adds log variables for ModSecurity interventions and matched rule IDs, skips deleted request/response headers, and adds `modsecurity_bypass`.

### modsecurity_bypass

* **Syntax:** *modsecurity_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by modsecurity. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by modsecurity.

[Back to TOC](#table-of-contents)

## ngx_stream_lua_module

The Stream `balancer_ssl_session_cache` directive works the same way as its [HTTP counterpart](#balancer_ssl_session_cache).

For asynchronous file operations and outbound HTTP requests, see [ngx.fs](#ngxfs) and [ngx.http](#ngxhttp).

### access_by_lua_block

* **Syntax:** `access_by_lua_block { lua-script }`

* **Default:** *-*

* **Context:** *stream, server*

* **Phase:** *access*

Runs Lua during the access phase of a TCP or UDP session, after `allow` and `deny` by default. The handler can yield, send data with `ngx.print` or `ngx.say`, or end the session with `ngx.exit`. See the [HTTP directive](https://github.com/openresty/lua-nginx-module#access_by_lua_block).

### access_by_lua_file

* **Syntax:** *access_by_lua_file path;*

* **Default:** *-*

* **Context:** *stream, server*

* **Phase:** *access*

Loads the Stream access handler from a file. Paths, variables and code caching follow the [HTTP directive](https://github.com/openresty/lua-nginx-module#access_by_lua_file).

### access_by_lua_no_postpone

* **Syntax:** *access_by_lua_no_postpone on | off;*

* **Default:** *access_by_lua_no_postpone off;*

* **Context:** *stream*

Controls whether the Lua handler runs at the end of the Stream access phase. See the [HTTP directive](https://github.com/openresty/lua-nginx-module#access_by_lua_no_postpone).

[Back to TOC](#table-of-contents)

## ngx_stream_log_module

### Conditional access_log

* **Syntax:** `access_log path format [buffer=size] [gzip[=level]] [flush=time] [if=condition] [sample=number];`

* **Syntax:** `access_log off;`

* **Default:** —

* **Context:** *stream, server, when*

Stream requires an explicit log format for each destination. The `when`, `if=` and `sample=` parameters follow the [HTTP directive](#conditional-access_log). See the [nginx Stream log documentation](https://nginx.org/en/docs/stream/ngx_stream_log_module.html#access_log) for the native directive.

[Back to TOC](#table-of-contents)

## ngx_stream_ssl_module

### ssl_certificate_load

* **Syntax:** *ssl_certificate_load default | runtime;*

* **Default:** *ssl_certificate_load default;*

* **Context:** *stream, server*

Stream uses the same modes as HTTP for loading server certificates and private keys. See [ssl_certificate_load](#ssl_certificate_load).

### ssl_certificate_compression

Stream supports the same certificate compression and stapling behavior as HTTP. See [ssl_certificate_compression](#ssl_certificate_compression).

### ssl_ocsp_http_client

* **Syntax:** *ssl_ocsp_http_client @name;*

* **Default:** *ssl_ocsp_http_client @client;*

* **Context:** *stream, server*

As in HTTP, this directive selects the client used to check the OCSP status of client certificates. See [ssl_ocsp_http_client](#ssl_ocsp_http_client).

### ssl_stapling_http_client

* **Syntax:** *ssl_stapling_http_client @name;*

* **Default:** *ssl_stapling_http_client @client;*

* **Context:** *stream, server*

As in HTTP, this directive selects the client used to fetch OCSP responses for stapling. See [ssl_stapling_http_client](#ssl_stapling_http_client).

### ssl_reject_handshake

* **Syntax:** *ssl_reject_handshake on | off;*

* **Default:** *ssl_reject_handshake off;*

* **Context:** *stream, server, when*

For the native behavior, see [ssl_reject_handshake](https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html#ssl_reject_handshake). Conditional configuration follows the [HTTP directive](#conditional-ssl_reject_handshake).

### ssl_delay_handshake

* **Syntax:** *ssl_delay_handshake time;*

* **Default:** *ssl_delay_handshake 0;*

* **Context:** *stream, server, when*

Stream applies the same handshake delay as HTTP, including before rejection. The delay counts toward `ssl_handshake_timeout`. See [ssl_delay_handshake](#ssl_delay_handshake).

### Variables about SSL handshake timestamps and time spent

Stream exposes the same handshake timestamps and durations as HTTP. See the [SSL handshake variables](#variables-about-ssl-handshake-timestamps-and-time-spent).

[Back to TOC](#table-of-contents)

## ngx_stream_proxy_module

For the Stream proxy directives that support `when`, see [Conditional upstream directives](#conditional-upstream-directives).

### proxy_ssl_certificate_load

* **Syntax:** *proxy_ssl_certificate_load default | runtime;*

* **Default:** *proxy_ssl_certificate_load default;*

* **Context:** *stream, server*

Stream uses the same modes as HTTP for loading client certificates and private keys for upstream TLS connections. See [proxy_ssl_certificate_load](#proxy_ssl_certificate_load).

[Back to TOC](#table-of-contents)

## ngx_stream_upstream_module

### Extra variables for upstream information

| Variable                | Description |
| ---                     | ---         |
| **$upstream_status**    | Keeps status of the upstream connection. For multiple connection attempts, values are separated by commas and colons like addresses in the $upstream_addr variable. If no status is available, a dash ("-") is shown. |

[Back to TOC](#table-of-contents)

# LuaRocks

LuaRocks is the package manager for Lua modules.

It allows you to create and install Lua modules as self-contained packages called rocks. You can download and install LuaRocks on Unix and Windows. [Get started](https://luarocks.org/#quick-start)

LuaRocks is free software and uses the same license as Lua.

[Back to TOC](#table-of-contents)

# Copyright & License

The bundle itself is licensed under the 2-clause BSD license.

NGINX is a registered trademark owned by F5 NETWORKS, INC.
OpenResty® is a registered trademark owned by OpenResty Inc.

The maintainer (Hanada) of this customized bundle is not sponsored by or affiliated with OpenResty Inc. or NGINX Official / F5 NETWORKS, INC.

See LICENSE for details.

[Back to TOC](#table-of-contents)
