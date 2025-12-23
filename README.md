# Name

OpenResty - A High Performance Web Server and CDN Cache Server Based on Nginx and LuaJIT

# Table of Contents

- [Name](#name)
- [Table of Contents](#table-of-contents)
- [Description](#description)
- [Components](#components)
  - [Components of official OpenResty bundle](#components-of-official-openresty-bundle)
  - [Components of this OpenResty bundle](#components-of-this-openresty-bundle)
  - [Components from lualocks](#components-from-lualocks)
- [Additional Features](#additional-features)
  - [ngx\_http](#ngx_http)
    - [Variables for timestamps and time spent on related operations](#variables-for-timestamps-and-time-spent-on-related-operations)
  - [ngx\_http\_core\_module](#ngx_http_core_module)
    - [Support for https\_allow\_http in listen directive](#support-for-https_allow_http-in-listen-directive)
    - [Enhancement of unique request id](#enhancement-of-unique-request-id)
    - [Optimization of default error page](#optimization-of-default-error-page)
    - [Support for ignoring invalid Range header](#support-for-ignoring-invalid-range-header)
    - [Support for error\_page directive with if parameter](#support-for-error_page-directive-with-if-parameter)
    - [More directives for not modified checking](#more-directives-for-not-modified-checking)
  - [ngx\_http\_ssl\_module](#ngx_http_ssl_module)
    - [Optimizing TLS over TCP to reduce latency](#optimizing-tls-over-tcp-to-reduce-latency)
    - [Strict SNI validation](#strict-sni-validation)
    - [Variables about SSL handshake timestamps and time spent](#variables-about-ssl-handshake-timestamps-and-time-spent)
  - [ngx\_http\_slice\_filter\_module](#ngx_http_slice_filter_module)
    - [slice\_allow\_methods](#slice_allow_methods)
    - [slice\_check\_etag](#slice_check_etag)
    - [slice\_check\_last\_modified](#slice_check_last_modified)
  - [ngx\_http\_sub\_filter\_module](#ngx_http_sub_filter_module)
    - [Conditional response replacement bypass](#conditional-response-replacement-bypass)
  - [ngx\_http\_proxy\_module and related modules](#ngx_http_proxy_module-and-related-modules)
    - [Support for inheritance in "proxy\_set\_header" and its friends](#support-for-inheritance-in-proxy_set_header-and-its-friends)
    - [Configuring sndbuf and rcvbuf for upstream connection](#configuring-sndbuf-and-rcvbuf-for-upstream-connection)
    - [Enhancement of upstream cookie handler](#enhancement-of-upstream-cookie-handler)
    - [Enhancement of upstream cache control](#enhancement-of-upstream-cache-control)
  - [ngx\_http\_upstream\_module](#ngx_http_upstream_module)
    - [Extra variables for upstream information](#extra-variables-for-upstream-information)
  - [ngx\_http\_realip\_module](#ngx_http_realip_module)
    - [Configuring real client IP with multiple request headers](#configuring-real-client-ip-with-multiple-request-headers)
  - [ngx\_http\_rewrite\_module](#ngx_http_rewrite_module)
    - [Additional operators for the "if" directive](#additional-operators-for-the-if-directive)
    - ["if" with multiple conditions](#if-with-multiple-conditions)
    - [Support for "elif" and "else" directives](#support-for-elif-and-else-directives)
  - [ngx\_http\_gunzip\_module](#ngx_http_gunzip_module)
    - [Support for forced gzip decompression](#support-for-forced-gzip-decompression)
  - [ngx\_http\_gzip\_filter\_module](#ngx_http_gzip_filter_module)
    - [gzip\_max\_length](#gzip_max_length)
    - [gzip\_bypass](#gzip_bypass)
  - [ngx\_http\_limit\_req\_module](#ngx_http_limit_req_module)
    - [Enhanced request rate limiting with custom key and rate parameters](#enhanced-request-rate-limiting-with-custom-key-and-rate-parameters)
  - [ngx\_http\_log\_module](#ngx_http_log_module)
    - [Inverse condition support for access\_log directive](#inverse-condition-support-for-access_log-directive)
  - [ngx\_http\_brotli\_filter\_module (3rd-party module)](#ngx_http_brotli_filter_module-3rd-party-module)
    - [brotli\_max\_length](#brotli_max_length)
    - [brotli\_bypass](#brotli_bypass)
  - [ngx\_http\_waf\_module (3rd-party module)](#ngx_http_waf_module-3rd-party-module)
    - [waf\_bypass](#waf_bypass)
    - [waf\_cc\_deny\_bypass](#waf_cc_deny_bypass)
    - [waf\_under\_attack\_bypass](#waf_under_attack_bypass)
    - [waf\_captcha\_bypass](#waf_captcha_bypass)
    - [waf\_modsecurity\_bypass](#waf_modsecurity_bypass)
  - [ngx\_http\_headers\_more\_filter\_module (3rd-party module)](#ngx_http_headers_more_filter_module-3rd-party-module)
    - [more\_set\_headers](#more_set_headers)
    - [more\_clear\_headers](#more_clear_headers)
    - [more\_set\_input\_headers](#more_set_input_headers)
    - [more\_clear\_input\_headers](#more_clear_input_headers)
- [Luarocks](#luarocks)
- [Copyright \& License](#copyright--license)

# Description

OpenResty is a full-fledged web application server by bundling the standard nginx core, lots of 3rd-party nginx modules, as well as most of their external dependencies.

This customized OpenResty bundle is designed to serve as a full-featured CDN cache server while retaining OpenResty's capabilities as a high-performance dynamic web platform.

Based on the official OpenResty, this bundle includes LuaRocks, additional patches, 3rd-party nginx modules and lua libraries.

This bundle is maintained by Hanada (im@hanada.info).

The bundled software components are copyrighted by the respective copyright holders.

[Back to TOC](#table-of-contents)

# Components

## Components of official OpenResty bundle

For details on OpenResty's bundled components and features, refer to [openresty.org](https://openresty.org/).

[Back to TOC](#table-of-contents)

## Components of this OpenResty bundle

The following components are additionally bundled with OpenResty, some of which are developed and maintained by Hanada.

* [ngx_backtrace_module](https://git.hanada.info/hanada/ngx_backtrace_module)
* [ngx_lua_events_module](https://github.com/Kong/lua-resty-events)
* [ngx_lua_resty_lmdb_module](https://github.com/Kong/lua-resty-lmdb)
* [ngx_http_access_control_module](https://git.hanada.info/hanada/ngx_http_access_control_module)
* [ngx_http_acme_module](https://github.com/nginx/nginx-acme)
* [ngx_http_auth_akamai_g2o_module](https://git.hanada.info/hanada/ngx_http_auth_akamai_g2o_module)
* [ngx_http_auth_hash_module](https://git.hanada.info/hanada/ngx_http_auth_hash_module)
* [ngx_http_auth_hmac_module](https://git.hanada.info/hanada/ngx_http_auth_hmac_module)
* [ngx_http_auth_internal_module](https://git.hanada.info/hanada/ngx_http_auth_internal_module)
* [ngx_http_auth_ldap_module](https://git.hanada.info/hanada/ngx_http_auth_ldap_module)
* [ngx_http_brotli_module](https://github.com/google/ngx_brotli)
* [ngx_http_cache_purge_module](https://github.com/nginx-modules/ngx_cache_purge)
* [ngx_http_compression_normalize_module](https://git.hanada.info/hanada/ngx_http_compression_normalize_module)
* [ngx_http_compression_vary_filter_module](https://git.hanada.info/hanada/ngx_http_compression_vary_filter_module)
* [ngx_http_cors_module](https://git.hanada.info/hanada/ngx_http_cors_module)
* [ngx_http_delay_module](https://git.hanada.info/hanada/ngx_http_delay_module)
* [ngx_http_error_log_write_module](https://git.hanada.info/hanada/ngx_http_error_log_write_module)
* [ngx_http_extra_variables_module](https://git.hanada.info/hanada/ngx_http_extra_variables_module)
* [ngx_http_flv_live_module](https://github.com/winshining/nginx-http-flv-module)
* [ngx_http_geoip2_module](https://github.com/leev/ngx_http_geoip2_module)
* [ngx_http_internal_redirect_module](https://git.hanada.info/hanada/ngx_http_internal_redirect_module)
* [ngx_http_label_module](https://git.hanada.info/hanada/ngx_http_label_module)
* [ngx_http_limit_traffic_rate_filter_module](https://github.com/nginx-modules/ngx_http_limit_traffic_ratefilter_module)
* [ngx_http_log_var_set_module](https://git.hanada.info/hanada/ngx_http_log_var_set_module)
* [ngx_http_loop_detect_module](https://git.hanada.info/hanada/ngx_http_loop_detect_module)
* [ngx_http_lua_config_module](https://git.hanada.info/hanada/ngx_http_lua_config_module)
* [ngx_http_lua_load_var_index_module](https://git.hanada.info/hanada/ngx_http_lua_load_var_index_module)
* [ngx_http_proxy_auth_akamai_netstorage_module](https://git.hanada.info/hanada/ngx_http_proxy_auth_akamai_netstorage_module)
* [ngx_http_proxy_auth_aws_module](https://git.hanada.info/hanada/ngx_http_proxy_auth_aws_module)
* [ngx_http_proxy_connect_module](https://github.com/chobits/ngx_http_proxy_connect_module)
* [ngx_http_proxy_var_set_module](https://git.hanada.info/hanada/ngx_http_proxy_var_set_module)
* [ngx_http_qrcode_module](https://git.hanada.info/hanada/ngx_http_qrcode_module)
* [ngx_http_replace_filter_module](https://github.com/OpenResty/replace-filter-nginx-module)
* [ngx_http_request_cookies_filter_module](https://git.hanada.info/hanada/ngx_http_request_cookies_filter_module)
* [ngx_http_rewrite_status_filter_module](https://git.hanada.info/hanada/ngx_http_rewrite_status_filter_module)
* [ngx_http_security_headers_module](https://git.hanada.info/hanada/ngx_http_security_headers_module)
* [ngx_http_server_redirect_module](https://git.hanada.info/hanada/ngx_http_server_redirect_module)
* [ngx_http_sorted_args_module](https://git.hanada.info/hanada/ngx_http_sorted_args_module)
* [ngx_http_sysguard_module](https://github.com/vozlt/nginx-module-sysguard)
* [ngx_http_trim_filter_module](https://github.com/alibaba/tengine/tree/master/modules/ngx_http_trim_filter_module)
* [ngx_http_cache_dechunk_filter_module](https://git.hanada.info/hanada/ngx_http_cache_dechunk_filter_module)
* [ngx_http_ua_parser_module](https://git.hanada.info/hanada/ngx_http_ua_parser_module)
* [ngx_http_unbrotli_filter_module](https://git.hanada.info/hanada/ngx_http_unbrotli_filter_module)
* [ngx_http_upstream_check_module](https://github.com/yaoweibin/nginx_upstream_check_module)
* [ngx_http_upstream_log_module](https://git.hanada.info/hanada/ngx_http_upstream_log_module)
* [ngx_http_var_module](https://git.hanada.info/hanada/ngx_http_var_module)
* [ngx_http_vhost_traffic_status_module](https://github.com/vozlt/nginx-module-vts)
* [ngx_http_waf_module](https://github.com/ADD-SP/ngx_waf/tree/current)
* [ngx_http_weserv_module](https://github.com/weserv/images)
* [ngx_http_zstd_module](https://git.hanada.info/hanada/ngx_http_zstd_module)
* [coreruleset](https://github.com/coreruleset/coreruleset)
* [uap-core](https://github.com/ua-parser/uap-core)
* [luarocks](https://luarocks.org/)
* [lua-resty-maxminddb](https://git.hanada.info/hanada/lua-resty-maxminddb)
* [lua-resty-multipart-parser](https://github.com/agentzh/lua-resty-multipart-parser)
* [lua-resty-balancer](https://github.com/OpenResty/lua-resty-balancer)

## Components from lualocks
* binaryheap
* luafilesystem
* penlight
* net-url
* api7-dkjson
* lyaml
* lrandom
* luaxxhash
* lrexlib-pcre
* jsonschema
* xml2lua
* lua-ffi-zlib
* lua-resty-openssl
* lua-resty-http
* lua-resty-hmac-ffi
* lua-resty-jwt
* lua-resty-session
* lua-resty-openidc
* lua-resty-timer
* api7-lua-resty-dns-client
* lua-resty-kafka
* lua-resty-template
* lua-resty-mlcache
* lua-resty-cookie
* lua-resty-worker-events
* lua-resty-healthcheck
* lua-resty-ipmatcher
* lua-resty-expr
* lua-resty-redis-connector


[Back to TOC](#table-of-contents)

# Additional Features

This bundle extends the functionality of the Nginx core and 3rd-party modules through patches.

The following are additional features supported in this bundle, while those already included in the official OpenResty bundle have been omitted for brevity.

[Back to TOC](#table-of-contents)

## ngx_http

### Variables for timestamps and time spent on related operations

The module [ngx_http_extra_variables_module](https://git.hanada.info/hanada/ngx_http_extra_variables_module) must be compiled to use these variables.

| Variable                               | Description |
| ---                                    | ---         |
| **$response_header_sent_msec**         | Response header sent timestamp in seconds with the milliseconds resolution. |
| **$request_handling_time**             | Keeps time spent on handling request internally from receiving the request to sending the response header to the client. |
| **$response_body_time**                | Keeps time spent on sending the response body to the client. |

[Back to TOC](#table-of-contents)

## ngx_http_core_module

### Support for https_allow_http in listen directive

Allows the server to accept both HTTP and HTTPS requests on the same port, which is useful for scenarios where special ports are used. The original work is from [Tengine](https://github.com/alibaba/tengine).

* **Syntax:** *listen address[:port] [ssl] **[https_allow_http]** ...;*

* **Default:** *listen *:80 | *:8000;*

* **Context:** *server*

When both the ssl and https_allow_http parameters are enabled for the listen directive, both https and http requests will be allowed.

### Enhancement of unique request id

Based on the original nginx built-in variable $request_id, it supports inheriting unique IDs from request headers or any variables. In addition to random hex id, unique ID generation also supports trace id based on request characteristics.

* **Syntax:** *request_id_algorithm hexid | traceid;*

* **Default:** *request_id_algorithm hexid;*

* **Context:** *http, server, location*

Specify the format of the request ID.

* **Syntax:** *request_id_header header_name;*

* **Default:** *-*

* **Context:** *http, server, location*

Specify the header name to be inherited by the request ID. If no header is specified, the request id will always be regenerated.

### Optimization of default error page

Optimize the information displayed on the default error page to facilitate the collection of error feedback from clients.

* **Syntax:** *error_page_server_info on | off;*

* **Default:** *error_page_server_info on;*

* **Context:** *http, server, location*

Show up the following information in a default 4xx/5xx error page: The date, request client ip, the request id, and the hostname serving the request are included.

* **Syntax:** *error_page_client_ip $variable;*

* **Default:** *error_page_client_ip $remote_addr;*

* **Context:** *http, server, location*

Specify the value of the ip item to be displayed on the default 4xx/5xx error page. Parameter value can contain variables. The value will be displayed on the default 
4xx/5xx error page only when the error_page_server_info directive is enabled.

### Support for ignoring invalid Range header

* **Syntax:** *ignore_invalid_range on | off;*

* **Default:** *ignore_invalid_range off;*

* **Context:** *http, server, location*

Specify whether to ignore an invalid range header. If enabled, invalid range headers are ignored, and the full content will be responded to the client. Otherwise, the client will receive a 416 status. The invalid range headers are not cleared, just ignored.

### Support for error_page directive with if parameter

* **Syntax:** *error_page code ... [=[response]] uri **[if=condition]**;*

* **Default:** *-*

* **Context:** *http, server, location*

For the original usage, please refer to [error_page](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page) of nginx documentation.

The `if` parameter enables conditional error page. The condition is evaluated before the error page is processed. If the condition value is not empty or `0`, the error page will be processed. Otherwise, the error page will not be processed. You can also achieve the opposite effect by changing `if=` to `if!=`.

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

### Optimizing TLS over TCP to reduce latency

By initially sending small (1 TCP segment) sized records, we are able to avoid HoL blocking of the first byte. This means TTFB is sometime lower by a whole RTT.

By sending increasingly larger records later in the connection, when HoL is not a problem, we reduce the overhead of TLS record (29 bytes per record with GCM/CHACHA-POLY).

Start each connection with small records (1369 byte by default, it can be changed with ssl_dyn_rec_size_lo).

After a given number of records (40, change with ssl_dyn_rec_threshold) start sending larger records (4229, ssl_dyn_rec_size_hi).

Eventually after the same number of records, start sending the largest records (ssl_buffer_size).

In case the connection idles for a given amount of time (1s, ssl_dyn_rec_timeout), the process repeats itself (i.e. begin sending small records again).

* **Syntax:** *ssl_dyn_rec on | off;*

* **Default:** *ssl_dyn_rec off;*

* **Context:** *http, server*

Enable dynamic tls records.

Unlike the original patch, the directive name is changed from `ssl_dyn_rec_enable` to `ssl_dyn_rec`.

* **Syntax:** *ssl_dyn_rec_timeout time;*

* **Default:** *ssl_dyn_rec_timeout 1s;*

* **Context:** *http, server*

We want the initial records to fit into one TCP segment so we don't get TCP HoL blocking due to TCP Slow Start.

A connection always starts with small records, but after a certain number of records have been sent, we increase the record size to reduce header overhead.

After a connection has idled for a given timeout, begin the process from the start. The actual parameters are configurable. If ssl_dyn_rec_timeout is 0, we assume ssl_dyn_rec is off.

* **Syntax:** *ssl_dyn_rec_size_lo number;*

* **Default:** *ssl_dyn_rec_size_lo 1369;*

* **Context:** *http, server*

Default sizes for the dynamic record sizes are defined to fit maximal TLS + IPv6 overhead in a single TCP segment for lo and 3 segments for hi: 1369 = 1500 - 40 (IP) - 20 (TCP) - 10 (Time) - 61 (Max TLS overhead)

* **Syntax:** *ssl_dyn_rec_size_hi number;*

* **Default:** *ssl_dyn_rec_size_hi 4229;*

* **Context:** *http, server*

4229 = (1500 - 40 - 20 - 10) * 3 - 61

* **Syntax:** *ssl_dyn_rec_threshold number;*

* **Default:** *ssl_dyn_rec_threshold 40;*

* **Context:** *http, server*

Visit [ngx_http_tls_dyn_size](https://github.com/nginx-modules/ngx_http_tls_dyn_size) repository for more information.

### Strict SNI validation

Adds the validation step of SNI and Host header, and when the request violate the rule, it immediately return status 421 Misdirected Request.

* **Syntax:** *ssl_strict_server_name on | off | mtls_only;*

* **Default:** *ssl_strict_server_name mtls_only;*

* **Context:** *http, server*

Enable Strict SNI validation. When the request SNI and Host header are different. it immediately return status 421 Misdirected Request. `mtls_only` is used to enable Strict SNI validation only with `ssl_verify_client` enabled.

### Variables about SSL handshake timestamps and time spent

New variables are introduced to get the start timestamp, end timestamp, and time taken for the SSL handshake.

| Variable                          | Description |
| ---                               | ---         |
| **$ssl_handshake_start_msec**     | SSL handshake start timestamp in seconds with the milliseconds resolution.|
| **$ssl_handshake_end_msec**       | SSL handshake finish timestamp in seconds with the milliseconds resolution.|
| **$ssl_handshake_time**           | Keeps time spent on ssl handshaking in seconds with the milliseconds resolution.|

[Back to TOC](#table-of-contents)

## ngx_http_slice_filter_module

### slice_allow_methods

* **Syntax:** *slice_allow_methods GET | HEAD ...;*

* **Default:** *slice_allow_methods GET HEAD;*

* **Context:** *http, server, location*

Allow splitting responses into slices if the client request method is listed in this directive. Note that if the slice directive is unset or has the zero value, splitting the response into slices will still be disabled.

### slice_check_etag

* **Syntax:** *slice_check_etag on | off;*

* **Default:** *slice_check_etag on;*

* **Context:** *http, server, location*

Whether to check the consistency of the Etag header in the slice. If it is enabled, the request will be terminated and an error will be reported when Etag mismatch in slice response occurs.

### slice_check_last_modified

* **Syntax:** *slice_check_last_modified on | off;*

* **Default:** *slice_check_last_modified off;*

* **Context:** *http, server, location*

Whether to check the consistency of the Last-Modified header in the slice. If it is enabled, the request will be terminated and an error will be reported when Last-Modified mismatch in slice response occurs.

[Back to TOC](#table-of-contents)

## ngx_http_sub_filter_module

### Conditional response replacement bypass

This patch introduces a directive sub_filter_bypass to bypass sub_filter based on the value of a set of variables.

* **Syntax:** *sub_filter_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the response will not be replaced. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be replaced.

```
sub_filter_bypass $cookie_nocache $arg_nocache$arg_comment;
sub_filter_bypass $http_pragma    $http_authorization;
```

[Back to TOC](#table-of-contents)

## ngx_http_proxy_module and related modules

### Support for inheritance in "proxy_set_header" and its friends

Introduces the `proxy_set_header_inherit` directive which blocks the merge inheritance in receiving contexts when set to off. The purpose of the added mechanics is to reduce repetition within the nginx configuration for universally set (or boilerplate) request headers, while maintaining flexibility to set additional headers for specific paths. The original patch is from [[PATCH] Added merge inheritance to proxy_set_header](https://mailman.nginx.org/pipermail/nginx-devel/2023-November/XUGFHDLSLRTFLWIBYPSE7LTXFJHNZE3E.html).

There is no change in behavior for existing configurations.

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

### Configuring sndbuf and rcvbuf for upstream connection

Introduces two new directives to set sndbuf and rcvbuf for upstream connection. The original work is from [Tengine](https://github.com/alibaba/tengine).

* **Syntax:** *proxy_sndbuf_size size;*

* **Default:** *-*

* **Context:** *http, server, location*

Sets the sndbuf size for upstream connection. If not set, the system allocated size is followed.

> fastcgi_sndbuf_size, scgi_sndbuf_size, uwsgi_sndbuf_size and grpc_sndbuf_size directives are also available.

* **Syntax:** *proxy_rcvbuf_size size;*

* **Default:** *-*

* **Context:** *http, server, location*

Sets the rcvbuf size for upstream connection. If not set, the system allocated size is followed.

> fastcgi_rcvbuf_size, scgi_rcvbuf_size, uwsgi_rcvbuf_size and grpc_rcvbuf_size are also available.

### Enhancement of upstream cookie handler

In addition to the original three directives(`proxy_cookie_domain`, `proxy_cookie_flags` and `proxy_cookie_path`), more processing directives are added to more efficiently rewrite the the "Set-Cookie" header of the upstream response.

* **Syntax:** *proxy_cookie_value off;*
*proxy_cookie_value cookie cookie_value replacement;*

* **Default:** *proxy_cookie_value off;*

* **Context:** *http, server, location*

Sets a text that should be changed in the cookie value of the "Set-Cookie" header fields of a proxied server response. Suppose a proxied server returned the "Set-Cookie" header field and cookie name "sessionid" with a value "1234567890". The directive
```nginx
proxy_cookie_value sessionid 1234567890 abcdefghij;
```
will rewrite cookie value to "abcdefghij".

The `cookie`, `cookie_value` and `replacement` strings can contain variables.
```nginx
proxy_cookie_value $http_set_cookie_name $http_match_cookie $http_new_cookie;
```

The `cookie` can also be specified using regular expressions.
```nginx
proxy_cookie_value ~session_.* 1234567890 abcdefghij;
```

The `cookie_value` can also be specified using regular expressions. In this case, `cookie_value` should either start from the "\~" symbol for a case-sensitive matching, or from the "\~*" symbols for case-insensitive matching. The regular expression can contain named and positional captures, and `replacement` can reference them:
```
proxy_cookie_value sessionid ~(\d+) abcdefghij$1;
```
Please note that The regular expression of `cookie` can contain named and positional captures, but `replacement` cannot reference them.

Several `proxy_cookie_value` directives can be specified on the same level. If several directives can be applied to the cookie, the first matching directive will be chosen.

The off parameter cancels the effect of the `proxy_cookie_value` directives inherited from the previous configuration level.


* **Syntax:** *proxy_cookie_max_age off;*
*proxy_cookie_max_age cookie cookie time;*

* **Default:** *proxy_cookie_max_age off;*

* **Context:** *http, server, location*

Sets the maximum age of the cookie in the "Set-Cookie" header fields of a proxied server response.

This directive allows controlling the expiration time of specific cookies by modifying their "Max-Age" or "Expires" attribute. if the "Max-Age" or "Expires" attribute is not set, "Max-Age" will be added to the cookie.

The `cookie` parameter specifies the name of the cookie to be modified, and the `time` parameter defines the maximum age to be set. The time value can be specified in seconds, or with time units like `1h`, `30m`, etc.
```nginx
proxy_cookie_max_age SESSION 1h;
```

The `cookie` can also be specified using regular expressions.
```nginx
proxy_cookie_max_age ~SESSION_.* 1h;
```

Several `proxy_cookie_max_age` directives can be specified on the same level. If several directives can be applied to the cookie, the first matching directive will be chosen.

The off parameter cancels the effect of the `proxy_cookie_max_age` directives inherited from the previous configuration level.

* **Syntax:** *proxy_hide_cookie cookie;*

* **Default:** *-*

* **Context:** *http, server, location*

The `proxy_hide_cookie` directive sets "Set-Cookie" fields that will not be passed by cookie name.

See also the [proxy_hide_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header) directive.

> fastcgi_hide_cookie, scgi_hide_cookie and uwsgi_hide_cookie directives are also available.

### Enhancement of upstream cache control

Introduces some new cache-related directives to enhance control over upstream cache behavior.

* **Syntax:** *proxy_ignore_cache_control field ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Disables processing of certain fields of Cache-Control header in the response from upstream. The following directives can be ignored:

* no-cache
* no-store
* private
* max-age
* s-maxage
* stale-while-revalidate
* stale-if-error

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

* **Default:** *proxy_cache_types text/html;*

* **Context:** *http, server, location*

Enables upstream cache with the specified MIME types in addition to “text/html”. The special value “*” matches any MIME type.

> fastcgi_cache_types, scgi_cache_types and uwsgi_cache_types directives are also available.

* **Syntax:** *proxy_cache_valid [code ...] time;*

* **Default:** *-*

* **Context:** *http, server, location*

Refer to [proxy_cache_valid](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid).
This directive has been changed to support configuring the cache time as a variable. Other behaviors remain unchanged.

* **Syntax:** *proxy_cache_vary bypass | clear | string;*

* **Default:** *proxy_cache_vary bypass;*

* **Context:** *http, server, location*

Controls Vary header handling for upstream cache.

Example:
```
proxy_cache_vary Test-Header;
```
If client request contains `Test-Header` header, then cache will be different for different values of `Test-Header` header.

Example:
```
proxy_cache_vary "Test-Header-A, Test-Header-B";
```
The cache will be differentiated based on the values ​​of the request headers `Test-Header-A` **and** `Test-Header-B`.

`bypass` is used to disable `Vary` header handling. In addition, the behavior is consistent with `bypass` if parameter value is empty.

`clear` is used to clear all `Vary` headers. Parameter value can contain variables.

This directive only affects upstream cache, not response headers for client. If you want to also change the `Vary` header of the response to the client, use the `proxy_hide_header` and `add_header` directives.

> fastcgi_cache_vary, scgi_cache_vary and uwsgi_cache_vary directives are also available.

* **Syntax:** *proxy_cache_force_invalidate string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the cached response will be forcibly invalidated. If at least one value of the string parameters is not empty and is not equal to "0", the corresponding cache entry will be marked as invalid. Subsequent requests matching this cache key will bypass the invalidated entry and fetch content from upstream. Invalidated cache entries receive `MISS` status, which triggers immediate upstream fetching while bypassing cache revalidation.

Example:
```
proxy_cache_force_invalidate $cookie_purge_cache $arg_purge$arg_admin;
proxy_cache_force_invalidate $http_cache_control $http_authorization;
```

It is primarily designed to address scenarios where requests may hit cached entries before the cache purge operation (based on pattern matching) completes. For other use cases, consider using `proxy_cache_bypass` and `proxy_no_cache` directives instead.

> fastcgi_cache_force_invalidate, scgi_cache_force_invalidate, uwsgi_cache_force_invalidate directives are also available.

* **Syntax:** *proxy_cache_force_expire string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the cached response will be forcibly expired. If at least one value of the string parameters is not empty and is not equal to "0", the corresponding cache entry will be marked as expired. Subsequent requests matching this cache key will fetch new content from upstream. Expired cache entries receive `EXPIRED` status. If the `proxy_cache_revalidate` directive is enabled, cache revalidation can be performed.

It is primarily designed to address scenarios where requests may hit cached entries before the cache purge operation (based on pattern matching) completes. For other use cases, consider using `proxy_cache_bypass` and `proxy_no_cache` directives instead.

> fastcgi_cache_force_expire, scgi_cache_force_expire, uwsgi_cache_force_expire directives are also available.

* **Syntax:** *proxy_cache_min_length size;*

* **Default:** *proxy_cache_min_length 0;*

* **Context:** *http, server, location*

Specifies the minimum response length that can be cached. Only the size of Content-Length header is checked. This directive will be ignored for chunked responses or responses with neither Content-Length header nor Transfer-Encoding header.

> fastcgi_cache_min_length, scgi_cache_min_length, uwsgi_cache_min_length directives are also available.

* **Syntax:** *proxy_cache_max_length size;*

* **Default:** *proxy_cache_max_length 0;*

* **Context:** *http, server, location*

Specifies the maximun response length that can be cached. Only the size of Content-Length header is checked. This directive will be ignored for chunked responses or responses with neither Content-Length header nor Transfer-Encoding header. The zero value disables maximum cache size limiting.

> fastcgi_cache_max_length, scgi_cache_max_length, uwsgi_cache_max_length directives are also available.

[Back to TOC](#table-of-contents)

## ngx_http_upstream_module

### Extra variables for upstream information

The module [ngx_http_extra_variables_module](https://git.hanada.info/hanada/ngx_http_extra_variables_module) must be compiled to use these variables.

| Variable                                  | Description |
| ---                                       | ---         |
| **$upstream_method**                      | Upstream method, usually “GET” or “POST”. |
| **$upstream_start_msec**                  | Keeps timestamp of upstream starts; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_start_msec**             | Keeps timestamp of latest upstream starts; the time is kept in seconds with millisecond resolution. |
| **$upstream_ssl_start_msec**              | Keeps timestamp of upstream ssl handshake starts; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_ssl_start_msec**         | Keeps timestamp of latest upstream ssl handshake starts; the time is kept in seconds with millisecond resolution. |
| **$upstream_send_start_msec**             | Keeps timestamp of upstream request send starts; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_send_start_msec**        | Keeps timestamp of latest upstream request send starts; the time is kept in seconds with millisecond resolution. |
| **$upstream_send_end_msec**               | Keeps timestamp of upstream request send ends; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_send_end_msec**          | Keeps timestamp of latest upstream request send ends; the time is kept in seconds with millisecond resolution. |
| **$upstream_header_msec**                 | Keeps timestamp of upstream response header sent; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_header_msec**            | Keeps timestamp of latest upstream response header sent; the time is kept in seconds with millisecond resolution. |
| **$upstream_end_msec**                    | Keeps timestamp of upstream response sent or abnormal interruption; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_end_msec**               | Keeps timestamp of latest upstream response sent or abnormal interruption; the time is kept in seconds with millisecond resolution. |
| **$upstream_transport_connect_time**      | Keeps time spent on establishing a connection with the upstream server; the time is kept in seconds with millisecond resolution. In case of SSL, does not include time spent on handshake. Times of several connections are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_transport_connect_time** | Keeps time spent on establishing a connection with the upstream server; the time is kept in seconds with millisecond resolution. In case of SSL, does not include time spent on handshake. |
| **$upstream_ssl_time**                    | Keeps time spent on upstream ssl handshake; the time is kept in seconds with millisecond resolution. Note that this timing starts only after receiving the upstream request header. Times of several ssl connections are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_ssl_time**               | Keeps time spent on latest upstream ssl handshake; the time is kept in seconds with millisecond resolution. Note that this timing starts only after receiving the upstream request header. |
| **$upstream_send_time**                   | Keeps time spent on sending request to the upstream server; the time is kept in seconds with millisecond resolution. Times of several send requests are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_send_time**              | Keeps time spent on sending request to the latest upstream server; the time is kept in seconds with millisecond resolution. |
| **$upstream_read_time**                   | Keeps time spent on reading response from the upstream server; the time is kept in seconds with millisecond resolution. Note that this timing starts only after receiving the upstream request header. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable. |
| **$upstream_last_read_time**              | Keeps time spent on reading response from the latest upstream server; the time is kept in seconds with millisecond resolution. Note that this timing starts only after receiving the upstream request header. |

[Back to TOC](#table-of-contents)

## ngx_http_realip_module

### Configuring real client IP with multiple request headers

* **Syntax:** *real_ip_header field | X-Real-IP | X-Forwarded-For | proxy_protocol;*

* **Default:** *real_ip_header X-Real-IP;*

* **Context:** *http, server, location*

Defines the request header fields whose value will be used to replace the client address. 

If multiple request fields are defined, the header values ​​will be checked in the order defined in the configuration, and the first header with a valid value will be used:

```
real_ip_header X-Real-IP Cdn-Src-Ip X-Forwarded-For;
```
The values ​​of the above headers will be checked in turn until a valid value is found.

The request header field value that contains an optional port is also used to replace the client port. The address and port should be specified according to RFC 3986.

The proxy_protocol parameter changes the client address to the one from the PROXY protocol header. The PROXY protocol must be previously enabled by setting the proxy_protocol parameter in the listen directive.

[Back to TOC](#table-of-contents)

## ngx_http_rewrite_module

The original work is from [SEnginx](https://github.com/NeusoftSecurity/SEnginx) and [nginx-if](https://github.com/pei-jikui/nginx-if).

Extends the `if` directive of the original rewrite module. It has the following features:

### Additional operators for the "if" directive

Except for the original `if` condition operators, also supports:
* `<`
* `>`
* `!<` or `>=`
* `!>` or `<=`
* `^~` (start with) or `!^~` (not start with)

The comparison symbol supports decimals and negative numbers. Non-numeric input will always result in a negative result.

### "if" with multiple conditions

* **Syntax:** *if (conditions) {...}*

* **Default:** *-*

* **Context:** *server, location*

Supports the use of `&&` and `||` operators in if.

Supports parenthesis-based subconditions.

Example:
```
if ($remote_addr = 192.168.1.1 && ($http_user_agent ~ Mozilla || $server_port > 808)) {
    return 404;
}
```

Known limits 1: 

When ues conditional grouping based on brackets. the last character of a conditional statement cannot be `)`, even if it is enclosed in quotes. For example, the following expression will cause a configuration test error.
```
if (($test_var = "test)" && $http_user_agent ~ Mozilla) || $server_port > 808) {
    return 404;
}
```
If you must use a string ending with `)`, you might consider using a variable to back it up.
```
set $value "test)";
if (($test_var = $value && $http_user_agent ~ Mozilla) || $server_port > 808) {
    return 404;
}
```
If it is a regular expression, you can avoid using `)` at the end in many ways.


Known limits 2:

All sub-conditions are evaluated first before calculating the expression result. This is different from the sub-condition processing logic of general programming languages.

Known limits 3:

Due to the limitations of nginx script engine, if you use regular capture, you will only get the capture group of the last matching regular expression.

### Support for "elif" and "else" directives

* **Syntax:** *elif (conditions) {...}*

* **Default:** *-*

* **Context:** *server, location*

Similar to if, but if this directive is not preceded by an if/elif directive, or the result of the leading if/elif directive is true, it will not take effect.

> This directive will create a new location just like if, please refer to [if is evil](https://web.archive.org/web/20231227223503/https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/)

* **Syntax:** *else {...}*

* **Default:** *-*

* **Context:** *server, location*

Similar to if and elif, but does not contain any conditional expressions, it is always true. If this directive is not preceded by an if/elif directive, or the result of the leading if/elif directive is true, it will not take effect.

> This directive will create a new location just like if, please refer to [if is evil](https://web.archive.org/web/20231227223503/https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/)

[Back to TOC](#table-of-contents)

## ngx_http_gunzip_module

### Support for forced gzip decompression

This is a simple patch modifying the NGINX gunzip filter module to force inflate compressed responses. This is desirable in the context of an upstream source that sends responses gzipped. Please understand this will decompress all content, so you want to specify its use as specific as possible to avoid decompressing content that you otherwise would want left untouched.

* It maintains transfering gzipped content between upstream server(s) and nginx, thus reducing network bandwidth.
* Some modules require the upstream content to be uncompressed to work properly.
* It allows nginx to recompress the data (i.e. brotli) before sending to the client.

The original patch is from [A patch to force the gunzip filter module work](http://mailman.nginx.org/pipermail/nginx-devel/2013-January/003276.html). The original author is Weibin Yao.

The gunzip module is not built by default, you must specify --with-http_gunzip_module when compiling nginx.

* **Syntax:** *gunzip_force string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines the conditions for forced brotli decompression. If at least one value in the string parameter is not empty and not equal to `0`, forced gzip decompression is performed. But it will not try to decompress responses that do not contain the response header Content-Encoding: gzip.

[Back to TOC](#table-of-contents)

## ngx_http_gzip_filter_module

### gzip_max_length

* **Syntax:** *gzip_max_length length;*

* **Default:** *gzip_max_length 0*;

* **Context:** *http, server, location*

Sets the maximum length of a response that will be gzipped. The length is determined only from the “Content-Length” response header field. A value of 0 means no upper limit.

###	gzip_bypass

* **Syntax:** *gzip_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the response will gzipped. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be gzipped.

[Back to TOC](#table-of-contents)

## ngx_http_limit_req_module

### Enhanced request rate limiting with custom key and rate parameters

* **Syntax:** *limit_req zone=name [burst=number] [nodelay | delay=number] [key=string] [rate=rate]*;

* **Default:** *-*

* **Context:** *http, server, location*

refer to [limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req)

The patch adds two parameters, key and rate. If not specified, the key and rate specified by limit_req_zone are used. The key can contain text, variables, and their combination. Requests with an empty key value are not accounted.

Additionally, multiple limit_req directives in the same configuration level are allowed to use the same zone.

* **Syntax:** *limit_req_zone key | key=string zone=name:size rate=rate*;

* **Default:** *-*
  
* **Context:** *http*

refer to [limit_req_zone](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req_zone)

The patch allows configuration in the format of key=string, but is also compatible with the original configuration syntax.

[Back to TOC](#table-of-contents)

## ngx_http_log_module

### Inverse condition support for access_log directive

* **Syntax:** *access_log path [format [buffer=size] [gzip[=level]] [flush=time] [if=condition]]*;  *access_log off*;

* **Default:** *access_log logs/access.log combined;*

* **Context:** *http, server, location, if in location, limit_except*

refer to [access_log](https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log)

Based on the original `if=` parameter, you can achieve the opposite effect by changing `if=` to `if!=`.

[Back to TOC](#table-of-contents)

## ngx_http_brotli_filter_module (3rd-party module)

refer to [ngx_brotli](https://github.com/google/ngx_brotli).

### brotli_max_length

* **Syntax:** *brotli_max_length length;*

* **Default:** *brotli_max_length 0*;

* **Context:** *http, server, location*

Sets the maximum length of a response that will be compressed. The length is determined only from the “Content-Length” response header field. A value of 0 means no upper limit.

###	brotli_bypass

* **Syntax:** *brotli_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the response will not be compressed. If at least one value of the string parameters is neither empty nor equal to ‘0’, the response will not be compressed.

[Back to TOC](#table-of-contents)

## ngx_http_waf_module (3rd-party module)

refer to [ngx_waf](https://github.com/ADD-SP/ngx_waf/tree/current).

This patch makes some changes to this module, mainly adding more switches for fine-grained control of WAF behavior. In addition, it also changes the appearance of the default challenge or error page and the path where the configuration file is read.

### waf_bypass

* **Syntax:** *waf_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf.

### waf_cc_deny_bypass

* **Syntax:** *waf_cc_deny_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf cc deny function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf cc deny function.

### waf_under_attack_bypass

* **Syntax:** *waf_under_attack_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf under attack function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf under attack function.

### waf_captcha_bypass

* **Syntax:** *waf_captcha_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf captcha function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf captcha function.

### waf_modsecurity_bypass

* **Syntax:** *waf_modsecurity_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf modsecurity function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf modsecurity function.

[Back to TOC](#table-of-contents)

## ngx_http_headers_more_filter_module (3rd-party module)

This module is included in the official openresty bundle.

### more_set_headers

* **Syntax:** *more_set_headers [-t <content-type list>]... [-s <status-code list>]... [-a] <new-header>... [if=condition];*

* **Default:** *-*

* **Context:** *http, server, location, location if*

refer to [more_set_headers](https://github.com/openresty/headers-more-nginx-module#more_set_headers). Only the `if` parameter is added, nothing else changes. You can also achieve the opposite effect by changing `if=` to `if!=`.

### more_clear_headers

* **Syntax:** *more_clear_headers [-t <content-type list>]... [-s <status-code list>]... <new-header>... [if=condition];*

* **Default:** *-*

* **Context:** *http, server, location, location if*

refer to [more_clear_headers](https://github.com/openresty/headers-more-nginx-module#more_clear_headers). Only the `if` parameter is added, nothing else changes. You can also achieve the opposite effect by changing `if=` to `if!=`.

###	more_set_input_headers

* **Syntax:** *more_set_input_headers [-r] [-t <content-type list>]... <new-header>... [if=condition];*

* **Default:** *-*

* **Context:** *http, server, location, location if*

refer to [more_set_input_headers](https://github.com/openresty/headers-more-nginx-module#more_set_input_headers). Only the `if` parameter is added, nothing else changes. You can also achieve the opposite effect by changing `if=` to `if!=`.

### more_clear_input_headers

* **Syntax:** *more_clear_input_headers [-t <content-type list>]... <new-header>... [if=condition];*

* **Default:** *-*

* **Context:** *http, server, location, location if*

refer to [more_clear_input_headers](https://github.com/openresty/headers-more-nginx-module#more_clear_input_headers). Only the `if` parameter is added, nothing else changes. You can also achieve the opposite effect by changing `if=` to `if!=`.

[Back to TOC](#table-of-contents)

# Luarocks

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