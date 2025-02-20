# Name

OpenResty - A High Performance Web Server and CDN Cache Server Based on Nginx and LuaJIT

# Table of Contents

- [Name](#name)
- [Table of Contents](#table-of-contents)
- [Description](#description)
- [Components](#components)
	- [Components of official OpenResty bundle](#components-of-official-openresty-bundle)
	- [Components of this OpenResty bundle](#components-of-this-openresty-bundle)
- [Additional Features](#additional-features)
	- [ngx\_lua module](#ngx_lua-module)
		- [Removal of h2 subrequest limitation](#removal-of-h2-subrequest-limitation)
	- [ngx\_http\_core\_module](#ngx_http_core_module)
		- [Support for https\_allow\_http in listen directive](#support-for-https_allow_http-in-listen-directive)
		- [Optimization of default error page](#optimization-of-default-error-page)
		- [Support for ignoring invalid Range header](#support-for-ignoring-invalid-range-header)
	- [ngx\_http\_ssl\_module](#ngx_http_ssl_module)
		- [Optimizing TLS over TCP to reduce latency](#optimizing-tls-over-tcp-to-reduce-latency)
	- [ngx\_http\_slice\_filter\_module](#ngx_http_slice_filter_module)
	- [ngx\_http\_sub\_filter\_module](#ngx_http_sub_filter_module)
	- [ngx\_http\_proxy\_module and related modules](#ngx_http_proxy_module-and-related-modules)
		- [Support for inheritance in "proxy\_set\_header"](#support-for-inheritance-in-proxy_set_header)
		- [Configuring sndbuf and rcvbuf for upstream connection](#configuring-sndbuf-and-rcvbuf-for-upstream-connection)
		- [Enhancement of upstream cache control](#enhancement-of-upstream-cache-control)
	- [ngx\_http\_realip\_module](#ngx_http_realip_module)
	- [ngx\_http\_rewrite\_module](#ngx_http_rewrite_module)
		- [Additional operators for the "if" directive](#additional-operators-for-the-if-directive)
		- ["if" with multiple conditions](#if-with-multiple-conditions)
		- [Support for "elif" and "else" directives](#support-for-elif-and-else-directives)
	- [ngx\_http\_gunzip\_module](#ngx_http_gunzip_module)
	- [ngx\_http\_gzip\_filter\_module](#ngx_http_gzip_filter_module)
	- [ngx\_http\_limit\_req\_module](#ngx_http_limit_req_module)
	- [ngx\_http\_brotli\_filter\_module (3rd-party module)](#ngx_http_brotli_filter_module-3rd-party-module)
	- [ngx\_http\_waf\_module (3rd-party module)](#ngx_http_waf_module-3rd-party-module)
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


* [ngx_backtrace_module](https://github.com/alibaba/tengine/tree/master/modules/ngx_backtrace_module)
* [ngx_lua_events_module](https://github.com/Kong/lua-resty-events)
* [ngx_http_access_control_module](https://git.hanada.info/hanada/ngx_http_access_control_module)
* [ngx_http_aws_auth_module](https://git.hanada.info/hanada/ngx_http_aws_auth_module)
* [ngx_http_brotli_module](https://github.com/google/ngx_brotli)
* [ngx_http_cache_purge_module](https://github.com/nginx-modules/ngx_cache_purge)
* [ngx_http_compress_normalize_module](https://git.hanada.info/hanada/ngx_http_compress_normalize_module)
* [ngx_http_compress_vary_filter_module](https://git.hanada.info/hanada/ngx_http_compress_vary_filter_module)
* [ngx_http_cors_module](https://git.hanada.info/hanada/ngx_http_cors_module)
* [ngx_http_dechunk_module](https://git.hanada.info/hanada/ngx_http_dechunk_module)
* [ngx_http_delay_module](https://git.hanada.info/hanada/ngx_http_delay_module)
* [ngx_http_extra_vars_module](https://git.hanada.info/hanada/ngx_http_extra_vars_module)
* [ngx_http_flv_live_module](https://github.com/winshining/nginx-http-flv-module)
* [ngx_http_geoip2_module](https://github.com/leev/ngx_http_geoip2_module)
* [ngx_http_internal_auth_module](https://git.hanada.info/hanada/ngx_http_internal_auth_module)
* [ngx_http_internal_redirect_module](https://git.hanada.info/hanada/ngx_http_internal_redirect_module)
* [ngx_http_limit_traffic_rate_filter_module](https://github.com/nginx-modules/ngx_http_limit_traffic_ratefilter_module)
* [ngx_http_log_var_set_module](https://git.hanada.info/hanada/ngx_http_log_var_set_module)
* [ngx_http_lua_var_module](https://github.com/api7/lua-var-nginx-module)
* [ngx_http_proxy_connect_module](https://github.com/chobits/ngx_http_proxy_connect_module)
* [ngx_http_proxy_var_set_module](https://git.hanada.info/hanada/ngx_http_proxy_var_set_module)
* [ngx_http_qrcode_module](https://github.com/soulteary/ngx_http_qrcode_module)
* [ngx_http_replace_filter_module](https://github.com/OpenResty/replace-filter-nginx-module)
* [ngx_http_secure_link_hash_module](https://git.hanada.info/hanada/ngx_http_secure_link_hash_module)
* [ngx_http_secure_link_hmac_module](https://git.hanada.info/hanada/ngx_http_secure_link_hmac_module)
* [ngx_http_security_headers_module](https://git.hanada.info/hanada/ngx_http_security_headers_module)
* [ngx_http_server_redirect_module](https://git.hanada.info/hanada/ngx_http_server_redirect_module)
* [ngx_http_sorted_querystring_module](https://git.hanada.info/hanada/ngx_http_sorted_querystring_module)
* [ngx_http_sysguard_module](https://github.com/vozlt/nginx-module-sysguard)
* [ngx_http_trim_filter_module](https://github.com/alibaba/tengine/tree/master/modules/ngx_http_trim_filter_module)
* [ngx_http_unbrotli_filter_module](https://git.hanada.info/hanada/ngx_http_unbrotli_filter_module)
* [ngx_http_unzstd_filter_module](https://git.hanada.info/hanada/ngx_http_unzstd_filter_module)
* [ngx_http_upstream_cache_vars_module](https://git.hanada.info/hanada/ngx_http_upstream_cache_vars_module)
* [ngx_http_upstream_check_module](https://github.com/yaoweibin/nginx_upstream_check_module)
* [ngx_http_upstream_log_module](https://git.hanada.info/hanada/ngx_http_upstream_log_module)
* [ngx_http_vhost_traffic_status_module](https://github.com/vozlt/nginx-module-vts)
* [ngx_http_waf_module](https://github.com/ADD-SP/ngx_waf)
* [ngx_http_weserv_module](https://github.com/weserv/images)
* [ngx_http_zstd_module](https://git.hanada.info/hanada/ngx_http_zstd_module)
* [luarocks](https://luarocks.org/)
* [lua-resty-maxminddb](https://git.hanada.info/hanada/lua-resty-maxminddb)
* [lua-resty-multipart-parser](https://github.com/agentzh/lua-resty-multipart-parser)
* [lua-resty-balancer](https://github.com/OpenResty/lua-resty-balancer)
* [lua-resty-ctx](https://github.com/Kong/kong/blob/master/kong/resty/ctx.lua)
* [lua-resty-http](https://luarocks.org/modules/pintsized/lua-resty-http)
* [lua-resty-hmac-ffi](https://luarocks.org/modules/jkeys089/lua-resty-hmac-ffi)
* [lua-resty-jwt](https://luarocks.org/modules/cdbattags/lua-resty-jwt)
* [lua-resty-openidc](https://luarocks.org/modules/hanszandbelt/lua-resty-openidc)
* [lua-resty-dns-client](https://luarocks.org/modules/membphis/api7-lua-resty-dns-client)
* [lua-resty-kafka](https://luarocks.org/modules/doujiang24/lua-resty-kafka)
* [lua-resty-template](https://luarocks.org/modules/bungle/lua-resty-template)
* [lua-resty-mlcache](https://luarocks.org/modules/thibaultcha/lua-resty-mlcache)
* [lua-resty-jit-uuid](https://luarocks.org/modules/thibaultcha/lua-resty-jit-uuid)
* [lua-resty-cookie](https://luarocks.org/modules/utix/lua-resty-cookie)
* [lua-resty-worker-events](https://luarocks.org/modules/kong/lua-resty-worker-events)
* [lua-resty-healthcheck](https://luarocks.org/modules/kong/lua-resty-healthcheck)
* [lua-resty-expr](https://luarocks.org/modules/membphis/lua-resty-expr)
* [lyaml](https://luarocks.org/modules/gvvaughan/lyaml)
* [lua-resty-redis-connector](https://luarocks.org/modules/pintsized/lua-resty-redis-connector)

[Back to TOC](#table-of-contents)

# Additional Features

This bundle extends the functionality of the Nginx core and 3rd-party modules through patches.

The following are additional features supported in this bundle, while those already included in the official OpenResty bundle have been omitted for brevity.

[Back to TOC](#table-of-contents)

## ngx_lua module

### Removal of h2 subrequest limitation

Remove the limitation introduced by ngx lua on initiating sub-requests for h2 and h3 requests. The master branch of ngx_lua has removed this limitation. This patch will be deprecated when the next openresty stable version is released.

Refer to [HTTP/2 with location.capture() re-enable](https://github.com/OpenResty/lua-nginx-module/issues/2243)

[Back to TOC](#table-of-contents)

## ngx_http_core_module

### Support for https_allow_http in listen directive

Allows the server to accept both HTTP and HTTPS requests on the same port, which is useful for scenarios where special ports are used. The original work is from [Tengine](https://github.com/alibaba/tengine).

* **Syntax:** *listen address[:port] [ssl] **[https_allow_http]** ...;*

* **Default:** *listen *:80 | *:8000;*

* **Context:** *server*

When both the ssl and https_allow_http parameters are enabled for the listen directive, both https and http requests will be allowed.

[Back to TOC](#table-of-contents)

### Optimization of default error page

Optimize the information displayed on the default error page to facilitate the collection of error feedback from clients.

* **Syntax:** *error_page_server_info on | off;*

* **Default:** *error_page_server_info on;*

* **Context:** *http, server, location*

Show up the following information in a default 4xx/5xx error page: The date, request client ip, the request id, and the hostname serving the request are included.

* **Syntax:** *error_page_client_ip string;*

* **Default:** *-*

* **Context:** *http, server, location*

Specify the value of the ip item to be displayed on the default 4xx/5xx error page. Parameter value can contain variables. The value will be displayed on the default 
4xx/5xx error page only when the error_page_server_info directive is enabled.

* **Syntax:** *error_page_request_id string;*

* **Default:** *-*

* **Context:** *http, server, location*

Specify the value of the request id item to be displayed on the default 4xx/5xx error page. Parameter value can contain variables. The value will be displayed on the default 4xx/5xx error page only when the error_page_server_info directive is enabled.

[Back to TOC](#table-of-contents)

### Support for ignoring invalid Range header

* **Syntax:** *ignore_invalid_range on | off;*

* **Default:** *ignore_invalid_range off;*

* **Context:** *http, server, location*

Specify whether to ignore an invalid range header. If enabled, invalid range headers are ignored, and the full content will be responded to the client. Otherwise, the client will receive a 416 status. The invalid range headers are not cleared, just ignored.

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

Unlike the original patch, the directive name is changed from ssl_dyn_rec_enable to ssl_dyn_rec.

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

[Back to TOC](#table-of-contents)

## ngx_http_slice_filter_module

* **Syntax:** *slice_allow_methods GET | HEAD ...;*

* **Default:** *slice_allow_methods GET HEAD;*

* **Context:** *http, server, location*

Allow splitting responses into slices if the client request method is listed in this directive. Note that if the slice directive is unset or has the zero value, splitting the response into slices will still be disabled.

* **Syntax:** *slice_check_etag on | off;*

* **Default:** *slice_check_etag on;*

* **Context:** *http, server, location*

Whether to check the consistency of the Etag header in the slice. If it is enabled, the request will be terminated and an error will be reported when Etag mismatch in slice response occurs.

* **Syntax:** *slice_check_last_modified on | off;*

* **Default:** *slice_check_last_modified off;*

* **Context:** *http, server, location*

Whether to check the consistency of the Last-Modified header in the slice. If it is enabled, the request will be terminated and an error will be reported when Last-Modified mismatch in slice response occurs.

[Back to TOC](#table-of-contents)

## ngx_http_sub_filter_module

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

### Support for inheritance in "proxy_set_header"

Introduces the 'proxy_set_header_inherit' directive which blocks the merge inheritance in receiving contexts when set to off. The purpose of the added mechanics is to reduce repetition within the nginx configuration for universally set (or boilerplate) request headers, while maintaining flexibility to set additional headers for specific paths. The original patch is from [[PATCH] Added merge inheritance to proxy_set_header](https://mailman.nginx.org/pipermail/nginx-devel/2023-November/XUGFHDLSLRTFLWIBYPSE7LTXFJHNZE3E.html). Additionally provides grpc support.

Also allows setting the :authory header (From [nginx-grpc_set_header_authority.patch](https://github.com/api7/apisix-nginx-module/blob/main/patch/1.25.3.1/nginx-grpc_set_header_authority.patch)).

There is no change in behavior for existing configurations.

* **Syntax:** *proxy_set_header_inherit on | off;*

* **Default:** *proxy_set_header_inherit off;*

* **Context:** *http, server, location*

Allows the merge inheritance of proxy_set_header in receiving contexts.

* **Syntax:** *grpc_set_header_inherit on | off;*

* **Default:** *grpc_set_header_inherit off;*

* **Context:** *http, server, location*

Allows the merge inheritance of grpc_set_header in receiving contexts.

[Back to TOC](#table-of-contents)

### Configuring sndbuf and rcvbuf for upstream connection

Introduces two new directives to set sndbuf and rcvbuf for upstream connection. The original work is from [Tengine](https://github.com/alibaba/tengine).

* **Syntax:** *proxy_sndbuf_size size;*

* **Default:** *-*

* **Context:** *http, server, location*

Sets the sndbuf size for upstream connection. If not set, the system allocated size is followed.

> fastcgi_sndbuf_size, scgi_sndbuf_size, uwsgi_sndbuf_size, grpc_sndbuf_size directives are also available.

* **Syntax:** *proxy_rcvbuf_size size;*

* **Default:** *-*

* **Context:** *http, server, location*

Sets the rcvbuf size for upstream connection. If not set, the system allocated size is followed.

> fastcgi_rcvbuf_size, scgi_rcvbuf_size, uwsgi_rcvbuf_size, grpc_rcvbuf_size are also available.

[Back to TOC](#table-of-contents)

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

> fastcgi_ignore_cache_control, scgi_ignore_cache_control, uwsgi_ignore_cache_control directives are also available.

* **Syntax:** *proxy_cache_min_age time;*

* **Default:** *proxy_cache_min_age 0s;*

* **Context:** *http, server, location*

If the received max-age/s-maxage of Cache-Control header from upstream is less than the specified minimum age, the max-age/s-maxage value is set to the configured minimum age value. For example, if the max-age/s-maxage value in the received HTTP header is 100s and the configured minimum age value is 200s, the effective cache time will be 200s. This directive does not rewrite the Cache-Control header. The value of this directive supports variables.

> fastcgi_cache_min_age, scgi_cache_min_age, uwsgi_cache_min_age directives are also available.

* **Syntax:** *proxy_cache_stale_if_error time;*

* **Default:** *proxy_cache_stale_if_error 0s;*

* **Context:** *http, server, location*

The stale-if-error extension of the Cache-Control header field permits using a stale cached response in case of an error. When stale-if-error is missing from Cache-Control header, this directive will take effect instead of the stale-if-error extension of the Cache-Control header. This directive has lower priority than using the directive parameters of proxy_cache_use_stale. The value of this directive supports variables.

> fastcgi_cache_stale_if_error, scgi_cache_stale_if_error, uwsgi_cache_stale_if_error directives are also available.

* **Syntax:** *proxy_cache_stale_while_revalidate time;*

* **Default:** *proxy_cache_stale_while_revalidate 0s;*

* **Context:** *http, server, location*

The stale-while-revalidate extension of the Cache-Control header field permits using a stale cached response if it is currently being updated. When stale-while-revalidate is missing from Cache-Control header, this directive will take effect instead of the stale-while-revalidate extension of the Cache-Control header. This directive has lower priority than using the directive parameters of proxy_cache_use_stale. The value of this directive supports variables.

> fastcgi_cache_stale_while_revalidate, scgi_cache_stale_while_revalidate, uwsgi_cache_stale_while_revalidate directives are also available.

* **Syntax:** *proxy_cache_types mime-type ...;*

* **Default:** *proxy_cache_types text/html;*

* **Context:** *http, server, location*

Enables upstream cache with the specified MIME types in addition to “text/html”. The special value “*” matches any MIME type.

> fastcgi_cache_types, scgi_cache_types, uwsgi_cache_types directives are also available.

* **Syntax:** *proxy_cache_valid [code ...] time;*

* **Default:** *-*

* **Context:** *http, server, location*

Refer to [proxy_cache_valid](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid).
This directive has been changed to support configuring the cache time as a variable. Other behaviors remain unchanged.

[Back to TOC](#table-of-contents)

## ngx_http_realip_module

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

Extends the "if" directive of the original rewrite module. It has the following features:

### Additional operators for the "if" directive

Except for the original "if" condition operators, also supports:
* <
* \>
* !< or >=
* !> or <=
* ^~ (start with) or !^~ (not start with)

The comparison symbol supports decimals and negative numbers. Non-numeric input will always result in a negative result.

[Back to TOC](#table-of-contents)

### "if" with multiple conditions

* **Syntax:** *if (conditions) {...}*

* **Default:** *-*

* **Context:** *server, location*

Supports the use of '&&' and '||' operators in if.

Supports parenthesis-based subconditions.

Example:
```
if ($remote_addr = 192.168.1.1 && ($http_user_agent ~ 'Mozilla' || $server_port > 808)) {
    return 404;
}
```

Known limits 1: 

When ues conditional grouping based on brackets. the last character of a conditional statement cannot be ')', even if it is enclosed in quotes. For example, the following expression will cause a configuration test error.
```
if (($test_var = "test)" && $http_user_agent ~ 'Mozilla') || $server_port > 808) {
    return 404
}
```
If you must use a string ending with ')', you might consider using a variable to back it up.
```
set $value "test)";
if (($test_var = $value && $http_user_agent ~ 'Mozilla') || $server_port > 808) {
    return 404
}
```
If it is a regular expression, you can avoid using ')' at the end in many ways.


Known limits 2:

All sub-conditions are evaluated first before calculating the expression result. This is different from the sub-condition processing logic of general programming languages.

Known limits 3:

Due to the limitations of nginx script engine, if you use regular capture, you will only get the capture group of the last matching regular expression.

[Back to TOC](#table-of-contents)

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

This is a simple patch modifying the NGINX gunzip filter module to force inflate compressed responses. This is desirable in the context of an upstream source that sends responses gzipped. Please read the "other comments" section to understand this will decompress all content, so you want to specify its use as specific as possible to avoid decompressing content that you otherwise would want left untouched.

This serves multiple purposes:

It maintains transfering gzipped content between upstream server(s) and nginx, thus reducing network bandwidth.
Some modules require the upstream content to be uncompressed to work properly.
It allows nginx to recompress the data (i.e. brotli) before sending to the client.
This has been successfully tested up to version 1.20.0 (the current release as of this writing). I don't think the gunzip module code changes much (if any), so it should patch cleanly against older / future versions.

The original patch is from [A patch to force the gunzip filter module work](http://mailman.nginx.org/pipermail/nginx-devel/2013-January/003276.html). The original author is Weibin Yao.

The gunzip module is not built by default, you must specify --with-http_gunzip_module when compiling nginx.

* **Syntax:** *gunzip_force string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines the conditions for forced brotli decompression. If at least one value in the string parameter is not empty and not equal to "0", forced gzip decompression is performed. But it will not try to decompress responses that do not contain the response header Content-Encoding: gzip.

[Back to TOC](#table-of-contents)

## ngx_http_gzip_filter_module

* **Syntax:** *gzip_max_length length;*

* **Default:** *gzip_max_length 0*;

* **Context:** *http, server, location*

Sets the maximum length of a response that will be gzipped. The length is determined only from the “Content-Length” response header field. A value of 0 means no upper limit.

* **Syntax:** *gzip_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the response will gzipped. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be gzipped.

[Back to TOC](#table-of-contents)

## ngx_http_limit_req_module

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

## ngx_http_brotli_filter_module (3rd-party module)

refer to [ngx_brotli](https://github.com/google/ngx_brotli).

* **Syntax:** *brotli_max_length length;*

* **Default:** *brotli_max_length 0*;

* **Context:** *http, server, location*

Sets the maximum length of a response that will be compressed. The length is determined only from the “Content-Length” response header field. A value of 0 means no upper limit.

* **Syntax:** *brotli_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the response will be compressed. If at least one value of the string parameters is neither empty nor equal to ‘0’, the response will not be compressed.

[Back to TOC](#table-of-contents)

## ngx_http_waf_module (3rd-party module)

refer to [ngx_waf](https://github.com/ADD-SP/ngx_waf/tree/current).

This patch makes some changes to this module, mainly adding more switches for fine-grained control of WAF behavior. In addition, it also changes the appearance of the default challenge or error page and the path where the configuration file is read.

* **Syntax:** *waf_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf.

* **Syntax:** *waf_cc_deny_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf cc deny function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf cc deny function.

* **Syntax:** *waf_under_attack_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf under attack function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf under attack function.

* **Syntax:** *waf_captcha_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf captcha function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf captcha function.

* **Syntax:** *waf_modsecurity_bypass string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf modsecurity function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf modsecurity function.

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