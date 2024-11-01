# Patches for core and modules

Enhance nginx core or openresty modules to implement more functions

## ngx_http_slice_filter_module_ext_1.21.4+.patch

This patch introduces a directive slice_allow_methods to control which request methods can be sliced. In addition, slice_check_etag and slice_check_last_modified are also introduced to control whether to check the consistency of these two headers.

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

## ngx_http_sub_filter_module_ext_1.25.3+.patch

This patch introduces a directive sub_filter_bypass to bypass sub_filter based on the value of a set of variables.

* **Syntax:** *sub_filter_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the response will not be replaced. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be replaced.

```
sub_filter_bypass $cookie_nocache $arg_nocache$arg_comment;
sub_filter_bypass $http_pragma    $http_authorization;
```

## ngx_http_listen_https_allow_http_1.21.4+.patch

This patch allows accepting http or https requests in the same port, which is useful for scenarios where special ports are used. The original work is from [Tengine](https://github.com/alibaba/tengine).

* **Syntax:** *listen address[:port] [ssl] **[https_allow_http]** ...;*

* **Default:** *listen *:80 | *:8000;*

* **Context:** *server*

When both the ssl and https_allow_http parameters are enabled for the listen directive, both https or http requests will be allowed.

## ngx_http_proxy_module_ext_1.25.3+.patch

This patch introduces the 'proxy_set_header_inherit' directive
which blocks the merge inheritance in receiving contexts when set to off. The purpose of the added mechanics is to reduce repetition within the
nginx configuration for universally set (or boilerplate) request
headers, while maintaining flexibility to set additional headers for
specific paths.
The original patch is from https://mailman.nginx.org/pipermail/nginx-devel/2023-November/XUGFHDLSLRTFLWIBYPSE7LTXFJHNZE3E.html
This patch additionally provides grpc support, Also allows setting the :authory header (From https://github.com/api7/apisix-nginx-module/blob/main/patch/1.25.3.1/nginx-grpc_set_header_authority.patch).

To enhance control over upstream cache behavior, this patch introduces some new cache-related directives.

There is no change in behavior for existing configurations.

* **Syntax:** *proxy_set_header_inherit on | off;*

* **Default:** *proxy_set_header_inherit off;*

* **Context:** *http, server, location*

Allows the merge inheritance of proxy_set_header in receiving contexts.

* **Syntax:** *grpc_set_header_inherit on | off;*

* **Default:** *grpc_set_header_inherit off;*

* **Context:** *http, server, location*

Allows the merge inheritance of grpc_set_header in receiving contexts.

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

If the received max-age/s-maxage of Cache-Control header from upstream is less than the specified minimum age, the max-age/s-maxage value is set to the configured minimum age value. For example, if the max-age/s-maxage value in the received HTTP header is 100s and the configured minimum age value is 200s, the effective cache time will be 200s. This directive does not rewrite the Cache-Control header.

> fastcgi_cache_min_age, scgi_cache_min_age, uwsgi_cache_min_age directives are also available.

* **Syntax:** *proxy_cache_stale_if_error time;*

* **Default:** *proxy_cache_stale_if_error 0s;*

* **Context:** *http, server, location*

The stale-if-error extension of the Cache-Control header field permits using a stale cached response in case of an error. When stale-if-error is missing from Cache-Control header, this directive will take effect instead of the stale-if-error extension of the Cache-Control header. This directive has lower priority than using the directive parameters of proxy_cache_use_stale.

> fastcgi_cache_stale_if_error, scgi_cache_stale_if_error, uwsgi_cache_stale_if_error directives are also available.

* **Syntax:** *proxy_cache_stale_while_revalidate time;*

* **Default:** *proxy_cache_stale_while_revalidate 0s;*

* **Context:** *http, server, location*

The stale-while-revalidate extension of the Cache-Control header field permits using a stale cached response if it is currently being updated. When stale-while-revalidate is missing from Cache-Control header, this directive will take effect instead of the stale-while-revalidate extension of the Cache-Control header. This directive has lower priority than using the directive parameters of proxy_cache_use_stale.

> fastcgi_cache_stale_while_revalidate, scgi_cache_stale_while_revalidate, uwsgi_cache_stale_while_revalidate directives are also available.

## ngx_http_realip_module_ext_1.25.3+.patch

* **Syntax:** *real_ip_header field | X-Real-IP | X-Forwarded-For | proxy_protocol;*

* **Default:** *real_ip_header X-Real-IP;*

* **Context:** *http, server, location*

Defines the request header fields whose value will be used to replace the client address. 

If multiple request fields are defined, the header values ​​will be checked in the order defined in the configuration, and the first header with a valid value will be used:

```
real_ip_header X-Real-IP Cdn-Src-Ip X-Forwarded-For;
```
The values ​​of the above headers will be checked in turn until a valid value is found.

The request header field value that contains an optional port is also used to replace the client port . The address and port should be specified according to RFC 3986.

The proxy_protocol parameter changes the client address to the one from the PROXY protocol header. The PROXY protocol must be previously enabled by setting the proxy_protocol parameter in the listen directive.

## ngx_http_rewrite_module_ext_1.25.3+.patch

The original work is from [SEnginx](https://github.com/NeusoftSecurity/SEnginx).

This patch extends the "if" directive of the original NGINX "rewrite" module. It has the following features:

### more conditions for "if" directive

Supports matching multiple conditions and the matching conditions can be "and" or "or".
Except for the original "if" condition operators, also supports:
* <
* \>
* !< or >=
* !> or <=

### "if" with multi conditions

* **Syntax:** *if_all (condition 1) (condition 2) ... {...}*

* **Default:** *-*

* **Context:** *server, location*

Specify multiple conditions. If all conditions are true, then execute the directives inside the braces"{}". This directive has the same behavior as the original "if" directive, but the following condition operators are added:
* <
* \>
* !< or >=
* !> or <=

Example:
```
if_all ($remote_addr = 192.168.1.1) ($http_user_agent ~ 'Mozilla') ($server_port > 808) {
    return 404;
}
```

* **Syntax:** *if_any (condition 1) (condition 2) ... {...}*

* **Default:** *-*

* **Context:** *server, location*

Specify multiple conditions. If any condition is true, then execute the directives inside the braces "{}". The other parts are the same as the "if_all" directive.

Known limits: 

The last character of a conditional statement cannot be ')', even if it is enclosed in quotes. For example, the following expression will cause a configuration test error.
```
if_all ($test_var = "test)") ($http_user_agent ~ 'Mozilla') ($server_port > 808) {
    return 404
}
```
If you must use a string ending with ')'， you might consider using a variable to back it up.
```
set $value "test)";
if_all ($test_var = $value) ($http_user_agent ~ 'Mozilla') ($server_port > 808) {
    return 404
}
```
If it is a regular expression, we can avoid using ')' at the end in many ways.

## ngx_http_default_error_page_optimize_1.25.3+.patch

This patch is used to optimize the information displayed on the default error page to facilitate the collection of error feedback from clients.

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

## ngx_http_gunzip_force_1.25.3+

This is a simple patch modifying the NGINX gunzip filter module to force inflate compressed responses. This is desirable in the context of an upstream source that sends responses gzipped. Please read the "other comments" section to understand this will decompress all content, so you want to specify its use as specific as possible to avoid decompressing content that you otherwise would want left untouched.

This serves multiple purposes:

It maintains transfering gzipped content between upstream server(s) and nginx, thus reducing network bandwidth.
Some modules require the upstream content to be uncompressed to work properly.
It allows nginx to recompress the data (i.e. brotli) before sending to the client.
This has been successfully tested up to version 1.20.0 (the current release as of this writing). I don't think the gunzip module code changes much (if any), so it should patch cleanly against older / future versions.

The original patch is from http://mailman.nginx.org/pipermail/nginx-devel/2013-January/003276.html. The original author is Weibin Yao.

NOTE: The gunzip module is not built by default, you must specify --with-http_gunzip_module when compiling nginx.

* **Syntax:** *gunzip_force string ...;*

* **Default:** *-*

* **Context:** *http, server, location*

Defines the conditions for forced brotli decompression. If at least one value in the string parameter is not empty and not equal to "0", forced gzip decompression is performed. But it will not try to decompress responses that do not contain the response header Content-Encoding: gzip.

## ngx_lua-remove_h2_subrequest_1.25.3.1+.patch

This patch is used to remove the limitation introduced by ngx lua on initiating sub-requests for h2 and h3 requests.

refer to [HTTP/2 with location.capture() re-enable](https://github.com/openresty/lua-nginx-module/issues/2243)

## ngx_http_gzip_filter_module_ext_1.25.3+

* **Syntax:** *gzip_max_length length;*

* **Default:** *gzip_max_length 0*;

* **Context:** *http, server, location*

Sets the maximum length of a response that will be gzipped. The length is determined only from the “Content-Length” response header field. A value of 0 means no upper limit.

* **Syntax:** *gzip_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the response will gzipped. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be gzipped.

## ngx_http_brotli_filter_ext.patch

* **Syntax:** *brotli_max_length length;*

* **Default:** *brotli_max_length 0*;

* **Context:** *http, server, location*

Sets the maximum length of a response that will be compressed. The length is determined only from the “Content-Length” response header field. A value of 0 means no upper limit.

* **Syntax:** *brotli_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the response will be compressed. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be compressed.