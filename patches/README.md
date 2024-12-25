# Patches for core and modules

Enhance nginx core or openresty modules to implement more functions

## Table of Contents
- [Patches for core and modules](#patches-for-core-and-modules)
  - [Table of Contents](#table-of-contents)
  - [ngx\_lua module](#ngx_lua-module)
    - [remove h2 subrequest limitation](#remove-h2-subrequest-limitation)
  - [ngx\_http\_core\_module](#ngx_http_core_module)
    - [listen https\_allow\_http](#listen-https_allow_http)
    - [optimize default error page](#optimize-default-error-page)
  - [ngx\_http\_slice\_filter\_module](#ngx_http_slice_filter_module)
  - [ngx\_http\_sub\_filter\_module](#ngx_http_sub_filter_module)
  - [ngx\_http\_proxy\_module and its friends](#ngx_http_proxy_module-and-its-friends)
    - ["proxy\_set\_header" support inherit](#proxy_set_header-support-inherit)
    - [custom sndbuf and rcvbuf for upstream connection](#custom-sndbuf-and-rcvbuf-for-upstream-connection)
    - [enhancement of upstream cache control](#enhancement-of-upstream-cache-control)
  - [ngx\_http\_realip\_module](#ngx_http_realip_module)
  - [ngx\_http\_rewrite\_module](#ngx_http_rewrite_module)
    - [more operators for "if" directive](#more-operators-for-if-directive)
    - ["if" with multi conditions](#if-with-multi-conditions)
    - [support "elif" and "else" directive](#support-elif-and-else-directive)
  - [ngx\_http\_gunzip\_module](#ngx_http_gunzip_module)
  - [ngx\_http\_gzip\_filter\_module](#ngx_http_gzip_filter_module)
  - [ngx\_http\_brotli\_filter\_module (Third-party Module)](#ngx_http_brotli_filter_module-third-party-module)

## ngx_lua module

### remove h2 subrequest limitation

Remove the limitation introduced by ngx lua on initiating sub-requests for h2 and h3 requests. The mainline version of ngx_lua has removed this limitation. This patch will be deprecated after the next latest version is released.

refer to [HTTP/2 with location.capture() re-enable](https://github.com/openresty/lua-nginx-module/issues/2243)


## ngx_http_core_module

### listen https_allow_http

Allows accepting http or https requests in the same port, which is useful for scenarios where special ports are used. The original work is from [Tengine](https://github.com/alibaba/tengine).

* **Syntax:** *listen address[:port] [ssl] **[https_allow_http]** ...;*

* **Default:** *listen *:80 | *:8000;*

* **Context:** *server*

When both the ssl and https_allow_http parameters are enabled for the listen directive, both https or http requests will be allowed.

### optimize default error page 

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

## ngx_http_sub_filter_module

This patch introduces a directive sub_filter_bypass to bypass sub_filter based on the value of a set of variables.

* **Syntax:** *sub_filter_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the response will not be replaced. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be replaced.

```
sub_filter_bypass $cookie_nocache $arg_nocache$arg_comment;
sub_filter_bypass $http_pragma    $http_authorization;
```

## ngx_http_proxy_module and its friends


### "proxy_set_header" support inherit
Introduces the 'proxy_set_header_inherit' directive which blocks the merge inheritance in receiving contexts when set to off. The purpose of the added mechanics is to reduce repetition within the nginx configuration for universally set (or boilerplate) request headers, while maintaining flexibility to set additional headers for specific paths. The original patch is from [\[PATCH\] Added merge inheritance to proxy_set_header](https://mailman.nginx.org/pipermail/nginx-devel/2023-November/XUGFHDLSLRTFLWIBYPSE7LTXFJHNZE3E.html). Additionally provides grpc support.

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


### custom sndbuf and rcvbuf for upstream connection

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


### enhancement of upstream cache control

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

## ngx_http_rewrite_module

The original work is from [SEnginx](https://github.com/NeusoftSecurity/SEnginx) and [nginx-if](https://github.com/pei-jikui/nginx-if).

Extends the "if" directive of the original rewrite module. It has the following features:

### more operators for "if" directive

Except for the original "if" condition operators, also supports:
* <
* \>
* !< or >=
* !> or <=
* ^~ (start with) or !^~ (not start with)

The comparison symbol supports decimals and negative numbers. Non-numeric input will always result in a negative result.

### "if" with multi conditions

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

### support "elif" and "else" directive

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

## ngx_http_gzip_filter_module

* **Syntax:** *gzip_max_length length;*

* **Default:** *gzip_max_length 0*;

* **Context:** *http, server, location*

Sets the maximum length of a response that will be gzipped. The length is determined only from the “Content-Length” response header field. A value of 0 means no upper limit.

* **Syntax:** *gzip_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the response will gzipped. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be gzipped.

## ngx_http_brotli_filter_module (Third-party Module)

refer to [ngx_brotli](https://github.com/google/ngx_brotli).

* **Syntax:** *brotli_max_length length;*

* **Default:** *brotli_max_length 0*;

* **Context:** *http, server, location*

Sets the maximum length of a response that will be compressed. The length is determined only from the “Content-Length” response header field. A value of 0 means no upper limit.

* **Syntax:** *brotli_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the response will be compressed. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be compressed.

## ngx_http_waf_module (Third-party Module)

refer to [ngx_waf](https://github.com/ADD-SP/ngx_waf/tree/current).

This patch makes some changes to this module, mainly adding more switches for fine-grained control of WAF behavior. In addition, it also changes the appearance of the default challenge or error page and the path where the configuration file is read.

* **Syntax:** *waf_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf.


* **Syntax:** *waf_cc_deny_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf cc deny function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf cc deny function.


* **Syntax:** *waf_under_attack_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf under attack function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf under attack function.

* **Syntax:** *waf_captcha_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf captcha function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf captcha function.

* **Syntax:** *waf_modsecurity_bypass string ...;*

* **Default:** *—*

* **Context:** *http, server, location*

Defines conditions under which the request will be checked by waf modsecurity function. If at least one value of the string parameters is not empty and is not equal to “0” then the request will be checked by waf modsecurity function.

## ngx_ssl_fingerprint_module (Third-party Module)

refer to [ngx_waf](https://github.com/macskas/nginx-ssl-fingerprint).

This patch changes variable names to avoid potential conflicts with $http_ prefixed variables.