Name
====

OpenResty - A High Performance Web Server and CDN Cache Server Based on Nginx and LuaJIT

This image adds luarocks, more patches, modules or lua libraries to the original OpenResty bundle (https://github.com/openresty/openresty).

This bundle is maintained by Hanada (im@hanada.info)

Table of Contents
=================

- [Name](#name)
- [Table of Contents](#table-of-contents)
- [Description](#description)
  - [Components of original OpenResty bundule](#components-of-original-openresty-bundule)
  - [Extra components of current OpenResty bundule](#extra-components-of-current-openresty-bundule)
- [Additional Features](#additional-features)
  - [resolv.conf parsing](#resolvconf-parsing)
  - [ngx_http_slice_module_ext patch](#ngx_http_slice_module_ext-patch)
  - [ngx_http_listen_https_allow_http patch](#ngx_http_listen_https_allow_http-patch)
  - [ngx_http_tls_dyn_size](#ngx_http_tls_dyn_size)
- [Copyright \& License](#copyright-license)

Description
===========

OpenResty is a full-fledged web application server by bundling the standard nginx core, lots of 3rd-party nginx modules, as well as most of their external dependencies.

This bundle is maintained by Hanada (im@hanada.info), and the original OpenResty bundle is maintained by Yichun Zhang (agentzh).

The bundled software components are copyrighted by the respective copyright holders.

[Back to TOC](#table-of-contents)

Components of original OpenResty bundule
--------------------

Below lists all the components bundled in original OpenResty.

Most of the components are enabled by default, but some are not.

[DrizzleNginxModule](https://openresty.org/en/drizzle-nginx-module.html), [PostgresNginxModule](https://openresty.org/en/postgres-nginx-module.html), and [IconvNginxModule](https://openresty.org/en/iconv-nginx-module.html) are not enabled by default. You need to specify the `--with-http_drizzle_module`, `--with-http_postgres_module`, and `--with-http_iconv_module` options, respectively, to enable them while building OpenResty.

Before the 1.5.8.1 release, the standard Lua 5.1 interpreter is enabled by default while [LuaJIT](https://openresty.org/en/luajit.html) 2.x is not. So for earlier releases, you need to explicitly specify the `--with-luajit` option (which is the default for 1.5.8.1+) to use [LuaJIT](https://openresty.org/en/luajit.html) 2.x.

Since the 1.15.8.1 release, the standard Lua 5.1 interpreter is not supported anymore. It is vividly recommended to use [OpenResty's branch of LuaJIT](https://github.com/openresty/luajit2) (already bundled and enabled by default in OpenResty releases since 1.5.8.1). This fork is regularly synchronized with the upstream LuaJIT repository, receives timely fixes, and implements additional features proper to OpenResty.

* [LuaJIT](https://openresty.org/en/luajit.html)
* [ArrayVarNginxModule](https://openresty.org/en/array-var-nginx-module.html)
* [AuthRequestNginxModule](https://openresty.org/en/auth-request-nginx-module.html)
* [CoolkitNginxModule](https://openresty.org/en/coolkit-nginx-module.html)
* [DrizzleNginxModule](https://openresty.org/en/drizzle-nginx-module.html)
* [EchoNginxModule](https://openresty.org/en/echo-nginx-module.html)
* [EncryptedSessionNginxModule](https://openresty.org/en/encrypted-session-nginx-module.html)
* [FormInputNginxModule](https://openresty.org/en/form-input-nginx-module.html)
* [HeadersMoreNginxModule](https://openresty.org/en/headers-more-nginx-module.html)
* [IconvNginxModule](https://openresty.org/en/iconv-nginx-module.html)
* [StandardLuaInterpreter](https://openresty.org/en/standard-lua-interpreter.html)
* [MemcNginxModule](https://openresty.org/en/memc-nginx-module.html)
* [Nginx](https://openresty.org/en/nginx.html)
* [NginxDevelKit](https://openresty.org/en/nginx-devel-kit.html)
* [LuaCjsonLibrary](https://openresty.org/en/lua-cjson-library.html)
* [LuaNginxModule](https://openresty.org/en/lua-nginx-module.html)
* [LuaRdsParserLibrary](https://openresty.org/en/lua-rds-parser-library.html)
* [LuaRedisParserLibrary](https://openresty.org/en/lua-redis-parser-library.html)
* [LuaRestyCoreLibrary](https://openresty.org/en/lua-resty-core-library.html)
* [LuaRestyDNSLibrary](https://openresty.org/en/lua-resty-dns-library.html)
* [LuaRestyLockLibrary](https://openresty.org/en/lua-resty-lock-library.html)
* [LuaRestyLrucacheLibrary](https://openresty.org/en/lua-resty-lrucache-library.html)
* [LuaRestyMemcachedLibrary](https://openresty.org/en/lua-resty-memcached-library.html)
* [LuaRestyMySQLLibrary](https://openresty.org/en/lua-resty-mysql-library.html)
* [LuaRestyRedisLibrary](https://openresty.org/en/lua-resty-redis-library.html)
* [LuaRestyStringLibrary](https://openresty.org/en/lua-resty-string-library.html)
* [LuaRestyUploadLibrary](https://openresty.org/en/lua-resty-upload-library.html)
* [LuaRestyUpstreamHealthcheckLibrary](https://openresty.org/en/lua-resty-upstream-healthcheck-library.html)
* [LuaRestyWebSocketLibrary](https://openresty.org/en/lua-resty-web-socket-library.html)
* [LuaRestyLimitTrafficLibrary](https://openresty.org/en/https://github.com/openresty/lua-resty-limit-traffic)
* [LuaRestyShellLibrary](https://openresty.org/en/https://github.com/openresty/lua-resty-shell)
* [LuaRestySignalLibrary](https://openresty.org/en/https://github.com/openresty/lua-resty-signal)
* [LuaTablePoolLibrary](https://openresty.org/en/https://github.com/openresty/lua-tablepool)
* [LuaUpstreamNginxModule](https://openresty.org/en/lua-upstream-nginx-module.html)
* [OPM](https://openresty.org/en/https://github.com/openresty/opm#readme)
* [PostgresNginxModule](https://openresty.org/en/postgres-nginx-module.html)
* [RdsCsvNginxModule](https://openresty.org/en/rds-csv-nginx-module.html)
* [RdsJsonNginxModule](https://openresty.org/en/rds-json-nginx-module.html)
* [RedisNginxModule](https://openresty.org/en/redis-nginx-module.html)
* [Redis2NginxModule](https://openresty.org/en/redis-2-nginx-module.html)
* [RestyCLI](https://openresty.org/en/resty-cli.html)
* [SetMiscNginxModule](https://openresty.org/en/set-misc-nginx-module.html)
* [SrcacheNginxModule](https://openresty.org/en/srcache-nginx-module.html)
* [StreamLuaNginxModule](https://openresty.org/en/https://github.com/openresty/stream-lua-nginx-module#readme)
* [XssNginxModule](https://openresty.org/en/xss-nginx-module.html)

[Back to TOC](#table-of-contents)

Extra components of current OpenResty bundule
--------------------

Listed below are all components currently bundled additionally with OpenResty. These components are bundled by Hanada.

* [ngx_http_brotli_module](https://github.com/google/ngx_brotli)
* [ngx_http_cache_purge_module](https://github.com/nginx-modules/ngx_cache_purge)
* [ngx_http_dav_ext_module](https://github.com/arut/nginx-dav-ext-module)
* [ngx_http_dechunk_module](https://git.hanada.info/hanada/ngx_http_dechunk_module)
* [ngx_http_extra_vars_module](https://git.hanada.info/hanada/ngx_http_extra_vars_module)
* [ngx_http_fancyindex_module](https://github.com/aperezdc/ngx-fancyindex)
* [ngx_http_flv_live_module](https://github.com/winshining/nginx-http-flv-module)
* [ngx_http_geoip2_module](https://github.com/leev/ngx_http_geoip2_module)
* [ngx_http_let_module](https://git.hanada.info/hanada/ngx_http_let_module)
* [ngx_http_lower_upper_case_module](https://git.hanada.info/hanada/ngx_http_lower_upper_case_module)
* [ngx_http_lua_cache_module](https://github.com/AlticeLabsProjects/lua-upstream-cache-nginx-module)
* [ngx_http_proxy_connect_module](https://github.com/chobits/ngx_http_proxy_connect_module)
* [ngx_http_qrcode_module](https://github.com/soulteary/ngx_http_qrcode_module)
* [ngx_http_replace_filter_module](https://github.com/openresty/replace-filter-nginx-module)
* [ngx_http_sorted_querystring_module](https://git.hanada.info/hanada/ngx_http_sorted_querystring_module)
* [ngx_http_upstream_check_module](https://github.com/yaoweibin/nginx_upstream_check_module)
* [ngx_http_upstream_log_module](https://git.hanada.info/hanada/ngx_http_upstream_log_module)
* [ngx_http_vhost_traffic_status_module](https://github.com/vozlt/nginx-module-vts)
* [ngx_http_vod_module](https://github.com/kaltura/nginx-vod-module)
* [ngx_http_zstd_module](https://git.hanada.info/hanada/ngx_http_zstd_module)
* [luarocks](https://luarocks.org/)
* [lua-resty-maxminddb](https://git.hanada.info/hanada/lua-resty-maxminddb)
* [lua-resty-multipart-parser](https://github.com/agentzh/lua-resty-multipart-parser)
* [lua-resty-balancer](https://github.com/openresty/lua-resty-balancer)
* [lua-resty-ctx](https://github.com/Kong/kong/blob/master/kong/resty/ctx.lua)
* [lua-resty-http](https://luarocks.org/modules/pintsized/lua-resty-http)
* [lua-resty-hmac-ffi](https://luarocks.org/modules/jkeys089/lua-resty-hmac-ffi)
* [lua-resty-jwt](https://luarocks.org/modules/cdbattags/lua-resty-jwt)
* [lua-resty-openidc](https://luarocks.org/modules/hanszandbelt/lua-resty-openidc)
* [lua-resty-dns-client](https://luarocks.org/modules/kong/lua-resty-dns-client)
* [lua-resty-kafka](https://luarocks.org/modules/doujiang24/lua-resty-kafka)
* [lua-resty-template](https://luarocks.org/modules/bungle/lua-resty-template)
* [lua-resty-mlcache](https://luarocks.org/modules/thibaultcha/lua-resty-mlcache)
* [lua-resty-jit-uuid](https://luarocks.org/modules/thibaultcha/lua-resty-jit-uuid)
* [lua-resty-cookie](https://luarocks.org/modules/utix/lua-resty-cookie)
* [lua-resty-worker-events](https://luarocks.org/modules/kong/lua-resty-worker-events)
* [lua-resty-healthcheck](https://luarocks.org/modules/kong/lua-resty-healthcheck)

[Back to TOC](#table-of-contents)

Additional Features
===================

In additional to the standard nginx core features, this bundle also supports the following:

[Back to TOC](#table-of-contents)

resolv.conf parsing
--------------------

**syntax:** *resolver address ... [valid=time] [ipv6=on|off] [local=on|off|path];*

**default:** *-*

**context:** *http, stream, server, location*

Similar to the [`resolver` directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver)
in standard nginx core with additional support for parsing additional resolvers from the `resolv.conf` file
format.

When `local=on`, the standard path of `/etc/resolv.conf` will be used. You may also specify arbitrary
path to be used for parsing, for example: `local=/tmp/test.conf`.

When `local=off`, parsing will be disabled (this is the default).

This feature is not available on Windows platforms.

[Back to TOC](#table-of-contents)

[ngx_http_slice_module_ext patch](https://git.hanada.info/hanada/ngx_core_patches)
--------------------

**syntax:** *slice_allow_methods GET | HEAD ...;*

**default:** *slice_allow_methods GET HEAD;*

**context:** *http, server, location*

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

[ngx_http_listen_https_allow_http patch](https://git.hanada.info/hanada/ngx_core_patches)
--------------------

**syntax:** *listen address[:port] [ssl] [https_allow_http] ...;*

**default:** *listen *:80 | *:8000;*

**context:** *server*

When both the ssl and https_allow_http parameters are enabled for the listen directive, both https or http requests will be allowed. This patch comes from Tengine.

[Back to TOC](#table-of-contents)

[ngx_http_tls_dyn_size](https://github.com/nginx-modules/ngx_http_tls_dyn_size)
--------------------

Start each connection with small records
(1369 byte default, change with `ssl_dyn_rec_size_lo`).

After a given number of records (40, change with `ssl_dyn_rec_threshold`)
start sending larger records (4229, `ssl_dyn_rec_size_hi`).

Eventually after the same number of records,
start sending the largest records (`ssl_buffer_size`).

In case the connection idles for a given amount of time
(1s, `ssl_dyn_rec_timeout`), the process repeats itself
(i.e. begin sending small records again).


* **syntax**: *ssl_dyn_rec_enable bool*

* **default**: *off*

* **context**: *http, server*


* **syntax**: *ssl_dyn_rec_timeout number*

* **default**: *1000*

* **context**: *http, server*

We want the initial records to fit into one TCP segment
so we don't get TCP HoL blocking due to TCP Slow Start.

A connection always starts with small records, but after
a given amount of records sent, we make the records larger
to reduce header overhead.

After a connection has idled for a given timeout, begin
the process from the start. The actual parameters are
configurable. If `ssl_dyn_rec_timeout` is `0`, we assume `ssl_dyn_rec` is `off`.


* **syntax**: *ssl_dyn_rec_size_lo number*

* **default**: *1369*

* **context**: *http, server*

Default sizes for the dynamic record sizes are defined to fit maximal
TLS + IPv6 overhead in a single TCP segment for lo and 3 segments for hi:
1369 = 1500 - 40 (IP) - 20 (TCP) - 10 (Time) - 61 (Max TLS overhead)


* **syntax**: *ssl_dyn_rec_size_hi number*

* **default**: *4229*

* **context**: *http, server*

4229 = (1500 - 40 - 20 - 10) * 3  - 61


* **syntax**: *ssl_dyn_rec_threshold number*

* **default**: *40*

* **context**: *http, server*


[Back to TOC](#table-of-contents)

Copyright & License
===========

The bundle itself is licensed under the 2-clause BSD license. See LICENSE for details.