# Intentionally empty: the version is read from util/ver at RESTY_COMMIT so it
# is not pinned separately from the upstream source revision.
ARG RESTY_VERSION
ARG RESTY_RELEASE="385"
ARG RESTY_COMMIT="f4fa4de37a3408f624e1a33f69e1d8817e2a99b5"
ARG RESTY_J="4"
ARG RESTY_IMAGE_BASE="debian"
ARG RESTY_IMAGE_TAG="trixie-slim"
ARG RESTY_GIT_MIRROR="github.com"
ARG RESTY_GIT_RAW_MIRROR="raw.githubusercontent.com"
ARG RESTY_GIT_REPO="git.hanada.info"
ARG RESTY_REPOSITORY="https://${RESTY_GIT_MIRROR}/openresty/openresty.git"
ARG RESTY_RUST_VERSION="1.89.0"
ARG RESTY_LUAROCKS_VERSION="3.13.0"
ARG RESTY_LUA_RESTY_BALANCER_VERSION="0.05"
ARG RESTY_LUA_RESTY_MLCACHE_VERSION="2.7.1"
ARG RESTY_JSONSCHEMA_VERSION="0.9.13"
ARG RESTY_LIBMAXMINDDB_VERSION="1.14.1"
ARG RESTY_OPENSSL_VERSION="3.5.9"
ARG RESTY_OPENSSL_PATCH_VERSION="3.5.5"
ARG RESTY_PCRE_VERSION="10.49"
ARG RESTY_ZLIB_VERSION="1.3.2"
ARG RESTY_ZSTD_VERSION="1.5.7"
ARG RESTY_LIBVIPS_VERSION="8.18.7"
ARG RESTY_MODSECURITY_VERSION="3.0.17"
ARG RESTY_OWSAP_CRS_VERSION="4.30.0"

# LuaRocks packages.
ARG RESTY_LUA_LOLHTML_VERSION="1.0.1-1"
ARG RESTY_LUA_RESTY_MULTIPART_PARSER_VERSION="1.1.0-1"
ARG RESTY_BINARYHEAP_VERSION="0.4-1"
ARG RESTY_LUAFILESYSTEM_VERSION="1.9.0-1"
ARG RESTY_PENLIGHT_VERSION="1.15.0-1"
ARG RESTY_NET_URL_VERSION="1.2-1"
ARG RESTY_API7_DKJSON_VERSION="0.1.1-0"
ARG RESTY_LYAML_VERSION="6.2.9-2"
ARG RESTY_LRANDOM_VERSION="20180729-1"
ARG RESTY_LUAXXHASH_VERSION="1.0.0-1"
ARG RESTY_XML2LUA_VERSION="1.6-2"
ARG RESTY_LUA_FFI_ZLIB_VERSION="0.6-0"
ARG RESTY_LUA_RESTY_OPENSSL_VERSION="1.9.0-1"
ARG RESTY_LUA_RESTY_HTTP_VERSION="0.18.0-0"
ARG RESTY_LUA_RESTY_HMAC_FFI_VERSION="0.06-1"
ARG RESTY_LUA_RESTY_JWT_VERSION="0.4.0-1"
ARG RESTY_LUA_RESTY_SESSION_VERSION="4.2.0-1"
ARG RESTY_LUA_RESTY_OPENIDC_VERSION="1.9.2-1"
ARG RESTY_LUA_RESTY_TIMER_VERSION="1.1.0-1"
ARG RESTY_LUA_RESTY_KAFKA_VERSION="0.23-0"
ARG RESTY_LUA_RESTY_TEMPLATE_VERSION="2.0-1"
ARG RESTY_LUA_RESTY_COOKIE_VERSION="0.4.1-1"
ARG RESTY_LUA_RESTY_WORKER_EVENTS_VERSION="2.0.1-1"
ARG RESTY_LUA_RESTY_HEALTHCHECK_VERSION="3.1.2-1"
ARG RESTY_LUA_RESTY_IPMATCHER_VERSION="0.6.1-0"
ARG RESTY_LUA_RESTY_EXPR_VERSION="1.3.2-0"
ARG RESTY_API7_LUA_RESTY_REDIS_CONNECTOR_VERSION="0.13.0-0"
ARG RESTY_LUA_RESTY_REDIS_CLUSTER_VERSION="1.3.3-0"
ARG RESTY_LUA_RESTY_TIMER_NG_VERSION="0.2.7-1"
ARG RESTY_LUA_RESTY_MAXMINDDB_VERSION="1.3.7-1"
ARG RESTY_LUA_RESTY_M3U8_VERSION="0.2-0"
ARG RESTY_LUA_RESTY_CTX_VERSION="1.0-0"
ARG RESTY_LUA_RESTY_GD_VERSION="2.3.3.4-1"
ARG RESTY_LUA_RESTY_CAPTCHA_VERSION="1.0.2-1"

# nginx modules.
ARG RESTY_NGX_BACKTRACE_MODULE_VERSION="0.1.1"
ARG RESTY_NGX_EXPR_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_GEOIP2_MODULE_VERSION="3.4.1"
ARG RESTY_NGX_HTTP_ACCESS_CONTROL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_AUTH_AKAMAI_G2O_MODULE_VERSION="1.0.1"
ARG RESTY_NGX_HTTP_AUTH_HASH_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_AUTH_HMAC_MODULE_VERSION="0.3.1"
ARG RESTY_NGX_HTTP_AUTH_INTERNAL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_BROTLI_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_CACHE_DECHUNK_FILTER_MODULE_VERSION="1.0.1"
ARG RESTY_NGX_HTTP_CACHE_PURGE_MODULE_VERSION="4.0.0-rc2"
ARG RESTY_NGX_HTTP_COMPRESSION_NORMALIZE_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_COMPRESSION_VARY_FILTER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_CORS_MODULE_VERSION="0.1.1"
ARG RESTY_NGX_HTTP_DELAY_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_ERROR_LOG_WRITE_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_EXTRA_VARIABLES_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_GRPC_FILTER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_GRPC_HEADERS_CONTROL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_GRPC_SET_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_HEADERS_CONTROL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_INTERNAL_REDIRECT_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_LABEL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_LIMIT_TRAFFIC_RATE_FILTER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_LOG_SET_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_LOOP_DETECT_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_MODSECURITY_MODULE_COMMIT="b7cf44e57bc386bc5c15e5c9319e6b6b719357f2"
ARG RESTY_NGX_HTTP_PROXY_ARGS_CONTROL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_PROXY_AUTH_AWS_MODULE_VERSION="2.1.2"
ARG RESTY_NGX_HTTP_PROXY_AUTH_BASIC_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_PROXY_AUTH_INTERNAL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_PROXY_AUTH_NETSTORAGE_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_PROXY_FILTER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_PROXY_HEADERS_CONTROL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_PROXY_REQUEST_COOKIES_CONTROL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_PROXY_SET_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_QRCODE_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_REPLACE_FILTER_MODULE_COMMIT="0b432c649d2dc27ca7cf122ed06ff24fd9d7b3cf"
ARG RESTY_NGX_HTTP_REWRITE_STATUS_FILTER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_SECURITY_HEADERS_FILTER_MODULE_VERSION="0.1.2"
ARG RESTY_NGX_HTTP_SERVER_REDIRECT_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_SORTED_ARGS_MODULE_VERSION="0.3.1"
ARG RESTY_NGX_HTTP_SYSGUARD_MODULE_VERSION="0.2.0"
ARG RESTY_NGX_HTTP_TRIM_FILTER_MODULE_VERSION="3.1.4"
ARG RESTY_NGX_HTTP_UA_PARSER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_UNBROTLI_FILTER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_UNDEFLATE_FILTER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_UNZSTD_FILTER_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_UPSTREAM_LOG_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_HTTP_WESERV_MODULE_COMMIT="4a57b01f44e53ec6704782532dd5eb1e72be6404"
ARG RESTY_NGX_HTTP_ZSTD_MODULE_VERSION="0.1.2"
ARG RESTY_NGX_LUA_CONFIG_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_LUA_EVENTS_MODULE_VERSION="0.3.1"
ARG RESTY_NGX_LUA_LOAD_VAR_INDEX_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_LUA_RESTY_LMDB_MODULE_VERSION="1.7.1"
ARG RESTY_NGX_LUA_UPSTREAM_STATE_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_SSL_FINGERPRINT_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_STAT_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_STREAM_ACCESS_CONTROL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_STREAM_ERROR_LOG_WRITE_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_STREAM_EXTRA_VARIABLES_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_STREAM_LABEL_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_STREAM_LOG_SET_MODULE_VERSION="1.0.0"
ARG RESTY_NGX_STREAM_LUA_UPSTREAM_MODULE_VERSION="1.0.0"
# ngx_tcp_fingerprint_module stream_support.
ARG RESTY_NGX_TCP_FINGERPRINT_MODULE_COMMIT="b96e30939a79b2970cfc01756c04e3b0167cb7c8"
ARG RESTY_NGX_VAR_MODULE_VERSION="1.0.0"

FROM dockerhub.hanada.info/rust:${RESTY_RUST_VERSION}-slim-trixie AS rust-toolchain

FROM dockerhub.hanada.info/${RESTY_IMAGE_BASE}:${RESTY_IMAGE_TAG} AS openresty-bundle

ARG RESTY_GIT_MIRROR
ARG RESTY_REPOSITORY
ARG RESTY_COMMIT
ARG RESTY_J

COPY util/rewrite-openresty-archives.sh /usr/local/bin/rewrite-openresty-archives

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        dos2unix \
        git \
        gzip \
        make \
        patch \
        perl \
        tar \
        wget

RUN mkdir -p /build/openresty \
    && git init /build/openresty \
    && git -C /build/openresty remote add origin "${RESTY_REPOSITORY}" \
    && git -C /build/openresty fetch --depth=1 origin "${RESTY_COMMIT}" \
    && test "$(git -C /build/openresty rev-parse FETCH_HEAD)" = "${RESTY_COMMIT}" \
    && git -C /build/openresty checkout --detach FETCH_HEAD \
    && bash /usr/local/bin/rewrite-openresty-archives \
         /build/openresty/util/mirror-tarballs \
         "${RESTY_GIT_MIRROR}" \
    && cd /build/openresty \
    && RESTY_VERSION="$(./util/ver)" \
    && test -n "${RESTY_VERSION}" \
    && MIRROR_JOBS="${RESTY_J}" make \
    && mv "openresty-${RESTY_VERSION}.tar.gz" /openresty.tar.gz \
    && printf '%s\n' "${RESTY_VERSION}" > /openresty-version

FROM dockerhub.hanada.info/${RESTY_IMAGE_BASE}:${RESTY_IMAGE_TAG} AS openresty-build

ARG RESTY_GIT_MIRROR
ARG RESTY_GIT_RAW_MIRROR
ARG RESTY_GIT_REPO
ARG RESTY_COMMIT
ARG RESTY_VERSION
ARG RESTY_RELEASE
ARG RESTY_J
ARG RESTY_LUAROCKS_VERSION
ARG RESTY_LUA_RESTY_BALANCER_VERSION
ARG RESTY_LUA_RESTY_MLCACHE_VERSION
ARG RESTY_JSONSCHEMA_VERSION
ARG RESTY_LIBMAXMINDDB_VERSION
ARG RESTY_OPENSSL_VERSION
ARG RESTY_OPENSSL_PATCH_VERSION
ARG RESTY_OPENSSL_BUILD_OPTIONS="\
    enable-camellia \
    enable-seed \
    enable-rfc3779 \
    enable-cms \
    enable-md2 \
    enable-rc5 \
    enable-weak-ssl-ciphers \
    enable-ssl3 \
    enable-ssl3-method \
    enable-md2 \
    enable-ktls \
    enable-fips \
"
ARG RESTY_PCRE_VERSION
ARG RESTY_PCRE_BUILD_OPTIONS="\
    --enable-jit --enable-pcre2grep-jit --disable-bsr-anycrlf --disable-coverage --disable-ebcdic --disable-fuzz-support \
    --disable-jit-sealloc --disable-never-backslash-C --enable-newline-is-lf --enable-pcre2-8 --enable-pcre2-16 --enable-pcre2-32 \
    --enable-pcre2grep-callout --enable-pcre2grep-callout-fork --disable-pcre2grep-libbz2 --disable-pcre2grep-libz --disable-pcre2test-libedit \
    --enable-percent-zt --disable-rebuild-chartables --enable-shared --disable-static --disable-silent-rules --enable-unicode --disable-valgrind \
    --with-match-limit=200000 \
"
ARG RESTY_ZLIB_VERSION
ARG RESTY_ZSTD_VERSION
ARG RESTY_LIBVIPS_VERSION
ARG RESTY_MODSECURITY_VERSION
ARG RESTY_OWSAP_CRS_VERSION

# LuaRocks packages.
ARG RESTY_LUA_LOLHTML_VERSION
ARG RESTY_LUA_RESTY_MULTIPART_PARSER_VERSION
ARG RESTY_BINARYHEAP_VERSION
ARG RESTY_LUAFILESYSTEM_VERSION
ARG RESTY_PENLIGHT_VERSION
ARG RESTY_NET_URL_VERSION
ARG RESTY_API7_DKJSON_VERSION
ARG RESTY_LYAML_VERSION
ARG RESTY_LRANDOM_VERSION
ARG RESTY_LUAXXHASH_VERSION
ARG RESTY_XML2LUA_VERSION
ARG RESTY_LUA_FFI_ZLIB_VERSION
ARG RESTY_LUA_RESTY_OPENSSL_VERSION
ARG RESTY_LUA_RESTY_HTTP_VERSION
ARG RESTY_LUA_RESTY_HMAC_FFI_VERSION
ARG RESTY_LUA_RESTY_JWT_VERSION
ARG RESTY_LUA_RESTY_SESSION_VERSION
ARG RESTY_LUA_RESTY_OPENIDC_VERSION
ARG RESTY_LUA_RESTY_TIMER_VERSION
ARG RESTY_LUA_RESTY_KAFKA_VERSION
ARG RESTY_LUA_RESTY_TEMPLATE_VERSION
ARG RESTY_LUA_RESTY_COOKIE_VERSION
ARG RESTY_LUA_RESTY_WORKER_EVENTS_VERSION
ARG RESTY_LUA_RESTY_HEALTHCHECK_VERSION
ARG RESTY_LUA_RESTY_IPMATCHER_VERSION
ARG RESTY_LUA_RESTY_EXPR_VERSION
ARG RESTY_API7_LUA_RESTY_REDIS_CONNECTOR_VERSION
ARG RESTY_LUA_RESTY_REDIS_CLUSTER_VERSION
ARG RESTY_LUA_RESTY_TIMER_NG_VERSION
ARG RESTY_LUA_RESTY_MAXMINDDB_VERSION
ARG RESTY_LUA_RESTY_M3U8_VERSION
ARG RESTY_LUA_RESTY_CTX_VERSION
ARG RESTY_LUA_RESTY_GD_VERSION
ARG RESTY_LUA_RESTY_CAPTCHA_VERSION

# nginx modules.
ARG RESTY_NGX_BACKTRACE_MODULE_VERSION
ARG RESTY_NGX_EXPR_MODULE_VERSION
ARG RESTY_NGX_GEOIP2_MODULE_VERSION
ARG RESTY_NGX_HTTP_ACCESS_CONTROL_MODULE_VERSION
ARG RESTY_NGX_HTTP_AUTH_AKAMAI_G2O_MODULE_VERSION
ARG RESTY_NGX_HTTP_AUTH_HASH_MODULE_VERSION
ARG RESTY_NGX_HTTP_AUTH_HMAC_MODULE_VERSION
ARG RESTY_NGX_HTTP_AUTH_INTERNAL_MODULE_VERSION
ARG RESTY_NGX_HTTP_BROTLI_MODULE_VERSION
ARG RESTY_NGX_HTTP_CACHE_DECHUNK_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_CACHE_PURGE_MODULE_VERSION
ARG RESTY_NGX_HTTP_COMPRESSION_NORMALIZE_MODULE_VERSION
ARG RESTY_NGX_HTTP_COMPRESSION_VARY_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_CORS_MODULE_VERSION
ARG RESTY_NGX_HTTP_DELAY_MODULE_VERSION
ARG RESTY_NGX_HTTP_ERROR_LOG_WRITE_MODULE_VERSION
ARG RESTY_NGX_HTTP_EXTRA_VARIABLES_MODULE_VERSION
ARG RESTY_NGX_HTTP_GRPC_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_GRPC_HEADERS_CONTROL_MODULE_VERSION
ARG RESTY_NGX_HTTP_GRPC_SET_MODULE_VERSION
ARG RESTY_NGX_HTTP_HEADERS_CONTROL_MODULE_VERSION
ARG RESTY_NGX_HTTP_INTERNAL_REDIRECT_MODULE_VERSION
ARG RESTY_NGX_HTTP_LABEL_MODULE_VERSION
ARG RESTY_NGX_HTTP_LIMIT_TRAFFIC_RATE_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_LOG_SET_MODULE_VERSION
ARG RESTY_NGX_HTTP_LOOP_DETECT_MODULE_VERSION
ARG RESTY_NGX_HTTP_MODSECURITY_MODULE_COMMIT
ARG RESTY_NGX_HTTP_PROXY_ARGS_CONTROL_MODULE_VERSION
ARG RESTY_NGX_HTTP_PROXY_AUTH_AWS_MODULE_VERSION
ARG RESTY_NGX_HTTP_PROXY_AUTH_BASIC_MODULE_VERSION
ARG RESTY_NGX_HTTP_PROXY_AUTH_INTERNAL_MODULE_VERSION
ARG RESTY_NGX_HTTP_PROXY_AUTH_NETSTORAGE_MODULE_VERSION
ARG RESTY_NGX_HTTP_PROXY_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_PROXY_HEADERS_CONTROL_MODULE_VERSION
ARG RESTY_NGX_HTTP_PROXY_REQUEST_COOKIES_CONTROL_MODULE_VERSION
ARG RESTY_NGX_HTTP_PROXY_SET_MODULE_VERSION
ARG RESTY_NGX_HTTP_QRCODE_MODULE_VERSION
ARG RESTY_NGX_HTTP_REPLACE_FILTER_MODULE_COMMIT
ARG RESTY_NGX_HTTP_REWRITE_STATUS_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_SECURITY_HEADERS_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_SERVER_REDIRECT_MODULE_VERSION
ARG RESTY_NGX_HTTP_SORTED_ARGS_MODULE_VERSION
ARG RESTY_NGX_HTTP_SYSGUARD_MODULE_VERSION
ARG RESTY_NGX_HTTP_TRIM_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_UA_PARSER_MODULE_VERSION
ARG RESTY_NGX_HTTP_UNBROTLI_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_UNDEFLATE_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_UNZSTD_FILTER_MODULE_VERSION
ARG RESTY_NGX_HTTP_UPSTREAM_LOG_MODULE_VERSION
ARG RESTY_NGX_HTTP_WESERV_MODULE_COMMIT
ARG RESTY_NGX_HTTP_ZSTD_MODULE_VERSION
ARG RESTY_NGX_LUA_CONFIG_MODULE_VERSION
ARG RESTY_NGX_LUA_EVENTS_MODULE_VERSION
ARG RESTY_NGX_LUA_LOAD_VAR_INDEX_MODULE_VERSION
ARG RESTY_NGX_LUA_RESTY_LMDB_MODULE_VERSION
ARG RESTY_NGX_LUA_UPSTREAM_STATE_MODULE_VERSION
ARG RESTY_NGX_SSL_FINGERPRINT_MODULE_VERSION
ARG RESTY_NGX_STAT_MODULE_VERSION
ARG RESTY_NGX_STREAM_ACCESS_CONTROL_MODULE_VERSION
ARG RESTY_NGX_STREAM_ERROR_LOG_WRITE_MODULE_VERSION
ARG RESTY_NGX_STREAM_EXTRA_VARIABLES_MODULE_VERSION
ARG RESTY_NGX_STREAM_LABEL_MODULE_VERSION
ARG RESTY_NGX_STREAM_LOG_SET_MODULE_VERSION
ARG RESTY_NGX_STREAM_LUA_UPSTREAM_MODULE_VERSION
ARG RESTY_NGX_TCP_FINGERPRINT_MODULE_COMMIT
ARG RESTY_NGX_VAR_MODULE_VERSION

ARG RESTY_PATH_OPTIONS="\
    --prefix=/usr/local/openresty \
    --sbin-path=/usr/local/openresty/sbin/nginx \
    --modules-path=/usr/local/openresty/modules \
    --conf-path=/usr/local/openresty/etc/nginx.conf \
    --http-log-path=/usr/local/openresty/var/log/access.log \
    --error-log-path=/usr/local/openresty/var/log/error.log \
    --pid-path=/usr/local/openresty/var/run/nginx.pid \
    --lock-path=/usr/local/openresty/var/run/nginx.lock \
    --http-client-body-temp-path=/usr/local/openresty/var/lib/tmp/client_body \
    --http-proxy-temp-path=/usr/local/openresty/var/lib/tmp/proxy \
    --http-fastcgi-temp-path=/usr/local/openresty/var/lib/tmp/fastcgi \
    --http-uwsgi-temp-path=/usr/local/openresty/var/lib/tmp/uwsgi \
    --http-scgi-temp-path=/usr/local/openresty/var/lib/tmp/scgi \
"
ARG RESTY_USER_OPTIONS="--user=nginx --group=nginx"
ARG RESTY_DEBUG_OPTIONS=""
ARG RESTY_CONFIG_OPTIONS="\
    --with-file-aio \
    --with-threads \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-http_json_module \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_realip_module \
    --with-http_degradation_module \
    --with-http_slice_module \
    --with-http_secure_link_module \
    --with-http_sub_module \
    --without-http_empty_gif_module \
    --with-ipv6 \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-stream_realip_module \
    --add-module=/build/modules/ngx_backtrace_module \
    --add-module=/build/modules/ngx_expr_module \
    --add-module=/build/modules/ngx_stat_module \
    --add-module=/build/modules/ngx_geoip2_module \
    --add-module=/build/modules/ngx_http_access_control_module \
    --add-module=/build/modules/ngx_http_auth_akamai_g2o_module \
    --add-module=/build/modules/ngx_http_auth_hash_module \
    --add-module=/build/modules/ngx_http_auth_hmac_module \
    --add-module=/build/modules/ngx_http_auth_internal_module \
    --add-module=/build/modules/ngx_http_brotli_module \
    --add-module=/build/modules/ngx_http_cache_purge_module \
    --add-module=/build/modules/ngx_http_compression_normalize_module \
    --add-module=/build/modules/ngx_http_compression_vary_filter_module \
    --add-module=/build/modules/ngx_http_headers_control_module \
    --add-module=/build/modules/ngx_http_cors_module \
    --add-module=/build/modules/ngx_http_delay_module \
    --add-module=/build/modules/ngx_http_error_log_write_module \
    --add-module=/build/modules/ngx_http_extra_variables_module \
    --add-module=/build/modules/ngx_http_internal_redirect_module \
    --add-module=/build/modules/ngx_http_label_module \
    --add-module=/build/modules/ngx_http_limit_traffic_rate_filter_module \
    --add-module=/build/modules/ngx_http_log_set_module \
    --add-module=/build/modules/ngx_http_loop_detect_module \
    --add-module=/build/modules/ngx_http_grpc_filter_module \
    --add-module=/build/modules/ngx_http_grpc_headers_control_module \
    --add-module=/build/modules/ngx_http_grpc_set_module \
    --add-module=/build/modules/ngx_http_proxy_filter_module \
    --add-module=/build/modules/ngx_http_proxy_auth_netstorage_module \
    --add-module=/build/modules/ngx_http_proxy_auth_aws_module \
    --add-module=/build/modules/ngx_http_proxy_auth_basic_module \
    --add-module=/build/modules/ngx_http_proxy_auth_internal_module \
    --add-module=/build/modules/ngx_http_proxy_headers_control_module \
    --add-module=/build/modules/ngx_http_proxy_request_cookies_control_module \
    --add-module=/build/modules/ngx_http_proxy_args_control_module \
    --add-module=/build/modules/ngx_http_proxy_set_module \
    --add-module=/build/modules/ngx_http_qrcode_module \
    --add-module=/build/modules/ngx_http_replace_filter_module \
    --add-module=/build/modules/ngx_http_rewrite_status_filter_module \
    --add-module=/build/modules/ngx_http_security_headers_filter_module \
    --add-module=/build/modules/ngx_http_server_redirect_module \
    --add-module=/build/modules/ngx_http_sorted_args_module \
    --add-module=/build/modules/ngx_http_sysguard_module \
    --add-module=/build/modules/ngx_http_trim_filter_module \
    --add-module=/build/modules/ngx_http_cache_dechunk_filter_module \
    --add-module=/build/modules/ngx_http_ua_parser_module \
    --add-module=/build/modules/ngx_http_unbrotli_filter_module \
    --add-module=/build/modules/ngx_http_undeflate_filter_module \
    --add-module=/build/modules/ngx_http_unzstd_filter_module \
    --add-module=/build/modules/ngx_http_upstream_log_module \
    --add-module=/build/modules/ngx_http_modsecurity_module \
    --add-module=/build/modules/ngx_http_weserv_module \
    --add-module=/build/modules/ngx_http_zstd_module \
    --add-module=/build/modules/ngx_lua_config_module \
    --add-module=/build/modules/ngx_lua_events_module \
    --add-module=/build/modules/ngx_lua_load_var_index_module \
    --add-module=/build/modules/ngx_lua_resty_lmdb_module \
    --add-module=/build/modules/ngx_lua_upstream_state_module \
    --add-module=/build/modules/ngx_ssl_fingerprint_module \
    --add-module=/build/modules/ngx_stream_access_control_module \
    --add-module=/build/modules/ngx_stream_error_log_write_module \
    --add-module=/build/modules/ngx_stream_extra_variables_module \
    --add-module=/build/modules/ngx_stream_label_module \
    --add-module=/build/modules/ngx_stream_log_set_module \
    --add-module=/build/modules/ngx_stream_lua_upstream_module \
    --add-module=/build/modules/ngx_tcp_fingerprint_module \
    --add-module=/build/modules/ngx_var_module \
"
ARG RESTY_LUAJIT_OPTIONS="--with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT'"
ARG RESTY_CONFIG_DEPS="--with-pcre --with-pcre-jit \
    --with-cc-opt='-DNGX_LUA_ABORT_AT_PANIC -Wp,-D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIE' \
    --with-ld-opt='-Wl,-rpath,/usr/local/openresty/lib -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--gc-sections -pie -ljemalloc' \
"

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:${PATH}

COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=openresty-bundle /openresty.tar.gz /build/openresty.tar.gz
COPY --from=openresty-bundle /openresty-version /build/openresty-version

# Prepare the build environment and validate the generated OpenResty bundle.
RUN BUNDLE_RESTY_VERSION="$(cat /build/openresty-version)" \
    && test -n "${BUNDLE_RESTY_VERSION}" \
    && { test -z "${RESTY_VERSION}" \
         || test "${RESTY_VERSION}" = "${BUNDLE_RESTY_VERSION}"; } \
    && test -n "${RESTY_RELEASE}" \
    && groupmod -n nginx www-data \
    && usermod -l nginx www-data \
    && DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        bison \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        flex \
        git \
        libcgif-dev \
        libcurl4-openssl-dev \
        libexif-dev \
        libexpat1-dev \
        libgd-dev \
        libglib2.0-dev \
        libheif-dev \
        libhwy-dev \
        libimagequant-dev \
        libjemalloc-dev \
        libjxl-dev \
        liblcms2-dev \
        libmagickcore-dev \
        libopenjp2-7-dev \
        libpango1.0-dev \
        libpoppler-glib-dev \
        libqrencode-dev \
        libre2-dev \
        librsvg2-dev \
        libspng-dev \
        libtiff-dev \
        libtool \
        libunwind-dev \
        libwebp-dev \
        libyajl-dev \
        libyaml-cpp-dev \
        libyaml-dev \
        meson \
        perl \
        pkgconf \
        unzip \
        wget \
    && if [ "${RESTY_GIT_MIRROR}" != "github.com" ]; then \
         git config --global \
           url."https://${RESTY_GIT_MIRROR}/".insteadOf \
           "https://github.com/"; \
       fi

# Fetch and unpack OpenResty, LuaRocks, and native library sources.
RUN mkdir -p /build/lib \
    && cd /build \
    && tar xzf openresty.tar.gz \
    && curl -fSLv https://luarocks.github.io/luarocks/releases/luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz -o luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && tar xzf luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && cd /build/lib \
    && curl -fSLv https://${RESTY_GIT_MIRROR}/maxmind/libmaxminddb/releases/download/${RESTY_LIBMAXMINDDB_VERSION}/libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz -o libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz \
    && tar xzf libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/openresty/sregex.git sregex \
    && curl -fSLv https://${RESTY_GIT_MIRROR}/madler/zlib/releases/download/v${RESTY_ZLIB_VERSION}/zlib-${RESTY_ZLIB_VERSION}.tar.gz -o zlib-${RESTY_ZLIB_VERSION}.tar.gz \
    && tar xzf zlib-${RESTY_ZLIB_VERSION}.tar.gz \
    && curl -fSLv https://${RESTY_GIT_MIRROR}/openssl/openssl/releases/download/openssl-${RESTY_OPENSSL_VERSION}/openssl-${RESTY_OPENSSL_VERSION}.tar.gz -o openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && tar xzf openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && curl -fSLv https://${RESTY_GIT_MIRROR}/PCRE2Project/pcre2/releases/download/pcre2-${RESTY_PCRE_VERSION}/pcre2-${RESTY_PCRE_VERSION}.tar.gz -o pcre2-${RESTY_PCRE_VERSION}.tar.gz \
    && tar xzf pcre2-${RESTY_PCRE_VERSION}.tar.gz \
    && curl -fSLv https://${RESTY_GIT_MIRROR}/facebook/zstd/releases/download/v${RESTY_ZSTD_VERSION}/zstd-${RESTY_ZSTD_VERSION}.tar.gz -o zstd-${RESTY_ZSTD_VERSION}.tar.gz \
    && tar xzf zstd-${RESTY_ZSTD_VERSION}.tar.gz \
    && curl -fSLv https://${RESTY_GIT_MIRROR}/libvips/libvips/releases/download/v${RESTY_LIBVIPS_VERSION}/vips-${RESTY_LIBVIPS_VERSION}.tar.xz -o vips-${RESTY_LIBVIPS_VERSION}.tar.xz \
    && tar xf vips-${RESTY_LIBVIPS_VERSION}.tar.xz \
    && git clone --depth=1 --recurse-submodules https://${RESTY_GIT_MIRROR}/ua-parser/uap-cpp.git uap-cpp \
    && git clone --depth=1 --recurse-submodules --branch v${RESTY_MODSECURITY_VERSION} https://${RESTY_GIT_MIRROR}/owasp-modsecurity/ModSecurity.git modsecurity

# Fetch nginx modules.
RUN mkdir -p /build/modules \
    && cd /build/modules \
    && git clone --depth=1 --branch "${RESTY_NGX_EXPR_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_expr_module.git ngx_expr_module \
    && git clone --depth=1 --branch "${RESTY_NGX_STAT_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_stat_module.git ngx_stat_module \
    && git clone --depth=1 --recurse-submodules --branch "${RESTY_NGX_HTTP_BROTLI_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_brotli_module.git ngx_http_brotli_module \
    && git clone --depth=1 --branch "${RESTY_NGX_SSL_FINGERPRINT_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_ssl_fingerprint_module.git ngx_ssl_fingerprint_module \
    && git init ngx_tcp_fingerprint_module \
    && git -C ngx_tcp_fingerprint_module remote add origin https://${RESTY_GIT_MIRROR}/HanadaLee/ngx_tcp_fingerprint_module.git \
    && git -C ngx_tcp_fingerprint_module fetch --depth=1 origin "${RESTY_NGX_TCP_FINGERPRINT_MODULE_COMMIT}" \
    && test "$(git -C ngx_tcp_fingerprint_module rev-parse FETCH_HEAD)" = "${RESTY_NGX_TCP_FINGERPRINT_MODULE_COMMIT}" \
    && git -C ngx_tcp_fingerprint_module checkout --detach FETCH_HEAD \
    && git init ngx_http_weserv_module \
    && git -C ngx_http_weserv_module remote add origin https://${RESTY_GIT_MIRROR}/weserv/images.git \
    && git -C ngx_http_weserv_module fetch --depth=1 origin "${RESTY_NGX_HTTP_WESERV_MODULE_COMMIT}" \
    && test "$(git -C ngx_http_weserv_module rev-parse FETCH_HEAD)" = "${RESTY_NGX_HTTP_WESERV_MODULE_COMMIT}" \
    && git -C ngx_http_weserv_module checkout --detach FETCH_HEAD \
    && git -C ngx_http_weserv_module submodule update --init --recursive \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_CACHE_PURGE_MODULE_VERSION}" https://${RESTY_GIT_MIRROR}/nginx-modules/ngx_cache_purge.git ngx_http_cache_purge_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_LIMIT_TRAFFIC_RATE_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_limit_traffic_rate_filter_module.git ngx_http_limit_traffic_rate_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_ACCESS_CONTROL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_access_control_module.git ngx_http_access_control_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_AUTH_AKAMAI_G2O_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_auth_akamai_g2o_module.git ngx_http_auth_akamai_g2o_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_AUTH_INTERNAL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_auth_internal_module.git ngx_http_auth_internal_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_AUTH_HASH_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_auth_hash_module.git ngx_http_auth_hash_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_AUTH_HMAC_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_auth_hmac_module.git ngx_http_auth_hmac_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_GRPC_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_grpc_filter_module.git ngx_http_grpc_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_GRPC_HEADERS_CONTROL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_grpc_headers_control_module.git ngx_http_grpc_headers_control_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_GRPC_SET_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_grpc_set_module.git ngx_http_grpc_set_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_filter_module.git ngx_http_proxy_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_ARGS_CONTROL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_args_control_module.git ngx_http_proxy_args_control_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_REQUEST_COOKIES_CONTROL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_request_cookies_control_module.git ngx_http_proxy_request_cookies_control_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_HEADERS_CONTROL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_headers_control_module.git ngx_http_proxy_headers_control_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_AUTH_NETSTORAGE_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_auth_netstorage_module.git ngx_http_proxy_auth_netstorage_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_AUTH_AWS_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_auth_aws_module.git ngx_http_proxy_auth_aws_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_AUTH_BASIC_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_auth_basic_module.git ngx_http_proxy_auth_basic_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_AUTH_INTERNAL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_auth_internal_module.git ngx_http_proxy_auth_internal_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_PROXY_SET_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_set_module.git ngx_http_proxy_set_module \
    && git clone --depth=1 --branch "${RESTY_NGX_GEOIP2_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_geoip2_module.git ngx_geoip2_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_SORTED_ARGS_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_sorted_args_module.git ngx_http_sorted_args_module \
    && git init ngx_http_replace_filter_module \
    && git -C ngx_http_replace_filter_module remote add origin https://${RESTY_GIT_MIRROR}/openresty/replace-filter-nginx-module.git \
    && git -C ngx_http_replace_filter_module fetch --depth=1 origin "${RESTY_NGX_HTTP_REPLACE_FILTER_MODULE_COMMIT}" \
    && test "$(git -C ngx_http_replace_filter_module rev-parse FETCH_HEAD)" = "${RESTY_NGX_HTTP_REPLACE_FILTER_MODULE_COMMIT}" \
    && git -C ngx_http_replace_filter_module checkout --detach FETCH_HEAD \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_ERROR_LOG_WRITE_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_error_log_write_module.git ngx_http_error_log_write_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_EXTRA_VARIABLES_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_extra_variables_module.git ngx_http_extra_variables_module \
    && git clone --depth=1 --branch "${RESTY_NGX_LUA_CONFIG_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_lua_config_module.git ngx_lua_config_module \
    && git clone --depth=1 --branch "${RESTY_NGX_LUA_LOAD_VAR_INDEX_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_lua_load_var_index_module.git ngx_lua_load_var_index_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_ZSTD_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_zstd_module.git ngx_http_zstd_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_CACHE_DECHUNK_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_cache_dechunk_filter_module.git ngx_http_cache_dechunk_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_UNBROTLI_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_unbrotli_filter_module.git ngx_http_unbrotli_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_UNDEFLATE_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_undeflate_filter_module.git ngx_http_undeflate_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_UNZSTD_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_unzstd_filter_module.git ngx_http_unzstd_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_DELAY_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_delay_module.git ngx_http_delay_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_SERVER_REDIRECT_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_server_redirect_module.git ngx_http_server_redirect_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_INTERNAL_REDIRECT_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_internal_redirect_module.git ngx_http_internal_redirect_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_UPSTREAM_LOG_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_upstream_log_module.git ngx_http_upstream_log_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_COMPRESSION_NORMALIZE_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_compression_normalize_module.git ngx_http_compression_normalize_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_COMPRESSION_VARY_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_compression_vary_filter_module.git ngx_http_compression_vary_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_REWRITE_STATUS_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_rewrite_status_filter_module.git ngx_http_rewrite_status_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_VAR_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_var_module.git ngx_var_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_SECURITY_HEADERS_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_security_headers_filter_module.git ngx_http_security_headers_filter_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_CORS_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_cors_module.git ngx_http_cors_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_LOG_SET_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_log_set_module.git ngx_http_log_set_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_LOOP_DETECT_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_loop_detect_module.git ngx_http_loop_detect_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_LABEL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_label_module.git ngx_http_label_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_HEADERS_CONTROL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_headers_control_module.git ngx_http_headers_control_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_UA_PARSER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_ua_parser_module.git ngx_http_ua_parser_module \
    && git clone --depth=1 --branch "${RESTY_NGX_BACKTRACE_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_backtrace_module.git ngx_backtrace_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_SYSGUARD_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_sysguard_module.git ngx_http_sysguard_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_QRCODE_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_qrcode_module.git ngx_http_qrcode_module \
    && git clone --depth=1 --branch "${RESTY_NGX_LUA_EVENTS_MODULE_VERSION}" https://${RESTY_GIT_MIRROR}/Kong/lua-resty-events.git ngx_lua_events_module \
    && git clone --depth=1 --branch "${RESTY_NGX_STREAM_ACCESS_CONTROL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_stream_access_control_module.git ngx_stream_access_control_module \
    && git clone --depth=1 --branch "${RESTY_NGX_STREAM_ERROR_LOG_WRITE_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_stream_error_log_write_module.git ngx_stream_error_log_write_module \
    && git clone --depth=1 --branch "${RESTY_NGX_STREAM_LOG_SET_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_stream_log_set_module.git ngx_stream_log_set_module \
    && git clone --depth=1 --branch "${RESTY_NGX_STREAM_LABEL_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_stream_label_module.git ngx_stream_label_module \
    && git clone --depth=1 --branch "${RESTY_NGX_STREAM_EXTRA_VARIABLES_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_stream_extra_variables_module.git ngx_stream_extra_variables_module \
    && git clone --depth=1 --branch "${RESTY_NGX_LUA_UPSTREAM_STATE_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_lua_upstream_state_module.git ngx_lua_upstream_state_module \
    && git clone --depth=1 --recurse-submodules --branch "v${RESTY_NGX_LUA_RESTY_LMDB_MODULE_VERSION}" https://${RESTY_GIT_MIRROR}/Kong/lua-resty-lmdb.git ngx_lua_resty_lmdb_module \
    && git clone --depth=1 --branch "${RESTY_NGX_STREAM_LUA_UPSTREAM_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_stream_lua_upstream_module.git ngx_stream_lua_upstream_module \
    && git clone --depth=1 --branch "${RESTY_NGX_HTTP_TRIM_FILTER_MODULE_VERSION}" https://${RESTY_GIT_REPO}/hanada/ngx_http_trim_filter_module.git ngx_http_trim_filter_module \
    && git init ngx_http_modsecurity_module \
    && git -C ngx_http_modsecurity_module remote add origin https://${RESTY_GIT_MIRROR}/owasp-modsecurity/ModSecurity-nginx.git \
    && git -C ngx_http_modsecurity_module fetch --depth=1 origin "${RESTY_NGX_HTTP_MODSECURITY_MODULE_COMMIT}" \
    && test "$(git -C ngx_http_modsecurity_module rev-parse FETCH_HEAD)" = "${RESTY_NGX_HTTP_MODSECURITY_MODULE_COMMIT}" \
    && git -C ngx_http_modsecurity_module checkout --detach FETCH_HEAD

# Fetch Lua libraries that are not included in the OpenResty bundle.
RUN mkdir -p /build/lualib \
    && cd /build/lualib \
    && git clone --depth=1 --branch v${RESTY_LUA_RESTY_BALANCER_VERSION} https://${RESTY_GIT_MIRROR}/openresty/lua-resty-balancer.git lua-resty-balancer \
    && git clone --depth=1 --branch v${RESTY_JSONSCHEMA_VERSION} https://${RESTY_GIT_MIRROR}/api7/jsonschema.git jsonschema \
    && git clone --depth=1 --branch supported_semaphore_wait_phases https://${RESTY_GIT_MIRROR}/HanadaLee/lua-resty-dns-client.git lua-resty-dns-client \
    && git clone --depth=1 --branch ${RESTY_LUA_RESTY_MLCACHE_VERSION} https://${RESTY_GIT_REPO}/hanada/lua-resty-mlcache.git lua-resty-mlcache

# Build foundational native libraries.
RUN cd /build/lib/libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION} \
    && ./configure \
    && make -j${RESTY_J} \
    && make check \
    && make install \
    && ldconfig \
    && cd /build/lib/sregex \
    && make -j${RESTY_J} \
    && make install \
    && ldconfig \
    && cd /build/lib/zlib-${RESTY_ZLIB_VERSION} \
    && ./configure \
    && make -j${RESTY_J} \
    && make install \
    && ldconfig \
    && cd /build/lib/openssl-${RESTY_OPENSSL_VERSION} \
    && echo 'patching OpenSSL 3.x for OpenResty' \
    && curl -fSLv https://${RESTY_GIT_RAW_MIRROR}/openresty/openresty/${RESTY_COMMIT}/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 \
    && ./config \
        shared zlib -g \
        --libdir=lib \
        ${RESTY_OPENSSL_BUILD_OPTIONS} \
    && make update \
    && make -j${RESTY_J} \
    && make -j${RESTY_J} install_sw \
    && ldconfig \
    && cd /build/lib/pcre2-${RESTY_PCRE_VERSION} \
    && ./configure \
        ${RESTY_PCRE_BUILD_OPTIONS} \
    && make -j${RESTY_J} \
    && make install \
    && ldconfig \
    && cd /build/lib/zstd-${RESTY_ZSTD_VERSION} \
    && make -j${RESTY_J} \
    && make install \
    && ldconfig

# Build higher-level libraries used by third-party nginx and Lua modules.
RUN cd /build/lib/vips-${RESTY_LIBVIPS_VERSION} \
    && meson setup build \
        --libdir=lib \
        --buildtype=release \
        -Dmodules=disabled \
        -Dfftw=disabled \
        -Dorc=disabled \
        -Dhighway=enabled \
        -Dpng=disabled \
        -Dspng=enabled \
        -Dpoppler=enabled \
        -Dpoppler-module=disabled \
        -Drsvg=enabled \
        -Dmagick=enabled \
        -Dmagick-module=disabled \
    && ninja -C build \
    && ninja -C build install \
    && ldconfig \
    && cd /build/lib/uap-cpp \
    && mkdir -p build \
    && cd build \
    && cmake -DBUILD_STATIC=OFF -DBUILD_TESTS=OFF .. \
    && make uap-cpp-shared \
    && make install \
    && ldconfig \
    && mkdir /usr/include/uap-cpp \
    && cp /build/lib/uap-cpp/UaParser /usr/include/uap-cpp \
    && cd /build/lib/modsecurity \
    && ./build.sh \
    && ./configure --prefix=/usr/local --disable-examples \
    && make -j${RESTY_J} \
    && make install \
    && ldconfig \
    && cd /build/modules/ngx_http_brotli_module \
    && mkdir -p deps/brotli/out \
    && cd deps/brotli/out \
    && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_C_FLAGS="-O3 -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" \
        -DCMAKE_CXX_FLAGS="-O3 -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" .. \
    && cmake --build . --config Release --target install \
    && ldconfig \
    && cd /build/modules/ngx_http_weserv_module \
    && meson setup build --prefix=/usr \
    && meson compile -C build \
    && meson install -C build \
    && ldconfig \
    && cd /build/lualib/lua-resty-balancer \
    && make -j${RESTY_J}

COPY patches /build/patches

# Apply local patches and brand the release.
RUN RESTY_VERSION="$(cat /build/openresty-version)" \
    && test -n "${RESTY_VERSION}" \
    && NGINX_VERSION="${RESTY_VERSION%.*}" \
    && OPENRESTY_DIR="/build/openresty-${RESTY_VERSION}" \
    && NGINX_DIR="${OPENRESTY_DIR}/bundle/nginx-${NGINX_VERSION}" \
    && cd /build/modules/ngx_tcp_fingerprint_module \
    && echo 'patching ngx_tcp_fingerprint_module to remove RTT collection' \
    && patch --batch --forward --fuzz=0 -p1 < /build/patches/ngx_tcp_fingerprint_module-no-rtt.patch \
    && cd /build/modules/ngx_http_cache_purge_module \
    && echo 'patching ngx_http_cache_purge_module for conditional proxy settings' \
    && patch -p1 < /build/patches/ngx_http_cache_purge_module-ext.patch \
    && cd /build/modules/ngx_http_modsecurity_module \
    && echo 'patching ngx_http_modsecurity_module' \
    && patch -p1 < /build/patches/ngx_http_modsecurity_module-ext.patch \
    && cd /build/modules/ngx_http_loop_detect_module \
    && echo 'patching ngx_http_loop_detect_module' \
    && patch -p1 < /build/patches/ngx_http_loop_detect_module-cdn_id.patch \
    && cd /build/modules/ngx_lua_resty_lmdb_module \
    && echo 'patching lua-resty-lmdb for preaccess_by_lua' \
    && patch -p1 < /build/patches/lua-resty-lmdb-preaccess_by_lua.patch \
    && cd /build/lualib/lua-resty-dns-client \
    && echo 'patching lua-resty-dns-client for preaccess_by_lua' \
    && patch -p1 < /build/patches/lua-resty-dns-client-preaccess_by_lua.patch \
    && cd "${OPENRESTY_DIR}" \
    && echo "patching openresty-${RESTY_VERSION}" \
    && patch -p1 < /build/patches/openresty-fix_prefix_1.27.1.2+.patch \
    && cd "${OPENRESTY_DIR}"/bundle/ngx_stream_lua-* \
    && echo "patching ngx_stream_lua_module" \
    && patch -p1 < /build/patches/ngx_stream_lua_module-expose_request_struct_0.0.18RC2+.patch \
    && patch -p1 < /build/patches/ngx_stream_lua_module-access_by_lua_0.0.18RC2+.patch \
    && cd "${OPENRESTY_DIR}"/bundle/lua-resty-websocket-* \
    && echo "patching lua-resty-websocket" \
    && patch -p1 < /build/patches/lua-resty-websocket-fix_stream_0.13+.patch \
    && cd "${OPENRESTY_DIR}"/bundle/lua-resty-core-* \
    && echo "patching lua-resty-core for preaccess_by_lua" \
    && patch -p1 < /build/patches/lua-resty-core-preaccess_by_lua.patch \
    && cd "${OPENRESTY_DIR}"/bundle/ngx_lua-* \
    && echo "patching ngx_http_lua_module for preaccess_by_lua" \
    && patch -p1 < /build/patches/ngx_http_lua_module-preaccess_by_lua.patch \
    && cd "${NGINX_DIR}" \
    && echo "patching nginx-${NGINX_VERSION} ext" \
    && patch -p1 < /build/patches/nginx-ext_1.31.7+.patch \
    && cd "${OPENRESTY_DIR}"/bundle/redis-nginx-module-* \
    && echo "patching ngx_http_redis_module" \
    && patch -p1 < /build/patches/ngx_http_redis_module-conditional_upstream.patch \
    && cd "${OPENRESTY_DIR}"/bundle/redis2-nginx-module-* \
    && echo "patching ngx_http_redis2_module" \
    && patch -p1 < /build/patches/ngx_http_redis2_module-conditional_upstream.patch \
    && cd "${OPENRESTY_DIR}"/bundle/drizzle-nginx-module-* \
    && echo "patching ngx_http_drizzle_module" \
    && patch -p1 < /build/patches/ngx_http_drizzle_module-conditional_upstream.patch \
    && cd "${OPENRESTY_DIR}"/bundle/ngx_postgres-* \
    && echo "patching ngx_postgres_module" \
    && patch -p1 < /build/patches/ngx_postgres_module-conditional_upstream.patch \
    && cd "${OPENRESTY_DIR}"/bundle/ngx_lua-* \
    && echo "patching ngx_http_lua_module for conditional upstream settings" \
    && patch -p1 < /build/patches/ngx_http_lua_module-conditional_upstream.patch \
    && cd "${NGINX_DIR}" \
    && echo "patching nginx-${NGINX_VERSION} for ngx_http_upstream_log_module" \
    && patch -p1 < /build/modules/ngx_http_upstream_log_module/ngx_http_upstream_log_1.25.3+.patch \
    && echo "patching nginx-${NGINX_VERSION} for ngx_ssl_fingerprint_module" \
    && patch -p1 < /build/modules/ngx_ssl_fingerprint_module/patches/nginx-1.29.3+.patch \
    && echo "resetting openresty release version" \
    && sed -i "s/\(openresty\/.*\)\"/\1.${RESTY_RELEASE}\"/" src/core/nginx.h

# Configure and install OpenResty.
RUN RESTY_VERSION="$(cat /build/openresty-version)" \
    && NGINX_VERSION="${RESTY_VERSION%.*}" \
    && OPENRESTY_DIR="/build/openresty-${RESTY_VERSION}" \
    && cd "${OPENRESTY_DIR}" \
    && eval ./configure -j${RESTY_J} ${RESTY_PATH_OPTIONS} ${RESTY_USER_OPTIONS} ${RESTY_DEBUG_OPTIONS} ${RESTY_CONFIG_OPTIONS} ${RESTY_CONFIG_DEPS} \
    && make -j${RESTY_J} \
    && make install \
    && cat "${OPENRESTY_DIR}/build/nginx-${NGINX_VERSION}/objs/ngx_modules.c"

# Assemble the OpenResty tree and install bundled Lua components.
RUN mkdir -p /usr/local/openresty/share \
    && mv /usr/local/openresty/html /usr/local/openresty/share \
    && rm -rf /usr/local/openresty/nginx \
    && mkdir -p /usr/local/openresty/var/lib/tmp \
    && mkdir -p /usr/local/openresty/cache/fastcgi \
        /usr/local/openresty/cache/proxy \
        /usr/local/openresty/cache/scgi \
        /usr/local/openresty/cache/uwsgi \
    && mkdir -p /usr/local/openresty/lib \
    && cd /usr/local/openresty/lib \
    && cp -r -d /usr/local/lib/*.so* . \
    && cp -r -d /usr/lib/*/libweserv.so* . \
    && echo "/usr/local/openresty/lib" | tee /etc/ld.so.conf.d/openresty.conf \
    && ldconfig \
    && cd /build/luarocks-${RESTY_LUAROCKS_VERSION} \
    && ./configure \
        --prefix=/usr/local/openresty/luajit \
        --with-lua=/usr/local/openresty/luajit \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 \
    && make -j${RESTY_J} build \
    && make -j${RESTY_J} install \
    && cd /build/modules \
    && cp -r ngx_lua_load_var_index_module/lualib/* /usr/local/openresty/lualib/ \
    && cp -r ngx_lua_events_module/lualib/* /usr/local/openresty/lualib/ \
    && cp -r ngx_lua_upstream_state_module/lualib/* /usr/local/openresty/lualib/ \
    && cp -r ngx_lua_config_module/lualib/* /usr/local/openresty/lualib/ \
    && cp -r ngx_lua_resty_lmdb_module/lib/* /usr/local/openresty/lualib/ \
    && cd /build/lualib \
    && cp -r lua-resty-balancer/lib/* /usr/local/openresty/lualib/ \
    && install -m 755 lua-resty-balancer/librestychash.so /usr/local/openresty/lualib/ \
    && cp -r jsonschema/lib/* /usr/local/openresty/lualib/ \
    && cp -r lua-resty-dns-client/src/* /usr/local/openresty/lualib/ \
    && cp -r lua-resty-mlcache/lib/* /usr/local/openresty/lualib/

# Install LuaRocks packages and runtime data, then trim the assembled tree.
RUN /usr/local/openresty/luajit/bin/luarocks install lua-lolhtml "${RESTY_LUA_LOLHTML_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-multipart-parser "${RESTY_LUA_RESTY_MULTIPART_PARSER_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install binaryheap "${RESTY_BINARYHEAP_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install luafilesystem "${RESTY_LUAFILESYSTEM_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install penlight "${RESTY_PENLIGHT_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install net-url "${RESTY_NET_URL_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install api7-dkjson "${RESTY_API7_DKJSON_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lyaml "${RESTY_LYAML_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lrandom "${RESTY_LRANDOM_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install luaxxhash "${RESTY_LUAXXHASH_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install xml2lua "${RESTY_XML2LUA_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-ffi-zlib "${RESTY_LUA_FFI_ZLIB_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-openssl "${RESTY_LUA_RESTY_OPENSSL_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-http "${RESTY_LUA_RESTY_HTTP_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-hmac-ffi "${RESTY_LUA_RESTY_HMAC_FFI_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-jwt "${RESTY_LUA_RESTY_JWT_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-session "${RESTY_LUA_RESTY_SESSION_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc "${RESTY_LUA_RESTY_OPENIDC_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-timer "${RESTY_LUA_RESTY_TIMER_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-kafka "${RESTY_LUA_RESTY_KAFKA_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-template "${RESTY_LUA_RESTY_TEMPLATE_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-cookie "${RESTY_LUA_RESTY_COOKIE_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-worker-events "${RESTY_LUA_RESTY_WORKER_EVENTS_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-healthcheck "${RESTY_LUA_RESTY_HEALTHCHECK_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-ipmatcher "${RESTY_LUA_RESTY_IPMATCHER_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-expr "${RESTY_LUA_RESTY_EXPR_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install api7-lua-resty-redis-connector "${RESTY_API7_LUA_RESTY_REDIS_CONNECTOR_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-redis-cluster "${RESTY_LUA_RESTY_REDIS_CLUSTER_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-timer-ng "${RESTY_LUA_RESTY_TIMER_NG_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-maxminddb "${RESTY_LUA_RESTY_MAXMINDDB_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-m3u8 "${RESTY_LUA_RESTY_M3U8_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-ctx "${RESTY_LUA_RESTY_CTX_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-gd "${RESTY_LUA_RESTY_GD_VERSION}" \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-captcha "${RESTY_LUA_RESTY_CAPTCHA_VERSION}" \
    && mkdir -p /usr/local/openresty/share/uap-core \
    && cp /build/lib/uap-cpp/uap-core/regexes.yaml /usr/local/openresty/share/uap-core \
    && cd /usr/local/openresty/share \
    && curl -fSLv https://${RESTY_GIT_MIRROR}/coreruleset/coreruleset/releases/download/v${RESTY_OWSAP_CRS_VERSION}/coreruleset-${RESTY_OWSAP_CRS_VERSION}-minimal.tar.gz -o coreruleset-${RESTY_OWSAP_CRS_VERSION}-minimal.tar.gz \
    && tar xzf coreruleset-${RESTY_OWSAP_CRS_VERSION}-minimal.tar.gz \
    && rm -f coreruleset-${RESTY_OWSAP_CRS_VERSION}-minimal.tar.gz \
    && mv coreruleset-${RESTY_OWSAP_CRS_VERSION} coreruleset \
    && cd coreruleset \
    && rm -rf docs \
    && cp crs-setup.conf.example crs-setup.conf \
    && if [ "${RESTY_DEBUG_OPTIONS#*--with-debug}" = "${RESTY_DEBUG_OPTIONS}" ]; then \
         find /usr/local/openresty -type f \
           \( -name '*.so' -o -name '*.so.*' \
              -o -path '/usr/local/openresty/sbin/nginx' \
              -o -path '/usr/local/openresty/luajit/bin/luajit-*' \) \
           -exec strip --strip-debug {} +; \
       fi \
    && cd /usr/local/openresty \
    && rm -rf pod site resty.index bin/md2pod.pl bin/nginx-xml2pod bin/restydoc bin/restydoc-index

FROM dockerhub.hanada.info/${RESTY_IMAGE_BASE}:${RESTY_IMAGE_TAG} AS runtime

ARG RESTY_IMAGE_BASE
ARG RESTY_IMAGE_TAG
ARG RESTY_VERSION
ARG RESTY_RELEASE
ARG RESTY_LUAROCKS_VERSION
ARG RESTY_LIBMAXMINDDB_VERSION
ARG RESTY_OPENSSL_VERSION
ARG RESTY_OPENSSL_PATCH_VERSION
ARG RESTY_PCRE_VERSION
ARG RESTY_ZLIB_VERSION
ARG RESTY_ZSTD_VERSION
ARG RESTY_MODSECURITY_VERSION

RUN groupmod -n nginx www-data \
    && usermod -l nginx www-data \
    && DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libcgif0 \
        libcurl4t64 \
        libexif12 \
        libexpat1 \
        libgd3 \
        libglib2.0-0t64 \
        libheif1 \
        libheif-plugin-aomenc \
        libhwy1t64 \
        libimagequant0 \
        libjemalloc2 \
        libjxl0.11 \
        liblcms2-2 \
        libmagickcore-7.q16-10 \
        libopenjp2-7 \
        libopenexr-3-1-30 \
        libpoppler-glib8t64 \
        libqrencode4 \
        libre2-11 \
        librsvg2-2 \
        libspng0 \
        libtiff6 \
        libunwind8 \
        libwebp7 \
        libwebpdemux2 \
        libwebpmux3 \
        libyajl2 \
        libyaml-0-2 \
        libyaml-cpp0.8 \
        tzdata \
    && echo "/usr/local/openresty/lib" > /etc/ld.so.conf.d/openresty.conf \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openresty-build /usr/local/openresty /usr/local/openresty

RUN ldconfig

LABEL maintainer="Hanada <im@hanada.info>"
LABEL resty_image_base="${RESTY_IMAGE_BASE}"
LABEL resty_image_tag="${RESTY_IMAGE_TAG}"
LABEL resty_version="${RESTY_VERSION}"
LABEL resty_release="${RESTY_RELEASE}"
LABEL resty_luarocks_version="${RESTY_LUAROCKS_VERSION}"
LABEL resty_openssl_patch_version="${RESTY_OPENSSL_PATCH_VERSION}"
LABEL resty_openssl_version="${RESTY_OPENSSL_VERSION}"
LABEL resty_pcre_version="${RESTY_PCRE_VERSION}"
LABEL resty_zlib_version="${RESTY_ZLIB_VERSION}"
LABEL resty_zstd_version="${RESTY_ZSTD_VERSION}"
LABEL resty_libmaxminddb_version="${RESTY_LIBMAXMINDDB_VERSION}"
LABEL resty_modsecurity_version="${RESTY_MODSECURITY_VERSION}"

WORKDIR /usr/local/openresty

# Add additional binaries into PATH for convenience
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/openresty/luajit/bin/:/usr/local/openresty/sbin/:/usr/local/openresty/bin/
ENV LUA_PATH="/usr/local/openresty/lualib/?.ljbc;/usr/local/openresty/lualib/?/init.ljbc;/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;./?.lua;/usr/local/openresty/luajit/share/luajit-2.1/?.lua;/usr/local/openresty/luajit/share/lua/5.1/?.lua;/usr/local/openresty/luajit/share/lua/5.1/?/init.lua"
ENV LUA_CPATH="/usr/local/openresty/lualib/?.so;./?.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so"

COPY conf/nginx.conf /usr/local/openresty/etc/nginx.conf
COPY conf/nginx.vh.default.conf /usr/local/openresty/etc/conf.d/default.conf
COPY conf/modsecurity.conf /usr/local/openresty/etc/modsecurity/modsecurity.conf

CMD ["/usr/local/openresty/sbin/nginx", "-g", "daemon off;"]

# Use SIGQUIT instead of default SIGTERM to cleanly drain requests
# See https://github.com/openresty/docker-openresty/blob/master/README.md#tips--pitfalls
STOPSIGNAL SIGQUIT
