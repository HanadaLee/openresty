# Intentionally empty: the version is read from util/ver at RESTY_COMMIT so it
# is not pinned separately from the upstream source revision.
ARG RESTY_VERSION
ARG RESTY_RELEASE="379"
ARG RESTY_COMMIT="810a7ded155e929050d34649a5d54bccb786c644"
ARG RESTY_J="4"
ARG RESTY_IMAGE_BASE="debian"
ARG RESTY_IMAGE_TAG="trixie-slim"
ARG RESTY_GIT_MIRROR="github.com"
ARG RESTY_GIT_RAW_MIRROR="raw.githubusercontent.com"
ARG RESTY_GIT_REPO="git.hanada.info"
ARG RESTY_REPOSITORY="https://${RESTY_GIT_MIRROR}/openresty/openresty.git"
ARG RESTY_LUAROCKS_VERSION="3.13.0"
ARG RESTY_LUA_RESTY_BALANCER_VERSION="0.05"
ARG RESTY_LIBMAXMINDDB_VERSION="1.14.1"
ARG RESTY_OPENSSL_VERSION="3.5.8"
ARG RESTY_OPENSSL_PATCH_VERSION="3.5.5"
ARG RESTY_PCRE_VERSION="10.48"
ARG RESTY_ZLIB_VERSION="1.3.2"
ARG RESTY_ZSTD_VERSION="1.5.7"
ARG RESTY_LIBVIPS_VERSION="8.18.6"
ARG RESTY_MODSECURITY_VERSION="3.0.16"
ARG RESTY_OWSAP_CRS_VERSION="4.29.0"

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
ARG RESTY_LUAROCKS_VERSION
ARG RESTY_LUA_RESTY_BALANCER_VERSION
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
ARG RESTY_J
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
    --add-module=/build/modules/ngx_condition_module \
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
    --add-module=/build/modules/ngx_var_module \
"
ARG RESTY_LUAJIT_OPTIONS="--with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT'"
ARG RESTY_CONFIG_DEPS="--with-pcre --with-pcre-jit \
    --with-cc-opt='-DNGX_LUA_ABORT_AT_PANIC -Wp,-D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIE' \
    --with-ld-opt='-Wl,-rpath,/usr/local/openresty/lib -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--gc-sections -pie' \
"

COPY --from=openresty-bundle /openresty.tar.gz /build/openresty.tar.gz
COPY --from=openresty-bundle /openresty-version /build/openresty-version
COPY patches /build/patches

RUN BUNDLE_RESTY_VERSION="$(cat /build/openresty-version)" \
    && test -n "${BUNDLE_RESTY_VERSION}" \
    && { test -z "${RESTY_VERSION}" \
         || test "${RESTY_VERSION}" = "${BUNDLE_RESTY_VERSION}"; } \
    && RESTY_VERSION="${BUNDLE_RESTY_VERSION}" \
    && export RESTY_VERSION \
    && test -n "${RESTY_RELEASE}" \
    && groupmod -n nginx www-data \
    && usermod -l nginx www-data \
    && DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libgd-dev \
        libheif-dev \
        libhwy-dev \
        libyaml-dev \
        libyaml-cpp-dev \
        unzip \
        git \
        curl \
        wget \
        libcurl4-openssl-dev \
        ca-certificates \
        bison \
        build-essential \
        cargo \
        perl \
        autoconf \
        automake \
        libtool \
        pkgconf \
        cmake \
        libglib2.0-dev \
        libexif-dev \
        libcgif-dev \
        liblcms2-dev \
        libimagequant-dev \
        libmagickcore-dev \
        libopenjp2-7-dev \
        libpango1.0-dev \
        libpoppler-glib-dev \
        librsvg2-dev \
        libjxl-dev \
        libexpat1-dev \
        libspng-dev \
        libtiff-dev \
        libwebp-dev \
        meson \
        flex \
        libunwind-dev \
        libqrencode-dev \
        libre2-dev \
        libyajl-dev \
        rustc \
    && if [ "${RESTY_GIT_MIRROR}" != "github.com" ]; then \
         git config --global \
           url."https://${RESTY_GIT_MIRROR}/".insteadOf \
           "https://github.com/"; \
       fi \
    && mkdir -p /build \
    && cd /build \
    && tar xzf openresty.tar.gz \
    && curl -fSLv https://luarocks.github.io/luarocks/releases/luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz -o luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && tar xzf luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && mkdir -p /build/lib /build/modules /build/lualib \
    && cd /build/lib \
    && curl -fSLv https://${RESTY_GIT_MIRROR}/libvips/libvips/releases/download/v${RESTY_LIBVIPS_VERSION}/vips-${RESTY_LIBVIPS_VERSION}.tar.xz -o vips-${RESTY_LIBVIPS_VERSION}.tar.xz \
    && tar xf vips-${RESTY_LIBVIPS_VERSION}.tar.xz \
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
    && git clone --depth=1 --recurse-submodules https://${RESTY_GIT_MIRROR}/ua-parser/uap-cpp.git uap-cpp \
    && git clone --depth=1 --recurse-submodules --branch v${RESTY_MODSECURITY_VERSION} https://${RESTY_GIT_MIRROR}/owasp-modsecurity/ModSecurity.git modsecurity \
    && cd /build/modules \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_condition_module.git ngx_condition_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_stat_module.git ngx_stat_module \
    && git clone --depth=1 --recurse-submodules https://${RESTY_GIT_REPO}/hanada/ngx_http_brotli_module.git ngx_http_brotli_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_ssl_fingerprint_module.git ngx_ssl_fingerprint_module \
    && git clone --depth=1 --recurse-submodules https://${RESTY_GIT_MIRROR}/weserv/images.git ngx_http_weserv_module \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/nginx-modules/ngx_cache_purge.git ngx_http_cache_purge_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_limit_traffic_rate_filter_module.git ngx_http_limit_traffic_rate_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_access_control_module.git ngx_http_access_control_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_auth_akamai_g2o_module.git ngx_http_auth_akamai_g2o_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_auth_internal_module.git ngx_http_auth_internal_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_auth_hash_module.git ngx_http_auth_hash_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_auth_hmac_module.git ngx_http_auth_hmac_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_grpc_filter_module.git ngx_http_grpc_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_grpc_headers_control_module.git ngx_http_grpc_headers_control_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_grpc_set_module.git ngx_http_grpc_set_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_filter_module.git ngx_http_proxy_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_args_control_module.git ngx_http_proxy_args_control_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_request_cookies_control_module.git ngx_http_proxy_request_cookies_control_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_headers_control_module.git ngx_http_proxy_headers_control_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_auth_netstorage_module.git ngx_http_proxy_auth_netstorage_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_auth_aws_module.git ngx_http_proxy_auth_aws_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_auth_basic_module.git ngx_http_proxy_auth_basic_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_auth_internal_module.git ngx_http_proxy_auth_internal_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_set_module.git ngx_http_proxy_set_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_geoip2_module.git ngx_geoip2_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_sorted_args_module.git ngx_http_sorted_args_module \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/openresty/replace-filter-nginx-module.git ngx_http_replace_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_error_log_write_module.git ngx_http_error_log_write_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_extra_variables_module.git ngx_http_extra_variables_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_lua_config_module.git ngx_lua_config_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_lua_load_var_index_module.git ngx_lua_load_var_index_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_zstd_module.git ngx_http_zstd_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_cache_dechunk_filter_module.git ngx_http_cache_dechunk_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_unbrotli_filter_module.git ngx_http_unbrotli_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_undeflate_filter_module.git ngx_http_undeflate_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_unzstd_filter_module.git ngx_http_unzstd_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_delay_module.git ngx_http_delay_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_server_redirect_module.git ngx_http_server_redirect_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_internal_redirect_module.git ngx_http_internal_redirect_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_upstream_log_module.git ngx_http_upstream_log_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_compression_normalize_module.git ngx_http_compression_normalize_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_compression_vary_filter_module.git ngx_http_compression_vary_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_rewrite_status_filter_module.git ngx_http_rewrite_status_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_var_module.git ngx_var_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_security_headers_filter_module.git ngx_http_security_headers_filter_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_cors_module.git ngx_http_cors_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_log_set_module.git ngx_http_log_set_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_loop_detect_module.git ngx_http_loop_detect_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_label_module.git ngx_http_label_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_headers_control_module.git ngx_http_headers_control_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_ua_parser_module.git ngx_http_ua_parser_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_backtrace_module.git ngx_backtrace_module \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/vozlt/nginx-module-sysguard.git ngx_http_sysguard_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_http_qrcode_module.git ngx_http_qrcode_module \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/Kong/lua-resty-events.git ngx_lua_events_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_stream_access_control_module.git ngx_stream_access_control_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_stream_error_log_write_module.git ngx_stream_error_log_write_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_stream_log_set_module.git ngx_stream_log_set_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_stream_label_module.git ngx_stream_label_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_stream_extra_variables_module.git ngx_stream_extra_variables_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_lua_upstream_state_module.git ngx_lua_upstream_state_module \
    && git clone --depth=1 --recurse-submodules https://${RESTY_GIT_MIRROR}/Kong/lua-resty-lmdb.git ngx_lua_resty_lmdb_module \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/ngx_stream_lua_upstream_module.git ngx_stream_lua_upstream_module \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/alibaba/tengine.git tengine \
    && mv tengine/modules/ngx_http_trim_filter_module ngx_http_trim_filter_module \
    && rm -rf tengine \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/owasp-modsecurity/ModSecurity-nginx.git ngx_http_modsecurity_module \
    && cd /build/lualib \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/agentzh/lua-resty-multipart-parser.git lua-resty-multipart-parser \
    && git clone --depth=1 --branch v${RESTY_LUA_RESTY_BALANCER_VERSION} https://${RESTY_GIT_MIRROR}/openresty/lua-resty-balancer.git lua-resty-balancer \
    && git clone --depth=1 https://${RESTY_GIT_MIRROR}/api7/jsonschema.git jsonschema \
    && git clone --depth=1 --branch supported_semaphore_wait_phases https://${RESTY_GIT_MIRROR}/HanadaLee/lua-resty-dns-client.git lua-resty-dns-client \
    && git clone --depth=1 https://${RESTY_GIT_REPO}/hanada/lua-resty-mlcache.git lua-resty-mlcache \
    && git clone --depth=1 --recurse-submodules https://${RESTY_GIT_MIRROR}/HanadaLee/lua-lolhtml.git \
    && cd /build/lib/libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION} \
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
    && echo 'patching OpenSSL 3.x for ngx_ssl_figerprint_module' \
    && patch -p1 < /build/modules/ngx_ssl_fingerprint_module/patches/openssl-3.5.5+.patch \
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
    && ldconfig \
    && cd /build/lib/vips-${RESTY_LIBVIPS_VERSION} \
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
        "$@" \
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
    && cd /build/lualib/lua-resty-balancer \
    && make -j${RESTY_J} \
    && make install \
    && cd /build/openresty-${RESTY_VERSION} \
    && echo "patching openresty-${RESTY_VERSION}" \
    && patch -p1 < /build/patches/openresty-fix_prefix_1.27.1.2+.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/ngx_stream_lua-* \
    && echo "patching ngx_stream_lua_module" \
    && patch -p1 < /build/patches/ngx_stream_lua_module-expose_request_struct_0.0.18RC2+.patch \
    && patch -p1 < /build/patches/ngx_stream_lua_module-access_by_lua_0.0.18RC2+.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/lua-resty-websocket-* \
    && echo "patching lua-resty-websocket" \
    && patch -p1 < /build/patches/lua-resty-websocket-fix_stream_0.13+.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/lua-resty-core-* \
    && echo "patching lua-resty-core for preaccess_by_lua" \
    && patch -p1 < /build/patches/lua-resty-core-preaccess_by_lua.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/ngx_lua-* \
    && echo "patching ngx_http_lua_module for preaccess_by_lua" \
    && patch -p1 < /build/patches/ngx_http_lua_module-preaccess_by_lua.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/nginx-$(echo ${RESTY_VERSION} | cut -c 1-6) \
    && echo "patching nginx-$(echo ${RESTY_VERSION} | cut -c 1-6) ext" \
    && patch -p1 < /build/patches/nginx-ext_1.31.6+.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/redis-nginx-module-* \
    && echo "patching ngx_http_redis_module" \
    && patch -p1 < /build/patches/ngx_http_redis_module-conditional_upstream.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/redis2-nginx-module-* \
    && echo "patching ngx_http_redis2_module" \
    && patch -p1 < /build/patches/ngx_http_redis2_module-conditional_upstream.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/drizzle-nginx-module-* \
    && echo "patching ngx_http_drizzle_module" \
    && patch -p1 < /build/patches/ngx_http_drizzle_module-conditional_upstream.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/ngx_postgres-* \
    && echo "patching ngx_postgres_module" \
    && patch -p1 < /build/patches/ngx_postgres_module-conditional_upstream.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/ngx_lua-* \
    && echo "patching ngx_http_lua_module for conditional upstream settings" \
    && patch -p1 < /build/patches/ngx_http_lua_module-conditional_upstream.patch \
    && cd /build/openresty-${RESTY_VERSION}/bundle/nginx-$(echo ${RESTY_VERSION} | cut -c 1-6) \
    && echo "patching nginx-$(echo ${RESTY_VERSION} | cut -c 1-6) for ngx_http_upstream_log_module" \
    && patch -p1 < /build/modules/ngx_http_upstream_log_module/ngx_http_upstream_log_1.25.3+.patch \
    && echo "patching nginx-$(echo ${RESTY_VERSION} | cut -c 1-6) for ngx_ssl_fingerprint_module" \
    && patch -p1 < /build/modules/ngx_ssl_fingerprint_module/patches/nginx-1.29.3+.patch \
    && echo "resetting openresty release version" \
    && sed -i "s/\(openresty\/.*\)\"/\1.${RESTY_RELEASE}\"/" src/core/nginx.h \
    && cd /build/openresty-${RESTY_VERSION} \
    && eval ./configure -j${RESTY_J} ${RESTY_PATH_OPTIONS} ${RESTY_USER_OPTIONS} ${RESTY_DEBUG_OPTIONS} ${RESTY_CONFIG_OPTIONS} ${RESTY_CONFIG_DEPS} \
    && make -j${RESTY_J} \
    && make install \
    && cat /build/openresty-${RESTY_VERSION}/build/nginx-$(echo ${RESTY_VERSION} | cut -c 1-6)/objs/ngx_modules.c \
    && mkdir -p /usr/local/openresty/share \
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
    && echo "/usr/local/openresty/lib" | tee /etc/ld.so.conf.d/openresty.conf \
    && ldconfig \
    && cd /usr/local/openresty/lualib \
    && cp -r -d /usr/local/lib/lua/*.so* . \
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
    && cp -r lua-resty-multipart-parser/lib/* /usr/local/openresty/lualib/ \
    && cp -r lua-resty-balancer/lib/* /usr/local/openresty/lualib/ \
    && cp -r jsonschema/lib/* /usr/local/openresty/lualib/ \
    && cp -r lua-resty-dns-client/src/* /usr/local/openresty/lualib/ \
    && cp -r lua-resty-mlcache/lib/* /usr/local/openresty/lualib/ \
    && cd /build/lualib/lua-lolhtml \
    && make -j${RESTY_J} CFLAGS="-O3 -fPIC -I/usr/local/openresty/luajit/include/luajit-2.1" \
    && cp lolhtml.so /usr/local/openresty/lualib \
    && /usr/local/openresty/luajit/bin/luarocks install binaryheap \
    && /usr/local/openresty/luajit/bin/luarocks install luafilesystem \
    && /usr/local/openresty/luajit/bin/luarocks install penlight \
    && /usr/local/openresty/luajit/bin/luarocks install net-url \
    && /usr/local/openresty/luajit/bin/luarocks install api7-dkjson \
    && /usr/local/openresty/luajit/bin/luarocks install lyaml \
    && /usr/local/openresty/luajit/bin/luarocks install lrandom \
    && /usr/local/openresty/luajit/bin/luarocks install luaxxhash \
    && /usr/local/openresty/luajit/bin/luarocks install xml2lua \
    && /usr/local/openresty/luajit/bin/luarocks install lua-ffi-zlib \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-openssl \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-http \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-hmac-ffi \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-jwt \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-session \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-timer \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-kafka \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-template \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-cookie \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-worker-events \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-healthcheck \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-ipmatcher \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-expr \
    && /usr/local/openresty/luajit/bin/luarocks install api7-lua-resty-redis-connector \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-redis-cluster \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-timer-ng \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-maxminddb \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-m3u8 \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-ctx \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-gd \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-captcha \
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
    && cp -r -d /usr/lib/*/libweserv.so* /usr/local/openresty/lib/ \
    && find /usr/local/openresty/lib -type f -name '*.so*' -exec strip --strip-unneeded {} + \
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
