ARG RESTY_IMAGE_BASE="alpine"
ARG RESTY_IMAGE_TAG="3.18"

FROM dockerhub.hanada.info/${RESTY_IMAGE_BASE}:${RESTY_IMAGE_TAG}

LABEL maintainer="Hanada <im@hanada.info>"

# Docker Build Arguments
ARG RESTY_GIT_MIRROR="fastgit.hanada.info"
ARG RESTY_GIT_RAW_MIRROR="raw.githubusercontent.com"
ARG RESTY_GIT_REPO="git.hanada.info"
ARG RESTY_VERSION="1.21.4.3"
ARG RESTY_RELEASE="30"
ARG RESTY_LUAROCKS_VERSION="3.9.2"
ARG RESTY_JEMALLOC_VERSION="5.3.0"
ARG RESTY_LIBMAXMINDDB_VERSION="1.7.1"
ARG RESTY_OPENSSL_URL_BASE="https://www.openssl.org/source"
ARG RESTY_OPENSSL_VERSION="1.1.1w"
ARG RESTY_OPENSSL_OPTIONS="\
    --with-openssl-opt='enable-weak-ssl-ciphers enable-tls1_3' \
"
ARG RESTY_PCRE_URL_BASE="https://ftp.exim.org/pub/pcre"
ARG RESTY_PCRE_VERSION="8.45"
ARG RESTY_PCRE_OPTIONS="\
    --with-pcre-jit \
    --with-pcre-conf-opt='--enable-utf --enable-unicode-properties --with-match-limit=200000' \
    --with-pcre-opt='-fPIC' \
"
ARG RESTY_ZLIB_URL_BASE="https://zlib.net"
ARG RESTY_ZLIB_VERSION="1.3"
ARG RESTY_ZLIB_OPTIONS=""
ARG RESTY_LIBATOMIC_VERSION="7.8.0"
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
ARG RESTY_USER_OPTIONS="--user=www-data --group=www-data"
ARG RESTY_J="4"
ARG RESTY_CONFIG_OPTIONS="\
    --with-compat \
    --with-file-aio \
    --with-poll_module \
    --with-threads \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_degradation_module \
    --with-http_slice_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --without-http_empty_gif_module \
"
ARG RESTY_CONFIG_OPTIONS_MORE="\
    --add-module=/build/ngx_http_cache_purge_module \
    --add-module=/build/ngx_http_brotli_module \
    --add-module=/build/ngx_http_geoip2_module \
    --add-module=/build/ngx_http_sorted_querystring_module \
    --add-module=/build/ngx_http_upstream_check_module \
    --add-module=/build/ngx_http_extra_vars_module \
    --add-module=/build/ngx_http_lua_cache_module \
    --add-dynamic-module=/build/ngx_http_dav_ext_module \
    --add-dynamic-module=/build/ngx_http_flv_module \
    --add-dynamic-module=/build/ngx_http_vhost_traffic_status_module \
    --add-dynamic-module=/build/ngx_http_fancyindex_module \
    --add-dynamic-module=/build/ngx_http_replace_filter_module \
"
ARG RESTY_ADD_PACKAGE_BUILDDEPS=""
ARG RESTY_ADD_PACKAGE_RUNDEPS="git"
ARG RESTY_EVAL_PRE_CONFIGURE=""
ARG RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE=""
ARG RESTY_EVAL_POST_MAKE=""

ARG _RESTY_CONFIG_DEPS="\
    --with-cc-opt='-g -Wp,-D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC' \
    --with-ld-opt='-Wl,-rpath,/usr/local/openresty/lib -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--no-whole-archive -Wl,--gc-sections -pie -ljemalloc -Wl,-Bdynamic -lm -lstdc++ -pthread -ldl -Wl,-E' \
"

LABEL resty_image_base="${RESTY_IMAGE_BASE}"
LABEL resty_image_tag="${RESTY_IMAGE_TAG}"
LABEL resty_version="${RESTY_VERSION}"
LABEL resty_release="${RESTY_RELEASE}"
LABEL resty_openssl_version="${RESTY_OPENSSL_VERSION}"
LABEL resty_pcre_version="${RESTY_PCRE_VERSION}"
LABEL resty_libatomic_version="${RESTY_LIBATOMIC_VERSION}"
LABEL resty_zlib_version="${RESTY_ZLIB_VERSION}"
LABEL resty_jemalloc_version="${RESTY_JEMALLOC_VERSION}"
LABEL resty_libmaxminddb_version="${RESTY_LIBMAXMINDDB_VERSION}"

RUN mkdir /build \
    && apk add -U tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && apk del tzdata \
    && apk add --no-cache --virtual .build-deps \
        build-base \
        coreutils \
        curl \
        gd-dev \
        geoip-dev \
        libxslt-dev \
        linux-headers \
        make \
        perl-dev \
        readline-dev \
        zlib-dev \
        bison \
        ${RESTY_ADD_PACKAGE_BUILDDEPS} \
    && apk add --no-cache \
        libgcc \
        libxslt \
        curl \
        perl \
        ${RESTY_ADD_PACKAGE_RUNDEPS} \
    && cd /build \
    && if [ -n "${RESTY_EVAL_PRE_CONFIGURE}" ]; then eval $(echo ${RESTY_EVAL_PRE_CONFIGURE}); fi \
    && cd /build \
    && curl -fSL https://${RESTY_GIT_MIRROR}/jemalloc/jemalloc/releases/download/${RESTY_JEMALLOC_VERSION}/jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2 -o jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2 \
    && tar xjf jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2 \
    && cd /build/jemalloc-${RESTY_JEMALLOC_VERSION} \
    && ./configure \
    && make -j${RESTY_J} \
        EXTRA_CXXFLAGS="-Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC" \
        EXTRA_CFLAGS="-Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC" \
    && make install \
    && cd /build \
    && curl -fSL https://${RESTY_GIT_MIRROR}/maxmind/libmaxminddb/releases/download/${RESTY_LIBMAXMINDDB_VERSION}/libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz -o libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz \
    && tar xzf libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz \
    && cd libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION} \
    && ./configure \
    && make -j${RESTY_J} \
    && make check \
    && make install \
    && cd /build \
    && git clone https://${RESTY_GIT_MIRROR}/openresty/sregex.git sregex \
    && cd sregex \
    && make -j${RESTY_J} \
    && make install \
    && cd /build \
    && curl -fSL "${RESTY_OPENSSL_URL_BASE}/openssl-${RESTY_OPENSSL_VERSION}.tar.gz" -o openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && tar xzf openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && cd /build \
    && curl -fSL ${RESTY_PCRE_URL_BASE}/pcre-${RESTY_PCRE_VERSION}.tar.gz -o pcre-${RESTY_PCRE_VERSION}.tar.gz \
    && tar xzf pcre-${RESTY_PCRE_VERSION}.tar.gz \
    && cd /build \
    && curl -fSL ${RESTY_ZLIB_URL_BASE}/zlib-${RESTY_ZLIB_VERSION}.tar.gz -o zlib-${RESTY_ZLIB_VERSION}.tar.gz \
    && tar xzf zlib-${RESTY_ZLIB_VERSION}.tar.gz \
    && cd /build \
    && curl -fSL https://${RESTY_GIT_MIRROR}/ivmai/libatomic_ops/releases/download/v${RESTY_LIBATOMIC_VERSION}/libatomic_ops-${RESTY_LIBATOMIC_VERSION}.tar.gz -o libatomic_ops-${RESTY_LIBATOMIC_VERSION}.tar.gz \
    && tar xzf libatomic_ops-${RESTY_LIBATOMIC_VERSION}.tar.gz \
    && cd libatomic_ops-${RESTY_LIBATOMIC_VERSION}/src \
    && ln -s -f ./.libs/libatomic_ops.a . \
    && cd /build \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/google/ngx_brotli.git ngx_http_brotli_module \
    && cd ngx_http_brotli_module \
    && sed -i "s|github.com|${RESTY_GIT_MIRROR}|g" .gitmodules \
    && git submodule update --init \
    && git clone https://${RESTY_GIT_MIRROR}/nginx-modules/ngx_cache_purge.git ngx_http_cache_purge_module \
    && git clone https://${RESTY_GIT_MIRROR}/leev/ngx_http_geoip2_module.git ngx_http_geoip2_module \
    && git clone https://${RESTY_GIT_MIRROR}/arut/nginx-dav-ext-module.git ngx_http_dav_ext_module \
    && git clone https://${RESTY_GIT_MIRROR}/winshining/nginx-http-flv-module.git ngx_http_flv_module \
    && git clone https://${RESTY_GIT_MIRROR}/vozlt/nginx-module-vts.git ngx_http_vhost_traffic_status_module \
    && git clone https://${RESTY_GIT_MIRROR}/yaoweibin/nginx_upstream_check_module.git ngx_http_upstream_check_module \
    && git clone https://${RESTY_GIT_MIRROR}/wandenberg/nginx-sorted-querystring-module.git ngx_http_sorted_querystring_module \
    && git clone https://${RESTY_GIT_MIRROR}/aperezdc/ngx-fancyindex.git ngx_http_fancyindex_module \
    && git clone https://${RESTY_GIT_MIRROR}/openresty/replace-filter-nginx-module.git ngx_http_replace_filter_module \
    && git clone https://${RESTY_GIT_REPO}/hanada/ngx_http_extra_vars_module.git ngx_http_extra_vars_module \
    && git clone https://${RESTY_GIT_MIRROR}/AlticeLabsProjects/lua-upstream-cache-nginx-module.git ngx_http_lua_cache_module \
    && git clone https://${RESTY_GIT_MIRROR}/nginx-modules/ngx_http_tls_dyn_size.git ngx_http_tls_dyn_size \
    && git clone https://${RESTY_GIT_REPO}/hanada/lua-resty-maxminddb.git lua-resty-maxminddb \
    && git clone https://${RESTY_GIT_MIRROR}/agentzh/lua-resty-multipart-parser.git lua-resty-multipart-parser \
    && cd /build \
    && curl -fSL https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz -o openresty-${RESTY_VERSION}.tar.gz \
    && tar xzf openresty-${RESTY_VERSION}.tar.gz \
    && cd openresty-${RESTY_VERSION}/bundle/nginx-$(echo ${RESTY_VERSION} | cut -c 1-6) \
    && curl -s https://${RESTY_GIT_REPO}/hanada/openresty/-/raw/main/patches/nginx_resty_request_id_1.21.4+.patch | patch -p1 \
    && patch -p1 < /build/ngx_http_upstream_check_module/check_1.20.1+.patch \
    && patch -p1 < /build/ngx_http_tls_dyn_size/nginx__dynamic_tls_records_1.17.7+.patch \
    && sed -i "s/\(openresty\/.*\)\"/\1-${RESTY_RELEASE}\"/" src/core/nginx.h \
    && cd /build/openresty-${RESTY_VERSION} \
    && if [ -n "${RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE}" ]; then eval $(echo ${RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE}); fi \
    && eval ./configure \
    ${RESTY_PATH_OPTIONS} \
    ${RESTY_USER_OPTIONS} \
    ${RESTY_CONFIG_OPTIONS} \
    --with-pcre=/build/pcre-${RESTY_PCRE_VERSION} \
    ${RESTY_PCRE_OPTIONS} \
    --with-zlib=/build/zlib-${RESTY_ZLIB_VERSION} \
    ${RESTY_ZLIB_OPTIONS} \
    --with-libatomic=/build/libatomic_ops-${RESTY_LIBATOMIC_VERSION} \
    --with-openssl=/build/openssl-${RESTY_OPENSSL_VERSION} \
    ${RESTY_OPENSSL_OPTIONS} \
    ${RESTY_CONFIG_OPTIONS_MORE} \
    ${_RESTY_CONFIG_DEPS} \
    && make -j${RESTY_J} \
    && make install \
    && mv /usr/local/openresty/nginx/html /usr/local/openresty \
    && rm -rf /usr/local/openresty/nginx \
    && mkdir -p /usr/local/openresty/var/lib/tmp \
    && mkdir -p /usr/local/openresty/cache/fastcgi \
        /usr/local/openresty/cache/proxy \
        /usr/local/openresty/cache/scgi \
        /usr/local/openresty/cache/uwsgi \
    && mkdir -p /usr/local/openresty/lib \
    && cd /usr/local/openresty/lib \
    && cp -r -d /usr/local/lib/*.so* . \
    && cp -r -d /usr/lib/libstdc++.so* . \
    && cd /usr/local/openresty/lualib \
    && ln -s ../lib/libmaxminddb.so . \
    && cd /build \
    && curl -fSL https://luarocks.github.io/luarocks/releases/luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz -o luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && tar xzf luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && cd luarocks-${RESTY_LUAROCKS_VERSION} \
    && ./configure \
        --prefix=/usr/local/openresty/luajit \
        --with-lua=/usr/local/openresty/luajit \
        --lua-suffix=jit-2.1.0-beta3 \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 \
    && make build \
    && make install \
    && cd /build \
    && cp -r lua-resty-maxminddb/lib/resty/* /usr/local/openresty/lualib/resty \
    && cp -r lua-resty-multipart-parser/lib/resty/* /usr/local/openresty/lualib/resty \
    && luarocks install lua-resty-http \
    && luarocks install lua-resty-hmac-ffi \
    && luarocks install lua-resty-jwt \
    && luarocks install lua-resty-openidc \
    && luarocks install lua-resty-dns-client \
    && cd /build \
    && if [ -n "${RESTY_EVAL_POST_MAKE}" ]; then eval $(echo ${RESTY_EVAL_POST_MAKE}); fi \
    && delgroup www-data \
    && deluser --remove-home $(getent passwd 33 | cut -d: -f1) \
    && adduser -s /sbin/nologin -g www-data -D -h /var/www --uid 33 www-data \
    && rm -rf /build \
    && rm -rf /usr/local/lib/* \
    && apk del .build-deps

# Add additional binaries into PATH for convenience
ENV PATH=$PATH:/usr/local/openresty/luajit/bin/:/usr/local/openresty/sbin/:/usr/local/openresty/bin/

# Copy nginx configuration files
# COPY etc /usr/local/openresty/nginx/etc

CMD [ "/usr/local/openresty/sbin/nginx", "-p", "/usr/local/openresty/", "-g", "daemon off;"]

# Use SIGQUIT instead of default SIGTERM to cleanly drain requests
# See https://github.com/openresty/docker-openresty/blob/master/README.md#tips--pitfalls
STOPSIGNAL SIGQUIT
