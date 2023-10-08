FROM dockerhub.hanada.info/library/ubuntu:20.04

LABEL maintainer="Hanada <im@hanada.info>"

# Docker Build Arguments
ARG RESTY_GIT_MIRROR="fastgit.hanada.info"
ARG RESTY_GIT_REPO="git.hanada.info"
ARG RESTY_VERSION="1.21.4.2"
ARG RESTY_JEMALLOC_VERSION="5.3.0"
ARG RESTY_LIBMAXMINDDB_VERSION="1.7.1"
ARG RESTY_OPENSSL_VERSION="1.1.1u"
ARG RESTY_OPENSSL_OPTIONS="-g enable-weak-ssl-ciphers enable-tls1_3"
ARG RESTY_PCRE_URL_BASE="https://ftp.exim.org/pub/pcre"
ARG RESTY_PCRE_VERSION="8.45"
ARG RESTY_PCRE_OPTIONS="\
    --with-pcre-jit \
    --with-pcre-conf-opt='--enable-utf --enable-unicode-properties --with-match-limit=200000' \
    --with-pcre-opt='-fPIC' \
"
ARG RESTY_ZLIB_URL_BASE="https://zlib.net/"
ARG RESTY_ZLIB_VERSION="1.2.13"
ARG RESTY_LIBATOMIC_VERSION="7.8.0"
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
    --add-module=/build/openresty/modules/ngx_http_cache_purge_module \
    --add-module=/build/openresty/modules/ngx_http_brotli_module \
    --add-module=/build/openresty/modules/ngx_http_geoip2_module \
    --add-module=/build/openresty/modules/ngx_http_upstream_check_module \
    --add-module=/build/openresty/modules/ngx_http_sorted_querystring_module \
    --add-module=/build/openresty/modules/ngx_http_lua_cache_module \
    --add-dynamic-module=/build/openresty/modules/ngx_http_dav_ext_module \
    --add-dynamic-module=/build/openresty/modules/ngx_http_flv_module \
    --add-dynamic-module=/build/openresty/modules/ngx_http_vhost_traffic_status_module \
    --add-dynamic-module=/build/openresty/modules/ngx_http_fancyindex_module \
    --add-dynamic-module=/build/openresty/modules/ngx_http_replace_filter_module \
"
ARG RESTY_ADD_PACKAGE_BUILDDEPS="git"
ARG RESTY_ADD_PACKAGE_RUNDEPS=""
ARG RESTY_EVAL_PRE_CONFIGURE=""
ARG RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE=""
ARG RESTY_EVAL_POST_MAKE=""

RUN mkdir /build \
    && sed -i 's@//.*archive.ubuntu.com@//mirrors.hanada.info@g' /etc/apt/sources.list \
    && sed -i 's@//security.ubuntu.com@//mirrors.hanada.info@g' /etc/apt/sources.list \
    && DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl \
        libpcre3-dev \
        libssl-dev \
        perl \
        make \
        build-essential \
        libxml2 \
        libxml2-dev \
        libxslt-dev \
        aptitude \
        ${RESTY_ADD_PACKAGE_BUILDDEPS} \
    && aptitude install -y --without-recommends libgd-dev \
    && cd /build \
    && if [ -n "${RESTY_EVAL_PRE_CONFIGURE}" ]; then eval $(echo ${RESTY_EVAL_PRE_CONFIGURE}); fi \
    && cd /build \
    && curl -fSL https://${RESTY_GIT_MIRROR}/jemalloc/jemalloc/releases/download/${RESTY_JEMALLOC_VERSION}/jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2 -o jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2
    && tar xjf jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2 \
    && cd /build/jemalloc-${RESTY_JEMALLOC_VERSION} \
    && ./configure \
    && make \
        EXTRA_CXXFLAGS="-Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC" \
        EXTRA_CFLAGS="-Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC" \
    && make install \
    && ldconfig \
    && cd /build \
    && curl -fSL https://${RESTY_GIT_MIRROR}/maxmind/libmaxminddb/releases/download/${RESTY_LIBMAXMINDDB_VERSION}/libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz -o libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz \
    && tar xzf libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz \
    && cd libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION} \
    && ./configure \
    && make \
    && make check \
    && make install \
    && ldconfig \
    && cd /build
    && git clone https://${RESTY_GIT_MIRROR}/openresty/sregex.git sregex\
    && cd sregex
    && make \
    && make install \
    && cd /build
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
    && cd libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}/src \
    && ln -s -f ./.libs/libatomic_ops.a .
    && cd /build \
    && git clone --depth=100 https://${RESTY_GIT_MIRROR}/google/ngx_brotli.git ngx_brotli_module \
    && cd ngx_brotli_module \
    && git reset --hard 63ca02abdcf79c9e788d2eedcc388d2335902e52 \
    && sed -i "s|github.com|${RESTY_GIT_MIRROR}|g" .gitmodules \
    && git submodule update --init \
    && cd /build \
    && git clone https://${RESTY_GIT_MIRROR}/vozlt/nginx-module-vts.git ngx_http_vhost_traffic_status_module \
    && git clone https://${RESTY_GIT_MIRROR}/openresty/replace-filter-nginx-module.git ngx_http_replace_filter_module \
    && git clone https://${RESTY_GIT_MIRROR}/wandenberg/nginx-sorted-querystring-module.git ngx_sorted_querystring_module \
    && git clone https://${RESTY_GIT_MIRROR}/yaoweibin/nginx_upstream_check_module.git ngx_upstream_check_module \
    && git clone https://${RESTY_GIT_MIRROR}/ledgetech/lua-resty-http.git lua-resty-http \






    && cd /build/openresty/bundle/nginx-1.21.4 \
    && patch -p1 < /build/openresty/patches/x_request_id_1.21.4+.patch \
    && patch -p1 < /build/openresty/patches/nginx__dynamic_tls_records_1.17.7+.patch \
    && patch -p1 < /build/openresty/modules/ngx_http_upstream_check_module/check_1.20.1+.patch \
    && cd /build/openresty/modules/ngx_brotli \
    && git submodule update --init \
    && cd /build/openresty \
    && ./configure \
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
        --user=www-data \
        --group=www-data \
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
        --with-pcre=/build/openresty/lib/pcre-8.45 \
        --with-pcre-opt='-fPIC' \
        --with-pcre-conf-opt='--enable-utf --enable-unicode-properties --with-match-limit=200000' \
        --with-pcre-jit \
        --with-pcre-opt=-g \
        --with-zlib=/build/openresty/lib/zlib-1.2.13 \
        --with-zlib-opt=-g \
        --with-libatomic=/build/openresty/lib/libatomic_ops-7.8.0 \
        --with-openssl=/build/openresty/lib/openssl-1.1.1u \
        --with-openssl-opt='-g enable-weak-ssl-ciphers enable-tls1_3' \
        --add-module=/build/openresty/modules/ngx_http_cache_purge_module \
        --add-module=/build/openresty/modules/ngx_http_brotli_module \
        --add-module=/build/openresty/modules/ngx_http_geoip2_module \
        --add-module=/build/openresty/modules/ngx_http_upstream_check_module \
        --add-module=/build/openresty/modules/ngx_http_sorted_querystring_module \
        --add-module=/build/openresty/modules/ngx_http_lua_cache_module \
        --add-dynamic-module=/build/openresty/modules/ngx_http_dav_ext_module \
        --add-dynamic-module=/build/openresty/modules/ngx_http_flv_module \
        --add-dynamic-module=/build/openresty/modules/ngx_http_vhost_traffic_status_module \
        --add-dynamic-module=/build/openresty/modules/ngx_http_fancyindex_module \
        --add-dynamic-module=/build/openresty/modules/ngx_http_replace_filter_module \
        --with-cc-opt='-O2 -g -O2 -Wp,-D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC' \
        --with-ld-opt='-Wl,-rpath,/usr/local/openresty/lib -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--no-whole-archive -Wl,--gc-sections -pie -ljemalloc -Wl,-Bdynamic -lm -lstdc++ -pthread -ldl -Wl,-E' \
    && make \
    && make install \
    && mv /usr/local/openresty/nginx/html /usr/local/openresty \
    && rm -rf /usr/local/openresty/nginx \
    && mkdir -p /usr/local/openresty/var/lib/tmp \
    && mkdir -p /usr/local/openresty/cache \
    && cd /usr/local/openresty/cache \
    && mkdir fastcgi proxy scgi uwsgi \
    && mkdir -p /usr/local/openresty/lib \
    && cd /usr/local/openresty/lib \
    && cp -d /usr/local/lib/* . \
    && rm *.a *.la \
    && cd /usr/local/openresty/lualib \
    && ln -s ../lib/libmaxminddb.so . \
    && cp -rfp /build/openresty/lualib /build/openresty/systemd /usr/local/openresty

WORKDIR /usr/local/openresty

# Add additional binaries into PATH for convenience
ENV PATH=$PATH:/usr/local/openresty/luajit/bin/:/usr/local/openresty/nginx/sbin/:/usr/local/openresty/bin/

# Copy nginx configuration files
# COPY etc /usr/local/openresty/nginx/etc

CMD [ "/usr/local/openresty/sbin/nginx", "-g", "daemon off;"]

# Use SIGQUIT instead of default SIGTERM to cleanly drain requests
# See https://github.com/openresty/docker-openresty/blob/master/README.md#tips--pitfalls
STOPSIGNAL SIGQUIT
