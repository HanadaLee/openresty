ARG RESTY_IMAGE_BASE="alpine"
ARG RESTY_IMAGE_TAG="3.18"

FROM dockerhub.hanada.info/${RESTY_IMAGE_BASE}:${RESTY_IMAGE_TAG}

LABEL maintainer="Hanada <im@hanada.info>"

# Docker Build Arguments
ARG RESTY_GIT_MIRROR="github.com"
ARG RESTY_GIT_RAW_MIRROR="raw.githubusercontent.com"
ARG RESTY_GIT_REPO="git.hanada.info"
ARG RESTY_VERSION="1.25.3.1"
ARG RESTY_RELEASE="82"
ARG RESTY_LUAROCKS_VERSION="3.9.2"
ARG RESTY_JEMALLOC_VERSION="5.3.0"
ARG RESTY_LIBMAXMINDDB_VERSION="1.7.1"
ARG RESTY_OPENSSL_FORK="quictls"
ARG RESTY_OPENSSL_VERSION="1.1.1w-quic1"
ARG RESTY_OPENSSL_OPTIONS="\
    --with-openssl-opt='\
        enable-camellia \
        enable-seed \
        enable-rfc3779 \
        enable-cms \
        enable-md2 \
        enable-rc5 \
        enable-weak-ssl-ciphers \
        enable-ssl3 \
        enable-ssl3-method' \
"
ARG RESTY_PCRE_URL_BASE="https://downloads.sourceforge.net/project/pcre/pcre"
ARG RESTY_PCRE_LIBRARY="PCRE"
ARG RESTY_PCRE_VERSION="8.45"
ARG RESTY_PCRE_OPTIONS="\
    --with-pcre-jit \
    --with-pcre-conf-opt='\
        --disable-cpp \
        --enable-jit \
        --enable-utf \
        --enable-unicode-properties \
        --with-match-limit=200000' \
    --with-pcre-opt='-fPIC' \
"
ARG RESTY_ZLIB_URL_BASE="https://zlib.net/fossils"
ARG RESTY_ZLIB_VERSION="1.3.1"
ARG RESTY_ZLIB_OPTIONS=""
ARG RESTY_ZSTD_VERSION="1.5.6"
ARG RESTY_ZSTD_OPTIONS=""
ARG RESTY_LIBATOMIC_VERSION="7.8.0"
ARG RESTY_LIBQRENCODE_VERSION="4.1.1"
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
ARG RESTY_J="8"
ARG RESTY_CONFIG_OPTIONS="\
    --with-compat \
    --with-file-aio \
    --with-poll_module \
    --with-threads \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
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
    --add-module=/build/modules/ngx_http_brotli_module \
    --add-module=/build/modules/ngx_http_cache_purge_module \
    --add-module=/build/modules/ngx_http_dav_ext_module \
    --add-module=/build/modules/ngx_http_dechunk_module \
    --add-module=/build/modules/ngx_http_extra_vars_module \
    --add-module=/build/modules/ngx_http_fancyindex_module \
    --add-module=/build/modules/ngx_http_flv_live_module \
    --add-module=/build/modules/ngx_http_geoip2_module \
    --add-module=/build/modules/ngx_http_lua_cache_module \
    --add-module=/build/modules/ngx_http_proxy_connect_module \
    --add-module=/build/modules/ngx_http_qrcode_module \
    --add-module=/build/modules/ngx_http_replace_filter_module \
    --add-module=/build/modules/ngx_http_sorted_querystring_module \
    --add-module=/build/modules/ngx_http_upstream_check_module \
    --add-module=/build/modules/ngx_http_vhost_traffic_status_module \
    --add-module=/build/modules/ngx_http_zstd_module \
"
ARG _RESTY_CONFIG_DEPS="\
    --with-cc-opt='-g -Wp,-D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC' \
    --with-ld-opt='-Wl,-rpath,/usr/local/openresty/lib -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--no-whole-archive -Wl,--gc-sections -pie -ljemalloc -Wl,-Bdynamic -lm -lstdc++ -pthread -ldl -Wl,-E' \
"

LABEL resty_image_base="${RESTY_IMAGE_BASE}"
LABEL resty_image_tag="${RESTY_IMAGE_TAG}"
LABEL resty_version="${RESTY_VERSION}"
LABEL resty_release="${RESTY_RELEASE}"
LABEL resty_openssl_fork="${RESTY_OPENSSL_FORK}"
LABEL resty_openssl_version="${RESTY_OPENSSL_VERSION}"
LABEL resty_pcre_library="${RESTY_PCRE_LIBRARY}"
LABEL resty_pcre_version="${RESTY_PCRE_VERSION}"
LABEL resty_libatomic_version="${RESTY_LIBATOMIC_VERSION}"
LABEL resty_zlib_version="${RESTY_ZLIB_VERSION}"
LABEL resty_zstd_version="${RESTY_ZSTD_VERSION}"
LABEL resty_jemalloc_version="${RESTY_JEMALLOC_VERSION}"
LABEL resty_libmaxminddb_version="${RESTY_LIBMAXMINDDB_VERSION}"
LABEL resty_libqrencode_version="${RESTY_LIBQRENCODE_VERSION}"

RUN apk add -U tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && apk del tzdata \
    && apk add --no-cache --virtual .build-deps \
        build-base \
        coreutils \
        gd-dev \
        geoip-dev \
        libxslt-dev \
        linux-headers \
        make \
        perl-dev \
        readline-dev \
        zlib-dev \
        bison \
        perl-dev \
        git \
        autoconf \
        automake \
        libtool \
        pkgconf \
        libpng-dev \
        cmake \
    && apk add --no-cache \
        bash \
        libgcc \
        libxslt \
        libgd \
        curl \
        perl \
        libintl \
        linux-headers \
        musl \
        outils-md5 \
        unzip \
        wget \
    && mkdir -p /build/lib /build/lualib /build/modules /build/patches \
    && cd /build/lib \
    && curl -fSL https://${RESTY_GIT_MIRROR}/jemalloc/jemalloc/releases/download/${RESTY_JEMALLOC_VERSION}/jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2 -o jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2 \
    && tar xjf jemalloc-${RESTY_JEMALLOC_VERSION}.tar.bz2 \
    && cd jemalloc-${RESTY_JEMALLOC_VERSION} \
    && ./configure \
    && make -j${RESTY_J} \
        EXTRA_CXXFLAGS="-Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC" \
        EXTRA_CFLAGS="-Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC" \
    && make install \
    && cd /build/lib \
    && curl -fSL https://${RESTY_GIT_MIRROR}/maxmind/libmaxminddb/releases/download/${RESTY_LIBMAXMINDDB_VERSION}/libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz -o libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz \
    && tar xzf libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION}.tar.gz \
    && cd libmaxminddb-${RESTY_LIBMAXMINDDB_VERSION} \
    && ./configure \
    && make -j${RESTY_J} \
    && make check \
    && make install \
    && cd /build/lib \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/openresty/sregex.git sregex \
    && cd sregex \
    && make -j${RESTY_J} \
    && make install \
    && cd /build/lib \
    && openssl_version_path=`echo -n ${RESTY_OPENSSL_VERSION} | sed 's/\./_/g'` \
    && curl -fSL https://${RESTY_GIT_MIRROR}/quictls/openssl/archive/refs/tags/OpenSSL_${openssl_version_path}.tar.gz -o OpenSSL_${openssl_version_path}.tar.gz \
    && tar xzf OpenSSL_${openssl_version_path}.tar.gz \
    && mv openssl-OpenSSL_${openssl_version_path} openssl-${RESTY_OPENSSL_VERSION} \
    && cd /build/lib \
    && curl -fSL ${RESTY_PCRE_URL_BASE}/${RESTY_PCRE_VERSION}/pcre-${RESTY_PCRE_VERSION}.tar.gz -o pcre-${RESTY_PCRE_VERSION}.tar.gz \
    && tar xzf pcre-${RESTY_PCRE_VERSION}.tar.gz \
    && cd /build/lib \
    && curl -fSL ${RESTY_ZLIB_URL_BASE}/zlib-${RESTY_ZLIB_VERSION}.tar.gz -o zlib-${RESTY_ZLIB_VERSION}.tar.gz \
    && tar xzf zlib-${RESTY_ZLIB_VERSION}.tar.gz \
    && cd /build/lib \
    && curl -fSL https://${RESTY_GIT_MIRROR}/facebook/zstd/releases/download/v${RESTY_ZSTD_VERSION}/zstd-${RESTY_ZSTD_VERSION}.tar.gz -o zstd-${RESTY_ZSTD_VERSION}.tar.gz \
    && tar xzf zstd-${RESTY_ZSTD_VERSION}.tar.gz \
    && cd zstd-${RESTY_ZSTD_VERSION} \
    && make -j${RESTY_J} \
    && make install \
    && cd /build/lib \
    && curl -fSL https://${RESTY_GIT_MIRROR}/ivmai/libatomic_ops/releases/download/v${RESTY_LIBATOMIC_VERSION}/libatomic_ops-${RESTY_LIBATOMIC_VERSION}.tar.gz -o libatomic_ops-${RESTY_LIBATOMIC_VERSION}.tar.gz \
    && tar xzf libatomic_ops-${RESTY_LIBATOMIC_VERSION}.tar.gz \
    && cd libatomic_ops-${RESTY_LIBATOMIC_VERSION}/src \
    && ln -s -f ./.libs/libatomic_ops.a . \
    && cd /build/lib \
    && curl -fSL https://${RESTY_GIT_MIRROR}/fukuchi/libqrencode/archive/refs/tags/v${RESTY_LIBQRENCODE_VERSION}.tar.gz -o libqrencode-${RESTY_LIBQRENCODE_VERSION}.tar.gz \
    && tar xzf libqrencode-${RESTY_LIBQRENCODE_VERSION}.tar.gz \
    && cd libqrencode-${RESTY_LIBQRENCODE_VERSION} \
    && cmake . \
    && make -j${RESTY_J} \
    && make install \
    && cd /build/modules \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/google/ngx_brotli.git ngx_http_brotli_module \
    && cd ngx_http_brotli_module \
    && sed -i "s|github.com|${RESTY_GIT_MIRROR}|g" .gitmodules \
    && git submodule update --init \
    && cd /build/modules \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/nginx-modules/ngx_cache_purge.git ngx_http_cache_purge_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/leev/ngx_http_geoip2_module.git ngx_http_geoip2_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/arut/nginx-dav-ext-module.git ngx_http_dav_ext_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/winshining/nginx-http-flv-module.git ngx_http_flv_live_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/vozlt/nginx-module-vts.git ngx_http_vhost_traffic_status_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/yaoweibin/nginx_upstream_check_module.git ngx_http_upstream_check_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_sorted_querystring_module.git ngx_http_sorted_querystring_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/aperezdc/ngx-fancyindex.git ngx_http_fancyindex_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/openresty/replace-filter-nginx-module.git ngx_http_replace_filter_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_extra_vars_module.git ngx_http_extra_vars_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/AlticeLabsProjects/lua-upstream-cache-nginx-module.git ngx_http_lua_cache_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/HanadaLee/ngx_http_zstd_module.git ngx_http_zstd_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_dechunk_module.git ngx_http_dechunk_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/chobits/ngx_http_proxy_connect_module.git ngx_http_proxy_connect_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/soulteary/ngx_http_qrcode_module.git ngx_http_qrcode_module_full \
    && mv ngx_http_qrcode_module_full/src ngx_http_qrcode_module \
    && rm -rf ngx_http_qrcode_module_full \
    && cd /build/patches \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_core_patches.git ngx_core_patches \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/nginx-modules/ngx_http_tls_dyn_size.git ngx_http_tls_dyn_size \
    && cd /build/lualib \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/lua-resty-maxminddb.git lua-resty-maxminddb \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/agentzh/lua-resty-multipart-parser.git lua-resty-multipart-parser \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/openresty/lua-resty-balancer.git lua-resty-balancer \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/Kong/kong.git kong \
    && cd lua-resty-balancer \
    && git checkout v0.05 \
    && make -j${RESTY_J} \
    && make install \
    && cd /build \
    && curl -fSL https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz -o openresty-${RESTY_VERSION}.tar.gz \
    && tar xzf openresty-${RESTY_VERSION}.tar.gz \
    && cd openresty-${RESTY_VERSION}/bundle/nginx-$(echo ${RESTY_VERSION} | cut -c 1-6) \
    && patch -p1 < /build/modules/ngx_http_extra_vars_module/ngx_http_extra_vars_1.25.3+.patch \
    && patch -p1 < /build/modules/ngx_http_upstream_check_module/check_1.20.1+.patch \
    && patch -p1 < /build/patches/ngx_core_patches/ngx_http_slice_allow_methods_directive_1.21.4+.patch \
    && patch -p1 < /build/patches/ngx_core_patches/ngx_http_listen_https_allow_http_1.25.3+.patch \
    && patch -p1 < /build/patches/ngx_http_tls_dyn_size/nginx__dynamic_tls_records_1.25.1+.patch \
    && sed -i "s/\(openresty\/.*\)\"/\1-${RESTY_RELEASE}\"/" src/core/nginx.h \
    && cd /build/openresty-${RESTY_VERSION} \
    && eval ./configure \
    ${RESTY_PATH_OPTIONS} \
    ${RESTY_USER_OPTIONS} \
    ${RESTY_CONFIG_OPTIONS} \
    --with-pcre=/build/lib/pcre-${RESTY_PCRE_VERSION} \
    ${RESTY_PCRE_OPTIONS} \
    --without-pcre2 \
    --with-zlib=/build/lib/zlib-${RESTY_ZLIB_VERSION} \
    ${RESTY_ZLIB_OPTIONS} \
    --with-libatomic=/build/lib/libatomic_ops-${RESTY_LIBATOMIC_VERSION} \
    --with-openssl=/build/lib/openssl-${RESTY_OPENSSL_VERSION} \
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
    && cp -r -d /usr/local/lib/lua/*.so* . \
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
    && cd /build/lualib \
    && cp -r lua-resty-maxminddb/lib/resty/* /usr/local/openresty/lualib/resty \
    && cp -r lua-resty-multipart-parser/lib/resty/* /usr/local/openresty/lualib/resty \
    && cp -r lua-resty-balancer/lib/resty/* /usr/local/openresty/lualib/resty \
    && cp -r kong/kong/resty/ctx.lua /usr/local/openresty/lualib/resty \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-http \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-hmac-ffi \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-jwt \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-dns-client \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-kafka \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-template \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-mlcache \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-jit-uuid \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-cookie \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-worker-events \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-healthcheck \
    && delgroup www-data \
    && deluser --remove-home $(getent passwd 33 | cut -d: -f1) \
    && adduser -s /sbin/nologin -g www-data -D -h /var/www --uid 33 www-data \
    && rm -rf /build \
    && rm -rf /usr/local/lib/* \
    && apk del .build-deps

# Add additional binaries into PATH for convenience
ENV PATH=$PATH:/usr/local/openresty/luajit/bin/:/usr/local/openresty/sbin/:/usr/local/openresty/bin/
ENV LUA_PATH="/usr/local/openresty/site/lualib/?.ljbc;/usr/local/openresty/site/lualib/?/init.ljbc;/usr/local/openresty/lualib/?.ljbc;/usr/local/openresty/lualib/?/init.ljbc;/usr/local/openresty/site/lualib/?.lua;/usr/local/openresty/site/lualib/?/init.lua;/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;./?.lua;/usr/local/openresty/luajit/share/luajit-2.1.0-beta3/?.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;/usr/local/openresty/luajit/share/lua/5.1/?.lua;/usr/local/openresty/luajit/share/lua/5.1/?/init.lua"
ENV LUA_CPATH="/usr/local/openresty/site/lualib/?.so;/usr/local/openresty/lualib/?.so;./?.so;/usr/local/lib/lua/5.1/?.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/loadall.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so"

CMD [ "/usr/local/openresty/sbin/nginx", "-p", "/usr/local/openresty/", "-g", "daemon off;"]

# Use SIGQUIT instead of default SIGTERM to cleanly drain requests
# See https://github.com/openresty/docker-openresty/blob/master/README.md#tips--pitfalls
STOPSIGNAL SIGQUIT
