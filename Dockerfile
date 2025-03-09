ARG RESTY_IMAGE_BASE="debian"
ARG RESTY_IMAGE_TAG="bookworm-slim"

FROM dockerhub.hanada.info/${RESTY_IMAGE_BASE}:${RESTY_IMAGE_TAG}

LABEL maintainer="Hanada <im@hanada.info>"

# Docker Build Arguments
ARG RESTY_IMAGE_BASE="debian"
ARG RESTY_IMAGE_TAG="bookworm-slim"
ARG RESTY_GIT_MIRROR="github.com"
ARG RESTY_GIT_RAW_MIRROR="raw.githubusercontent.com"
ARG RESTY_GIT_REPO="git.hanada.info"
ARG RESTY_VERSION="1.27.1.1"
ARG RESTY_RELEASE="185"
ARG RESTY_LUAROCKS_VERSION="3.11.0"
ARG RESTY_JEMALLOC_VERSION="5.3.0"
ARG RESTY_LIBMAXMINDDB_VERSION="1.7.1"
ARG RESTY_OPENSSL_FORK="quictls"
ARG RESTY_OPENSSL_VERSION="1.1.1w-quic1"
ARG RESTY_OPENSSL_PATCH_VERSION="1.1.1f"
ARG RESTY_OPENSSL_BUILD_OPTIONS="\
    no-threads \
    shared \
    zlib \
    -g \
    enable-camellia \
    enable-seed \
    enable-rfc3779 \
    enable-cms \
    enable-md2 \
    enable-rc5 \
    enable-weak-ssl-ciphers \
    enable-ssl3 \
    enable-ssl3-method \
"
ARG RESTY_PCRE_URL_BASE="https://downloads.sourceforge.net/project/pcre/pcre"
ARG RESTY_PCRE_LIBRARY="PCRE"
ARG RESTY_PCRE_VERSION="8.45"
ARG RESTY_PCRE_BUILD_OPTIONS="\
    --enable-jit \
    --disable-cpp \
    --enable-jit \
    --enable-utf \
    --enable-unicode-properties \
    --with-match-limit=200000 \
"
ARG RESTY_PCRE_OPTIONS="--with-pcre-jit"
ARG RESTY_ZLIB_URL_BASE="https://zlib.net/fossils"
ARG RESTY_ZLIB_VERSION="1.3.1"
ARG RESTY_ZSTD_VERSION="1.5.6"
ARG RESTY_LIBATOMIC_VERSION="7.8.0"
ARG RESTY_LIBQRENCODE_VERSION="4.1.1"
ARG RESTY_LIBVIPS_VERSION="8.16.0"
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
ARG RESTY_J="8"
ARG RESTY_CONFIG_OPTIONS="\
    --with-file-aio \
    --with-threads \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-http_auth_request_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_realip_module \
    --with-http_degradation_module \
    --with-http_slice_module \
    --with-http_sub_module \
    --without-http_empty_gif_module \
    --with-ipv6 \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
"
ARG RESTY_CONFIG_OPTIONS_MORE="\
    --add-module=/build/modules/ngx_backtrace_module \
    --add-module=/build/modules/ngx_lua_events_module \
    --add-module=/build/modules/ngx_http_access_control_module \
    --add-module=/build/modules/ngx_http_aws_auth_module \
    --add-module=/build/modules/ngx_http_brotli_module \
    --add-module=/build/modules/ngx_http_cache_purge_module \
    --add-module=/build/modules/ngx_http_compress_normalize_module \
    --add-module=/build/modules/ngx_http_compress_vary_filter_module \
    --add-module=/build/modules/ngx_http_cors_module \
    --add-module=/build/modules/ngx_http_delay_module \
    --add-module=/build/modules/ngx_http_extra_variables_module \
    --add-module=/build/modules/ngx_http_flv_live_module \
    --add-module=/build/modules/ngx_http_geoip2_module \
    --add-module=/build/modules/ngx_http_internal_auth_module \
    --add-module=/build/modules/ngx_http_internal_redirect_module \
    --add-module=/build/modules/ngx_http_limit_traffic_rate_filter_module \
    --add-module=/build/modules/ngx_http_log_var_set_module \
    --add-module=/build/modules/ngx_http_lua_load_var_index_module \
    --add-module=/build/modules/ngx_http_proxy_connect_module \
    --add-module=/build/modules/ngx_http_proxy_var_set_module \
    --add-module=/build/modules/ngx_http_qrcode_module \
    --add-module=/build/modules/ngx_http_replace_filter_module \
    --add-module=/build/modules/ngx_http_rewrite_status_filter_module \
    --add-module=/build/modules/ngx_http_secure_link_hash_module \
    --add-module=/build/modules/ngx_http_secure_link_hmac_module \
    --add-module=/build/modules/ngx_http_security_headers_module \
    --add-module=/build/modules/ngx_http_server_redirect_module \
    --add-module=/build/modules/ngx_http_sorted_querystring_module \
    --add-module=/build/modules/ngx_http_sysguard_module \
    --add-module=/build/modules/ngx_http_trim_filter_module \
    --add-module=/build/modules/ngx_http_cache_dechunk_filter_module \
    --add-module=/build/modules/ngx_http_unbrotli_filter_module \
    --add-module=/build/modules/ngx_http_upstream_check_module \
    --add-module=/build/modules/ngx_http_upstream_log_module \
    --add-module=/build/modules/ngx_http_var_module \
    --add-module=/build/modules/ngx_http_vhost_traffic_status_module \
    --add-module=/build/modules/ngx_http_waf_module \
    --add-module=/build/modules/ngx_http_weserv_module \
    --add-module=/build/modules/ngx_http_zstd_module \
"
ARG _RESTY_CONFIG_DEPS="\
    --with-cc-opt='-DNGX_LUA_ABORT_AT_PANIC -Wp,-D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC' \
    --with-ld-opt='-Wl,-rpath,/usr/local/openresty/lib/ -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--no-whole-archive -Wl,--gc-sections -pie -ljemalloc -Wl,-Bdynamic -lm -lstdc++ -pthread -ldl -Wl,-E' \
"

LABEL resty_image_base="${RESTY_IMAGE_BASE}"
LABEL resty_image_tag="${RESTY_IMAGE_TAG}"
LABEL resty_version="${RESTY_VERSION}"
LABEL resty_release="${RESTY_RELEASE}"
LABEL resty_luarocks_version="${RESTY_LUAROCKS_VERSION}"
LABEL resty_openssl_patch_version="${RESTY_OPENSSL_PATCH_VERSION}"
LABEL resty_openssl_version="${RESTY_OPENSSL_VERSION}"
LABEL resty_openssl_fork="${RESTY_OPENSSL_FORK}"
LABEL resty_pcre_library="${RESTY_PCRE_LIBRARY}"
LABEL resty_pcre_version="${RESTY_PCRE_VERSION}"
LABEL resty_libatomic_version="${RESTY_LIBATOMIC_VERSION}"
LABEL resty_zlib_version="${RESTY_ZLIB_VERSION}"
LABEL resty_zstd_version="${RESTY_ZSTD_VERSION}"
LABEL resty_jemalloc_version="${RESTY_JEMALLOC_VERSION}"
LABEL resty_libmaxminddb_version="${RESTY_LIBMAXMINDDB_VERSION}"
LABEL resty_libqrencode_version="${RESTY_LIBQRENCODE_VERSION}"

ENV TZ="Asia/Shanghai"

RUN groupmod -n nginx www-data \
    && usermod -l nginx www-data \
    && echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list \
    && DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -t bookworm-backports \
        libheif1 \
        libheif-plugin-aomenc \
        libheif-plugin-x265 \
        libheif-dev \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libgd3 \
        libgd-dev \
        libyaml-0-2 \
        libyaml-dev \
        tzdata \
        unzip \
        wget \
        git \
        curl \
        libcurl4 \
        libcurl4-openssl-dev \
        ca-certificates \
        bison \
        build-essential \
        gettext-base \
        libncurses5 \
        libncurses5-dev \
        libperl5.36 \
        libperl-dev \
        libreadline8 \
        libreadline-dev \
        libxslt1.1 \
        libxslt1-dev \
        make \
        perl \
        autoconf \
        automake \
        libtool \
        pkgconf \
        cmake \
        libglib2.0-0 \
        libglib2.0-dev \
        libwebpmux3 \
        libwebpdemux2 \
        libexif12 \
        libexif-dev \
        librsvg2-2 \
        librsvg2-dev \
        libcgif0 \
        libcgif-dev \
        libarchive13 \
        libarchive-dev \
        libfftw3-dev \
        libfftw3-double3 \
        liblcms2-2 \
        liblcms2-dev \
        libspng0 \
        libspng-dev \
        libimagequant0 \
        libimagequant-dev \
        liborc-0.4-0 \
        liborc-0.4-dev \
        libcfitsio10 \
        libcfitsio-dev \
        libopenexr-3-1-30 \
        libopenexr-dev \
        libopenjp2-7 \
        libopenjp2-7-dev \
        libjxl0.7 \
        libjxl-dev \
        libexpat1 \
        libexpat1-dev \
        libffi8 \
        libffi-dev \
        libpng16-16 \
        libpng-dev \
        libtiff6 \
        libtiff-dev \
        libwebp7 \
        libwebp-dev \
        meson \
        flex \
        libmodsecurity3 \
        libmodsecurity-dev \
        libsodium23 \
        libsodium-dev \
    && ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && dpkg-reconfigure -f noninteractive tzdata \
    && mkdir -p /build/lib /build/patches /build/modules /build/lualib \
    && cd /build/patches \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/openresty.git openresty \
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
    && curl -fSL ${RESTY_ZLIB_URL_BASE}/zlib-${RESTY_ZLIB_VERSION}.tar.gz -o zlib-${RESTY_ZLIB_VERSION}.tar.gz \
    && tar xzf zlib-${RESTY_ZLIB_VERSION}.tar.gz \
    && cd zlib-${RESTY_ZLIB_VERSION} \
    && ./configure \
    && make -j${RESTY_J} \
    && make install \
    && cd /build/lib \
    && openssl_version_path=`echo -n ${RESTY_OPENSSL_VERSION} | sed 's/\./_/g'` \
    && curl -fSL https://${RESTY_GIT_MIRROR}/quictls/openssl/archive/refs/tags/OpenSSL_${openssl_version_path}.tar.gz -o OpenSSL_${openssl_version_path}.tar.gz \
    && tar xzf OpenSSL_${openssl_version_path}.tar.gz \
    && mv openssl-OpenSSL_${openssl_version_path} openssl-${RESTY_OPENSSL_VERSION} \
    && cd openssl-${RESTY_OPENSSL_VERSION} \
    && if [ $(echo ${RESTY_OPENSSL_VERSION} | cut -c 1-5) = "1.1.1" ] ; then \
        echo 'patching OpenSSL 1.1.1 for OpenResty' \
        && curl -fSL https://raw.githubusercontent.com/openresty/openresty/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 ; \
    fi \
    && if [ $(echo ${RESTY_OPENSSL_VERSION} | cut -c 1-5) = "1.1.0" ] ; then \
        echo 'patching OpenSSL 1.1.0 for OpenResty' \
        && curl -fSL https://raw.githubusercontent.com/openresty/openresty/ed328977028c3ec3033bc25873ee360056e247cd/patches/openssl-1.1.0j-parallel_build_fix.patch | patch -p1 \
        && curl -fSL https://raw.githubusercontent.com/openresty/openresty/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 ; \
    fi \
    && ./config \
        ${RESTY_OPENSSL_BUILD_OPTIONS} \
    && make update \
    && make -j${RESTY_J} \
    && make install_sw \
    && cd /build/lib \
    && curl -fSL ${RESTY_PCRE_URL_BASE}/${RESTY_PCRE_VERSION}/pcre-${RESTY_PCRE_VERSION}.tar.gz -o pcre-${RESTY_PCRE_VERSION}.tar.gz \
    && tar xzf pcre-${RESTY_PCRE_VERSION}.tar.gz \
    && cd pcre-${RESTY_PCRE_VERSION} \
    && ./configure \
        ${RESTY_PCRE_BUILD_OPTIONS} \
    && make -j${RESTY_J} \
    && make install \
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
    && cd .. \
    && ./configure \
    && make -j${RESTY_J} \
    && make install \
    && cd /build/lib \
    && curl -fSL https://${RESTY_GIT_MIRROR}/fukuchi/libqrencode/archive/refs/tags/v${RESTY_LIBQRENCODE_VERSION}.tar.gz -o libqrencode-${RESTY_LIBQRENCODE_VERSION}.tar.gz \
    && tar xzf libqrencode-${RESTY_LIBQRENCODE_VERSION}.tar.gz \
    && cd libqrencode-${RESTY_LIBQRENCODE_VERSION} \
    && cmake . \
    && make -j${RESTY_J} \
    && make install \
    && cd /build/lib \
    && curl -fSL https://${RESTY_GIT_MIRROR}/libvips/libvips/releases/download/v${RESTY_LIBVIPS_VERSION}/vips-${RESTY_LIBVIPS_VERSION}.tar.xz -o vips-${RESTY_LIBVIPS_VERSION}.tar.xz \
    && tar -xf vips-${RESTY_LIBVIPS_VERSION}.tar.xz \
    && cd vips-${RESTY_LIBVIPS_VERSION} \
    && meson setup build --libdir=lib --buildtype=release "$@" \
    && ninja -C build \
    && ninja -C build install \
    && cd /build/modules \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/google/ngx_brotli.git ngx_http_brotli_module \
    && cd ngx_http_brotli_module \
    && sed -i "s|github.com|${RESTY_GIT_MIRROR}|g" .gitmodules \
    && git submodule update --init \
    && patch -p1 < /build/patches/openresty/patches/ngx_http_brotli_filter_module-ext.patch \
    && mkdir -p deps/brotli/out \
    && cd deps/brotli/out \
    && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_C_FLAGS="-O2 -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" \
        -DCMAKE_CXX_FLAGS="-O2 -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" .. \
    && cmake --build . --config Release --target install \
    && cd /build/modules \
    && git clone --depth=10 --recurse-submodules https://${RESTY_GIT_MIRROR}/weserv/images.git ngx_http_weserv_module \
    && cd ngx_http_weserv_module \
    && mkdir build \
    && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TOOLS=ON -DINSTALL_NGX_MODULE=OFF \
    && make -j${RESTY_J} \
    && make install \
    && cd /build/modules \
    && git clone --depth=10 --branch current https://${RESTY_GIT_MIRROR}/ADD-SP/ngx_waf.git ngx_http_waf_module \
    && cd ngx_http_waf_module \
    && patch -p1 < /build/patches/openresty/patches/ngx_http_waf_module-ext.patch \
    && git clone --depth=10 --branch v1.7.16 https://${RESTY_GIT_MIRROR}/DaveGamble/cJSON.git lib/cjson \
    && git clone --depth=10 --branch v2.3.0 https://${RESTY_GIT_MIRROR}/troydhanson/uthash.git lib/uthash \
    && cd /build/modules \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/winshining/nginx-http-flv-module.git ngx_http_flv_live_module \
    && cd ngx_http_flv_live_module \
    && patch -p1 < /build/patches/openresty/patches/ngx_http_flv_live_module-server_metadata.patch \
    && cd /build/modules \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/nginx-modules/ngx_cache_purge.git ngx_http_cache_purge_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_limit_traffic_rate_filter_module.git ngx_http_limit_traffic_rate_filter_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_access_control_module.git ngx_http_access_control_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_aws_auth_module.git ngx_http_aws_auth_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/leev/ngx_http_geoip2_module.git ngx_http_geoip2_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/vozlt/nginx-module-vts.git ngx_http_vhost_traffic_status_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/yaoweibin/nginx_upstream_check_module.git ngx_http_upstream_check_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_sorted_querystring_module.git ngx_http_sorted_querystring_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/openresty/replace-filter-nginx-module.git ngx_http_replace_filter_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_extra_variables_module.git ngx_http_extra_variables_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_lua_load_var_index_module.git ngx_http_lua_load_var_index_module \ 
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_zstd_module.git ngx_http_zstd_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_cache_dechunk_filter_module.git ngx_http_cache_dechunk_filter_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/chobits/ngx_http_proxy_connect_module.git ngx_http_proxy_connect_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_unbrotli_filter_module.git ngx_http_unbrotli_filter_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_delay_module.git ngx_http_delay_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_server_redirect_module.git ngx_http_server_redirect_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_internal_auth_module.git ngx_http_internal_auth_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_internal_redirect_module.git ngx_http_internal_redirect_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_upstream_log_module.git ngx_http_upstream_log_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_compress_normalize_module.git ngx_http_compress_normalize_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_compress_vary_filter_module.git ngx_http_compress_vary_filter_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_rewrite_status_filter_module.git ngx_http_rewrite_status_filter_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_var_module.git ngx_http_var_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_security_headers_module.git ngx_http_security_headers_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_secure_link_hash_module.git ngx_http_secure_link_hash_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_secure_link_hmac_module.git ngx_http_secure_link_hmac_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_cors_module.git ngx_http_cors_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_log_var_set_module.git ngx_http_log_var_set_module \
    && git clone --depth=10 https://${RESTY_GIT_REPO}/hanada/ngx_http_proxy_var_set_module.git ngx_http_proxy_var_set_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/vozlt/nginx-module-sysguard.git ngx_http_sysguard_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/Kong/lua-resty-events.git ngx_lua_events_module \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/alibaba/tengine.git tengine \
    && mv tengine/modules/ngx_backtrace_module ngx_backtrace_module \
    && mv tengine/modules/ngx_http_trim_filter_module ngx_http_trim_filter_module \
    && rm -rf tengine \
    && git clone --depth=10 https://${RESTY_GIT_MIRROR}/soulteary/ngx_http_qrcode_module.git ngx_http_qrcode_module_full \
    && mv ngx_http_qrcode_module_full/src ngx_http_qrcode_module \
    && rm -rf ngx_http_qrcode_module_full \
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
    && patch -p1 < /build/patches/openresty/patches/nginx-ext_1.27.1+.patch \
    && patch -p1 < /build/modules/ngx_http_upstream_log_module/ngx_http_upstream_log_1.25.3+.patch \
    && patch -p1 < /build/modules/ngx_http_upstream_check_module/check_1.20.1+.patch \
    && patch -p1 < /build/modules/ngx_http_proxy_connect_module/patch/proxy_connect_rewrite_102101.patch \
    && sed -i "s/\(openresty\/.*\)\"/\1-${RESTY_RELEASE}\"/" src/core/nginx.h \
    && cd /build/openresty-${RESTY_VERSION}/bundle/ngx_lua-* \
    && patch -p1 < /build/patches/openresty/patches/ngx_lua_module-remove_h2_subrequest.patch \
    && cd /build/openresty-${RESTY_VERSION} \
    && eval ./configure \
    ${RESTY_PATH_OPTIONS} \
    ${RESTY_USER_OPTIONS} \
    ${RESTY_CONFIG_OPTIONS} \
    --with-pcre \
    ${RESTY_PCRE_OPTIONS} \
    --with-libatomic \
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
    && cd /usr/local/openresty/lualib \
    && cp -r -d /usr/local/lib/lua/*.so* . \
    && cd /build \
    && curl -fSL https://luarocks.github.io/luarocks/releases/luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz -o luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && tar xzf luarocks-${RESTY_LUAROCKS_VERSION}.tar.gz \
    && cd luarocks-${RESTY_LUAROCKS_VERSION} \
    && ./configure \
        --prefix=/usr/local/openresty/luajit \
        --with-lua=/usr/local/openresty/luajit \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 \
    && make build \
    && make install \
    && cd /build/modules \
    && cp -r ngx_http_lua_load_var_index_module/lualib/resty/*.lua /usr/local/openresty/lualib/resty \
    && mkdir -p /usr/local/openresty/lualib/resty/events/compat \
    && cp -r ngx_lua_events_module/lualib/resty/events/*.lua /usr/local/openresty/lualib/resty/events \
    && cp -r ngx_lua_events_module/lualib/resty/events/compat/*.lua /usr/local/openresty/lualib/resty/events/compat \
    && cd /build/modules \
    && cd /build/lualib \
    && cp -r lua-resty-maxminddb/lib/resty/* /usr/local/openresty/lualib/resty \
    && cp -r lua-resty-multipart-parser/lib/resty/* /usr/local/openresty/lualib/resty \
    && cp -r lua-resty-balancer/lib/resty/* /usr/local/openresty/lualib/resty \
    && cp -r kong/kong/resty/ctx.lua /usr/local/openresty/lualib/resty \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-http \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-hmac-ffi \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-jwt \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc \
    && /usr/local/openresty/luajit/bin/luarocks install api7-lua-resty-dns-client \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-kafka \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-template \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-mlcache \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-jit-uuid \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-cookie \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-worker-events \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-healthcheck \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-expr \
    && /usr/local/openresty/luajit/bin/luarocks install lyaml \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-redis-connector \
    && /usr/local/openresty/luajit/bin/luarocks install api7-dkjson \
    && /usr/local/openresty/luajit/bin/luarocks install net-url \
    && /usr/local/openresty/luajit/bin/luarocks install luafilesystem \
    && /usr/local/openresty/luajit/bin/luarocks install jsonschema \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-ipmatcher \
    && /usr/local/openresty/luajit/bin/luarocks install binaryheap \
    && /usr/local/openresty/luajit/bin/luarocks install penlight \
    && /usr/local/openresty/luajit/bin/luarocks install xml2lua \
    && apt-get purge -y \
        libgd-dev \
        make \
        autoconf \
        automake \
        libtool \
        pkgconf \
        cmake \
        git \
        wget \
        unzip \
        bison \
        libglib2.0-dev \
        meson \
        libopenjp2-7-dev \
        libjxl-dev \
        libimagequant-dev \
        libarchive-dev \
        librsvg2-dev \
        libopenexr-dev \
        libcfitsio-dev \
        libcgif-dev \
        libexif-dev \
        liborc-0.4-dev \
        libfftw3-dev \
        libspng-dev \
        libreadline-dev \
        libxslt1-dev \
        libperl-dev \
        libncurses5-dev \
        libgd-dev \
        libyaml-dev \
        libheif-dev \
        libexpat1-dev \
        libffi-dev \
        libpng-dev \
        libtiff-dev \
        libwebp-dev \
        liblcms2-dev \
        flex \
        libmodsecurity-dev \
        libsodium-dev \
        libcurl4-openssl-dev \
    && DEBIAN_FRONTEND=noninteractive apt-get autoremove -y \
    && DEBIAN_FRONTEND=noninteractive apt-get clean -y \
    && rm -rf /build \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/* \
    && rm -rf /usr/local/share/man/man1/* \
    && rm -rf /usr/local/share/man/man3/* \
    && rm -rf /usr/local/share/doc/* \
    && rm -rf /usr/local/include/* \
    && rm -rf /usr/local/bin/* \
    && rm -rf /var/cache/* \
    && rm -rf /var/log/apt/* \
    && rm -rf /var/log/*.log \
    && rm -rf /tmp/* \
    && ldconfig

WORKDIR /usr/local/openresty

# Add additional binaries into PATH for convenience
ENV PATH=$PATH:/usr/local/openresty/luajit/bin/:/usr/local/openresty/sbin/:/usr/local/openresty/bin/
ENV LD_LIBRARY_PATH=/usr/local/openresty/lib/
ENV LUA_PATH="/usr/local/openresty/site/lualib/?.ljbc;/usr/local/openresty/site/lualib/?/init.ljbc;/usr/local/openresty/lualib/?.ljbc;/usr/local/openresty/lualib/?/init.ljbc;/usr/local/openresty/site/lualib/?.lua;/usr/local/openresty/site/lualib/?/init.lua;/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;./?.lua;/usr/local/openresty/luajit/share/luajit-2.1/?.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;/usr/local/openresty/luajit/share/lua/5.1/?.lua;/usr/local/openresty/luajit/share/lua/5.1/?/init.lua"
ENV LUA_CPATH="/usr/local/openresty/site/lualib/?.so;/usr/local/openresty/lualib/?.so;./?.so;/usr/local/lib/lua/5.1/?.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/loadall.so;/usr/local/openresty/luajit/lib/lua/5.1/?.so"


COPY nginx.conf /usr/local/openresty/etc/nginx.conf
COPY nginx.vh.default.conf /usr/local/openresty/etc/conf.d/default.conf

CMD ["/usr/local/openresty/sbin/nginx", "-p", "/usr/local/openresty/", "-g", "daemon off;"]

# Use SIGQUIT instead of default SIGTERM to cleanly drain requests
# See https://github.com/openresty/docker-openresty/blob/master/README.md#tips--pitfalls
STOPSIGNAL SIGQUIT
