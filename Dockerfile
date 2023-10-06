FROM dockerhub.hanada.info/library/ubuntu:20.04

WORKDIR /build/openresty

COPY . ./

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.hanada.info@g' /etc/apt/sources.list && \
    sed -i 's@//security.ubuntu.com@//mirrors.hanada.info@g' /etc/apt/sources.list && \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git \
        curl \
        libpcre3-dev \
        libssl-dev \
        perl \
        make \
        build-essential \
        libxml2 \
        libxml2-dev \
        libxslt-dev \
        aptitude && \
    aptitude install -y --without-recommends libgd-dev && \
    cd /build/openresty/lib/jemalloc-5.3.0 && \
    ./configure && \
    make \
        EXTRA_CXXFLAGS="-Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC" \
        EXTRA_CFLAGS="-Wformat -Werror=format-security -Wno-missing-attributes -Wno-unused-variable -fstack-protector-strong -ffunction-sections -fdata-sections -fPIC" && \
    make install && \
    ldconfig && \
    cd /build/openresty/lib/libmaxminddb-1.7.1 && \
    ./configure && \
    make && \
    make check && \
    make install && \
    ldconfig && \
    cd /build/openresty/lib/sregex && \
    make && \
    make install && \
    cd /build/openresty/lib/libatomic_ops-7.8.0/src && \
    ln -s -f ./.libs/libatomic_ops.a . && \
    cd /build/openresty/bundle/nginx-1.21.4 && \
    patch -p1 < /build/openresty/patches/x_request_id_1.21.4+.patch && \
    patch -p1 < /build/openresty/patches/nginx__dynamic_tls_records_1.17.7+.patch && \
    patch -p1 < /build/openresty/modules/ngx_http_upstream_check_module/check_1.20.1+.patch && \
    cd /build/openresty/modules/ngx_brotli && \
    git submodule update --init && \
    cd /build/openresty && \
    ./configure \
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
        --with-ld-opt='-Wl,-rpath,/usr/local/openresty/lib -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--no-whole-archive -Wl,--gc-sections -pie -ljemalloc -Wl,-Bdynamic -lm -lstdc++ -pthread -ldl -Wl,-E' && \
    make && \
    make install && \
    mv /usr/local/openresty/nginx/html /usr/local/openresty && \
    rm -rf /usr/local/openresty/nginx && \
    mkdir -p /usr/local/openresty/var/lib/tmp && \
    mkdir -p /usr/local/openresty/cache && \
    cd /usr/local/openresty/cache && \
    mkdir fastcgi proxy scgi uwsgi && \
    mkdir -p /usr/local/openresty/lib && \
    cd /usr/local/openresty/lib && \
    cp -d /usr/local/lib/* . && \
    rm *.a *.la && \
    cd /usr/local/openresty/lualib && \
    ln -s ../lib/libmaxminddb.so . && \
    cp -rfp /build/openresty/lualib /build/openresty/systemd /usr/local/openresty


WORKDIR /usr/local/openresty

ENV PATH=$PATH:/usr/local/openresty/luajit/bin/:/usr/local/openresty/nginx/sbin/:/usr/local/openresty/bin/

CMD [ "/usr/local/openresty/sbin/nginx", "-g", "daemon off;"]





