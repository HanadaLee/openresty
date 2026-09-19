#!/usr/bin/perl

# Tests for condition-aware directives sharing the http upstream configuration.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http cache fastcgi uwsgi scgi grpc
	memcached tunnel http_ssl ngx_condition_module/)->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream drizzle_backend {
        drizzle_server 127.0.0.1:1 dbname=test user=test password=test
            protocol=mysql;
    }

    upstream postgres_backend {
        postgres_server 127.0.0.1:1 dbname=test user=test password=test;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        condition enabled str_in $http_x_case enabled;

        location /fastcgi {
            when enabled {
                fastcgi_buffering off;
                fastcgi_request_buffering off;
                fastcgi_ignore_client_abort on;
                fastcgi_connect_timeout 1s;
                fastcgi_send_timeout 1s;
                fastcgi_read_timeout 1s;
                fastcgi_force_ranges on;
                fastcgi_limit_rate 1k;
                fastcgi_cache_max_range_offset 1k;
                fastcgi_cache_methods POST;
                fastcgi_cache_use_stale error;
                fastcgi_cache_lock on;
                fastcgi_cache_lock_age 1s;
                fastcgi_cache_lock_timeout 1s;
                fastcgi_cache_background_update on;
                fastcgi_cache_min_uses 2;
                fastcgi_cache_min_length 1k;
                fastcgi_cache_max_length 1m;
                fastcgi_cache_vary off;
                fastcgi_cache_hide_cookies on;
                fastcgi_ignore_cache_control no-store;
                fastcgi_hide_cookie secret;
                fastcgi_pass_request_headers on;
                fastcgi_pass_request_body on;
                fastcgi_next_upstream error;
                fastcgi_next_upstream_timeout 1s;
                fastcgi_next_upstream_tries 2;
                fastcgi_ignore_headers X-Accel-Redirect;
            }

            fastcgi_pass 127.0.0.1:8091;
        }

        location /uwsgi {
            when enabled {
                uwsgi_buffering off;
                uwsgi_request_buffering off;
                uwsgi_ignore_client_abort on;
                uwsgi_connect_timeout 1s;
                uwsgi_send_timeout 1s;
                uwsgi_read_timeout 1s;
                uwsgi_force_ranges on;
                uwsgi_limit_rate 1k;
                uwsgi_cache_max_range_offset 1k;
                uwsgi_cache_methods POST;
                uwsgi_cache_use_stale error;
                uwsgi_cache_lock on;
                uwsgi_cache_lock_age 1s;
                uwsgi_cache_lock_timeout 1s;
                uwsgi_cache_background_update on;
                uwsgi_cache_min_uses 2;
                uwsgi_cache_min_length 1k;
                uwsgi_cache_max_length 1m;
                uwsgi_cache_vary off;
                uwsgi_cache_hide_cookies on;
                uwsgi_ignore_cache_control no-store;
                uwsgi_hide_cookie secret;
                uwsgi_pass_request_headers on;
                uwsgi_pass_request_body on;
                uwsgi_next_upstream error;
                uwsgi_next_upstream_timeout 1s;
                uwsgi_next_upstream_tries 2;
                uwsgi_ignore_headers X-Accel-Redirect;
                uwsgi_ssl_name condition.example;
                uwsgi_ssl_server_name on;
            }

            uwsgi_pass 127.0.0.1:8092;
        }

        location /scgi {
            when enabled {
                scgi_buffering off;
                scgi_request_buffering off;
                scgi_ignore_client_abort on;
                scgi_connect_timeout 1s;
                scgi_send_timeout 1s;
                scgi_read_timeout 1s;
                scgi_force_ranges on;
                scgi_limit_rate 1k;
                scgi_cache_max_range_offset 1k;
                scgi_cache_methods POST;
                scgi_cache_use_stale error;
                scgi_cache_lock on;
                scgi_cache_lock_age 1s;
                scgi_cache_lock_timeout 1s;
                scgi_cache_background_update on;
                scgi_cache_min_uses 2;
                scgi_cache_min_length 1k;
                scgi_cache_max_length 1m;
                scgi_cache_vary off;
                scgi_cache_hide_cookies on;
                scgi_ignore_cache_control no-store;
                scgi_hide_cookie secret;
                scgi_pass_request_headers on;
                scgi_pass_request_body on;
                scgi_next_upstream error;
                scgi_next_upstream_timeout 1s;
                scgi_next_upstream_tries 2;
                scgi_ignore_headers X-Accel-Redirect;
            }

            scgi_pass 127.0.0.1:8093;
        }

        location /grpc {
            when enabled {
                grpc_connect_timeout 1s;
                grpc_send_timeout 1s;
                grpc_read_timeout 1s;
                grpc_next_upstream error;
                grpc_next_upstream_timeout 1s;
                grpc_next_upstream_tries 2;
                grpc_ignore_headers X-Accel-Redirect;
                grpc_ssl_name condition.example;
                grpc_ssl_server_name on;
            }

            grpc_pass grpc://127.0.0.1:8094;
        }

        location /memcached {
            set $memcached_key key;

            when enabled {
                memcached_connect_timeout 1s;
                memcached_send_timeout 1s;
                memcached_read_timeout 1s;
                memcached_next_upstream error;
                memcached_next_upstream_timeout 1s;
                memcached_next_upstream_tries 2;
            }

            memcached_pass 127.0.0.1:8095;
        }

        location /redis {
            set $redis_key key;

            when enabled {
                redis_connect_timeout 1s;
                redis_send_timeout 1s;
                redis_read_timeout 1s;
                redis_next_upstream error timeout;
                redis_next_upstream_timeout 1s;
                redis_next_upstream_tries 2;
            }

            redis_pass 127.0.0.1:1;
        }

        location /redis2 {
            when enabled {
                redis2_connect_timeout 1s;
                redis2_send_timeout 1s;
                redis2_read_timeout 1s;
                redis2_next_upstream error timeout;
            }

            redis2_query get key;
            redis2_pass 127.0.0.1:1;
        }

        location /drizzle {
            when enabled {
                drizzle_connect_timeout 1s;
                drizzle_send_query_timeout 1s;
            }

            drizzle_query "select 1";
            drizzle_pass drizzle_backend;
        }

        location /postgres {
            when enabled {
                postgres_connect_timeout 1s;
                postgres_result_timeout 1s;
            }

            postgres_query "select 1";
            postgres_pass postgres_backend;
        }
    }

    server {
        listen       127.0.0.1:8087;
        server_name  localhost;

        condition enabled str_in $http_x_case enabled;

        when enabled {
            tunnel_connect_timeout 1s;
            tunnel_send_timeout 1s;
            tunnel_read_timeout 1s;
            tunnel_next_upstream error;
            tunnel_next_upstream_timeout 1s;
            tunnel_next_upstream_tries 2;
        }

        tunnel_pass 127.0.0.1:8096;
    }
}

EOF

$t->run();

###############################################################################

like(request('/fastcgi'), qr/502 Bad Gateway/, 'fastcgi condition path');
like(request('/uwsgi'), qr/502 Bad Gateway/, 'uwsgi condition path');
like(request('/scgi'), qr/502 Bad Gateway/, 'scgi condition path');
like(request('/grpc'), qr/502 Bad Gateway/, 'grpc condition path');
like(request('/memcached'), qr/502 Bad Gateway/,
	'memcached condition path');
like(request('/redis'), qr/502 Bad Gateway/, 'redis condition path');
like(request('/redis2'), qr/502 Bad Gateway/, 'redis2 condition path');
like(request('/drizzle'), qr/502 Bad Gateway/, 'drizzle condition path');
like(request('/postgres'), qr/502 Bad Gateway/, 'postgres condition path');

my $tunnel = http(<<'EOF', PeerAddr => '127.0.0.1:' . port(8087));
CONNECT 127.0.0.1:8096 HTTP/1.1
Host: 127.0.0.1:8096
X-Case: enabled
Connection: close

EOF

like($tunnel, qr/502 Bad Gateway/, 'tunnel condition path');

pass('all shared upstream directives accepted in when');

###############################################################################

sub request {
	my ($uri) = @_;
	return http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
X-Case: enabled
Connection: close

EOF
}

###############################################################################
