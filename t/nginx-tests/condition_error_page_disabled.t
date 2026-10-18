#!/usr/bin/perl

# OpenResty's no_error_pages explicitly cuts off conditional inheritance.

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http rewrite proxy ngx_expr_module/)->plan(5);
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr no bool false;
    error_page 404 502 = @parent;
    server {
        listen 127.0.0.1:8080;
        no_error_pages;
        location @parent { return 200 parent; }
        location @local { return 200 local; }
        location = /absent { return 404; }
        location = /miss {
            when no { error_page 404 = @local; }
            return 404;
        }
        location = /local {
            error_page 404 = @local;
            return 404;
        }
        location = /upstream {
            when no { error_page 502 = @local; }
            proxy_intercept_errors on;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /off {
            no_error_pages;
            return 404;
        }
    }
    server {
        listen 127.0.0.1:8081;
        error_page 404 /unused;
        location / { return 502 upstream; }
    }
}
EOF
$t->run();
like(http_get('/absent'), qr/^HTTP\/1\.[01] 404 /, 'parent disables inheritance');
like(http_get('/miss'), qr/^HTTP\/1\.[01] 404 /, 'miss stops at disabled parent');
like(http_get('/local'), qr/\r\n\r\nlocal\z/, 'child can define a new group');
like(http_get('/upstream'), qr/\r\n\r\nupstream\z/, 'upstream respects disabled parent');
like(http_get('/off'), qr/^HTTP\/1\.[01] 404 /, 'explicit local disable');
