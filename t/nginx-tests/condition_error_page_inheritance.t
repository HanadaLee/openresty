#!/usr/bin/perl

# Dynamic whole-group error_page inheritance, including upstream interception.

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http rewrite proxy ngx_expr_module/)->plan(21);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr no bool false;
    expr selected str_eq $arg_mode yes;
    error_page 404 502 = @parent;
    server {
        listen 127.0.0.1:8080;
        when no { error_page 404 = @inactive; }
        location @parent { return 200 parent; }
        location @local { return 200 local; }
        location @inactive { return 200 inactive; }
        location @method { return 200 "$request_method:$args"; }
        location = /uri-target { return 200 "$request_method:$args"; }
        location = /absent { return 404; }
        location = /conditional {
            when selected { error_page 404 = @local; }
            return 404;
        }
        location = /different {
            when selected { error_page 500 = @local; }
            return 404;
        }
        location = /unconditional {
            error_page 500 = @local;
            return 404;
        }
        location = /ordered {
            when selected { error_page 404 = @local; }
            error_page 404 = @parent;
            return 404;
        }
        location /nested/ {
            when no { error_page 404 = @inactive; }
            location = /nested/child {
                when no { error_page 404 = @inactive; }
                return 404;
            }
        }
        location = /named {
            when selected { error_page 404 = @method; }
            return 404;
        }
        location = /uri {
            when selected { error_page 404 = /uri-target?target=yes; }
            return 404;
        }
        location = /override {
            error_page 404 =201 /uri-target;
            return 404;
        }
        location = /failed-target {
            when selected { error_page 404 = /missing-target; }
            return 404;
        }
        location = /missing-target { return 500; }
        location = /upstream {
            when selected { error_page 502 = @local; }
            proxy_intercept_errors on;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /upstream-different {
            when selected { error_page 500 = @local; }
            proxy_intercept_errors on;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /upstream-status {
            expr bad_gateway str_eq $upstream_status 502;
            when bad_gateway { error_page 502 = @local; }
            proxy_intercept_errors on;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /upstream-disabled {
            proxy_intercept_errors off;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /redefined {
            expr no bool true;
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

sub body {
    my ($uri, $body, $label) = @_;
    like(http_get($uri), qr/\r\n\r\n\Q$body\E\z/, $label);
}
body('/absent', 'parent', 'absent child traverses inactive server');
body('/conditional', 'parent', 'local miss inherits');
body('/conditional?mode=yes', 'local', 'local hit replaces parent group');
body('/different', 'parent', 'different status with inactive condition inherits');
like(http_get('/different?mode=yes'), qr/^HTTP\/1\.[01] 404 /,
    'active group without matching status does not inherit');
like(http_get('/unconditional'), qr/^HTTP\/1\.[01] 404 /,
    'unconditional other status blocks parent');
body('/ordered?mode=yes', 'local', 'first matching local mapping wins');
body('/ordered', 'parent', 'same-level unconditional mapping remains available');
body('/nested/child', 'parent', 'multiple inactive levels fall through');
like(http("POST /named?mode=yes HTTP/1.0\r\nContent-Length: 0\r\n\r\n"),
    qr/\r\n\r\nPOST:mode=yes\z/, 'named target preserves method and arguments');
like(http("POST /uri?mode=yes HTTP/1.0\r\nContent-Length: 0\r\n\r\n"),
    qr/\r\n\r\nGET:target=yes\z/, 'URI target changes method and arguments');
like(http_get('/override'), qr/^HTTP\/1\.[01] 201 /, 'explicit response override');
like(http_get('/failed-target?mode=yes'), qr/^HTTP\/1\.[01] 500 /,
    'target failure does not fall back to parent mapping');
body('/upstream', 'parent', 'upstream interception inherits on miss');
body('/upstream?mode=yes', 'local', 'upstream interception uses local hit');
body('/upstream-different', 'parent', 'upstream other-status miss inherits');
body('/upstream-different?mode=yes', 'upstream',
    'upstream active other-status group blocks parent');
body('/upstream-status', 'local', 'upstream status condition in both consumers');
body('/upstream-disabled', 'upstream', 'interception remains disabled');
body('/redefined', 'inactive', 'parent mapping uses current expression definition');
body('/conditional', 'parent', 'subsequent request chooses group independently');
