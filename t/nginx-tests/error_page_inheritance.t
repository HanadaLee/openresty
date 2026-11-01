#!/usr/bin/perl

# Copyright (C) Hanada

# Error page inheritance with no_error_pages and conditional mappings.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http rewrite proxy/);
my $expr = $t->has_module('ngx_expr_module');

plan 'no_plan';

my $conditional = $expr ? <<'EOF' : '';
        location /disabled/conditional {
            when selected { error_page 404 = @local; }
            return 404;
        }
EOF

my $sparse = $expr ? <<'EOF' : '';
        when selected { error_page 404 = @local; }
        location @local { return 200 local; }
EOF

my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    %%EXPR%%
    server {
        listen 127.0.0.1:8080;
        server_name inherited;
        error_page 404 = @parent;
        location @parent { return 200 parent; }
        location @local { return 200 local; }
        location /inherited { return 404; }
        location /disabled/ {
            no_error_pages;
            return 404;
            location /disabled/child { return 404; }
            location /disabled/local {
                error_page 404 = @local;
                return 404;
            }
            %%CONDITIONAL%%
        }
        location /upstream {
            no_error_pages;
            proxy_intercept_errors on;
            proxy_pass http://127.0.0.1:8081;
        }
    }
    server {
        listen 127.0.0.1:8080;
        server_name sparse;
        %%SPARSE%%
        location / { return 404; }
    }
    server {
        listen 127.0.0.1:8081;
        location / { return 404 upstream; }
    }
}
EOF

my $declaration = $expr ? 'expr selected str_eq $arg_mode yes;' : '';
$config =~ s/%%EXPR%%/$declaration/;
$config =~ s/%%CONDITIONAL%%/$conditional/;
$config =~ s/%%SPARSE%%/$sparse/;

$t->write_file_expand('nginx.conf', $config);
$t->run();

like(http_get('/inherited'), qr/\r\n\r\nparent\z/,
    'inherit server error page');
like(http_get('/disabled/'), qr/^HTTP\/1\.[01] 404 /,
    'no_error_pages blocks parent');
like(http_get('/disabled/child'), qr/^HTTP\/1\.[01] 404 /,
    'child inherits disabled error pages');
like(http_get('/disabled/local'), qr/\r\n\r\nlocal\z/,
    'child can define its own error page');
like(http_get('/upstream'), qr/\r\n\r\nupstream\z/,
    'no_error_pages blocks upstream interception');
like(http("GET / HTTP/1.0\r\nHost: sparse\r\n\r\n"),
    qr/^HTTP\/1\.[01] 404 /, 'unset main error pages are safe');

if ($expr) {
    like(http_get('/disabled/conditional'), qr/^HTTP\/1\.[01] 404 /,
        'conditional miss respects disabled parent');
    like(http_get('/disabled/conditional?mode=yes'), qr/\r\n\r\nlocal\z/,
        'conditional match overrides disabled parent');
    like(http("GET /?mode=yes HTTP/1.0\r\nHost: sparse\r\n\r\n"),
        qr/\r\n\r\nlocal\z/, 'conditional mapping with unset main error pages');
}

$t->stop();

for my $directives (
    'no_error_pages; error_page 404 /fallback;',
    'error_page 404 /fallback; no_error_pages;',
    'no_error_pages; no_error_pages;'
) {
    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        $directives
    }
}
EOF
    my $output = $t->dump_config();
    isnt($?, 0, 'reject conflicting or duplicate directives');
    like($output, qr/conflicts with|is duplicate/, 'configuration diagnosis');
}
