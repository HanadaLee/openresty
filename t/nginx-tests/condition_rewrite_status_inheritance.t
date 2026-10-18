#!/usr/bin/perl

# Nearest matching status rule, without cascading rewrites.

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_expr_module
    ngx_http_rewrite_status_filter_module/)->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr no bool false;
    expr selected str_eq $arg_mode yes;
    expr original str_eq $status 201;
    when original { rewrite_status 203; }
    server {
        listen 127.0.0.1:8080;
        when no { rewrite_status 404; }
        location = /absent { return 201 body; }
        location = /conditional {
            when selected { rewrite_status 202; }
            return 201 body;
        }
        location = /same {
            when selected { rewrite_status 201; }
            return 201 body;
        }
        location = /ordered {
            when selected { rewrite_status 202; }
            rewrite_status 206;
            rewrite_status 418;
            return 201 body;
        }
        location = /unchanged { return 200 body; }
        location /parent/ {
            when no { rewrite_status 404; }
            location = /parent/child {
                when no { rewrite_status 418; }
                return 201 body;
            }
        }
        location = /redefined {
            expr original bool true;
            return 200 body;
        }
    }
}
EOF
$t->run();

sub status {
    my ($uri, $code, $label) = @_;
    like(http_get($uri), qr/^HTTP\/1\.[01] $code /, $label);
}
status('/absent', 203, 'absent child and inactive server inherit http rule');
status('/conditional', 203, 'miss falls back to parent');
status('/conditional?mode=yes', 202, 'hit prevents cascading parent rewrite');
status('/same?mode=yes', 201, 'same target still blocks parent');
status('/same', 203, 'same target rule miss inherits');
status('/ordered?mode=yes', 202, 'first matching local rule wins');
status('/ordered', 206, 'unconditional local fallback blocks parent');
status('/unchanged', 200, 'all levels miss leaves status unchanged');
status('/parent/child', 203, 'multiple inactive levels fall through');
status('/redefined', 203, 'parent rules use current expression definitions');
status('/conditional', 203, 'repeat request does not retain previous selection');
