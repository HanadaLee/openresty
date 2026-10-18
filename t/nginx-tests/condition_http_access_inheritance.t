#!/usr/bin/perl

# Conditional rule groups and access_inherit ordering.

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http rewrite access ngx_expr_module
    ngx_http_access_control_module/)->plan(23);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr yes bool true;
    expr no bool false;
    expr selected str_eq $arg_mode yes;
    access deny;

    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        when no { access allow; }

        location = /absent { alias %%TESTDIR%%/ok; }
        location = /miss {
            when selected { access allow; }
            alias %%TESTDIR%%/ok;
        }
        location = /predicate {
            when selected { access allow $arg_allow; }
            alias %%TESTDIR%%/ok;
        }
        location = /off {
            access_inherit off;
            when no { access deny; }
            alias %%TESTDIR%%/ok;
        }
        location = /before {
            access_inherit before;
            access allow;
            alias %%TESTDIR%%/ok;
        }
        location = /after {
            access_inherit after;
            when selected { access allow $arg_allow; }
            alias %%TESTDIR%%/ok;
        }
        location = /status {
            access_deny_status 401;
            when selected { access_deny_status 418; }
            alias %%TESTDIR%%/ok;
        }
        location /parent/ {
            access_inherit off;
            when selected { access deny; }
            location = /parent/child {
                access_inherit before;
                access allow;
                alias %%TESTDIR%%/ok;
            }
        }
        location /allow/ {
            access allow;
            location = /allow/before {
                access_inherit before;
                access deny;
                alias %%TESTDIR%%/ok;
            }
        }
        location = /other-access {
            satisfy any;
            access allow;
            deny all;
            alias %%TESTDIR%%/ok;
        }
        location = /methods {
            access allow;
            alias %%TESTDIR%%/ok;
            limit_except GET { access deny; }
        }
        location /redefined/ {
            expr selected bool false;
            when selected { access deny; }
            location = /redefined/child {
                expr selected bool true;
                alias %%TESTDIR%%/ok;
            }
        }
    }
}
EOF

$t->write_file('ok', 'ok');
$t->run();

sub status {
    my ($uri, $code, $label) = @_;
    like(http_get($uri), qr/^HTTP\/1\.[01] $code /, $label);
}

status('/absent', 403, 'absent child traverses all-miss server');
status('/miss', 403, 'all local conditions miss: inherit deny');
status('/miss?mode=yes', 200, 'local when hit overrides parent deny');
status('/predicate', 403, 'inactive predicate group inherits deny');
status('/predicate?mode=yes', 200, 'active group with empty predicate blocks parent');
status('/predicate?mode=yes&allow=0', 200, 'zero predicate is not an inheritance miss');
status('/predicate?mode=yes&allow=00', 200, 'double zero is true');
status('/off', 200, 'off blocks parent even when every local condition misses');
status('/before', 403, 'before includes effective grandparent deny');
status('/after', 403, 'after consults parent on when miss');
status('/after?mode=yes&allow=0', 403, 'after consults parent on predicate miss');
status('/after?mode=yes&allow=1', 200, 'allow terminates after traversal');
status('/status', 401, 'inherited deny uses current location status');
status('/status?mode=yes', 418, 'inherited deny uses current conditional status');
status('/parent/child', 200, 'parent off is respected during before traversal');
status('/parent/child?mode=yes', 403, 'parent active deny wins before child');
status('/allow/before', 200, 'parent allow is not confused with no decision');
status('/other-access', 403, 'allow does not bypass other access handlers');
status('/methods', 200, 'GET uses outer rules');
like(http('POST /methods HTTP/1.0' . "\r\nContent-Length: 0\r\n\r\n"),
    qr/^HTTP\/1\.[01] 403 /, 'limit_except has its own rules');
status('/redefined/child', 403, 'inherited rules use current expression definition');
status('/miss?mode=yes', 200, 'hit after miss does not mutate configuration');
status('/miss', 403, 'miss after hit still inherits');
