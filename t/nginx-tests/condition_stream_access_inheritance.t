#!/usr/bin/perl

# Stream conditional rule groups and access_inherit ordering.

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;
use Test::Nginx::Stream qw/stream/;

my $t = Test::Nginx->new()->has(qw/stream stream_return stream_access
    ngx_expr_module ngx_stream_access_control_module/)->plan(15);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
stream {
    %%TEST_GLOBALS_STREAM%%
    expr yes bool true;
    expr no bool false;
    expr selected bool false;
    when selected { access allow; }
    access deny;

    server {
        listen 127.0.0.1:8100;
        return ok;
    }
    server {
        listen 127.0.0.1:8101;
        when no { access allow; }
        return ok;
    }
    server {
        listen 127.0.0.1:8102;
        when yes { access allow; }
        return ok;
    }
    server {
        listen 127.0.0.1:8103;
        when yes { access allow ""; }
        return ok;
    }
    server {
        listen 127.0.0.1:8104;
        when yes { access allow 0; }
        return ok;
    }
    server {
        listen 127.0.0.1:8105;
        access_inherit off;
        when no { access deny; }
        return ok;
    }
    server {
        listen 127.0.0.1:8106;
        access_inherit before;
        access allow;
        return ok;
    }
    server {
        listen 127.0.0.1:8107;
        access_inherit after;
        access allow;
        return ok;
    }
    server {
        listen 127.0.0.1:8108;
        access_inherit after;
        access allow 0;
        return ok;
    }
    server {
        listen 127.0.0.1:8109;
        access_inherit after;
        access allow 00;
        return ok;
    }
    server {
        listen 127.0.0.1:8110;
        expr selected bool true;
        access_inherit before;
        access deny;
        return ok;
    }
    server {
        listen 127.0.0.1:8111;
        access allow;
        deny all;
        return ok;
    }
    server {
        listen 127.0.0.1:8112;
        access_inherit after;
        when no { access allow; }
        return ok;
    }
}
EOF
$t->run();

sub response { return stream('127.0.0.1:' . port(shift))->read(); }
is(response(8100), '', 'absent local rules inherit deny');
is(response(8101), '', 'all when miss inherit deny');
is(response(8102), 'ok', 'active local group overrides deny');
is(response(8103), 'ok', 'empty predicate still selects local group');
is(response(8104), 'ok', 'zero predicate still selects local group');
is(response(8105), 'ok', 'off blocks parent on miss');
is(response(8106), '', 'before parent deny wins');
is(response(8107), 'ok', 'after local allow stops traversal');
is(response(8108), '', 'after false predicate continues to parent');
is(response(8109), 'ok', 'double zero predicate matches');
is(response(8110), 'ok', 'parent allow stops traversal using current expression');
is(response(8111), '', 'allow does not skip native access module');
is(response(8112), '', 'after when miss continues to parent');
is(response(8102), 'ok', 'repeat hit is independent');
is(response(8101), '', 'repeat miss is independent');
