#!/usr/bin/perl

# Tests for condition-aware HTTP and Stream access_log directives.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http stream stream_return ngx_expr_module/)
	->plan(10);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format condition_test '$uri:$status';

    expr h_true bool true;
    expr h_false bool false;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /hit {
            when h_true {
                access_log off;
            }

            access_log %%TESTDIR%%/http-hit.log condition_test;
            return 204;
        }

        location = /miss {
            when h_false {
                access_log off;
            }

            access_log %%TESTDIR%%/http-miss.log condition_test;
            return 204;
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    log_format condition_test '$remote_addr';

    expr s_true bool true;
    expr s_false bool false;

    server {
        listen  127.0.0.1:8081;

        when s_true {
            access_log off;
        }

        access_log %%TESTDIR%%/stream-hit.log condition_test;
        return hit;
    }

    server {
        listen  127.0.0.1:8082;

        when s_false {
            access_log off;
        }

        access_log %%TESTDIR%%/stream-miss.log condition_test;
        return miss;
    }

    server {
        listen  127.0.0.1:8083;

        access_log off;
        access_log %%TESTDIR%%/stream-always-off.log condition_test;
        return always-off;
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/hit'), qr/^HTTP\/1\.1 204/, 'HTTP matched access_log off');
like(http_get('/miss'), qr/^HTTP\/1\.1 204/, 'HTTP missed access_log off');
is(stream('127.0.0.1:' . port(8081))->read(), 'hit',
    'Stream matched access_log off');
is(stream('127.0.0.1:' . port(8082))->read(), 'miss',
    'Stream missed access_log off');
is(stream('127.0.0.1:' . port(8083))->read(), 'always-off',
    'Stream unconditional access_log off');

$t->stop();

is($t->read_file('http-hit.log'), '',
    'HTTP matched access_log off suppresses logging');
is($t->read_file('http-miss.log'), "/miss:204\n",
    'HTTP missed access_log off preserves logging');
is($t->read_file('stream-hit.log'), '',
    'Stream matched access_log off suppresses logging');
is($t->read_file('stream-miss.log'), "127.0.0.1\n",
    'Stream missed access_log off preserves logging');
is($t->read_file('stream-always-off.log'), '',
    'Stream unconditional access_log off suppresses logging');

###############################################################################
