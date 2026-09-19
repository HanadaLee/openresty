#!/usr/bin/perl

# Tests for the patched default CDN identifier in ngx_http_loop_detect_module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http ngx_http_loop_detect_module/)
	->plan(4);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /default {
            loop_detect on;
            loop_detect_max_allow_loops 2;
            add_header X-Loop
                "$loop_detect_current_loops|$loop_detect_proxy_add_cdn_loop";
            alias %%TESTDIR%%/ok;
        }
    }
}

EOF

$t->write_file('ok', 'ok');
$t->run();

###############################################################################

is(loop_value(http_get('/default')), '0|openresty; loops=1',
	'default identifier starts a new OpenResty loop entry');
is(loop_value(cdn_get('openresty; loops=1')),
	'1|openresty; loops=2',
	'default identifier recognizes an existing OpenResty entry');
is(loop_value(cdn_get('nginx; loops=99')),
	'0|openresty; loops=1, nginx; loops=99',
	'former default identifier is preserved as a foreign entry');
like(cdn_get('openresty; loops=3'), qr/508 /,
	'default identifier participates in loop rejection');

###############################################################################

sub cdn_get {
	my ($value) = @_;
	return http(<<EOF);
GET /default HTTP/1.0
Host: localhost
CDN-Loop: $value

EOF
}

sub loop_value {
	my ($response) = @_;
	$response =~ /^X-Loop:\s*(.+?)\x0d?$/mi;
	return $1;
}

###############################################################################
