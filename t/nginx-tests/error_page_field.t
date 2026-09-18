#!/usr/bin/perl

# Tests for the NGX_RESTY_EXT error_page_field directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(21)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    error_page_format json;
    error_page_field uri $uri;
    error_page_field missing $arg_missing;

    server {
        listen       127.0.0.1:8080;
        server_name  inherited.example;

        location /inherit {
            return 403;
        }

        location /override {
            error_page_field method $request_method;
            error_page_field value $http_x_field;
            return 403;
        }

        location /xml {
            error_page_format xml;
            error_page_field value $http_x_field;
            error_page_field missing $arg_missing;
            return 403;
        }

        location /html {
            error_page_format default;
            error_page_field value $http_x_field;
            error_page_field missing $arg_missing;
            return 403;
        }

        location /parent {
            error_page_field parent $uri;

            location = /parent/child {
                return 403;
            }
        }

        location /redirect {
            return 301 /target;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  server.example;

        error_page_field server_name $server_name;

        location / {
            return 403;
        }
    }
}

EOF

$t->run();

###############################################################################

my $inherited = http_get('/inherit');
like(http_body($inherited), qr/"uri": "\/inherit", "missing": "-"\}$/,
	'location inherits fields and missing variable uses a dash');
unlike(http_body($inherited),
	qr/"date"|"client_ip"|"server"|"request_id"/,
	'configured fields omit legacy fields');
is(response_length($inherited), length(http_body($inherited)),
	'inherited fields content length');

my $empty = http_get('/inherit?missing=');
like(http_body($empty), qr/"uri": "\/inherit", "missing": "-"\}$/,
	'json empty variable uses a dash');

my $override = http(
	"GET /override HTTP/1.0\r\n"
	. "Host: localhost\r\n"
	. "X-Field: test\"value\\path&x\r\n"
	. "\r\n"
);
like(http_body($override),
	qr/"method": "GET", "value": "test\\"value\\\\path&x"\}$/,
	'location fields use and escape variables');
unlike(http_body($override), qr/"uri"|"missing"/,
	'location fields replace inherited fields');
is(response_length($override), length(http_body($override)),
	'location fields content length');

my $xml = http(
	"GET /xml HTTP/1.0\r\n"
	. "Host: localhost\r\n"
	. "X-Field: xml&<>\r\n"
	. "\r\n"
);
like(http_body($xml), qr/<value>xml&amp;&lt;&gt;<\/value>/,
	'xml field value is escaped');
like(http_body($xml), qr/<missing>-<\/missing>/,
	'xml missing variable uses a dash');
unlike(http_body($xml), qr/<uri>/,
	'xml location fields replace inherited fields');
is(response_length($xml), length(http_body($xml)),
	'xml fields content length');

my $xml_empty = http_get('/xml?missing=');
like(http_body($xml_empty), qr/<missing>-<\/missing>/,
	'xml empty variable uses a dash');

my $html = http(
	"GET /html HTTP/1.0\r\n"
	. "Host: localhost\r\n"
	. "X-Field: html&<>\r\n"
	. "\r\n"
);
like(http_body($html), qr/<td>value<\/td>\r?\n<td>html&amp;&lt;&gt;<\/td>/,
	'html field name and value are rendered');
like(http_body($html), qr/<td>missing<\/td>\r?\n<td>-<\/td>/,
	'html missing variable uses a dash');
unlike(http_body($html),
	qr/<td>Date<\/td>|<td>Client IP<\/td>|<td>Server<\/td>|
		<td>Request ID<\/td>/,
	'html configured fields omit legacy fields');
is(response_length($html), length(http_body($html)),
	'html fields content length');

my $html_empty = http_get('/html?missing=');
like(http_body($html_empty), qr/<td>missing<\/td>\r?\n<td>-<\/td>/,
	'html empty variable uses a dash');

my $nested = http_get('/parent/child');
like(http_body($nested), qr/"parent": "\/parent\/child"\}$/,
	'nested location inherits parent location fields');
unlike(http_body($nested), qr/"uri"|"missing"/,
	'nested location does not inherit replaced http fields');

my $server = http_get('/',
	socket => IO::Socket::INET->new('127.0.0.1:' . port(8081)));
like(http_body($server), qr/"server_name": "server\.example"\}$/,
	'server fields replace http fields');

my $redirect = http_get('/redirect');
unlike(http_body($redirect), qr/"uri"|"missing"/,
	'redirect response omits supplemental fields');

###############################################################################

sub http_body {
	my ($response) = @_;
	return $response =~ /\r?\n\r?\n(.*)\z/ms ? $1 : '';
}

sub response_length {
	my ($response) = @_;
	return $response =~ /^Content-Length:\s*(\d+)/mi ? $1 : 0;
}

###############################################################################
