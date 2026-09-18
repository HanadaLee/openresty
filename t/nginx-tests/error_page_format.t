#!/usr/bin/perl

# Tests for the NGX_RESTY_EXT error_page_format directive.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

my @format_cases = (
	[301, 301, 'Moved Permanently', ''],
	[302, 302, 'Found', ''],
	[303, 303, 'See Other', ''],
	[307, 307, 'Temporary Redirect', ''],
	[308, 308, 'Permanent Redirect', ''],
	[400, 400, 'Bad Request',
		'The server could not process the request because it was invalid.'],
	[401, 401, 'Unauthorized',
		'Valid authentication credentials were not provided.'],
	[402, 402, 'Payment Required', ''],
	[403, 403, 'Forbidden',
		'You do not have permission to access this resource.'],
	[404, 404, 'Not Found', 'The requested resource could not be found.'],
	[405, 405, 'Method Not Allowed',
		'The requested method is not supported for this resource.'],
	[406, 406, 'Not Acceptable',
		'The server cannot provide a response matching the request headers.'],
	[407, 407, 'Proxy Authentication Required',
		'Valid proxy authentication credentials were not provided.'],
	[409, 409, 'Conflict',
		'The request conflicts with the current state of the resource.'],
	[410, 410, 'Gone', 'The requested resource is no longer available.'],
	[411, 411, 'Length Required',
		'The request must include a valid Content-Length header.'],
	[412, 412, 'Precondition Failed',
		'One or more conditions in the request headers were not met.'],
	[413, 413, 'Content Too Large',
		"The request content exceeds the server's allowed size."],
	[414, 414, 'URI Too Long',
		"The request URI exceeds the server's allowed length."],
	[415, 415, 'Unsupported Media Type',
		'The server does not support the request content type.'],
	[416, 416, 'Range Not Satisfiable',
		'The server cannot provide the requested range.'],
	[421, 421, 'Misdirected Request',
		'The request was sent to a server that cannot handle it.'],
	[429, 429, 'Too Many Requests',
		'The client sent too many requests within a short period.'],
	[494, 400, 'Bad Request',
		'A request header or cookie exceeds the allowed size.'],
	[495, 400, 'Bad Request',
		'The client certificate could not be verified.'],
	[496, 400, 'Bad Request',
		'The request did not include the required client certificate.'],
	[497, 400, 'Bad Request',
		'The plain HTTP request was sent to HTTPS port.'],
	[498, 498, 'Not Found', 'The requested resource could not be found.'],
	[500, 500, 'Internal Server Error',
		'The server encountered an unexpected error.'],
	[501, 501, 'Not Implemented',
		'The server does not support the requested functionality.'],
	[502, 502, 'Bad Gateway',
		'The upstream server returned an invalid response.'],
	[503, 503, 'Service Unavailable',
		'The server is temporarily unable to process the request.'],
	[504, 504, 'Gateway Timeout',
		'The upstream server did not respond within the allowed time.'],
	[505, 505, 'HTTP Version Not Supported',
		'The server does not support the HTTP version used by the request.'],
	[507, 507, 'Insufficient Storage',
		'The server does not have enough storage to complete the request.'],
);

my $status_locations = join "\n", map {
	my $code = $_->[0];
	my $value = $code =~ /^(?:301|302|303|307|308)$/
		? "$code /redirected" : $code;

	<<EOF
        location = /status/$code {
            return $value;
        }
EOF
} @format_cases;

my $config = <<'EOF';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    error_page_format default;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        error_page_format json;

        location /default {
            error_page_format default;
            return 403;
        }

        location /json {
            return 403;
        }

        location /xml {
            error_page_format xml;
            return 403;
        }

%%STATUS_LOCATIONS%%
    }
}

EOF

$config =~ s/%%STATUS_LOCATIONS%%/$status_locations/;

my $t = Test::Nginx->new()->has(qw/http rewrite/)
	->write_file_expand('nginx.conf', $config);

$t->run()->plan(14 + @format_cases);

###############################################################################

my $default = http_get('/default');
like($default, qr/Content-Type: text\/html\r?\n/i,
	'default format keeps HTML content type');
like(http_body($default), qr/<h1>403 Forbidden<\/h1>/,
	'default format keeps HTML body');
like(http_body($default),
	qr/<p>You do not have permission to access this resource\.<\/p>/,
	'default format wraps the shared message in a paragraph');
unlike(http_body($default), qr/<table>|<td>/,
	'default format omits supplemental fields');
is(response_length($default), length(http_body($default)),
	'default content length matches body');

my $json = http_get('/json');
like($json, qr/Content-Type: application\/json\r?\n/i,
	'json format content type');
like(http_body($json),
	qr/^\{"status":\x20403,\x20"error":\x20"Forbidden",\x20
		"message":\x20"You\x20do\x20not\x20have\x20permission\x20to\x20
		access\x20this\x20resource\."/x,
	'json format status and message');
unlike(http_body($json), qr/"date"|"client_ip"|"server"|"request_id"/,
	'json format omits supplemental fields');
is(response_length($json), length(http_body($json)),
	'json content length matches body');

my $xml = http_get('/xml');
like($xml, qr/Content-Type: application\/xml\r?\n/i,
	'xml format content type');
like(http_body($xml),
	qr/<status>403<\/status>\r?\n\s*<error>Forbidden<\/error>/,
	'xml format status and error');
like(http_body($xml),
	qr/<message>You do not have permission to access this resource\.<\/message>/,
	'xml format message');
unlike(http_body($xml), qr/<date>|<client_ip>|<server>|<request_id>/,
	'xml format omits supplemental fields');
is(response_length($xml), length(http_body($xml)),
	'xml content length matches body');

for my $case (@format_cases) {
	my ($code, $status, $reason, $message) = @$case;
	my $body = http_body(http_get("/status/$code"));

	like($body,
		qr/^\{"status": $status, "error": "\Q$reason\E", "message": "\Q$message\E"/,
		"json error information for $code");
}

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
