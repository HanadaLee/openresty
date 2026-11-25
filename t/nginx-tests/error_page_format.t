#!/usr/bin/perl

# Tests for the NGX_EXT error_page_format directive.

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
		'The server rejected this request as invalid.'],
	[401, 401, 'Unauthorized',
		'Valid credentials are required.'],
	[402, 402, 'Payment Required', ''],
	[403, 403, 'Forbidden',
		'The client does not have the required permission.'],
	[404, 404, 'Not Found', 'The server could not find what was requested.'],
	[405, 405, 'Method Not Allowed',
		'This HTTP method is not allowed for the requested URL.'],
	[406, 406, 'Not Acceptable',
		'No available response matches your content preferences.'],
	[407, 407, 'Proxy Authentication Required',
		'The proxy requires valid credentials.'],
	[409, 409, 'Conflict',
		'The request cannot be completed in the current state.'],
	[410, 410, 'Gone',
		'What was requested is no longer available.'],
	[411, 411, 'Length Required',
		'The request must include a valid Content-Length header.'],
	[412, 412, 'Precondition Failed',
		'A condition in the request headers was not met.'],
	[413, 413, 'Content Too Large',
		"The request content exceeds the server's allowed size."],
	[414, 414, 'URI Too Long',
		"The request URI exceeds the server's allowed length."],
	[415, 415, 'Unsupported Media Type',
		'The server cannot accept the format of the request body.'],
	[416, 416, 'Range Not Satisfiable',
		'The server cannot provide the requested range.'],
	[421, 421, 'Misdirected Request',
		'The request reached the wrong server.'],
	[429, 429, 'Too Many Requests',
		'The request rate exceeds the limit.'],
	[494, 400, 'Bad Request',
		'A request header or cookie exceeds the allowed size.'],
	[495, 400, 'Bad Request',
		'The client certificate could not be verified.'],
	[496, 400, 'Bad Request',
		'The request did not include the required client certificate.'],
	[497, 400, 'Bad Request',
		'The plain HTTP request was sent to HTTPS port.'],
	[498, 498, 'Not Found', 'The server could not find what was requested.'],
	[500, 500, 'Internal Server Error',
		'The server encountered an unexpected error.'],
	[501, 501, 'Not Implemented',
		'The server does not support the requested functionality.'],
	[502, 502, 'Bad Gateway',
		'The upstream server returned an invalid response.'],
	[503, 503, 'Service Unavailable',
		'The server is temporarily unable to process the request.'],
	[504, 504, 'Gateway Timeout',
		'The upstream server did not respond in time.'],
	[505, 505, 'HTTP Version Not Supported',
		'The server does not support this HTTP version.'],
	[507, 507, 'Insufficient Storage',
		'There is not enough storage to complete this request.'],
);

my $status_locations = join "\n", map {
	my $code = $_->[0];
	my $value = $code =~ /^(?:301|302|303|307|308)$/
		? "$code /redirected" : $code;

	join "\n", map {
		<<EOF
        location = /$_/$code {
            error_page_format $_;
            server_tokens off;
            return $value;
        }
EOF
	} qw/default json xml/
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

        location /too-long {
            error_page_format default;
            return 414;
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

$t->run()->plan(17 + 3 * @format_cases);

###############################################################################

my $default = http_get('/default');
like($default, qr/Content-Type: text\/html\r?\n/i,
	'default format keeps HTML content type');
like(http_body($default), qr{<h1><b>403</b> <span>Forbidden</span></h1>},
	'default format keeps HTML body');
like(http_body($default),
	qr{<p>The client does not have the required permission\.</p>},
	'default format shows the HTML error description');
unlike(http_body($default), qr/<dl>|<dt>|dl\{display:grid/,
	'default format omits supplemental fields');
is(response_length($default), length(http_body($default)),
	'default content length matches body');

my $too_long = http_body(http_get('/too-long'));
like($too_long, qr{<b>414</b> <span>URI Too Long</span>},
	'414 displays its status and title');
is(() = $too_long =~ /<h1>/g, 1, '414 has only one heading');
unlike(http_head('/default'), qr/<main>/, 'HEAD does not send the HTML card');

my $json = http_get('/json');
like($json, qr/Content-Type: application\/json\r?\n/i,
	'json format content type');
like(http_body($json),
	qr/^\{"status":403,"reason":"Forbidden","message":
		"The\x20client\x20does\x20not\x20have\x20the\x20
		required\x20permission\."/x,
	'json format status and message');
unlike(http_body($json), qr/"date"|"client_ip"|"server"|"request_id"/,
	'json format omits supplemental fields');
is(response_length($json), length(http_body($json)),
	'json content length matches body');

my $xml = http_get('/xml');
like($xml, qr/Content-Type: application\/xml\r?\n/i,
	'xml format content type');
like(http_body($xml),
	qr/<Error><Status>403<\/Status><Reason>Forbidden<\/Reason>/,
	'xml format status and reason');
like(http_body($xml),
	qr/<Message>The client does not have the required permission\.<\/Message>/,
	'xml format message');
unlike(http_body($xml), qr/<date>|<client_ip>|<server>|<request_id>/,
	'xml format omits supplemental fields');
is(response_length($xml), length(http_body($xml)),
	'xml content length matches body');

for my $case (@format_cases) {
	my ($code, $status, $reason, $message) = @$case;
	my $body = http_body(http_get("/json/$code"));

	like($body,
		qr/^\{"status":$status,"reason":"\Q$reason\E","message":"\Q$message\E"/,
		"json error information for $code");

	my $xml = http_body(http_get("/xml/$code"));
	like($xml, qr{<Message>\Q$message\E</Message>}, "xml message for $code");

	my $html = http_body(http_get("/default/$code"));
	my ($text) = $html =~ m{<p>(.*?)</p>};
	is(defined $text ? $text : '', $message, "html message for $code");
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
