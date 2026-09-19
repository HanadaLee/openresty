#!/usr/bin/perl

# Tests for grpc upstream request header variables.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 grpc/)->plan(24);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081;
        server_name  backend;

        http2 on;
        default_type application/grpc;
        add_trailer grpc-status 0 always;

        location / {
            return 200 "$http_x_configured|$http_x_incoming|$http_x_duplicate|$http_x_long";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /variables {
            grpc_set_header Host grpc.example;
            grpc_set_header X-Configured "configured-$arg_value";
            grpc_set_header X-Duplicate first;
            grpc_set_header X-Duplicate second;
            grpc_set_header X-Removed "";

            add_header X-Grpc-Host $grpc_http_host always;
            add_header X-Grpc-Configured $grpc_http_x_configured always;
            add_header X-Grpc-Incoming $grpc_http_x_incoming always;
            add_header X-Grpc-Duplicate $grpc_http_x_duplicate always;
            add_header X-Grpc-Missing "[$grpc_http_x_missing]" always;
            add_header X-Grpc-Removed "[$grpc_http_x_removed]" always;
            add_header X-Grpc-Long $grpc_http_x_long always;

            grpc_pass grpc://127.0.0.1:8081;
        }

        location = /default-host {
            add_header X-Grpc-Host $grpc_http_host always;
            grpc_pass grpc://127.0.0.1:8081;
        }

        location = /suppressed {
            grpc_set_header X-Incoming "";
            add_header X-Grpc-Incoming "[$grpc_http_x_incoming]" always;
            grpc_pass grpc://127.0.0.1:8081;
        }

        location = /not-grpc {
            add_header X-Grpc-Missing "[$grpc_http_x_missing]" always;
            return 200;
        }
    }
}

EOF

$t->run()->waitforsocket('127.0.0.1:' . port(8080));

###############################################################################

my $long = 'x' x 512;
my $response = response('/variables?value=dynamic', <<EOF);
X-Incoming: incoming
X-Long: $long
EOF

like($response, qr/^HTTP\/1\.1 200 /, 'request succeeds');
is(header_value($response, 'X-Grpc-Host'), 'grpc.example',
	'host is the grpc authority');
is(header_value($response, 'X-Grpc-Configured'), 'configured-dynamic',
	'configured header is exposed');
is(header_value($response, 'X-Grpc-Incoming'), 'incoming',
	'passed request header is exposed');
is(header_value($response, 'X-Grpc-Duplicate'), 'first, second',
	'duplicate headers are combined');
is(header_value($response, 'X-Grpc-Missing'), '[]',
	'missing header is not found');
is(header_value($response, 'X-Grpc-Removed'), '[]',
	'empty configured header is omitted');
is(header_value($response, 'X-Grpc-Long'), $long,
	'long passed header is exposed');
is(http_content($response),
	"configured-dynamic|incoming|first, second|$long",
	'variables match headers sent upstream');

for my $size (16, 255, 256, 511, 1024, 4096) {
	my $value = 'x' x $size;
	my $boundary_response = response('/variables?value=boundary', <<EOF);
X-Incoming: incoming
X-Long: $value
EOF

	like($boundary_response, qr/^HTTP\/1\.1 200 /,
		"request with a $size-byte forwarded header succeeds");
	is(header_value($boundary_response, 'X-Grpc-Long'), $value,
		"$size-byte forwarded header is exposed intact");
}

like(header_value(response('/default-host'), 'X-Grpc-Host'),
	qr/^127\.0\.0\.1:\d+$/, 'default authority is exposed');
is(header_value(response('/suppressed', "X-Incoming: hidden\n"),
	'X-Grpc-Incoming'), '[]', 'configured header suppression is respected');
is(header_value(response('/not-grpc'), 'X-Grpc-Missing'), '[]',
	'variable is not found outside a grpc request');

###############################################################################

sub header_value {
	my ($response, $name) = @_;
	my ($value) = $response =~ /^\Q$name\E:\s*(.*?)\x0d?$/mi;

	return $value;
}


sub response {
	my ($uri, $headers) = @_;
	$headers ||= '';

	return http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
${headers}Connection: close

EOF
}

###############################################################################
