#!/usr/bin/perl

# Tests that grpc request-header variables observe header-control mutations.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http grpc
	ngx_http_grpc_filter_module ngx_http_grpc_headers_control_module/)
	->plan(6);

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
            return 200 "ok";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /variables {
            grpc_request_header_control set X-Set $arg_value;
            grpc_request_header_control clear X-Clear;
            grpc_request_header_control append X-Append appended;
            grpc_request_header_control rewrite X-Rewrite rewritten;

            add_header X-Grpc-Set $grpc_http_x_set always;
            add_header X-Grpc-Clear "[$grpc_http_x_clear]" always;
            add_header X-Grpc-Append $grpc_http_x_append always;
            add_header X-Grpc-Rewrite $grpc_http_x_rewrite always;

            grpc_pass grpc://127.0.0.1:8081;
        }
    }
}

EOF

$t->run()->waitforsocket('127.0.0.1:' . port(8080));

my $response = http(<<'EOF');
GET /variables?value=dynamic HTTP/1.1
Host: localhost
X-Set: old
X-Clear: remove
X-Append: base
X-Rewrite: old
Connection: close

EOF

is(header_value($response, 'X-Grpc-Set'), 'dynamic',
	'grpc variable sees a replaced request header');
is(header_value($response, 'X-Grpc-Clear'), '[]',
	'grpc variable sees a cleared request header');
is(header_value($response, 'X-Grpc-Append'), 'base, appended',
	'grpc variable combines appended request headers');
is(header_value($response, 'X-Grpc-Rewrite'), 'rewritten',
	'grpc variable sees a rewritten request header');

my $long = 'x' x 1024;
my $long_response = http(<<EOF);
GET /variables?value=$long HTTP/1.1
Host: localhost
Connection: close

EOF

like($long_response, qr/^HTTP\/1\.1 200 /,
	'filter-created long request header succeeds');
is(header_value($long_response, 'X-Grpc-Set'), $long,
	'filter-created long request header is exposed intact');

sub header_value {
	my ($response, $name) = @_;
	my ($value) = $response =~ /^\Q$name\E:\s*(.*?)\x0d?$/gmi;

	return $value;
}
