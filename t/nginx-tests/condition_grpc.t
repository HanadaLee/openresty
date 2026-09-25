#!/usr/bin/perl

# (C) Hanada

# Tests for conditional grpc directives.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 grpc
	ngx_expr_module/)->plan(5);

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

        expr method str_in $arg_case method variable;

        location /method {
            when method {
                grpc_method GET;
            }

            grpc_method POST;
            grpc_pass grpc://127.0.0.1:8081;
        }

        location /order {
            grpc_method POST;

            when method {
                grpc_method GET;
            }

            grpc_pass grpc://127.0.0.1:8081;
        }

        location /variable {
            when method {
                grpc_method $arg_method;
            }

            grpc_method POST;
            grpc_pass grpc://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        http2 on;

        default_type application/grpc;
        add_trailer grpc-status 0 always;

        location / {
            return 200 $request_method;
        }
    }
}

EOF

$t->run();

###############################################################################

pass('conditional grpc_method accepted');

is(Test::Nginx::http_content(http_get('/method')), 'POST',
	'grpc_method default');
is(Test::Nginx::http_content(http_get('/method?case=method')), 'GET',
	'grpc_method condition');
is(Test::Nginx::http_content(http_get('/order?case=method')), 'POST',
	'grpc_method configuration order');
is(Test::Nginx::http_content(
	http_get('/variable?case=variable&method=PATCH')), 'PATCH',
	'grpc_method condition with variable');

###############################################################################
