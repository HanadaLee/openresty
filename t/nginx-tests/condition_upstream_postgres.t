#!/usr/bin/perl

# Tests for condition-aware ngx_postgres upstream settings.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_postgres_module ngx_condition_module/)->plan(1);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream postgres_backend {
        postgres_server 127.0.0.1:1 dbname=test user=test password=test;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        condition enabled str_in $http_x_case enabled;

        location /postgres {
            when enabled {
                postgres_connect_timeout 1s;
                postgres_result_timeout 1s;
            }

            postgres_query "select 1";
            postgres_pass postgres_backend;
        }
    }
}

EOF

$t->run();

###############################################################################

like(request('/postgres'), qr/502 Bad Gateway/,
	'postgres condition path');

###############################################################################

sub request {
	my ($uri) = @_;
	return http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
X-Case: enabled
Connection: close

EOF
}

###############################################################################
