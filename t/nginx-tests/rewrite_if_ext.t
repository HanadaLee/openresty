#!/usr/bin/perl

# (C) Hanada

# Tests for extended rewrite "if" condition operators.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(28)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /starts {
            if ($arg_value ^~ $arg_match) {
                return 204;
            }
        }

        location /not-starts {
            if ($arg_value !^~ $arg_match) {
                return 204;
            }
        }

        location /ends {
            if ($arg_value ~$ $arg_match) {
                return 204;
            }
        }

        location /not-ends {
            if ($arg_value !~$ $arg_match) {
                return 204;
            }
        }

        location /number-equal {
            if ($arg_value == $arg_match) {
                return 204;
            }
        }

        location /number-equal-logic {
            if ($arg_value == 01.0 && ($arg_match == -2 || $arg_match == 3)) {
                return 204;
            }
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/starts?value=abcdef&match=abc'), qr/ 204 /,
	'starts with');
unlike(http_get('/starts?value=zabcdef&match=abc'), qr/ 204 /,
	'starts with mismatch');
like(http_get('/starts?value=abc&match=abc'), qr/ 204 /,
	'starts with equal');
like(http_get('/starts?value=abc&match='), qr/ 204 /,
	'starts with empty');
unlike(http_get('/starts?value=ab&match=abc'), qr/ 204 /,
	'starts with shorter value');

unlike(http_get('/not-starts?value=abcdef&match=abc'), qr/ 204 /,
	'not starts with mismatch');
like(http_get('/not-starts?value=zabcdef&match=abc'), qr/ 204 /,
	'not starts with');
unlike(http_get('/not-starts?value=abc&match='), qr/ 204 /,
	'not starts with empty');
like(http_get('/not-starts?value=ab&match=abc'), qr/ 204 /,
	'not starts with shorter value');

like(http_get('/ends?value=abcdef&match=def'), qr/ 204 /,
	'ends with');
unlike(http_get('/ends?value=abcdefx&match=def'), qr/ 204 /,
	'ends with mismatch');
like(http_get('/ends?value=def&match=def'), qr/ 204 /,
	'ends with equal');
like(http_get('/ends?value=def&match='), qr/ 204 /,
	'ends with empty');
unlike(http_get('/ends?value=de&match=def'), qr/ 204 /,
	'ends with shorter value');

unlike(http_get('/not-ends?value=abcdef&match=def'), qr/ 204 /,
	'not ends with mismatch');
like(http_get('/not-ends?value=abcdefx&match=def'), qr/ 204 /,
	'not ends with');
unlike(http_get('/not-ends?value=def&match='), qr/ 204 /,
	'not ends with empty');
like(http_get('/not-ends?value=de&match=def'), qr/ 204 /,
	'not ends with shorter value');

like(http_get('/number-equal?value=1&match=1'), qr/ 204 /,
	'number equal integers');
like(http_get('/number-equal?value=1&match=1.0'), qr/ 204 /,
	'number equal normalized decimals');
like(http_get('/number-equal?value=01.000&match=1'), qr/ 204 /,
	'number equal leading zeroes');
like(http_get('/number-equal?value=-01.250&match=-1.25'), qr/ 204 /,
	'number equal negative decimals');
like(http_get('/number-equal?value=-0.0&match=0'), qr/ 204 /,
	'number equal signed zero');
unlike(http_get('/number-equal?value=1&match=2'), qr/ 204 /,
	'number equal mismatch');
unlike(http_get('/number-equal?value=abc&match=abc'), qr/ 204 /,
	'number equal invalid left operand');
unlike(http_get('/number-equal?value=1&match=abc'), qr/ 204 /,
	'number equal invalid right operand');
like(http_get('/number-equal-logic?value=1&match=-2'), qr/ 204 /,
	'number equal in nested logic');
unlike(http_get('/number-equal-logic?value=1&match=4'), qr/ 204 /,
	'number equal in nested logic mismatch');

###############################################################################
