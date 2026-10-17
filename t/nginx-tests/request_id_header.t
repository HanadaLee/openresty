#!/usr/bin/perl

# Tests for inherited request ID character and length validation.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    request_id_header X-Request-ID;
    large_client_header_buffers 4 8k;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Test-Request-ID $request_id;

        location / {
            return 200 "$request_id|$request_id";
        }

        location /trace {
            request_id_algorithm traceid;
            return 200 "$request_id|$request_id";
        }

        location /disabled {
            request_id_header "";
            return 200 "$request_id|$request_id";
        }

        location /override {
            request_id_header X-Trace-ID;
            return 200 "$request_id|$request_id";
        }
    }
}

EOF

my $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-';
my $maximum = ('a' x 1023) . '_';
my $oversize = 'a' x 1025;

# label, raw request headers, inherited value (undef means generate a new ID).

my @cases = (
    [ 'missing', '', undef ],
    [ 'empty', "X-Request-ID:\r\n", undef ],
    [ 'space only', "X-Request-ID:   \r\n", undef ],
    [ 'single character', "X-Request-ID: a\r\n", 'a' ],
    [ 'allowed alphabet', "X-Request-ID: $alphabet\r\n", $alphabet ],
    [ 'hostname', "X-Request-ID: edge-01.example.com\r\n", 'edge-01.example.com' ],
    [ 'character set only', "X-Request-ID: ._-\r\n", '._-' ],
    [ 'case insensitive header', "x-rEqUeSt-Id: AbC-09_x.y\r\n", 'AbC-09_x.y' ],
    [ '1024 bytes', "X-Request-ID: $maximum\r\n", $maximum ],
    [ '1025 bytes', "X-Request-ID: $oversize\r\n", undef ],
    [ 'invalid final byte', 'X-Request-ID: ' . ('a' x 1023) . "/\r\n", undef ],
    [ 'first duplicate wins',
        "X-Request-ID: first\r\nX-Request-ID: second\r\n", 'first' ],
    [ 'invalid first duplicate',
        "X-Request-ID: bad/value\r\nX-Request-ID: second\r\n", undef ],
    [ 'empty first duplicate',
        "X-Request-ID:\r\nX-Request-ID: second\r\n", undef ],
    [ 'oversize first duplicate',
        "X-Request-ID: $oversize\r\nX-Request-ID: second\r\n", undef ],
    [ 'later duplicate ignored',
        "X-Request-ID: first\r\nX-Request-ID: bad/value\r\n", 'first' ],
    [ 'later header list part',
        join('', map { "X-Padding-$_: a\r\n" } 1 .. 40)
        . "X-Request-ID: later.part\r\n", 'later.part' ],
);

for my $char (' ', "\t", '/', '\\', ':', '@', ';', ',', '=', '+', '%',
    '"', "'", '<', '>', '?', '#', '!', '$', '&', '*', '(', ')', '[', ']',
    '{', '}', '|', '^', '~', '`', "\x01", "\x1f", "\x7f", "\x80",
    "\xc3\xa9", "\xe4\xb8\xad")
{
    push @cases, [ 'invalid bytes ' . unpack('H*', $char),
        "X-Request-ID: a${char}b\r\n", undef ];
}

$t->plan(scalar(@cases) * 2 * 4 + 4 * 4 + 1)->run();

###############################################################################

my $hexid = qr/\A[0-9a-f]{32}\z/;
my $traceid = qr/\A[0-9a-f]+_[A-Za-z0-9._-]+_[0-9]+-[0-9]+-[0-9]+\z/;

for my $algorithm ([ '/', $hexid, 'hexid' ], [ '/trace', $traceid, 'traceid' ]) {
    my ($uri, $format, $name) = @$algorithm;

    for my $case (@cases) {
        my ($label, $headers, $expected) = @$case;
        check_id($uri, $headers, $expected, $format, "$name $label");
    }
}

check_id('/disabled', "X-Request-ID: supplied\r\n", undef, $hexid,
    'header inheritance disabled');
check_id('/override', "X-Request-ID: ignored\r\nX-Trace-ID: selected\r\n",
    'selected', $hexid, 'header name overridden');

my $id1 = check_id('/', "X-Request-ID: bad/value\r\n", undef, $hexid,
    'invalid ID generates a fresh value');
my $id2 = check_id('/', "X-Request-ID: bad/value\r\n", undef, $hexid,
    'repeated invalid ID generates a fresh value');
isnt($id1, $id2, 'different requests do not reuse the rejected ID');

###############################################################################

sub check_id {
    my ($uri, $headers, $expected, $format, $label) = @_;

    my $response = http("GET $uri HTTP/1.0\r\nHost: localhost\r\n"
        . $headers . "\r\n");
    like($response, qr/^HTTP\/1\.[01] 200 /, "$label response");

    my ($body) = $response =~ /\r\n\r\n(.*)\z/s;
    my ($first, $second) = split /\|/, defined $body ? $body : '', -1;
    my ($header) = $response =~ /^X-Test-Request-ID:[ \t]*(.*?)\r?$/mi;

    if (defined $expected) {
        is($first, $expected, "$label inherited value");
    } else {
        like($first, $format, "$label generated value");
    }

    is($second, $first, "$label stable variable");
    is($header, $first, "$label stable response header");
    return $first;
}

###############################################################################
