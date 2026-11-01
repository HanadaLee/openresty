#!/usr/bin/perl

# Copyright (C) Hanada

# Multipart ranges with slice, including inactive-slice regressions.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy slice rewrite/);
plan 'no_plan';

my $cache = $t->has_module('cache');
my $expr = $t->has_module('ngx_expr_module');
my $data = join('', map { sprintf '%08x', $_ } 0 .. 32767);
my @paths = ('proxy', 'unbuffered');
my $cache_config = '';
my $locations = '';

if ($expr) {
	$locations .= <<'EOF';
        location /conditional/ {
            expr use_slices str_eq $arg_slice yes;
            when use_slices { slice on; }
            slice_size 16k;
            proxy_pass http://127.0.0.1:8081/;
            proxy_set_header Range $slice_range;
        }
EOF
}

if ($cache) {
	$cache_config = 'proxy_cache_path %%TESTDIR%%/cache keys_zone=cache:1m;';
	push @paths, qw/cache bypass minuses/;
	for my $name (qw/cache bypass minuses/) {
		my $extra = $name eq 'bypass' ? 'proxy_cache_bypass 1;'
			: $name eq 'minuses' ? 'proxy_cache_min_uses 3;' : '';
		$locations .= <<EOF;
        location /$name/ {
            slice on;
            slice_size 16k;
            proxy_pass http://127.0.0.1:8081/;
            proxy_set_header Range \$slice_range;
            proxy_cache cache;
            proxy_cache_key "\$uri\$is_args\$args[\$slice_range]";
            proxy_cache_valid 200 206 1h;
            $extra
        }
EOF
	}
}

my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    error_log %%TESTDIR%%/error.log info;
    default_type application/octet-stream;
    sendfile on;
    proxy_buffer_size 4k;
    proxy_buffers 4 4k;
    proxy_force_ranges on;
    CACHE_CONFIG
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        location /static/ { alias %%TESTDIR%%/; }
        location /proxy/ {
            slice on;
            slice_size 16k;
            proxy_pass http://127.0.0.1:8081/;
            proxy_set_header Range $slice_range;
        }
        location /unbuffered/ {
            slice on;
            slice_size 16k;
            proxy_buffering off;
            proxy_pass http://127.0.0.1:8081/;
            proxy_set_header Range $slice_range;
        }
        location /plain/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_set_header Range "";
        }
        location /disabled/ {
            slice off;
            proxy_pass http://127.0.0.1:8081/;
            proxy_set_header Range $slice_range;
        }
        location /bypassed/ {
            slice on;
            slice_bypass 1;
            proxy_pass http://127.0.0.1:8081/;
            proxy_set_header Range $slice_range;
        }
        location /ignored/ {
            slice on;
            slice_size 16k;
            proxy_pass http://127.0.0.1:8081/ignore/;
            proxy_set_header Range $slice_range;
        }
        location /limited/ {
            slice on;
            slice_size 16k;
            max_ranges 1;
            proxy_pass http://127.0.0.1:8081/;
            proxy_set_header Range $slice_range;
        }
        location /broken {
            slice on;
            slice_size 2;
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Range $slice_range;
        }
        CACHE_LOCATIONS
    }
    server {
        listen 127.0.0.1:8081;
        server_name origin;
        location / {}
        location /ignore/ { alias %%TESTDIR%%/; max_ranges 0; }
        location /broken {
            add_header Content-Range "bytes 0-1/8";
            return 206 a;
        }
        location /broken_long {
            add_header Content-Range "bytes 0-1/8";
            return 206 abc;
        }
        location /broken_length {
            if ($http_range = "bytes=4-5") {
                add_header Content-Range "bytes 4-5/9";
                return 206 ef;
            }
            add_header Content-Range "bytes 0-1/8";
            return 206 ab;
        }
    }
}
EOF
$config =~ s/CACHE_CONFIG/$cache_config/;
$config =~ s/CACHE_LOCATIONS/$locations/;
$t->write_file_expand('nginx.conf', $config);
$t->write_file('data', $data);
$t->run();

my @cases = (
	['same buffer', '10-19,30-39', [[10, 19], [30, 39]]],
	['cross slice', '16000-17000,33000-33100', [[16000, 17000], [33000, 33100]]],
	['distant', '100-199,200000-200099', [[100, 199], [200000, 200099]]],
	['reverse', '200000-200099,100-199', [[200000, 200099], [100, 199]]],
	['suffix', '-17,0-15', [[262127, 262143], [0, 15]]],
	['open end', '262130-,0-15', [[262130, 262143], [0, 15]]],
	['overlap', '100-199,150-249', [[100, 199], [150, 249]]],
	['duplicate', '100-199,100-199', [[100, 199], [100, 199]]],
	['boundary', '16383-16384,32768-32769', [[16383, 16384], [32768, 32769]]],
);

for my $path (@paths) {
	for my $case (@cases) {
		for my $attempt (1, 2) {
			multipart("/$path/data?case=$case->[0]&x=bytes=200000",
				$case->[1], $case->[2], "$path $case->[0] $attempt");
		}
	}
}

multipart('/static/data', '100-199,200000-200099',
	[[100, 199], [200000, 200099]], 'ordinary static multipart');

if ($expr) {
	multipart('/conditional/data?slice=yes', '10-19,30-39',
		[[10, 19], [30, 39]], 'matching when enables multipart');
	my $r = get('/conditional/data?slice=no', '10-19,30-39');
	like($r, qr/^HTTP\/1\.1 200 /, 'false when retains 200 response');
	is(body($r), $data, 'false when retains complete body');
}

for my $path (qw/plain disabled bypassed ignored limited/) {
	my $r = get("/$path/data", '100-199,200000-200099');
	like($r, qr/^HTTP\/1\.1 200 /, "$path retains 200 response");
	is(body($r), $data, "$path retains complete body");
}

my $r = get('/proxy/data', '999999-1000000,2000000-3000000');
like($r, qr/^HTTP\/1\.1 416 /, 'unsatisfiable ranges');
$r = get('/proxy/data', 'x-y,0-1');
like($r, qr/^HTTP\/1\.1 416 /, 'invalid ranges');
$r = get('/proxy/data', '0-262143,0-262143');
like($r, qr/^HTTP\/1\.1 200 /, 'excessive total length falls back');
is(body($r), $data, 'fallback body starts at zero');
$r = get('/proxy/data', '100-199,999999-1000000');
like($r, qr/^Content-Range: bytes 100-199\/262144\r?$/m,
	'one satisfiable range uses native singlepart');
is(body($r), substr($data, 100, 100), 'native singlepart body');

my $headers = http_head('/static/data');
my ($etag) = $headers =~ /^ETag: (.+)\r?$/m;
$etag =~ s/\r$//;
$r = get('/proxy/data', '10-19,200000-200009', "If-None-Match: $etag\r\n");
like($r, qr/^HTTP\/1\.1 304 /, 'conditional 304 precedes multipart');
$r = get('/proxy/data', '10-19,200000-200009', "If-Match: \"other\"\r\n");
like($r, qr/^HTTP\/1\.1 412 /, 'conditional 412 precedes multipart');
$r = get('/proxy/data', '10-19,200000-200009', "If-Range: \"other\"\r\n");
like($r, qr/^HTTP\/1\.1 200 /, 'If-Range mismatch retains 200');
is(body($r), $data, 'If-Range mismatch retains full body');
multipart('/proxy/data', '10-19,200000-200009', [[10, 19], [200000, 200009]],
	'If-Range match', "If-Range: $etag\r\n");

$r = http("HEAD /proxy/data HTTP/1.0\r\nHost: localhost\r\n"
	. "Range: bytes=0-1,3-4\r\n\r\n");
like($r, qr/^HTTP\/1\.1 200 /, 'HEAD retains original slice behavior');
is(body($r), '', 'HEAD has no response body');

$r = get('/broken', '1-1,5-5');
unlike($r, qr/--[0-9]+--\r\n$/, 'short slice does not complete multipart');
like($t->read_file('error.log'), qr/incomplete multipart slice response/,
	'no-progress slice is rejected');
$r = get('/broken_long', '0-0,5-5');
unlike($r, qr/--[0-9]+--\r\n$/, 'oversized slice does not complete multipart');
like($t->read_file('error.log'), qr/too much data in multipart slice response/,
	'oversized slice is rejected');
$r = get('/broken_length', '0-0,5-5');
unlike($r, qr/--[0-9]+--\r\n$/, 'changed resource length does not complete multipart');
like($t->read_file('error.log'), qr/complete length mismatch in slice response/,
	'changed resource length is rejected');

$t->stop();
unlike($t->read_file('error.log'), qr/\[(?:alert|crit)\]/,
	'no alert or critical errors');
unlike($t->read_file('error.log'), qr/AddressSanitizer|runtime error:/,
	'no sanitizer errors');

sub get {
	my ($uri, $range, $headers) = @_;
	$headers //= '';
	$uri =~ s/ /%20/g;
	return http("GET $uri HTTP/1.0\r\nHost: localhost\r\n"
		. "Range: bytes=$range\r\n$headers\r\n");
}

sub body {
	my ($r) = @_;
	my (undef, $body) = split(/\r\n\r\n/, $r, 2);
	return $body // '';
}

sub multipart {
	my ($uri, $ranges, $expected, $name, $headers) = @_;
	my $r = get($uri, $ranges, $headers);
	like($r, qr/^HTTP\/1\.1 206 /, "$name status");
	my ($boundary) = $r =~ /Content-Type: multipart\/byteranges; boundary=(\w+)/;
	my ($length) = $r =~ /Content-Length: (\d+)/;
	my $body = body($r);
	is(length($body), $length, "$name content length");
	my $valid = defined($boundary);
	if ($valid) {
		my @parts = split(/\r\n--\Q$boundary\E/, $body);
		$valid &&= shift(@parts) eq '' && pop(@parts) eq "--\r\n";
		$valid &&= @parts == @$expected;
		for my $i (0 .. $#parts) {
			my ($head, $value) = split(/\r\n\r\n/, $parts[$i], 2);
			my ($a, $b, $total) = $head =~ /Content-Range: bytes (\d+)-(\d+)\/(\d+)/;
			$valid &&= defined($a) && defined($expected->[$i])
				&& $a == $expected->[$i][0] && $b == $expected->[$i][1]
				&& $total == length($data)
				&& $value eq substr($data, $a, $b - $a + 1);
		}
	}
	ok($valid, "$name ranges and body");
}
