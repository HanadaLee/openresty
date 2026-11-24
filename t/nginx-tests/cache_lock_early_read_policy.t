#!/usr/bin/perl

# Copyright (C) Hanada
# Cache policy, background updates and persisted cache hits with early reads.

use strict;
use warnings;
use Test::More;
use IO::Select;
use Time::HiRes qw/sleep/;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx;
use CacheEarlyRead;

my $t = Test::Nginx->new()->has(qw/http proxy cache http_slice threads/);
plan skip_all => 'requires nginx extensions on Linux' if $^O ne 'linux' || $t->has_module('--without-ext');
my $expr = $t->has_module('ngx_expr_module|ngx_condition_module');
my $when = $expr ? <<'EOF' : '';
location /cond/ {
    expr shared str_eq $http_x_share yes;
    when shared { proxy_cache_lock_early_read on; }
    proxy_pass http://127.0.0.1:8081;
}
EOF
start_cache($t, <<'HTTP', $when . <<'SERVER');
proxy_cache_path cache keys_zone=c:4m keys_state=%%TESTDIR%%/state/c use_temp_path=off;
proxy_cache_path other keys_zone=other:4m use_temp_path=on;
HTTP
proxy_cache c;
proxy_cache_key $uri;
proxy_cache_lock on;
proxy_cache_lock_age 5s;
proxy_cache_lock_timeout 500ms;
proxy_cache_valid 200 206 1m;
location / {
    proxy_cache_lock_early_read on;
    proxy_ignore_headers Vary Set-Cookie Cache-Control;
    proxy_pass http://127.0.0.1:8081;
}
location /unused-slice/ {
    slice on;
    slice_size 128k;
    proxy_cache_lock_early_read on;
    proxy_pass http://127.0.0.1:8081;
}
location /ignored-range/ {
    slice on;
    slice_size 128k;
    set $saved_range $slice_range;
    proxy_cache_key $uri$saved_range;
    proxy_set_header Range $saved_range;
    proxy_cache_lock_early_read on;
    proxy_pass http://127.0.0.1:8081;
}
location /off/ { proxy_pass http://127.0.0.1:8081; }
location /temp/ {
    proxy_cache other;
    proxy_cache_lock_early_read on;
    proxy_pass http://127.0.0.1:8081;
}
location /unbuffered/ {
    proxy_buffering off;
    proxy_cache_lock_early_read on;
    proxy_pass http://127.0.0.1:8081;
}
location /thread/ {
    aio threads;
    aio_write on;
    proxy_cache_lock_early_read on;
    proxy_pass http://127.0.0.1:8081;
}
location /stale/ {
    proxy_cache_lock_early_read on;
    proxy_cache_valid 200 1s;
    proxy_cache_use_stale updating;
    proxy_pass http://127.0.0.1:8081;
}
SERVER

my $legacy = legacy_guard($t);
for my $case (['/off/a'], ['/temp/a'], ['/unbuffered/a'], ['/thread/a', '', 1],
	['/unused-slice/a', '', 1], ['/ignored-range/a', '', 1],
	['/multi-request', 'Range: bytes=0-7,16-31'], ['/multipart'],
	['/auth', 'Authorization: Basic Zm9vOmJhcg=='], ['/cookie', 'Cookie: a=b'],
	['/condition', 'If-None-Match: "none"'], ['/vary'], ['/set-cookie'],
	['/encoded'], ['/private'], ($expr ? (['/cond/no'], ['/cond/yes', 'X-Share: yes', 1]) : ()))
{
	my ($path, $extra, $early) = @$case;
	$extra .= "\r\n" if $extra;
	my $a = headers(send_req(socket_for(), $path, $extra));
	my $first = read_body($a, 1);
	is($a->{h}{'x-cache'}, 'MISS', "$path writer");
	my $b = send_req(socket_for($a->{h}{'x-pid'}), $path, $extra);
	my $prefix = '';
	if ($early && !$legacy) {
		headers($b); $prefix = read_body($b, 1);
		is($b->{h}{'x-cache'}, 'MISS', "$path attached reader");
		sleep 0.60; # The lock timeout no longer applies once attached.
	} elsif (IO::Select->new($b->{socket})->can_read(0.17)) {
		cmp_ok(scalar @{origin_hits($t, $path)}, '>', 1, "$path independent origin");
	}
	release_fill($t, $path);
	my $body = origin_body($path, 1);
	ok($first . read_body($a) eq $body, "$path complete writer");
	headers($b) unless length $prefix;
	my $data = $prefix . read_body($b);
	ok($data eq $body || $data eq origin_body($path, 2), "$path complete response");
	my $count = @{origin_hits($t, $path)};
	if ($early && !$legacy) { is($count, 1, "$path single fill"); }
	else { ok($b->{h}{'x-cache'} eq 'HIT' || $count > 1, "$path regular cache path"); }
}

my $path = '/stale/a';
my $v1 = origin_body($path, 1);
is(fetch($path)->{h}{'x-cache'}, 'MISS', 'initial stale fixture');
sleep 2.1;
my $a = headers(send_req(socket_for(), $path));
my $first = read_body($a, 1);
my $old = fetch($path);
is($old->{h}{'x-cache'}, 'UPDATING', 'expired object served during update');
ok($old->{body} eq $v1, 'UPDATING returns the old representation');
release_fill($t, $path);
ok($first . read_body($a) eq origin_body($path, 2), 'writer receives new representation');
is(scalar @{origin_hits($t, $path)}, 2, 'only the writer refreshed the cache');
my $saved = $expr ? '/cond/yes' : '/thread/a';
$t->stop();
ok(-f $t->testdir() . '/state/c', 'saved cache zone');
$t->run();
my $hit = fetch($saved, "X-Share: yes\r\n");
is($hit->{h}{'x-cache'}, 'HIT', 'persisted cache hit after restart');
ok($hit->{body} eq origin_body($saved, 1), 'persisted body');
is(scalar @{origin_hits($t, $saved)}, 1, 'no origin request after restart');
finish_cache($t);
undef $t;
done_testing();
