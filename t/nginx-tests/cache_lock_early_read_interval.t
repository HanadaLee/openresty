#!/usr/bin/perl

# Copyright (C) Hanada

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";
use IO::Select;
use Test::More;
use Test::Nginx;
use Time::HiRes qw/time/;
use CacheEarlyRead;

my $t = Test::Nginx->new()->has(qw/http proxy cache/);
plan skip_all => 'requires nginx extensions on Linux'
	if $^O ne 'linux' || $t->has_module('--without-ext');

start_cache($t, 'proxy_cache_path cache keys_zone=c:4m use_temp_path=off;', <<'EOF');
proxy_cache c;
proxy_cache_key shared;
proxy_cache_valid 200 1m;
proxy_cache_lock on;
proxy_cache_lock_timeout 5s;
proxy_cache_lock_early_read on;
proxy_read_timeout 15s;
location /slow/ {
    proxy_cache_lock_poll_interval 4s;
    proxy_pass http://127.0.0.1:8081/obj/;
}
location /fast/ {
    proxy_cache_lock_poll_interval 40ms;
    proxy_pass http://127.0.0.1:8081/obj/;
}
location /timed/ {
    proxy_cache_lock_poll_interval 4s;
    proxy_read_timeout 400ms;
    proxy_pass http://127.0.0.1:8081/obj/;
}
EOF

sub start_reader {
	my ($path, $not_pid) = @_;
	my $r = headers(send_req(socket_for($not_pid), $path));
	is($r->{status}, 200, "$path status");
	$r->{prefix} = read_body($r, 8192);
	return $r;
}

SKIP: {
	skip 'early reads unavailable without in-flight invalidation guard', 1 if legacy_guard($t);
	subtest 'shared polling and individual reader deadline' => sub {
		my $path = '/obj/shared';
		my $writer = start_reader('/slow/shared');
		my $pid = $writer->{h}{'x-pid'};
		my $slow = start_reader('/slow/shared', $pid);
		my $quick = start_reader('/fast/shared', $pid);
		my $timed = start_reader('/timed/shared', $pid);
		is($slow->{h}{'x-pid'}, $quick->{h}{'x-pid'}, 'same reader worker');
		isnt($slow->{h}{'x-pid'}, $pid, 'different worker from the publisher');
		my $started = time;
		my $partial = $timed->{prefix} . read_body($timed, undef, 1);
		cmp_ok(time - $started, '<', 2, 'idle reader observes its own timeout');
		cmp_ok(length($partial), '<', length(origin_body($path, 1)),
			'reader timed out before writer released');
		# Drain the already published prefix before observing the release.
		my $available = length($partial) - length($slow->{prefix});
		$slow->{prefix} .= read_body($slow, $available) if $available > 0;
		ok(!IO::Select->new($slow->{socket})->can_read(0.12),
			'other reader still waiting');
		my $wakes = () = $t->read_file('error.log') =~ /http cache early wake:/g;
		cmp_ok($wakes, '<=', 3,
			'idle shared file does not repeatedly wake all readers');
		release_fill($t, $path);
		ok(IO::Select->new($slow->{socket})->can_read(2),
			'shorter interval also wakes the slow reader');
		for my $r ($writer, $slow, $quick) {
			ok($r->{prefix} . read_body($r) eq origin_body($path, 1),
				'body is complete');
		}
		is_deeply(origin_hits($t, $path), [''], 'one fill across both workers');
	};
}
finish_cache($t);
undef $t;
done_testing();
