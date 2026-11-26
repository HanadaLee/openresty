#!/usr/bin/perl

# Copyright (C) Hanada
# Active fills during writer replacement, worker exit, reload and purge.

use strict;
use warnings;
use Test::More;
use Time::HiRes qw/sleep time/;
use JSON::PP qw/decode_json/;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx;
use CacheEarlyRead;

my $t = Test::Nginx->new()->has(qw/http proxy cache/);
plan skip_all => 'requires nginx extensions on Linux' if $^O ne 'linux' || $t->has_module('--without-ext');
my $purge = $t->has_module('(?:ngx_(?:http_)?cache_purge(?:_module)?|/purge)(?:\s|$)');
my $http = 'proxy_cache_path cache keys_zone=c:4m use_temp_path=off;';
$http .= <<'EOF' if $purge;
cache_purge_index_store %%TESTDIR%%/store;
cache_purge_state_zone zone=purge:1m;
cache_key_namespace $http_x_namespace;
cache_key_host cache.test;
cache_key_scheme http;
cache_key_uri $uri;
EOF
my $control = $purge ? <<'EOF' : '';
location = /control { proxy_cache_purge on; cache_key_uri $http_x_target; }
location /ops/ { cache_purge_api; }
EOF
my $key = $purge ? 'proxy_cache_purge on; proxy_cache_key $cache_key_full;' : 'proxy_cache_key $uri;';
start_cache($t, $http, $control . "location / { $key\n" . <<'EOF');
    proxy_cache c;
    proxy_cache_valid 200 1m;
    proxy_cache_lock on;
    proxy_cache_lock_age 750ms;
    proxy_cache_lock_timeout 2s;
    proxy_read_timeout 2500ms;
    proxy_cache_lock_early_read on;
    proxy_pass http://127.0.0.1:8081;
}
EOF
my $seq = 0;
sub purge {
	my ($path, $action, $type, $ns) = @_;
	my $id = ++$seq;
	my $ms = int(time * 1000);
	my $r = fetch('/control', "X-Target: $path\r\nX-Namespace: " . ($ns || '')
		. "\r\nX-Cache-Purge-Type: " . ($type || 'url') . "\r\nX-Cache-Purge-Action: $action\r\n"
		. "X-Cache-Purge-Operation-Id: race-$id\r\nX-Cache-Purge-Issued-At: $ms\r\n", 'PURGE');
	is($r->{status}, 202, "$action $path accepted");
}
sub index_ready { decode_json(fetch('/ops/capabilities')->{body})->{ready} }
wait_for(\&index_ready, 'purge manager') if $purge;
my @killed;
my @cases = qw/age short/;
push @cases, qw/delete invalidate key prefix unrelated other-namespace before-attach excluded-vary/ if $purge;
# Restart workers last: the index handoff deliberately bypasses cache hits.
push @cases, qw/reader-exit writer-exit reload/;
@cases = ('guard') if legacy_guard($t);
for my $mode (@cases) {
	my $path = "/$mode/object";
	my $a = headers(send_req(socket_for(), $path));
	my $pid = $a->{h}{'x-pid'};
	my $first = read_body($a, 1);
	my $b = socket_for($pid);
	my $v1 = origin_body($path, 1);
	my $v2 = origin_body($path, 2);
	if ($mode =~ /^(guard|before-attach|excluded-vary)$/) {
		purge($path, 'delete') if $mode eq 'before-attach';
		purge('/other/', 'delete', 'prefix') if $mode eq 'excluded-vary';
		my $r = send_req($b, $path);
		if ($mode eq 'guard') {
			ok(!IO::Select->new($b)->can_read(0.25), 'legacy purge guard keeps the follower waiting');
		}
		release_fill($t, $path);
		headers($r);
		my $new = $mode eq 'before-attach';
		is($r->{h}{'x-cache'}, $new ? 'MISS' : 'HIT', "$mode follower status");
		ok(read_body($r) eq ($new ? $v2 : $v1), "$mode follower generation");
		ok($first . read_body($a) eq $v1, "$mode writer generation");
		is(scalar @{origin_hits($t, $path)}, $new ? 2 : 1, "$mode origin count");
		my $hit = fetch($path);
		is($hit->{h}{'x-cache'}, 'HIT', "$mode subsequent hit");
		ok($hit->{body} eq ($new ? $v2 : $v1), "$mode cached generation");
		next;
	}
	my $r = headers(send_req($b, $path));
	my $other = $r->{h}{'x-pid'};
	isnt($other, $pid, "$mode different workers"); is($r->{h}{'x-cache'}, 'MISS', "$mode reader attached");
	my $prefix = read_body($r, 8192);
	ok($prefix eq substr($v1, 0, 8192), "$mode early body");
	my $manager;
	if ($mode =~ /^(writer|reader)-exit$/) {
		my $victim = $mode eq 'writer-exit' ? $pid : $other;
		kill('KILL', $victim) == 1 or die "kill $victim: $!";
		push @killed, $victim;
	} elsif ($mode eq 'reload') {
		($manager) = $t->read_file('error.log') =~ /start cache manager process (\d+)/;
		die 'cache manager pid not found' if $purge && !$manager;
		$t->reload();
		wait_for(sub {
			my $n = fetch('/pid')->{body};
			$n =~ /^\d+$/ && $n != $pid && $n != $other;
		}, 'new worker');
	} elsif ($mode eq 'age') {
		sleep 0.80;
		my $next = fetch($path);
		is($next->{h}{'x-cache'}, 'MISS', 'new lock owner'); ok($next->{body} eq $v2, 'replacement fill');
	} elsif ($mode eq 'key') { purge($path, 'delete', 'key'); }
	elsif ($mode eq 'prefix') { purge('/other-prefix/', 'delete', 'prefix'); }
	elsif ($mode eq 'unrelated') { purge('/other/object', 'delete'); }
	elsif ($mode eq 'other-namespace') { purge($path, 'delete', 'url', 'other'); }
	elsif ($mode ne 'short') { purge($path, $mode); }
	release_fill($t, $path);
	my $same = $mode =~ /^(reload|unrelated|other-namespace|reader-exit)$/;
	if ($same || $mode eq 'age') {
		ok($first . read_body($a) eq $v1, "$mode writer finished");
		ok($prefix . read_body($r) eq $v1, "$mode pinned generation") unless $mode eq 'reader-exit';
	} else {
		read_body($r, undef, 1); cmp_ok($r->{left}, '>', 0, "$mode interrupted follower");
		ok($first . read_body($a) eq $v1, "$mode writer finished") unless $mode =~ /^(short|writer-exit)$/;
		my $next = fetch($path); is($next->{h}{'x-cache'}, 'MISS', "$mode refetch"); ok($next->{body} eq $v2, "$mode new generation");
	}
	if ($mode eq 'reload' && $purge) {
		wait_for(sub { !kill(0, $manager) }, 'old cache manager exit', 10);
		wait_for(\&index_ready, 'cache lookups after reload');
	}
	my $hit = fetch($path);
	is($hit->{h}{'x-cache'}, 'HIT', "$mode subsequent hit");
	ok($hit->{body} eq ($same ? $v1 : $v2), "$mode cached generation");
	is(scalar @{origin_hits($t, $path)}, $same ? 1 : 2, "$mode origin count");
}
finish_cache($t, @killed);
undef $t;
done_testing();
