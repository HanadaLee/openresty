#!/usr/bin/perl

# Copyright (C) Hanada
# Expired cache refresh coalescing, bounded waits, generation handoff and purge.

use strict;
use warnings;

use Test::More;
use Time::HiRes qw/sleep time/;
use IO::Socket::INET;
use IO::Select;
use Digest::MD5 qw/md5_hex/;
use Fcntl qw/:flock SEEK_SET/;
use POSIX ();
use JSON::PP qw/decode_json/;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx qw/:DEFAULT http_end/;

my $t = Test::Nginx->new()->has(qw/http proxy cache ngx_expr_module/);
plan skip_all => 'requires nginx extensions on Linux'
	if $^O ne 'linux' || $t->has_module('--without-ext');
my $purge = $t->has_module('(?:ngx_(?:http_)?cache_purge(?:_module)?|/purge)(?:\s|$)');
my $dir = $t->testdir();
chmod 0755, $dir or die "chmod test directory: $!";
for my $name (qw/cache store/) {
	mkdir "$dir/$name" or die "mkdir $name: $!";
	chmod 0777, "$dir/$name" or die "chmod $name: $!";
}
my $threads = $t->has_module('--with-threads');
my $aio = $threads
	? 'location /threads/ { aio threads; proxy_pass http://127.0.0.1:8081; }' : '';
my $extra = $purge ? <<'EOF' : '';
    cache_purge_index_store %%TESTDIR%%/store;
    cache_purge_state_zone zone=purge:1m;
    cache_key_host cache.test;
    cache_key_scheme http;
    cache_key_uri $uri;
EOF
my $control = $purge ? <<'EOF' : '';
        location = /control {
            proxy_cache_purge on;
            cache_key_uri $http_x_target;
        }
        location /ops/ {
            cache_purge_api;
        }
EOF
my $key = $purge ? 'proxy_cache_purge on; proxy_cache_key $cache_key_full;'
	: 'proxy_cache_key $uri;';
my $age_key = $purge ? 'cache_key_uri /age-switch; proxy_cache_key $cache_key_full;'
	: 'proxy_cache_key age-switch;';
$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
master_process on;
worker_processes 2;
events {
    accept_mutex off;
}
http {
    %%TEST_GLOBALS_HTTP%%
    proxy_cache_path %%TESTDIR%%/cache levels=1:2 keys_zone=c:4m use_temp_path=off;
    $extra
    server {
        listen 127.0.0.1:8080;
        expr enabled str_in \$http_x_enable yes;
        expr aged num_ge \$request_time 0.1;
        add_header X-Cache \$upstream_cache_status always;
        proxy_cache c;
        $key
        proxy_cache_lock on;
        proxy_cache_lock_expired on;
        proxy_cache_lock_poll_interval 20ms;
        proxy_cache_lock_timeout 1500ms;
        proxy_cache_lock_age 5s;
        proxy_cache_revalidate on;
        proxy_cache_valid 200 1s;
        proxy_read_timeout 10s;
        open_file_cache max=100 inactive=30s;
        open_file_cache_valid 60s;
        $control
        location = /pid {
            return 200 \$pid;
        }
        $aio
        location /off/ {
            proxy_cache_lock_expired off;
            proxy_pass http://127.0.0.1:8081;
        }
        location /nolock/ {
            proxy_cache_lock off;
            proxy_pass http://127.0.0.1:8081;
        }
        location /norevalidate/ {
            proxy_cache_revalidate off;
            proxy_pass http://127.0.0.1:8081;
        }
        location /zero/ {
            proxy_cache_lock_timeout 0;
            proxy_pass http://127.0.0.1:8081;
        }
        location /timeout/ {
            proxy_cache_lock_timeout 125ms;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /age-seed {
            $age_key
            proxy_cache_lock_age 60s;
            proxy_pass http://127.0.0.1:8081/age-switch-200;
        }
        location = /age-short {
            $age_key
            proxy_cache_lock_age 150ms;
            proxy_cache_lock_poll_interval 4s;
            proxy_cache_lock_timeout 2s;
            proxy_pass http://127.0.0.1:8081/age-switch-200;
        }
        location /reload/ {
            proxy_cache_lock_age 30s;
            proxy_pass http://127.0.0.1:8081;
        }
        location /age/ {
            proxy_cache_lock_age 150ms;
            proxy_pass http://127.0.0.1:8081;
        }
        location /stale/ {
            proxy_cache_use_stale updating;
            proxy_pass http://127.0.0.1:8081;
        }
        location /background/ {
            proxy_cache_use_stale updating;
            proxy_cache_background_update on;
            proxy_pass http://127.0.0.1:8081;
        }
        location /background-conditional/ {
            when aged {
                proxy_cache_lock_expired on;
            }
            proxy_cache_lock_expired off;
            proxy_cache_use_stale updating;
            proxy_cache_background_update on;
            proxy_set_header X-Origin-Time \$request_time;
            add_header X-Cache \$upstream_cache_status always;
            add_header X-Request-Time \$request_time always;
            proxy_pass http://127.0.0.1:8081;
        }
        location /must/ {
            proxy_cache_use_stale updating;
            proxy_cache_background_update on;
            proxy_pass http://127.0.0.1:8081;
        }
        location /error/ {
            proxy_cache_use_stale error http_500;
            proxy_pass http://127.0.0.1:8081;
        }
        location /conditional/ {
            when enabled {
                proxy_cache_lock_expired on;
            }
            proxy_cache_lock_expired off;
            proxy_pass http://127.0.0.1:8081;
        }
        location / {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}
EOF
$t->run_daemon(\&origin, $dir);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

sub wait_for {
	my ($test, $why, $timeout) = @_;
	my $until = time + ($timeout // 5);
	until ($test->()) {
		die "timed out waiting for $why\n" if time > $until;
		sleep 0.01;
	}
}

sub hits {
	my ($uri) = @_;
	my $name = "$dir/" . md5_hex($uri) . '.hits';
	return [] unless -e $name;
	open my $f, '<', $name or die "open hits: $!";
	flock($f, LOCK_SH) or die "flock hits: $!";
	chomp(my @hits = <$f>);
	return \@hits;
}

sub release {
	my ($uri, $n) = @_;
	$t->write_file(md5_hex($uri) . ".$n.go", '1');
}

sub begin {
	my ($uri, $headers) = @_;
	return http("GET $uri HTTP/1.1\r\nHost: localhost\r\n" . ($headers || '')
		. "Connection: close\r\n\r\n", start => 1);
}

sub finish {
	my ($socket) = @_;
	my $raw = http_end($socket);
	my ($status) = $raw =~ /^HTTP\/1.[01] (\d+)/;
	my ($cache) = $raw =~ /^X-Cache: ([^\r\n]+)/mi;
	my (undef, $body) = split /\r\n\r\n/, $raw, 2;
	return {status => $status || 0, cache => $cache || '', body => $body || '', raw => $raw};
}

sub get {
	finish(begin(@_));
}

sub warm {
	my ($uri, $header) = @_;
	my $r = get($uri, $header);
	is($r->{cache}, 'MISS', "$uri warm miss");
	is(get($uri, $header)->{cache}, 'HIT', "$uri warm hit");
	sleep 2.05;
}

sub coalesce {
	my ($uri, $header, $status, $body) = @_;
	warm($uri, $header);
	my $a = begin($uri, $header);
	wait_for(sub { @{hits($uri)} == 2 }, "$uri owner");
	my @b = map { begin($uri, $header) } 1 .. 5;
	sleep 0.15;
	is(scalar @{hits($uri)}, 2, "$uri one refresh across workers");
	release($uri, 2);
	my $first = finish($a);
	is($first->{cache}, $status, "$uri owner status");
	is($first->{body}, $body, "$uri owner body");
	my @r = map { finish($_) } @b;
	is(scalar(grep { $_->{cache} eq 'HIT' } @r), 5, "$uri followers reopen as HIT");
	is(scalar(grep { $_->{body} eq $body } @r), 5, "$uri follower bodies");
	is(scalar @{hits($uri)}, 2, "$uri exactly one origin refresh");
}

# The main request has already spent time reading its headers, while its new
# background child evaluates $request_time from its own request start.
sub background_conditional {
	my $uri = '/background-conditional/200';
	warm($uri);
	my $a = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
		PeerPort => port(8080), Proto => 'tcp') or die "connect: $!";
	$a->autoflush(1);
	print $a "GET $uri HTTP/1.1\r\nHost: localhost\r\n";
	sleep 0.25;
	print $a "Connection: close\r\n\r\n";
	wait_for(sub { @{hits($uri)} == 2 }, 'conditional background child reaches origin');
	open my $f, '<', "$dir/" . md5_hex($uri) . '.times' or die "open times: $!";
	my @times = <$f>;
	close $f;
	cmp_ok($times[1], '<', 0.1, 'background child reevaluates conditional option off');
	release($uri, 2);
	my $r = finish($a);
	is($r->{cache}, 'STALE', 'conditional main request starts background owner');
	my ($elapsed) = $r->{raw} =~ /^X-Request-Time: ([^\r\n]+)/mi;
	cmp_ok($elapsed // 0, '>=', 0.1, 'main request enables conditional expired lock');
	release($uri, 3);
	$r = get($uri);
	is($r->{cache}, 'HIT', 'background child inherits already acquired parent lease');
	is($r->{body}, 'body-2', 'conditional background owner commits refreshed entity');
}

if ($purge) {
	wait_for(sub { decode_json(get('/ops/capabilities')->{body})->{ready} }, 'purge index');
}

background_conditional();
coalesce('/on/304', '', 'REVALIDATED', 'body-1');
coalesce('/on/200', '', 'EXPIRED', 'body-2');
coalesce('/norevalidate/304', '', 'EXPIRED', 'body-2');
coalesce('/on/no-validator', '', 'EXPIRED', 'body-2');
coalesce('/threads/200', '', 'EXPIRED', 'body-2') if $threads;
coalesce('/must/304', '', 'REVALIDATED', 'body-1');
coalesce('/conditional/304', "X-Enable: yes\r\n", 'REVALIDATED', 'body-1');

for my $uri ('/off/304', '/nolock/304', '/conditional/off') {
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, "$uri first refresh");
	my $b = begin($uri);
	wait_for(sub { @{hits($uri)} == 3 }, "$uri independent refresh");
	release($uri, 2);
	release($uri, 3);
	is(finish($a)->{status}, 200, "$uri first response");
	is(finish($b)->{status}, 200, "$uri second response");
}

for my $uri ('/timeout/304', '/zero/304') {
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, "$uri owner");
	my $started = time;
	my $b = begin($uri);
	wait_for(sub { @{hits($uri)} == 3 }, "$uri independent timeout origin");
	cmp_ok(time - $started, '<', 0.45, "$uri absolute deadline");
	is(hits($uri)->[2], '-', "$uri strips cache-generated validator");
	release($uri, 3);
	my $r = finish($b);
	is($r->{status}, 200, "$uri timeout gives entity, not bare 304");
	is($r->{body}, 'body-3', "$uri uncached entity");
	release($uri, 2);
	is(finish($a)->{cache}, 'REVALIDATED', "$uri owner kept its lock");
	is(get($uri)->{body}, 'body-1', "$uri timeout response did not replace cache");
}

# Preserve validators supplied by a client taking the independent timeout path.
{
	my $uri = '/zero/client';
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, 'client validator owner');
	my $b = begin($uri, "If-None-Match: \"client\"\r\n");
	wait_for(sub { @{hits($uri)} == 3 }, 'client validator independent origin');
	is(hits($uri)->[2], '"client"', 'client validator preserved');
	release($uri, 3);
	is(finish($b)->{status}, 304, 'client conditional response preserved');
	release($uri, 2);
	finish($a);
}

for my $case ('200', 'late-304', '200-after', 'late-304-after') {
	my $uri = "/age/$case";
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, "$uri original owner");
	sleep 0.2;
	my $b = begin($uri);
	wait_for(sub { @{hits($uri)} == 3 }, "$uri new owner");
	if ($case =~ /-after$/) {
		release($uri, 3);
		is(finish($b)->{body}, 'body-3', "$uri replacement published first");
		release($uri, 2);
		finish($a);
		is(get($uri)->{body}, 'body-3',
			"$uri late old owner cannot overwrite committed replacement");
	} else {
		release($uri, 2);
		finish($a);
		my $c = begin($uri);
		sleep 0.08;
		is(scalar @{hits($uri)}, 3, "$uri late owner cannot unlock replacement");
		release($uri, 3);
		is(finish($b)->{body}, 'body-3', "$uri replacement owner entity");
		is(finish($c)->{body}, 'body-3', "$uri follower entity");
		is(get($uri)->{body}, 'body-3', "$uri old owner cannot overwrite replacement");
	}
}

# The same key can be populated by a location with a much longer lock age.
# Owner identity must not turn that old deadline into the next round's age.
{
	my $origin = '/age-switch-200';
	is(get('/age-seed')->{cache}, 'MISS', 'long-age cold owner seeded shared key');
	is(get('/age-short')->{cache}, 'HIT', 'short-age location shares the seeded key');
	sleep 2.05;
	my $a = begin('/age-short');
	wait_for(sub { @{hits($origin)} == 2 }, 'short-age expired owner');
	my $started = time;
	my $b = begin('/age-short');
	wait_for(sub { @{hits($origin)} == 3 }, 'short-age takeover despite long poll', 0.7);
	cmp_ok(time - $started, '<', 0.65,
		'first wait is bounded by 150ms age, not old 60s age or 4s poll');
	release($origin, 3);
	is(finish($b)->{body}, 'body-3', 'short-age replacement published');
	release($origin, 2);
	is(finish($a)->{body}, 'body-2',
		'replaced short-age owner still receives its response');
	is(get('/age-short')->{body}, 'body-3', 'separate generation excludes late old owner');
}

for my $uri ('/stale/304', '/background/304') {
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, "$uri refresh started");
	is(get($uri)->{cache}, 'UPDATING', "$uri stale policy wins before wait");
	release($uri, 2);
	my $r = finish($a);
	is($r->{cache}, $uri =~ /background/ ? 'STALE' : 'REVALIDATED',
		"$uri refresh owner status");
	wait_for(sub { get($uri)->{cache} eq 'HIT' }, "$uri committed");
	is(scalar @{hits($uri)}, 2, "$uri background avoids waiting on its own lock");
}

# A failed owner releases the round without handing every follower write access.
{
	my $uri = '/error/fail';
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, 'failed owner');
	my $b = begin($uri);
	release($uri, 2);
	is(finish($a)->{cache}, 'STALE', 'owner stale-if-error policy retained');
	wait_for(sub { @{hits($uri)} == 3 }, 'follower re-elected after failure');
	release($uri, 3);
	is(finish($b)->{body}, 'body-3', 'follower completes after owner failure');
}

# The initiating client can leave while another request finishes the refresh.
{
	my $uri = '/on/abort-fail';
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, 'aborted owner');
	my $b = begin($uri);
	close $a;
	release($uri, 2);
	wait_for(sub { @{hits($uri)} == 3 }, 'follower after client abort and owner failure');
	release($uri, 3);
	is(finish($b)->{body}, 'body-3', 'follower survives initiating client abort');
	release($uri, 2);
	is(get($uri)->{body}, 'body-3', 'aborted owner does not reclaim cache');
}

# Native policy can keep a cacheable origin alive after the client leaves.
# A follower's timeout then permits an uncached independent response.
{
	my $uri = '/on/abort-continues';
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, 'continuing origin after abort');
	my $b = begin($uri);
	close $a;
	wait_for(sub { @{hits($uri)} == 3 }, 'independent follower after abort timeout');
	is(hits($uri)->[2], '-', 'abort timeout follower has no cache validator');
	release($uri, 3);
	is(finish($b)->{body}, 'body-3', 'abort timeout follower gets independent entity');
	release($uri, 2);
	release($uri, 4);
	my $fresh = get($uri);
	like($fresh->{body}, qr/^body-[24]$/,
		'abort timeout response did not acquire write permission');
	is(get($uri)->{body}, $fresh->{body}, 'cache continues after initiating client abort');
}

# Distinct Vary variants elect independently and reopen the correct inode.
{
	my $uri = '/on/vary-304';
	my $en = "Accept-Language: en\r\n";
	my $de = "Accept-Language: de\r\n";
	is(get($uri, $en)->{body}, 'body-1-en', 'first Vary variant warm');
	release($uri, 2);
	is(get($uri, $de)->{body}, 'body-2-de', 'secondary Vary variant warm');
	sleep 2.05;
	my $a = begin($uri, $en);
	wait_for(sub { @{hits($uri)} == 3 }, 'first Vary refresh');
	my $b = begin($uri, $de);
	wait_for(sub { @{hits($uri)} == 4 }, 'secondary Vary refresh');
	my $c = begin($uri, $en);
	my $d = begin($uri, $de);
	sleep 0.1;
	is(scalar @{hits($uri)}, 4, 'one refresh per variant');
	release($uri, 3);
	release($uri, 4);
	is(finish($a)->{body}, 'body-1-en', 'first Vary owner body');
	is(finish($b)->{body}, 'body-2-de', 'secondary Vary owner body');
	my $r = finish($c);
	is($r->{cache}, 'HIT', 'first Vary follower reopened');
	is($r->{body}, 'body-1-en', 'first Vary follower body');
	$r = finish($d);
	is($r->{cache}, 'HIT', 'secondary Vary follower reopened');
	is($r->{body}, 'body-2-de', 'secondary Vary follower body');
}

# Existing workers keep a live lease while new workers accept followers.
{
	my $uri = '/reload/200';
	warm($uri);
	my $a = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, 'reload original owner');
	my $log = $t->read_file('error.log');
	my %old = map { $_ => 1 } $log =~ /start worker process (\d+)/g;
	my ($manager) = $log =~ /start cache manager process (\d+)/;
	die 'cache manager pid not found' if $purge && !$manager;
	$t->reload();
	wait_for(sub {
		my $pid = get('/pid')->{body};
		$pid =~ /^\d+$/ && !$old{$pid};
	}, 'replacement worker');
	# The shared ready flag can still belong to the retiring manager.
	wait_for(sub { !kill(0, $manager) }, 'old cache manager exit', 10) if $purge;
	wait_for(sub { decode_json(get('/ops/capabilities')->{body})->{ready} },
		'purge manager after reload', 10) if $purge;
	my $b = begin($uri);
	sleep 0.1;
	is(scalar @{hits($uri)}, 2, 'reload preserves the in-flight lease');
	release($uri, 2);
	is(finish($a)->{body}, 'body-2', 'old worker completes cache owner');
	my $r = finish($b);
	is($r->{cache}, 'HIT', 'new worker follower reopens after old worker publication');
	is($r->{body}, 'body-2', 'new worker receives the published generation');
}

if ($purge) {
	my $seq = 0;
	for my $case ('delete', 'invalidate', 'delete-late-304', 'invalidate-late-304') {
		my ($action) = $case =~ /^(delete|invalidate)/;
		my $uri = "/on/purge-$case";
		warm($uri);
		my $a = begin($uri);
		wait_for(sub { @{hits($uri)} == 2 }, "$action old owner");
		my $b = begin($uri);
		my $ms = int(time * 1000);
		my $r = http("PURGE /control HTTP/1.1\r\nHost: localhost\r\n"
			. "X-Target: $uri\r\nX-Cache-Purge-Type: url\r\n"
			. "X-Cache-Purge-Action: $action\r\nX-Cache-Purge-Operation-Id: expired-"
			. ++$seq . "\r\nX-Cache-Purge-Issued-At: $ms\r\nConnection: close\r\n\r\n");
		like($r, qr/^HTTP\/1.[01] 202 /, "$action purge accepted");
		release($uri, 2);
		finish($a);
		wait_for(sub { @{hits($uri)} == 3 }, "$action purge follower refresh");
		release($uri, 3);
		is(finish($b)->{body}, 'body-3', "$action follower uses post-purge entity");
		release($uri, 4);
		my $fresh = get($uri);
		like($fresh->{body}, qr/^body-[34]$/,
			"$action old refresh did not revive deleted entity");
		is(get($uri)->{body}, $fresh->{body}, "$action subsequent fresh entity");
	}
}

$t->stop();
my $log = $t->read_file('error.log');
unlike($log, qr/\[(?:alert|crit)\]/, 'no cache cleanup or descriptor lifecycle alerts');
undef $t;
done_testing();

sub serve {
	my ($client, $dir) = @_;
	my $request = <$client> || return;
	my ($uri) = $request =~ /^GET (\S+) / or return;
	my $validator = '-';
	my $lang = '';
	my $request_time = '-';
	while (<$client>) {
		last if /^\r?\n$/;
		$validator = $1 if /^If-None-Match:\s*([^\r\n]+)/i;
		$lang = $1 if /^Accept-Language:\s*([^\r\n]+)/i;
		$request_time = $1 if /^X-Origin-Time:\s*([^\r\n]+)/i;
	}
	my $key = "$dir/" . md5_hex($uri);
	open my $f, '+>>', "$key.hits" or die "open hits: $!";
	flock($f, LOCK_EX) or die "flock: $!";
	seek($f, 0, SEEK_SET) or die "seek: $!";
	my @previous = <$f>;
	my $n = @previous + 1;
	print {$f} "$validator\n";
	close $f;
	open my $times, '>>', "$key.times" or die "open times: $!";
	print {$times} "$request_time\n";
	close $times;
	wait_for(sub { -e "$key.$n.go" }, "$uri origin release $n", 15) if $n > 1;
	my $not_modified = $n > 1 && $validator ne '-'
		&& ($uri =~ /304/ && $uri !~ /late-304/ || $uri =~ /late-304/ && $n == 2
			|| $uri =~ /client/ && $validator eq '"client"');
	my $fail = $uri =~ /fail/ && $n == 2;
	my $status = $fail ? '500 Internal Server Error'
		: $not_modified ? '304 Not Modified' : '200 OK';
	my $body = $not_modified ? '' : "body-$n";
	$body .= "-$lang" if !$not_modified && $uri =~ /vary/;
	my $cc = 'max-age=1' . ($uri =~ m{^/must/} ? ', must-revalidate' : '');
	my $etag = $uri =~ /no-validator/ ? '' : "ETag: \"one\"\r\n";
	my $vary = $uri =~ /vary/ ? "Vary: Accept-Language\r\n" : '';
	$client->autoflush(1);
	print $client "HTTP/1.1 $status\r\nContent-Length: " . length($body)
		. "\r\nCache-Control: $cc\r\n$etag$vary" . "Connection: close\r\n\r\n$body";
}

sub origin {
	my ($dir) = @_;
	my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
		LocalPort => port(8081), Listen => 64, ReuseAddr => 1) or die "listen: $!";
	$SIG{CHLD} = 'IGNORE';
	while (my $client = $server->accept()) {
		my $pid = fork();
		die "fork: $!" unless defined $pid;
		if (!$pid) {
			$SIG{PIPE} = 'IGNORE';
			close $server;
			eval { serve($client, $dir) };
			close $client;
			POSIX::_exit(0);
		}
		close $client;
	}
}
