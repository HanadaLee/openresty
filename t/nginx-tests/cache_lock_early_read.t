#!/usr/bin/perl

# Copyright (C) Hanada
# A follower on another worker reads an unfinished cache file and survives
# cancellation of the request that started the fill.

use strict;
use warnings;
use Test::More;
use Socket qw/SOL_SOCKET SO_LINGER/;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx;
use Test::Nginx::HTTP2;
use Test::Nginx::HTTP3;
use CacheEarlyRead;

my $t = Test::Nginx->new()->has(qw/http proxy cache/);
plan skip_all => 'requires nginx extensions on Linux' if $^O ne 'linux' || $t->has_module('--without-ext');
my $slice = $t->has_module('http_slice');
my $h2 = $t->has_module('http_v2') && $t->has_feature('socket_ssl_alpn');
my $h3 = $t->has_module('http_v3') && $t->has_feature('cryptx');
my $dir = $t->testdir();
my $tls = '';
if ($h2 || $h3) {
	$t->has_daemon('openssl');
	$t->write_file('openssl.conf', "[req]\ndistinguished_name = dn\n[dn]\n");
	system('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-config', "$dir/openssl.conf",
		'-subj', '/CN=localhost', '-days', '1', '-keyout', "$dir/test.key", '-out', "$dir/test.crt") == 0 or die 'openssl req';
	$tls = "ssl_certificate test.crt; ssl_certificate_key test.key;\n";
	$tls .= "listen 127.0.0.1:8082 ssl reuseport; http2 on;\n" if $h2;
	$tls .= "listen 127.0.0.1:%%PORT_8980_UDP%% quic reuseport;\n" if $h3;
}
my $locations = $slice ? <<'EOF' : '';
location /slice/ {
    slice on;
    slice_size 128k;
    proxy_cache_key $uri$slice_range;
    proxy_set_header Range $slice_range;
    proxy_pass http://127.0.0.1:8081;
}
location /saved/ {
    slice on;
    slice_size 128k;
    set $saved_range $slice_range;
    proxy_cache_key $uri$saved_range;
    proxy_set_header Range $saved_range;
    proxy_pass http://127.0.0.1:8081;
}
EOF
start_cache($t, 'proxy_cache_path cache levels=1:2 keys_zone=c:4m use_temp_path=off;', $tls . $locations . <<'EOF');
proxy_cache c;
proxy_cache_valid 200 206 1m;
proxy_cache_lock on;
proxy_cache_lock_age 5s;
proxy_cache_lock_timeout 2s;
proxy_cache_lock_early_read on;
proxy_ignore_client_abort off;
location /obj/ {
    proxy_cache_key $uri;
    proxy_pass http://127.0.0.1:8081;
}
location /range/ {
    proxy_cache_key $uri|$http_range;
    proxy_set_header Range $http_range;
    proxy_pass http://127.0.0.1:8081;
}
EOF

# A framed connection stays open after stream cancellation. Probe /pid on
# that connection first so selection itself never starts another cache fill.
sub framed {
	my ($proto) = @_;
	if ($proto eq 'h2') {
		my $c = Test::Nginx::HTTP2->new(port(8082), SSL => 1, alpn => 'h2');
		$c->h2_window(1 << 21);
		$c->h2_settings(0, 4 => 1 << 20);
		return $c;
	}
	my $c = Test::Nginx::HTTP3->new();
	$c->h3_max_data(1 << 21);
	return $c;
}

sub stream {
	my ($c, $proto, $path, $range) = @_;
	my @h = (':method' => 'GET', ':scheme' => 'https', ':authority' => 'localhost', ':path' => $path);
	push @h, range => $range if length $range;
	my @fields;
	push @fields, { name => shift @h, value => shift @h } while @h;
	my $id = $c->new_stream({ headers => \@fields });
	$c->h3_max_data(1 << 20, $id) if $proto eq 'h3';
	return { conn => $c, id => $id, body => '', h => {}, proto => $proto };
}

sub frames {
	my ($r, $end) = @_;
	my $partial = !$end && $r->{proto} eq 'h3';
	wait_for(sub {
		my $frames = $r->{conn}->read(all => [{ sid => $r->{id}, $end ? (fin => 1) : (type => 'DATA') }],
			wait => $partial ? 0.10 : 3);
		for (@$frames) {
			next unless defined $_->{sid} && $_->{sid} == $r->{id};
			$r->{h} = $_->{headers} if $_->{type} eq 'HEADERS';
			$r->{body} .= $_->{data} if $_->{type} eq 'DATA';
			$r->{end} = 1 if ($_->{type} eq 'DATA' || $_->{type} eq 'HEADERS') && ($_->{flags} & 1);
		}
		# nginx may declare a single DATA frame for the full Content-Length.
		# HTTP3.pm returns it only when complete. Inspect its buffered prefix
		# without consuming it, so read() still validates the entire frame.
		if ($partial && !length($r->{body})) {
			my $f = $r->{conn}{frames_incomplete}[$r->{id}];
			if ($f && defined $f->{type} && $f->{type} == 0 && length($f->{buf}) > $f->{offset}) {
				$r->{prefix} = substr($f->{buf}, $f->{offset});
			}
		}
		return $end ? $r->{end} : length($r->{body}) || length($r->{prefix} // '');
	}, "$r->{proto} response on stream $r->{id}");
}

sub begin_read {
	my ($proto, $path, $range, $other) = @_;
	if ($proto eq 'h1') {
		my $s = socket_for($other);
		my $r = headers(send_req($s, $path, $range ? "Range: $range\r\n" : ''));
		$r->{h}{':status'} = $r->{status}; $r->{body} = read_body($r, 8192);
		return $r;
	}
	for (1 .. 100) {
		my $c = framed($proto);
		if (defined $other) {
			my $pid = stream($c, $proto, '/pid', '');
			frames($pid, 1);
			next if $other == $pid->{body};
		}
		my $r = stream($c, $proto, $path, $range);
		frames($r, 0);
		return $r;
	}
	die "could not select another $proto worker";
}

sub cancel_fill {
	my ($proto, $r) = @_;
	my $pid = $r->{h}{'x-pid'};
	my $marker;
	open my $log, '<', "$dir/error.log" or die "error.log: $!";
	seek $log, 0, 2 or die "seek: $!";
	if ($proto eq 'h1') {
		setsockopt($r->{socket}, SOL_SOCKET, SO_LINGER, pack('ii', 1, 0)) or die "setsockopt: $!";
		close $r->{socket}; $marker = qr/prematurely closed connection|Connection reset by peer/;
	} elsif ($proto eq 'h2') {
		$r->{conn}->h2_rst($r->{id}, 8); $marker = qr/client canceled stream $r->{id}\b/;
	} else {
		$r->{conn}->stop_sending($r->{id}, 0x10c);
		my $id = sprintf '%x', $r->{id}; $marker = qr/STOP_SENDING id:0x$id err:0x10c/;
	}
	if ($proto ne 'h1') {
		my $probe = stream($r->{conn}, $proto, '/pid', '');
		frames($probe, 1);
		is($probe->{body}, $pid, "$proto connection survives cancellation");
	}
	wait_for(sub {
		seek $log, 0, 1; # clear EOF before reading newly appended debug lines
		while (<$log>) { return 1 if / $pid#/ && /$marker/; }
		return 0;
	}, "$proto worker to process cancellation before releasing the origin");
}

my $first = 'bytes=0-131071';
my $second = 'bytes=131072-262143';
my @locations = ('obj', 'range', $slice ? ('slice', 'saved') : ());

sub check_pair {
	my ($proto, $reader, $loc) = @_;
	my $path = "/$loc/$proto-$reader";
	my $range = $loc eq 'obj' ? '' : $first;
	my $a = begin_read($proto, $path, $range);
	my $b = begin_read($reader, $path, $range, $a->{h}{'x-pid'});
	isnt($b->{h}{'x-pid'}, $a->{h}{'x-pid'}, "$path different workers");
	my $body = origin_body($path, 1, $range);
	for my $r ($a, $b) {
		is($r->{h}{'x-cache'}, 'MISS', "$path early status");
		is($r->{h}{':status'}, $range ? 206 : 200, "$path HTTP status");
		is($r->{h}{'content-range'}, $range ? 'bytes 0-131071/262144' : undef, "$path Content-Range");
		my $prefix = $r->{prefix} // $r->{body};
		ok(length($prefix) && $prefix eq substr($body, 0, length($prefix)), "$path early prefix");
	}
	cancel_fill($proto, $a);
	release_fill($t, $path);
	if ($reader eq 'h1') { $b->{body} .= read_body($b); } else { frames($b, 1); }
	ok($b->{body} eq $body, "$path follower receives complete body");
	my $hit = fetch($path, $range ? "Range: $range\r\n" : '');
	ok($hit->{h}{'x-cache'} eq 'HIT' && $hit->{body} eq $body, "$path subsequent hit");
	is_deeply(origin_hits($t, $path), [$range], "$path single origin");
}

if (legacy_guard($t)) {
	my $path = '/obj/guard';
	my $a = begin_read('h1', $path, '');
	my $b = send_req(socket_for($a->{h}{'x-pid'}), $path);
	ok(!IO::Select->new($b->{socket})->can_read(0.25), 'legacy guard waits for ordinary cache publication');
	release_fill($t, $path);
	headers($b);
	is($b->{h}{'x-cache'}, 'HIT', 'legacy guard: follower hit after publication');
	ok($a->{body} . read_body($a) eq origin_body($path, 1) && read_body($b) eq origin_body($path, 1), 'both bodies complete');
	is_deeply(origin_hits($t, $path), [''], 'one origin request');
} else {
	for my $location (grep { $_ ne 'obj' } @locations) {
		my $path = "/$location/independent";
		my $a = begin_read('h1', $path, $first);
		my $b = begin_read('h1', $path, $second, $a->{h}{'x-pid'});
		is($a->{status}, 206, "$location first partial response");
		is($b->{status}, 206, "$location second partial response");
		is($a->{h}{'content-range'}, 'bytes 0-131071/262144', "$location first range");
		is($b->{h}{'content-range'}, 'bytes 131072-262143/262144', "$location second range");
		is_deeply(origin_hits($t, $path), [$first, $second], "$location independent fills");
		release_fill($t, $path);
		for my $item ([$a, $first], [$b, $second]) {
			my ($r, $range) = @$item;
			my $body = origin_body($path, 1, $range);
			ok($r->{body} . read_body($r) eq $body, "$location distinct range bytes");
			my $hit = fetch($path, "Range: $range\r\n");
			ok($hit->{h}{'x-cache'} eq 'HIT' && $hit->{body} eq $body, "$location range hit");
		}
	}
	if ($slice) {
		my $path = '/slice/multi';
		my $body = origin_body($path, 1) . origin_body($path, 1, $second);
		my $a = headers(send_req(socket_for(), $path));
		my $prefix = read_body($a, 131073);
		my $b = headers(send_req(socket_for($a->{h}{'x-pid'}), $path));
		is($a->{status}, 200, 'assembled writer status');
		is($b->{status}, 200, 'assembled reader status');
		ok($prefix eq substr($body, 0, 131073) && read_body($b, 131073) eq $prefix,
			'second slice is available before origin completes');
		release_fill($t, $path);
		ok($prefix . read_body($a) eq $body && $prefix . read_body($b) eq $body, 'both sliced bodies complete');
		my $hit = fetch($path);
		ok($hit->{h}{'x-cache'} eq 'HIT' && $hit->{body} eq $body, 'assembled cache hit');
		is_deeply(origin_hits($t, $path), [$first, $second], 'one origin per slice');
	}
	SKIP: {
		skip 'cancellation acknowledgement needs a debug build', 1 unless $t->has_module('--with-debug');
		for my $proto (qw/h1 h2 h3/) {
			subtest $proto => sub {
				plan skip_all => 'HTTP/2 with ALPN unavailable' if $proto eq 'h2' && !$h2;
				plan skip_all => 'HTTP/3 or CryptX unavailable' if $proto eq 'h3' && !$h3;
				for my $reader ($proto eq 'h1' ? ('h1') : ('h1', $proto)) {
					for my $loc (@locations) {
						check_pair($proto, $reader, $loc);
					}
				}
			};
		}
	}
}
finish_cache($t);
undef $t;
done_testing();
