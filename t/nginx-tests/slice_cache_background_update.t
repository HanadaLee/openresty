#!/usr/bin/perl

# Copyright (C) Hanada

# Cache background updates retain only the current slice range.

use strict;
use warnings;

use Test::More;
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw/sleep time/;
use Digest::MD5 qw/md5_hex/;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy cache slice rewrite/);
plan skip_all => 'requires nginx extensions' if $t->has_module('--without-ext');
my $mirror = $t->has_module('mirror');
my $auth = $t->has_module('auth_request');
my $expr = $t->has_module('ngx_expr_module');
my $extra = $mirror ? <<'EOF' : '';
        location = /mirror-parent {
            proxy_cache off;
            set $prepared_range $slice_range;
            mirror /ordinary;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /ordinary {
            internal;
            proxy_cache off;
            proxy_pass http://127.0.0.1:8081;
        }
EOF
$extra .= <<'EOF' if $auth;
        location = /auth-parent {
            proxy_cache off;
            auth_request /ordinary-auth;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /ordinary-auth {
            internal;
            proxy_cache off;
            proxy_pass http://127.0.0.1:8081;
        }
EOF
$extra .= <<'EOF' if $expr;
        location = /conditional {
            slice off;
            expr enabled str_eq $uri /never;
            when enabled {
                slice on;
            }
            proxy_pass http://127.0.0.1:8081;
        }
EOF
my $conf = <<'EOF';
%%TEST_GLOBALS%%
worker_processes 2;
events {
}
http {
    %%TEST_GLOBALS_HTTP%%
    proxy_cache_path %%TESTDIR%%/cache keys_zone=c:1m;
    server {
        listen 127.0.0.1:8080;
        slice on;
        slice_size 8;
        proxy_set_header Range $slice_range;
        proxy_cache c;
        proxy_cache_key $uri$slice_range;
        proxy_cache_valid 200 206 1s;
        proxy_cache_use_stale updating;
        proxy_cache_background_update on;
        add_header X-Cache $upstream_cache_status always;
        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location = /bypass {
            slice_bypass 1;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /plain {
            slice off;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /noctx {
            proxy_set_header Range "";
            proxy_cache_key $uri;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /redirected {
            proxy_cache off;
            proxy_pass http://127.0.0.1:8081/ordinary-redirect;
        }
        EXTRA
    }
}
EOF
$conf =~ s/EXTRA/$extra/;
$t->write_file_expand('nginx.conf', $conf);
$t->write_file('version', '1');
$t->run_daemon(\&origin, $t->testdir());
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->run();

my @paths = qw/single multi multipart bad200 badrange bad416 redirect/;
for my $path (@paths) {
	my $r = get($path, $path eq 'multi' ? '' : '8-10');
	like($r, qr/^HTTP\/1\.1 (?:200|206) /, "$path warm response");
	is(body($r), $path eq 'multi' ? data(1) : substr(data(1), 8, 3),
		"$path warm body");
}
my @ordinary = (qw/plain noctx bypass/, $expr ? 'conditional' : ());
for my $path (@ordinary) {
	is(body(get($path)), data(1), "$path warm body");
}
# The multipart fixture must also contain the noninitial slices.
get('multipart', '24-25,0-1');
my $multipart_warm = hits('multipart');
$t->write_file('hold-multi', '1');
$t->write_file('hold-multipart', '1');
$t->write_file('version', '2');
sleep 2.1;

for my $path (@ordinary) {
	my $r = get($path);
	is(body($r), data(1), "$path stale body");
	is(body(refreshed($path)), data(2), "$path ordinary update remains valid");
	is_deeply(ranges($path), ['', ''], "$path has no artificial slice range");
}

my $r = get('single', '8-10');
like($r, qr/^X-Cache: STALE\r?$/m, 'single stale response');
is(body($r), substr(data(1), 8, 3), 'single stale body');
wait_for(sub { hits('single') >= 2 }, 'single background origin');
my $hit = refreshed('single', '8-10');
like($hit, qr/^X-Cache: HIT\r?$/m, 'single refreshed cache hit');
is(body($hit), substr(data(2), 8, 3), 'new ETag accepted');
is_deeply(ranges('single'), ['bytes=8-15', 'bytes=8-15'],
	'background key and origin retain the nonzero slice');

$r = get('multi');
is(body($r), data(1), 'all slices serve their stale bodies');
unlink $t->testdir() . '/hold-multi' or die $!;
wait_for(sub { hits('multi') >= 8 }, 'all background slices');
for my $start (0, 8, 16, 24) {
	refreshed('multi', "$start-" . ($start + 1));
}
$hit = refreshed('multi');
is(body($hit), data(2), 'all background slices refreshed');
is_deeply([sort @{ranges('multi')}],
	[sort map { my $s = "bytes=$_-" . ($_ + 7); ($s, $s) } (0, 8, 16, 24)],
	'parent cursor cannot change queued background ranges');

$r = get('multipart', '24-25,0-1');
like($r, qr/Content-Range: bytes 24-25\/32\r?\n\r?\nYZ\r?\n/s,
	'out of order multipart stale high slice');
like($r, qr/Content-Range: bytes 0-1\/32\r?\n\r?\nAB\r?\n/s,
	'out of order multipart stale low slice');
unlink $t->testdir() . '/hold-multipart' or die $!;
wait_for(sub { hits('multipart') >= $multipart_warm + 2 }, 'multipart background slices');
for my $start (0, 24) {
	refreshed('multipart', "$start-" . ($start + 1));
}
$hit = refreshed('multipart', '24-25,0-1');
like($hit, qr/Content-Range: bytes 24-25\/32\r?\n\r?\nyz\r?\n/s,
	'multipart background high slice refreshed');
like($hit, qr/Content-Range: bytes 0-1\/32\r?\n\r?\nab\r?\n/s,
	'multipart background low slice refreshed');
ok(!grep($_ eq '', @{ranges('multipart')}), 'multipart background always has range');

for my $path (qw/bad200 badrange bad416/) {
	$r = get($path, '8-10');
	like($r, qr/^X-Cache: STALE\r?$/m, "$path serves stale before rejected update");
	is(body($r), substr(data(1), 8, 3), "$path stale body survives background failure");
	wait_for(sub { hits($path) >= 2 }, "$path rejected background response");
}
wait_for(sub { hits('redirect') >= 1 }, 'redirect fixture');
$r = get('redirect', '8-10');
is(body($r), substr(data(1), 8, 3), 'redirect keeps frontend stale body');
wait_for(sub { hits('ordinary-redirect') >= 1 }, 'background internal redirect');
is_deeply(ranges('ordinary-redirect'), [''], 'internal redirect clears snapshot');

if ($mirror) {
	get('mirror-parent', '8-10');
	wait_for(sub { hits('ordinary') >= 1 }, 'ordinary mirror request');
	is_deeply(ranges('ordinary'), [''], 'ordinary background mirror has no slice snapshot');
}

if ($auth) {
	$r = get('auth-parent', '8-10');
	is(body($r), substr(data(2), 8, 3), 'parent slices after an empty auth range');
	is_deeply(ranges('auth-parent'), ['bytes=8-15'],
		'empty auth range cannot poison parent variables');
	wait_for(sub { hits('ordinary-auth') >= 1 }, 'ordinary auth request');
	is_deeply(ranges('ordinary-auth'), [''], 'ordinary auth request has no slice snapshot');
}

# A rejected refresh must leave the previous cache file intact, then recover.
sleep 0.1;
$t->write_file('version', '3');
for my $path (qw/bad200 badrange bad416/) {
	$r = get($path, '8-10');
	is(body($r), substr(data(1), 8, 3), "$path did not replace old slice");
	$hit = refreshed($path, '8-10');
	is(body($hit), substr(data(3), 8, 3), "$path later valid update recovers");
	like($hit, qr/^X-Cache: HIT\r?$/m, "$path recovery is cached");
}

$t->stop();
my $log = $t->read_file('error.log');
unlike($log, qr/\[alert\]|AddressSanitizer|runtime error:/, 'no unexpected runtime errors');
like($log, qr/unexpected status code 200 in slice response/, '200 refresh rejected by slice');
like($log, qr/unexpected range in slice response/, 'incorrect 206 rejected by slice');
like($log, qr/unexpected status code 416 in slice response/, '416 refresh rejected by slice');
for my $path (@paths) {
	ok(!-f $t->testdir() . '/cache/' . md5_hex("/$path"),
		"$path does not create an unsliced cache key");
}
undef $t;
done_testing();

sub data {
	return $_[0] == 1 ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'
		: $_[0] == 2 ? 'abcdefghijklmnopqrstuvwxyz012345'
		: 'abcdefghijklmnopqrstuvwxyz987654';
}

sub get {
	my ($path, $range) = @_;
	my $h = $range ? "Range: bytes=$range\r\n" : '';
	my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
		PeerPort => port(8080), Proto => 'tcp', Timeout => 5) or die "connect: $!";
	$c->autoflush(1);
	print $c "GET /$path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n$h\r\n";
	my $r = '';
	while (1) {
		if ($r =~ /\r\n\r\n/s) {
			my $end = $+[0];
			my ($length) = substr($r, 0, $end) =~ /^Content-Length: (\d+)/mi;
			last if defined($length) && length($r) >= $end + $length;
		}
		die "response timeout for $path" unless IO::Select->new($c)->can_read(5);
		my $n = sysread($c, my $buf, 16384);
		die "read: $!" unless defined $n;
		last unless $n;
		$r .= $buf;
	}
	close $c;
	return $r;
}

sub body {
	my ($r) = @_;
	$r =~ s/.*?\r\n\r\n//s;
	return $r;
}

sub ranges {
	my ($path) = @_;
	my $file = $t->testdir() . "/$path.hits";
	return [] unless -e $file;
	open my $f, '<', $file or die "open $file: $!";
	chomp(my @lines = <$f>);
	return \@lines;
}

sub hits {
	return scalar @{ranges($_[0])};
}

sub wait_for {
	my ($test, $why) = @_;
	my $until = time + 5;
	until ($test->()) {
		die "timeout: $why" if time > $until;
		sleep 0.01;
	}
}

sub refreshed {
	my ($path, $range) = @_;
	my $r;
	wait_for(sub {
		$r = get($path, $range);
		$r =~ /^X-Cache: HIT\r?$/m;
	},
		"$path refreshed cache");
	return $r;
}

sub origin {
	my ($dir) = @_;
	my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
		LocalPort => port(8081), Listen => 32, ReuseAddr => 1) or die "listen: $!";
	while (my $c = $server->accept()) {
		$c->autoflush(1);
		my $request = <$c> || next;
		my ($path) = $request =~ m{^\S+ /([^? ]+)};
		my $range = '';
		while (<$c>) {
			last if /^\r?\n$/;
			$range = $1 if /^Range:\s*(\S+)/i;
		}
		open my $f, '>>', "$dir/$path.hits" or die "open hits: $!";
		print {$f} "$range\n";
		close $f;
		open $f, '<', "$dir/version" or die "open version: $!";
		my $v = <$f>;
		close $f;
		while (-e "$dir/hold-$path") {
			sleep 0.01;
		}
		my $body = data($v);
		my $status = '200 OK';
		my $headers = '';
		if ($v == 2 && $path eq 'redirect') {
			$headers = "X-Accel-Redirect: /redirected\r\n";
		} elsif ($range && !($v == 2 && $path eq 'bad200')) {
			my ($start, $end) = $range =~ /^bytes=(\d+)-(\d+)$/;
			if ($v == 2 && $path eq 'bad416') {
				$status = '416 Range Not Satisfiable';
				$headers = 'Content-Range: bytes */4' . "\r\n";
				$body = '';
			} else {
				$start = 0 if $v == 2 && $path eq 'badrange';
				$end = $start + 7 if $v == 2 && $path eq 'badrange';
				$end = length($body) - 1 if $end >= length($body);
				$status = '206 Partial Content';
				$headers = "Content-Range: bytes $start-$end/"
					. length($body) . "\r\n";
				$body = substr($body, $start, $end - $start + 1);
			}
		}
		print $c "HTTP/1.1 $status\r\nContent-Length: " . length($body)
			. "\r\nETag: \"v$v\"\r\nCache-Control: max-age=" . ($v == 1 ? 1 : 60)
			. "\r\n$headers" . "Connection: close\r\n\r\n$body";
		close $c;
	}
}
