#!/usr/bin/perl

# Copyright (C) Hanada
# Cache lock polling uses one request value and one absolute wait deadline.

use strict;
use warnings;

use Test::More;
use IO::Select;
use IO::Socket::INET;
use Fcntl qw/:flock SEEK_SET/;
use Digest::MD5 qw/md5_hex/;
use POSIX ();
use Time::HiRes qw/sleep time/;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx qw/:DEFAULT http_start http_end/;

my $t = Test::Nginx->new()->has(qw/http proxy cache/);
plan skip_all => 'requires nginx extensions on Linux'
	if $^O ne 'linux' || $t->has_module('--without-ext');
my $expr = $t->has_module('ngx_expr_module|ngx_condition_module');
my $dir = $t->testdir();

for my $scope (qw/http server location/) {
	my ($ok, $output) = config_test($scope, '1ms');
	ok($ok, "$scope accepts the minimum interval") or diag $output;
	($ok, $output) = config_test($scope, '0');
	ok(!$ok, "$scope rejects zero");
	like($output, qr/proxy_cache_lock_poll_interval.*greater than zero/,
		"$scope reports the valid lower bound");
}
for my $value ('0ms', '-1ms', 'invalid') {
	my ($ok, $output) = config_test('location', $value);
	ok(!$ok, "rejects $value") or diag $output;
}
SKIP: {
	skip 'requires condition expressions', 2 unless $expr;
	my ($ok, $output) = config_test('when', '1ms');
	ok($ok, 'when accepts a positive interval') or diag $output;
	($ok, $output) = config_test('when', '0ms');
	ok(!$ok, 'when rejects zero') or diag $output;
}

my $when = $expr ? <<'EOF' : '';
        location /when/ {
            expr fast str_eq $http_x_poll fast;
            when fast {
                proxy_cache_lock_poll_interval 50ms;
            }
            proxy_cache_lock_poll_interval 500ms;
            proxy_pass http://127.0.0.1:8081;
        }
EOF
$t->write_file_expand('nginx.conf', <<'EOF' . $when . <<'EOF2');
%%TEST_GLOBALS%%
daemon off;
worker_processes 2;
events {
    worker_connections 128;
}
http {
    %%TEST_GLOBALS_HTTP%%
    proxy_cache_path cache keys_zone=c:1m use_temp_path=off;
    proxy_cache c;
    proxy_cache_key $uri;
    proxy_cache_valid 200 1m;
    proxy_cache_lock on;
    proxy_cache_lock_timeout 3s;
    proxy_cache_lock_age 5s;
    proxy_read_timeout 5s;
    add_header X-Cache $upstream_cache_status always;
    server {
        listen 127.0.0.1:8080;
        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /fast/ {
            proxy_cache_lock_poll_interval 50ms;
            proxy_pass http://127.0.0.1:8081;
        }
        location /timeout/ {
            proxy_cache_lock_timeout 650ms;
            proxy_pass http://127.0.0.1:8081;
        }
        location /short-timeout/ {
            proxy_cache_lock_poll_interval 2s;
            proxy_cache_lock_timeout 180ms;
            proxy_pass http://127.0.0.1:8081;
        }
        location /age/ {
            proxy_cache_lock_age 120ms;
            proxy_pass http://127.0.0.1:8081;
        }
        location /early/ {
            proxy_cache_lock_early_read on;
            proxy_cache_lock_poll_interval 500ms;
            proxy_cache_lock_timeout 650ms;
            proxy_pass http://127.0.0.1:8081;
        }
EOF
    }
    server {
        listen 127.0.0.1:8082;
        proxy_cache_lock_poll_interval 50ms;
        location / {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}
EOF2

chmod 0755, $dir or die "chmod: $!";
mkdir "$dir/cache" or die "mkdir: $!";
chmod 0777, "$dir/cache" or die "chmod: $!";
$t->run_daemon(\&origin, $dir);
$t->waitforsocket('127.0.0.1:' . port(8081));
unlink "$dir/nginx.pid";
$t->run();

poll_case('/default/one', 8080, '', 0.35, 0.9,
	'default 500ms poll');
poll_case('/fast/one', 8080, '', 0.08, 0.38,
	'location overrides default');
poll_case('/inherit/one', 8082, '', 0.08, 0.38,
	'location inherits server interval');
SKIP: {
	skip 'requires condition expressions', 10 unless $expr;
	poll_case('/when/fast', 8080, "X-Poll: fast\r\n", 0.08, 0.38,
		'when selects the request interval');
	poll_case('/when/default', 8080, '', 0.35, 0.9,
		'when keeps the fallback interval');
}

timeout_case('/timeout/one', 0.50, 0.90,
	'repeated ordinary polling respects the absolute deadline');
timeout_case('/short-timeout/one', 0.10, 0.45,
	'first poll is capped by the wait deadline');
timeout_case('/age/one', 0.04, 0.38,
	'first poll is capped by the remaining lock age');
timeout_case('/early/one', 0.50, 0.90,
	'early attachment retries keep the original wait deadline');

$t->stop();
# Reuse the listeners and origin with a new key to exercise http inheritance.
my $conf = $t->read_file('nginx.conf');
$conf =~ s/(proxy_cache_path cache)/proxy_cache_lock_poll_interval 50ms;\n    $1/;
$t->write_file('nginx.conf', $conf);
$t->run();
poll_case('/http-inherit/one', 8080, '', 0.08, 0.38,
	'server and location inherit the http interval');
$t->stop();
my $log = $t->read_file('error.log');
unlike($log, qr/proxy_cache_lock_early_read disabled:/,
	'early-read invalidation guard is active');
unlike($log, qr/\[alert\]/, 'no alerts');
unlike($log, qr/AddressSanitizer|runtime error:/, 'no sanitizer errors');
undef $t;
done_testing();

sub request {
	my ($path, $listen, $extra) = @_;
	my $socket = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
		PeerPort => port($listen // 8080), Proto => 'tcp', Timeout => 5)
		or die "connect: $!";
	return http_start("GET $path HTTP/1.1\r\nHost: localhost\r\n"
		. ($extra // '') . "Connection: close\r\n\r\n", socket => $socket);
}

sub hits {
	my ($path) = @_;
	my $file = "$dir/" . md5_hex($path) . '.hits';
	return [] unless -f $file;
	open my $fh, '<', $file or die "open hits: $!";
	flock($fh, LOCK_SH) or die "flock: $!";
	chomp(my @times = <$fh>);
	return \@times;
}

sub wait_for {
	my ($test, $why) = @_;
	my $deadline = time + 4;
	until ($test->()) {
		die "timed out waiting for $why" if time >= $deadline;
		sleep 0.005;
	}
}

sub release {
	my ($path) = @_;
	$t->write_file(md5_hex($path) . '.go', '1');
}

sub poll_case {
	my ($path, $listen, $extra, $low, $high, $name) = @_;
	my $writer = request($path, $listen, $extra);
	wait_for(sub { @{hits($path)} == 1 }, "$name writer");
	my $start = time;
	my $reader = request($path, $listen, $extra);
	sleep 0.12;
	release($path);
	my $response = http_end($reader);
	my $elapsed = time - $start;
	like($response, qr/X-Cache: HIT\r\n/i, "$name follower reads committed cache");
	cmp_ok($elapsed, '>=', $low, "$name lower timing bound");
	cmp_ok($elapsed, '<', $high, "$name upper timing bound");
	like(http_end($writer), qr/body 1$/, "$name writer completes");
	is(scalar @{hits($path)}, 1, "$name uses one origin request");
}

sub timeout_case {
	my ($path, $low, $high, $name) = @_;
	my $writer = request($path);
	wait_for(sub { @{hits($path)} == 1 }, "$name writer");
	my $start = time;
	my $reader = request($path);
	wait_for(sub { @{hits($path)} >= 2 }, "$name second origin");
	my $elapsed = hits($path)->[1] - $start;
	cmp_ok($elapsed, '>=', $low, "$name lower timing bound");
	cmp_ok($elapsed, '<', $high, "$name upper timing bound");
	like(http_end($reader), qr/body 2$/, "$name returns independent response");
	release($path);
	like(http_end($writer), qr/body 1$/, "$name writer completes");
}

sub config_test {
	my ($scope, $value) = @_;
	my $setting = "proxy_cache_lock_poll_interval $value;";
	my ($http, $server) = ('', '');
	if ($scope eq 'http') {
		$http = $setting;
	} elsif ($scope eq 'server') {
		$server = $setting;
	} elsif ($scope eq 'when') {
		$server = "expr selected str_eq \$http_x_poll fast; "
			. "location / { when selected { $setting } }";
	} else {
		$server = "location / { $setting }";
	}
	$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
events {
}
http {
    %%TEST_GLOBALS_HTTP%%
    $http
    server {
        listen 127.0.0.1:8080;
        $server
    }
}
EOF
	my $pid = open(my $pipe, '-|');
	die "fork: $!" unless defined $pid;
	if (!$pid) {
		open STDERR, '>&STDOUT' or die "dup stderr: $!";
		exec($Test::Nginx::NGINX, '-t', '-p', "$dir/", '-c', 'nginx.conf',
			'-e', 'error.log') or die "exec nginx: $!";
	}
	local $/;
	my $output = <$pipe>;
	close $pipe;
	return ($? == 0, $output);
}

sub origin {
	my ($directory) = @_;
	my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
		LocalPort => port(8081), Listen => 32, ReuseAddr => 1)
		or die "listen: $!";
	$SIG{CHLD} = 'IGNORE';
	while (my $client = $server->accept()) {
		my $pid = fork();
		die "fork: $!" unless defined $pid;
		if (!$pid) {
			close $server;
			$client->autoflush(1);
			my $line = <$client> // '';
			my ($path) = $line =~ /^GET (\S+) /;
			POSIX::_exit(0) unless defined $path;
			while (<$client>) {
				last if /^\r?\n$/;
			}
			my $key = "$directory/" . md5_hex($path);
			open my $fh, '+>>', "$key.hits" or die "open hits: $!";
			flock($fh, LOCK_EX) or die "flock: $!";
			seek($fh, 0, SEEK_SET) or die "seek: $!";
			my @previous = <$fh>;
			my $n = @previous + 1;
			print {$fh} time . "\n";
			close $fh;
			if ($n == 1) {
				my $deadline = time + 10;
				while (!-f "$key.go" && time < $deadline) {
					sleep 0.005;
				}
			}
			my $body = "body $n";
			print $client "HTTP/1.1 200 OK\r\nContent-Length: " . length($body)
				. "\r\nCache-Control: max-age=300\r\nConnection: close\r\n\r\n$body";
			close $client;
			POSIX::_exit(0);
		}
		close $client;
	}
}
