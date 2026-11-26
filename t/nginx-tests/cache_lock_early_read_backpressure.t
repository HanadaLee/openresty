#!/usr/bin/perl

# Copyright (C) Hanada

# A backpressured reader must resume after its shared queue loses the minimum
# interval reader, including threaded reads and a failed publisher.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::More;
use Test::Nginx;
use Socket qw/SOL_SOCKET SO_RCVBUF SO_LINGER pack_sockaddr_in inet_aton/;
use IO::Socket::INET;
use Digest::MD5 qw/md5_hex/;
use Fcntl qw/:flock/;
use POSIX ();
use Time::HiRes qw/sleep time/;
use CacheEarlyRead;

my $t = Test::Nginx->new()->has(qw/http proxy cache/);
plan skip_all => 'requires nginx extensions on Linux'
	if $^O ne 'linux' || $t->has_module('--without-ext');
my $threads = $t->has_module('threads');
my $pool = $threads ? 'thread_pool default threads=2;' : '';
my $thread_location = $threads ? <<'EOF' : '';
        location /thread/ {
            aio threads;
            sendfile off;
            proxy_cache_lock_poll_interval 4s;
            proxy_pass http://127.0.0.1:8081/obj/;
        }
EOF
my $dir = $t->testdir();
chmod 0755, $dir or die "chmod: $!";
mkdir "$dir/cache" or die "mkdir: $!";
chmod 0777, "$dir/cache" or die "chmod cache: $!";
my $conf = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
worker_processes 2;
POOL
events {
    worker_connections 256;
}
http {
    %%TEST_GLOBALS_HTTP%%
    sendfile on;
    proxy_cache_path cache keys_zone=c:4m use_temp_path=off;
    server {
        listen 127.0.0.1:8080 reuseport sndbuf=4k;
        location = /pid {
            return 200 $pid;
        }
        add_header X-Pid $pid always;
        add_header X-Connection $connection always;
        add_header X-Cache $upstream_cache_status always;
        proxy_cache c;
        proxy_cache_key $http_x_key;
        proxy_cache_valid 200 1m;
        proxy_cache_lock on;
        proxy_cache_lock_age 10s;
        proxy_cache_lock_timeout 5s;
        proxy_cache_lock_early_read on;
        proxy_read_timeout 15s;
        send_timeout 10s;
        location /slow/ {
            proxy_cache_lock_poll_interval 4s;
            proxy_pass http://127.0.0.1:8081/obj/;
        }
        location /fast/ {
            proxy_cache_lock_poll_interval 40ms;
            proxy_pass http://127.0.0.1:8081/obj/;
        }
        location /broken/ {
            proxy_cache_lock_poll_interval 4s;
            proxy_pass http://127.0.0.1:8081/short/;
        }
        THREAD_LOCATION
    }
}
EOF
$conf =~ s/POOL/$pool/;
$conf =~ s/THREAD_LOCATION/$thread_location/;
$t->write_file_expand('nginx.conf', $conf);
$t->run_daemon(\&origin, $dir);
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->run();

SKIP: {
	skip 'early reads unavailable without in-flight invalidation guard', 1
		if legacy_guard($t);
	for my $case (
		['sendfile', 'slow', '/obj/', 0],
		['thread', 'thread', '/obj/', 0],
		['failure', 'broken', '/short/', 1]
	) {
		my ($name, $location, $origin_prefix, $failed) = @$case;
		SKIP: {
			skip 'aio threads not compiled', 1 if $name eq 'thread' && !$threads;
			subtest "$name backpressure after minimum reader disconnect" => sub {
				my $path = "/$location/$name";
				my $origin = "$origin_prefix$name";
				my $extra = "X-Key: $name\r\n";
				my $publisher_socket = socket_for();
				my $pid = read_body(headers(send_req($publisher_socket, '/pid')));
				my $writer = send_req($publisher_socket, $path, $extra);

				# The buffered publisher need not send a response while the
				# origin is paused.  Wait for the cached prefix instead.
				my $temp = "$dir/cache/" . md5_hex($name);
				wait_for(sub { grep { -s $_ >= 32768 } glob("$temp.*") },
					'publisher has written the cache prefix');

				my $socket = small_socket($pid);
				my $slow = headers(send_req($socket, $path, $extra));
				my $prefix = read_body($slow, 8192);
				is($slow->{h}{'x-cache'}, 'MISS',
					'slow reader attached before commit');
				isnt($slow->{h}{'x-pid'}, $pid,
					'publisher and reader use different workers');
				is($prefix, substr(origin_body($origin, 1), 0, 8192),
					'correct early prefix');
				my $connection = $slow->{h}{'x-connection'};
				wait_for(sub {
					my $log = $t->read_file('error.log');
					return 1 if $log =~ /\*$connection\b[^\n]*(?:sendfile\(\) is not ready|writev\(\) not ready)/;
					while ($log =~ /\*$connection\b[^\n]*(?:sendfile|writev): (-?\d+) of (\d+)/g) {
						return 1 if $1 < $2;
					}
					return 0;
				}, 'actual TCP output backpressure');
				pass('slow reader reached a short write or EAGAIN');

				my $wakes = () = $t->read_file('error.log')
					=~ /http cache early wake:/g;
				my $fast = headers(send_req(socket_for($pid),
					"/fast/$name", $extra));
				read_body($fast, 8192);
				is($fast->{h}{'x-pid'}, $slow->{h}{'x-pid'},
					'minimum reader shares reader worker');
				is($fast->{h}{'x-cache'}, 'MISS',
					'minimum reader attached to the same fill');
				wait_for(sub {
					my $now = () = $t->read_file('error.log')
						=~ /http cache early wake:/g;
					return $now > $wakes;
				}, 'minimum reader shared timer');
				pass('minimum reader entered the shared timer queue');
				my $fast_connection = $fast->{h}{'x-connection'};
				setsockopt($fast->{socket}, SOL_SOCKET, SO_LINGER, pack('ii', 1, 0))
					or die "SO_LINGER: $!";
				close $fast->{socket};
				wait_for(sub {
					$t->read_file('error.log') =~ /\*$fast_connection\b[^\n]*http close request/
				}, 'minimum reader cleanup');
				pass('minimum reader cleanup completed');

				release_fill($t, $origin);
				headers($writer);
				is($writer->{h}{'x-cache'}, 'MISS', 'publisher cache miss');
				my $publisher = read_body($writer, undef, $failed);
				setsockopt($slow->{socket}, SOL_SOCKET, SO_RCVBUF,
					pack('i', 131072))
					or die "SO_RCVBUF enlarge: $!";
				my $started = time;
				my $received = $prefix . read_body($slow, undef, $failed);
				my $elapsed = time - $started;
				note sprintf('%s readiness resumed in %.3fs', $name, $elapsed);
				cmp_ok($elapsed, '<', 2.5,
					'write readiness resumes before the four second '
					. 'reader timer');
				if ($failed) {
					cmp_ok(length($publisher), '<',
						length(origin_body($origin, 1)),
						'publisher was incomplete');
					cmp_ok(length($received), '<',
						length(origin_body($origin, 1)),
						'reader cannot complete a failed generation');
					my $next = headers(send_req(socket_for(), $path, $extra));
					is($next->{h}{'x-cache'}, 'MISS',
						'failed fill was not committed');
					is(read_body($next), origin_body($origin, 2),
						'next generation can fill');
				} else {
					is($publisher, origin_body($origin, 1),
						'publisher body is complete');
					is($received, origin_body($origin, 1),
						'reader body includes the final byte');
				}

				my $hit = headers(send_req(socket_for(), $path, $extra));
				is($hit->{h}{'x-cache'}, 'HIT',
					'subsequent request is a cache hit');
				is(read_body($hit), origin_body($origin, $failed ? 2 : 1),
					'cached generation is complete');
				is(scalar @{origin_hits($t, $origin)}, $failed ? 2 : 1,
					'expected number of origin fills');
				if ($name eq 'thread') {
					like($t->read_file('error.log'),
						qr/\*$connection\b[^\n]*http thread:/,
						'reader threaded file IO completed');
				}
			};
		}
	}
}
finish_cache($t);
undef $t;
done_testing();


sub small_socket {
	my ($other) = @_;
	for (1 .. 100) {
		my $s = IO::Socket::INET->new(Proto => 'tcp') or die "socket: $!";
		setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', 4096))
			or die "SO_RCVBUF before connect: $!";
		$s->connect(pack_sockaddr_in(port(8080), inet_aton('127.0.0.1')))
			or die "connect: $!";
		my $r = headers(send_req($s, '/pid'));
		my $pid = read_body($r);
		return $s if $pid != $other;
		close $s;
	}
	die 'could not select another worker';
}

sub serve {
	my ($c, $dir) = @_;
	my $request = <$c> || return;
	my ($path) = $request =~ m{^GET (\S+)} or return;
	while (<$c>) {
		last if /^\r?\n$/;
	}
	my $key = "$dir/" . md5_hex($path);
	open my $f, '+>>', "$key.hits" or die "hits: $!";
	flock($f, LOCK_EX) or die "flock: $!";
	seek($f, 0, 0) or die "seek: $!";
	my @previous = <$f>;
	my $version = @previous + 1;
	print {$f} "\n";
	close $f;
	my $body = origin_body($path, $version);
	print $c "HTTP/1.1 200 OK\r\nContent-Length: " . length($body)
		. "\r\nETag: \"one\"\r\nCache-Control: max-age=300\r\nConnection: close\r\n\r\n"
		. substr($body, 0, 98304);
	wait_for(sub { -e "$key.go" }, 'controlled fill release', 20) if $version == 1;
	print $c substr($body, 98304) unless $version == 1 && $path =~ m{^/short/};
}

sub origin {
	my ($dir) = @_;
	my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
		LocalPort => port(8081), Listen => 32, ReuseAddr => 1) or die "listen: $!";
	$SIG{CHLD} = 'IGNORE';
	while (my $c = $server->accept()) {
		my $pid = fork();
		die "fork: $!" unless defined $pid;
		if (!$pid) {
			close $server;
			$c->autoflush(1);
			serve($c, $dir);
			close $c;
			POSIX::_exit(0);
		}
		close $c;
	}
}
