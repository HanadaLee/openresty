#!/usr/bin/perl

# Copyright (C) Hanada
# A resumed expired-lock waiter preserves bypass and native stale policy.

use strict;
use warnings;

use Test::More;
use Time::HiRes qw/sleep time/;
use IO::Socket::INET;
use Digest::MD5 qw/md5_hex/;
use Fcntl qw/:flock SEEK_SET/;
use POSIX ();
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx qw/:DEFAULT http_end/;

my $t = Test::Nginx->new()->has(qw/http proxy cache ngx_expr_module/);
plan skip_all => 'requires nginx extensions on Linux'
	if $^O ne 'linux' || $t->has_module('--without-ext');
my $dir = $t->testdir();
chmod 0755, $dir or die "chmod test directory: $!";
mkdir "$dir/cache" or die "mkdir cache: $!";
chmod 0777, "$dir/cache" or die "chmod cache: $!";
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
master_process on;
worker_processes 2;
events {
    accept_mutex off;
}
http {
    %%TEST_GLOBALS_HTTP%%
    map $request_time $late_bypass {
        volatile;
        ~^0\.0 0;
        default 1;
    }
    proxy_cache_path %%TESTDIR%%/cache levels=1:2 keys_zone=c:4m use_temp_path=off;
    server {
        listen 127.0.0.1:8080;
        expr aged num_gt $request_time 0.05;
        add_header X-Cache $upstream_cache_status always;
        proxy_cache c;
        proxy_cache_key $uri;
        proxy_cache_lock on;
        proxy_cache_lock_expired on;
        proxy_cache_lock_poll_interval 150ms;
        proxy_cache_lock_timeout 2s;
        proxy_cache_lock_age 5s;
        proxy_cache_revalidate on;
        proxy_read_timeout 5s;
        proxy_next_upstream off;
        proxy_pass_header ETag;
        location /bypass-background/ {
            proxy_cache_bypass $late_bypass;
            when aged {
                proxy_cache_use_stale updating;
                proxy_cache_background_update on;
            }
            proxy_cache_use_stale off;
            proxy_cache_background_update off;
            proxy_pass http://127.0.0.1:8081;
        }
        location /timeout-background/ {
            proxy_cache_lock_timeout 150ms;
            proxy_cache_lock_poll_interval 500ms;
            when aged {
                proxy_cache_use_stale updating;
                proxy_cache_background_update on;
            }
            proxy_cache_use_stale off;
            proxy_cache_background_update off;
            proxy_pass http://127.0.0.1:8081;
        }
        location /bypass-error/ {
            proxy_cache_bypass $late_bypass;
            proxy_cache_use_stale error http_500;
            proxy_pass http://127.0.0.1:8081;
        }
        location /timeout-error/ {
            proxy_cache_lock_timeout 150ms;
            proxy_cache_lock_poll_interval 500ms;
            proxy_cache_use_stale error http_500;
            proxy_pass http://127.0.0.1:8081;
        }
        location /bypass-must/ {
            proxy_cache_bypass $late_bypass;
            proxy_cache_use_stale updating error http_500;
            proxy_cache_background_update on;
            proxy_pass http://127.0.0.1:8081;
        }
        location /timeout-must/ {
            proxy_cache_lock_timeout 150ms;
            proxy_cache_lock_poll_interval 500ms;
            proxy_cache_use_stale updating error http_500;
            proxy_cache_background_update on;
            proxy_pass http://127.0.0.1:8081;
        }
    }
}
EOF
$t->run_daemon(\&origin, $dir);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

sub wait_for {
	my ($test, $why) = @_;
	my $until = time + 5;
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
	return {status => $status || 0, cache => $cache || '', body => $body || ''};
}

sub get {
	finish(begin(@_));
}

my @cases = (
	['/bypass-background/ok', 200, 'BYPASS', 'body-3'],
	['/timeout-background/ok', 200, 'EXPIRED', 'body-3'],
	['/bypass-error/500', 500, 'BYPASS', 'body-3'],
	['/bypass-error/close', 502, 'BYPASS', undef],
	['/timeout-error/500', 200, 'STALE', 'body-1'],
	['/timeout-error/close', 200, 'STALE', 'body-1'],
	['/bypass-must/500', 500, 'BYPASS', 'body-3'],
	['/timeout-must/500', 500, 'EXPIRED', 'body-3'],
	['/timeout-must/close', 502, 'EXPIRED', undef],
);
for my $case (@cases) {
	my ($uri) = @$case;
	is(get($uri)->{cache}, 'MISS', "$uri warm miss");
	is(get($uri)->{cache}, 'HIT', "$uri warm hit");
}
sleep 2.05;

for my $case (@cases) {
	my ($uri, $status, $cache, $body) = @$case;
	my $owner = begin($uri);
	wait_for(sub { @{hits($uri)} == 2 }, "$uri owner at origin");
	my $follower = begin($uri, "If-None-Match: \"client\"\r\n");
	my $response = finish($follower);
	is($response->{status}, $status, "$uri follower HTTP status");
	is($response->{cache}, $cache, "$uri follower cache status");
	if (defined $body) {
		is($response->{body}, $body, "$uri follower entity");
	} else {
		unlike($response->{body}, qr/body-1/, "$uri does not serve cached entity");
	}
	wait_for(sub { @{hits($uri)} >= 3 }, "$uri independent origin request");
	my $seen = hits($uri);
	is(scalar @$seen, 3, "$uri exactly one independent origin request");
	is($seen->[1], '"one"', "$uri owner uses cached validator");
	is($seen->[2], '"client"', "$uri independent request preserves client validator");
	$t->write_file(md5_hex($uri) . '.release', '1');
	my $updated = finish($owner);
	is($updated->{cache}, 'EXPIRED', "$uri owner refresh status");
	is($updated->{body}, 'body-2', "$uri owner refresh entity");
	my $fresh = get($uri);
	is($fresh->{cache}, 'HIT', "$uri owner commits cache");
	is($fresh->{body}, 'body-2', "$uri independent response did not replace owner");
	is(scalar @{hits($uri)}, 3, "$uri no additional refresh");
}

$t->stop();
my $log = $t->read_file('error.log');
unlike($log, qr/\[(?:alert|crit)\]/, 'no lifecycle alerts');
undef $t;
done_testing();

sub serve {
	my ($client, $dir) = @_;
	my $request = <$client> || return;
	my ($uri) = $request =~ /^GET (\S+) / or return;
	my $validator = '-';
	while (<$client>) {
		last if /^\r?\n$/;
		$validator = $1 if /^If-None-Match:\s*([^\r\n]+)/i;
	}
	my $key = "$dir/" . md5_hex($uri);
	open my $f, '+>>', "$key.hits" or die "open hits: $!";
	flock($f, LOCK_EX) or die "flock hits: $!";
	seek($f, 0, SEEK_SET) or die "seek hits: $!";
	my @previous = <$f>;
	my $n = @previous + 1;
	print {$f} "$validator\n";
	close $f;
	wait_for(sub { -e "$key.release" }, "$uri owner release") if $n == 2;
	return if $n == 3 && $uri =~ m{/close$};
	my $status = $n == 3 && $uri =~ m{/500$}
		? '500 Internal Server Error' : '200 OK';
	my $body = "body-$n";
	my $cc = $n == 1 ? 'max-age=1' : 'max-age=60';
	$cc .= ', must-revalidate' if $uri =~ /-must\//;
	$client->autoflush(1);
	print $client "HTTP/1.1 $status\r\nContent-Length: " . length($body)
		. "\r\nCache-Control: $cc\r\nETag: \"one\"\r\n"
		. "Connection: close\r\n\r\n$body";
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
