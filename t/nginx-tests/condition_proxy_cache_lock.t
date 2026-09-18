#!/usr/bin/perl

# Tests for condition-aware http proxy cache lock directives.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy cache ngx_condition_module/)
	->plan(15);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache levels=1:2 keys_zone=NAME:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        condition lock str_in $http_x_case lock;
        condition timeout str_in $http_x_case timeout;
        condition age str_in $http_x_case age;

        location /lock/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;

            when lock {
                proxy_cache_lock on;
            }

            proxy_cache_lock off;
        }

        location /timeout/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_lock on;

            when timeout {
                proxy_cache_lock_timeout 100ms;
            }

            proxy_cache_lock_timeout 1s;
        }

        location /age/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_lock on;

            when age {
                proxy_cache_lock_age 100ms;
            }

            proxy_cache_lock_age 10s;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon, port(8081));
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my @s = map { get('/lock/on', 'lock', start => 1) } 1 .. 3;
my @r = map { http_end($_) } @s;

like($r[0], qr/request 1/, 'proxy_cache_lock condition first');
like($r[1], qr/request 1/, 'proxy_cache_lock condition second');
like($r[2], qr/request 1/, 'proxy_cache_lock condition third');

@s = map { get('/lock/off', '', start => 1) } 1 .. 3;
my $r = join '', map { http_end($_) } @s;

like($r, qr/request 1/, 'proxy_cache_lock default first');
like($r, qr/request 3/, 'proxy_cache_lock default last');

@s = map { get('/timeout/on', 'timeout', start => 1) } 1 .. 3;
@r = map { http_end($_) } @s;

like($r[0], qr/request 1/, 'proxy_cache_lock_timeout condition first');
like(join('', @r[1, 2]), qr/request (2.*request 3|3.*request 2)/s,
	'proxy_cache_lock_timeout condition rest');
like(get('/timeout/on', 'timeout'), qr/request 1/,
	'proxy_cache_lock_timeout condition cached');

@s = map { get('/timeout/off', '', start => 1) } 1 .. 3;
@r = map { http_end($_) } @s;

is(scalar(grep { /request 1/ } @r), 3,
	'proxy_cache_lock_timeout default');
unlike(join('', @r), qr/request [23]/,
	'proxy_cache_lock_timeout default single fill');

my $first = get('/age/on', 'age', start => 1);
select undef, undef, undef, 0.2;
like(get('/age/on', 'age'), qr/request 2/,
	'proxy_cache_lock_age condition');
like(http_end($first), qr/request 1/,
	'proxy_cache_lock_age condition first');

$first = get('/age/off', '', start => 1);
select undef, undef, undef, 0.2;
like(get('/age/off', ''), qr/request 1/, 'proxy_cache_lock_age default');
like(http_end($first), qr/request 1/,
	'proxy_cache_lock_age default first');

pass('all proxy cache lock directives accepted in when');

###############################################################################

sub get {
	my ($uri, $case, %extra) = @_;
	my $header = $case eq '' ? '' : "X-Case: $case\r\n";

	return http("GET $uri HTTP/1.1\r\nHost: localhost\r\n"
		. $header . "Connection: close\r\n\r\n", %extra);
}

sub http_daemon {
	my ($port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1,
	) or die "Can't create listening socket: $!\n";

	my $num = 0;
	my $uri = '';

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		my $current = '';

		while (<$client>) {
			$current = $1 if /^GET ([^ ]+) HTTP/;
			last if /^\x0d?\x0a?$/;
		}

		next if $current eq '';

		if ($current ne $uri) {
			$uri = $current;
			$num = 0;
		}

		select undef, undef, undef, 0.5;
		$num++;
		my $body = "request $num";

		print $client "HTTP/1.1 200 OK\r\n"
			. "Cache-Control: max-age=300\r\n"
			. "Content-Type: text/html\r\n"
			. "Content-Length: " . length($body) . "\r\n"
			. "Connection: close\r\n\r\n$body";
		close $client;
	}
}

###############################################################################
