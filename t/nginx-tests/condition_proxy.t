#!/usr/bin/perl

# Tests for condition-aware http proxy module directives.

###############################################################################

use warnings;
use strict;

use IO::Select;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw/ time /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite http_ssl
	ngx_condition_module/)->has_daemon('openssl')->plan(35);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream retry {
        server 127.0.0.1:8088 max_fails=0;
        server 127.0.0.1:8089 backup;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        condition method str_in $arg_case method;
        condition version str_in $arg_case version;
        condition redirect str_in $arg_case redirect;
        condition ranges str_in $arg_case ranges;
        condition headers str_in $arg_case headers;
        condition buffering str_in $arg_case buffering;
        condition request_buffering str_in $arg_case request_buffering;
        condition abort str_in $arg_case abort;
        condition connect_timeout str_in $arg_case connect_timeout;
        condition send_timeout str_in $arg_case send_timeout;
        condition read_timeout str_in $arg_case read_timeout;
        condition limit_rate str_in $arg_case limit_rate;
        condition next str_in $arg_case next;
        condition tries str_in $arg_case tries;
        condition next_timeout str_in $arg_case next_timeout;
        condition ssl_server_name str_in $arg_case ssl_server_name;
        condition ssl_name str_in $arg_case ssl_name;
        condition pass_headers str_in $arg_case pass_headers;
        condition pass_body str_in $arg_case pass_body;

        location /basic/ {
            proxy_pass http://127.0.0.1:8081/;

            when method {
                proxy_method POST;
            }
            when version {
                proxy_http_version 1.1;
            }
            when redirect {
                proxy_redirect http://backend.example/ /rewritten/;
            }
            when ranges {
                proxy_force_ranges on;
            }
            when headers {
                proxy_ignore_headers X-Accel-Redirect;
            }
            when abort {
                proxy_ignore_client_abort on;
            }
            when connect_timeout {
                proxy_connect_timeout 1s;
            }
            when send_timeout {
                proxy_send_timeout 1s;
            }

            proxy_method GET;
            proxy_http_version 1.0;
            proxy_redirect off;
            proxy_force_ranges off;
            proxy_ignore_client_abort off;
            proxy_limit_rate 0;
            proxy_connect_timeout 5s;
            proxy_send_timeout 5s;
        }

        location /order/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_method GET;

            when method {
                proxy_method POST;
            }
        }

        location /stream/ {
            proxy_pass http://127.0.0.1:8085/;

            when buffering {
                proxy_buffering off;
            }

            proxy_buffering on;
        }

        location /upload/ {
            proxy_pass http://127.0.0.1:8086/;

            when request_buffering {
                proxy_request_buffering off;
            }

            proxy_request_buffering on;
        }

        location /pass/ {
            proxy_pass http://127.0.0.1:8082/;

            when pass_headers {
                proxy_pass_request_headers off;
            }
            when pass_body {
                proxy_pass_request_body off;
            }

            proxy_pass_request_headers on;
            proxy_pass_request_body on;
        }

        location /slow/ {
            proxy_pass http://127.0.0.1:8087/;

            when read_timeout {
                proxy_read_timeout 1s;
            }

            proxy_read_timeout 100ms;
        }

        location /rate/ {
            proxy_pass http://127.0.0.1:8081/data;

            when limit_rate {
                proxy_limit_rate 20k;
            }

            proxy_limit_rate 0;
        }

        location /next/ {
            proxy_pass http://retry/plain;

            when next {
                proxy_next_upstream http_500;
            }

            proxy_next_upstream off;
        }

        location /tries/ {
            proxy_pass http://retry/plain;
            proxy_next_upstream http_500;

            when tries {
                proxy_next_upstream_tries 2;
            }

            proxy_next_upstream_tries 1;
        }

        location /next-timeout/ {
            proxy_pass http://retry/delayed;
            proxy_next_upstream http_500;

            when next_timeout {
                proxy_next_upstream_timeout 1s;
            }

            proxy_next_upstream_timeout 1ms;
        }

        location /ssl-server-name/ {
            proxy_pass https://127.0.0.1:8084/;
            proxy_ssl_session_reuse off;
            proxy_ssl_name named.example;

            when ssl_server_name {
                proxy_ssl_server_name on;
            }

            proxy_ssl_server_name off;
        }

        location /ssl-name/ {
            proxy_pass https://127.0.0.1:8084/;
            proxy_ssl_session_reuse off;
            proxy_ssl_server_name on;

            when ssl_name {
                proxy_ssl_name named.example;
            }

            proxy_ssl_name default.example;
        }

        location = /internal-result {
            internal;
            return 200 internal;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location = /echo {
            return 200 "$request_method|$server_protocol";
        }

        location = /redirect {
            return 302 http://backend.example/old;
        }

        location = /accel {
            add_header X-Accel-Redirect /internal-result;
            return 200 backend;
        }

        location = /range {
            max_ranges 0;
            add_header Last-Modified "Mon, 28 Sep 1970 06:00:00 GMT";
            return 200 SEE-THIS;
        }

        location = /data {
        }
    }

    server {
        listen       127.0.0.1:8084 ssl default_server;
        server_name  default.example named.example;

        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;

        add_header X-SNI "$ssl_server_name" always;
        return 200 ssl;
    }

    server {
        listen       127.0.0.1:8089;
        server_name  localhost;

        return 200 backup;
    }
}

EOF

$t->write_file('openssl.conf', <<'EOF');
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate: $!\n";

$t->write_file('data', 'X' x 40000);

$t->run_daemon(\&http_daemon, port(8085), 'stream');
$t->run_daemon(\&upload_daemon, port(8086));
$t->run_daemon(\&request_daemon, port(8082));
$t->run_daemon(\&http_daemon, port(8087), 'slow');
$t->run_daemon(\&http_daemon, port(8088), 'retry');
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8085));
$t->waitforsocket('127.0.0.1:' . port(8086));
$t->waitforsocket('127.0.0.1:' . port(8082));
$t->waitforsocket('127.0.0.1:' . port(8087));
$t->waitforsocket('127.0.0.1:' . port(8088));

###############################################################################

pass('all condition-aware proxy directives accepted');

like(http_get('/basic/echo'), qr/GET\|HTTP\/1\.0/,
	'proxy_method default');
like(http_get('/basic/echo?case=method'), qr/POST\|HTTP\/1\.0/,
	'proxy_method condition');
like(http_get('/order/echo?case=method'), qr/GET\|HTTP\/1\.1/,
	'configuration order takes priority');

like(http_get('/basic/echo?case=version'), qr/GET\|HTTP\/1\.1/,
	'proxy_http_version condition');

like(http_get('/basic/redirect'),
	qr/^Location: http:\/\/backend\.example\/old\x0d?$/mi,
	'proxy_redirect default');
like(http_get('/basic/redirect?case=redirect'),
	qr/^Location: http:\/\/localhost:8080\/rewritten\/old\x0d?$/mi,
	'proxy_redirect condition');

unlike(range('/basic/range', 'bytes=4-'), qr/^THIS$/m,
	'proxy_force_ranges default');
like(range('/basic/range?case=ranges', 'bytes=4-'), qr/^THIS$/m,
	'proxy_force_ranges condition');

like(http_get('/basic/accel'), qr/^internal$/m,
	'proxy_ignore_headers default');
like(http_get('/basic/accel?case=headers'), qr/^backend$/m,
	'proxy_ignore_headers condition');

like(http_get('/basic/echo?case=abort'), qr/GET\|HTTP\/1\.0/,
	'proxy_ignore_client_abort condition path');
like(http_get('/basic/echo?case=connect_timeout'), qr/GET\|HTTP\/1\.0/,
	'proxy_connect_timeout condition path');
like(http_get('/basic/echo?case=send_timeout'), qr/GET\|HTTP\/1\.0/,
	'proxy_send_timeout condition path');

cmp_ok(first_body_delay('/stream/'), '>=', 0.35,
	'proxy_buffering default');
cmp_ok(first_body_delay('/stream/?case=buffering'), '<', 0.35,
	'proxy_buffering condition');

is(upload('/upload/'), 'buffered', 'proxy_request_buffering default');
is(upload('/upload/?case=request_buffering'), 'streamed',
	'proxy_request_buffering condition');

like(pass_request('/pass/'), qr/^yes\|DATA$/m,
	'proxy pass request defaults');
like(pass_request('/pass/?case=pass_headers'), qr/^no\|DATA$/m,
	'proxy_pass_request_headers condition');
like(pass_request('/pass/?case=pass_body'), qr/^yes\|$/m,
	'proxy_pass_request_body condition');

like(http_get('/slow/'), qr/504 Gateway Timeout/,
	'proxy_read_timeout default');
like(http_get('/slow/?case=read_timeout'), qr/slow/,
	'proxy_read_timeout condition');

like(http_get('/next/'), qr/500 Internal Server Error/,
	'proxy_next_upstream default');
like(http_get('/next/?case=next'), qr/backup/,
	'proxy_next_upstream condition');

like(http_get('/tries/'), qr/500 Internal Server Error/,
	'proxy_next_upstream_tries default');
like(http_get('/tries/?case=tries'), qr/backup/,
	'proxy_next_upstream_tries condition');

like(http_get('/next-timeout/'), qr/500 Internal Server Error/,
	'proxy_next_upstream_timeout default');
like(http_get('/next-timeout/?case=next_timeout'), qr/backup/,
	'proxy_next_upstream_timeout condition');

unlike(http_get('/ssl-server-name/'), qr/^X-SNI:/mi,
	'proxy_ssl_server_name default');
like(http_get('/ssl-server-name/?case=ssl_server_name'),
	qr/^X-SNI: named\.example\x0d?$/mi, 'proxy_ssl_server_name condition');

like(http_get('/ssl-name/'), qr/^X-SNI: default\.example\x0d?$/mi,
	'proxy_ssl_name default');
like(http_get('/ssl-name/?case=ssl_name'),
	qr/^X-SNI: named\.example\x0d?$/mi, 'proxy_ssl_name condition');

my $start = time();
like(http_get('/rate/?case=limit_rate'), qr/^(X){40000}$/m,
	'proxy_limit_rate condition body');
cmp_ok(time() - $start, '>=', 1, 'proxy_limit_rate condition');

###############################################################################

sub range {
	my ($uri, $value) = @_;
	return http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close
Range: $value

EOF
}

sub first_body_delay {
	my ($uri) = @_;
	my $client = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";

	$client->autoflush(1);
	my $start = time();
	print $client "GET $uri HTTP/1.1\r\n"
		. "Host: localhost\r\nConnection: close\r\n\r\n";

	my $response = '';
	while ($response !~ /\x0d?\x0a\x0d?\x0a./s) {
		my $n = sysread($client, my $buf, 4096);
		last unless $n;
		$response .= $buf;
	}

	close $client;
	return time() - $start;
}

sub upload {
	my ($uri) = @_;
	my $client = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";

	$client->autoflush(1);
	print $client "POST $uri HTTP/1.1\r\n"
		. "Host: localhost\r\nContent-Length: 10\r\n"
		. "Connection: close\r\n\r\nFIRST";
	select undef, undef, undef, 0.4;
	eval { print $client 'LAST!' };

	my $response = '';
	while (sysread($client, my $buf, 4096)) {
		$response .= $buf;
	}

	close $client;
	$response =~ s/^.*?\x0d?\x0a\x0d?\x0a//s;
	return $response;
}

sub pass_request {
	my ($uri) = @_;
	return http("POST $uri HTTP/1.1\r\nHost: localhost\r\n"
		. "X-Pass: yes\r\nContent-Length: 4\r\n"
		. "Connection: close\r\n\r\nDATA");
}

sub http_daemon {
	my ($port, $type) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1,
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		while (<$client>) {
			$headers .= $_;
			last if /^\x0d?\x0a?$/;
		}

		next if $headers eq '';

		if ($type eq 'slow') {
			select undef, undef, undef, 0.4;
			print $client <<'EOF';
HTTP/1.1 200 OK
Content-Length: 4
Connection: close

slow
EOF

		} elsif ($type eq 'retry') {
			select undef, undef, undef, 0.1 if $headers =~ m{/delayed};
			print $client <<'EOF';
HTTP/1.1 500 Internal Server Error
Content-Length: 7
Connection: close

primary
EOF

		} else {
			print $client "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n"
				. "Connection: close\r\n\r\nFIRST";
			select undef, undef, undef, 0.5;
			print $client 'LAST!';
		}

		close $client;
	}
}

sub upload_daemon {
	my ($port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1,
	) or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		my $request = '';

		while ($request !~ /\x0d?\x0a\x0d?\x0a/s) {
			last unless sysread($client, my $buf, 4096);
			$request .= $buf;
		}

		my (undef, $body) = split /\x0d?\x0a\x0d?\x0a/, $request, 2;
		$body = '' unless defined $body;

		my $select = IO::Select->new($client);
		if (length($body) < 10 && $select->can_read(0.1)) {
			sysread($client, my $buf, 4096);
			$body .= $buf if defined $buf;
		}

		my $result = length($body) == 10 ? 'buffered' : 'streamed';
		print $client "HTTP/1.1 200 OK\r\nContent-Length: "
			. length($result) . "\r\nConnection: close\r\n\r\n$result";
		close $client;
	}
}

sub request_daemon {
	my ($port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1,
	) or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		my $request = '';

		while ($request !~ /\x0d?\x0a\x0d?\x0a/s) {
			last unless sysread($client, my $buf, 4096);
			$request .= $buf;
		}

		next if $request eq '';

		my ($headers, $body) = split /\x0d?\x0a\x0d?\x0a/, $request, 2;
		$body = '' unless defined $body;

		my $select = IO::Select->new($client);
		if (length($body) < 4 && $select->can_read(0.1)) {
			sysread($client, my $buf, 4096);
			$body .= $buf if defined $buf;
		}

		my $header = $headers =~ /^X-Pass:\s*yes\x0d?$/mi ? 'yes' : 'no';
		my $result = "$header|$body";
		print $client "HTTP/1.1 200 OK\r\nContent-Length: "
			. length($result) . "\r\nConnection: close\r\n\r\n$result";
		close $client;
	}
}

###############################################################################
