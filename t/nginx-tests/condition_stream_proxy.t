#!/usr/bin/perl

# Tests for condition-aware stream proxy module directives.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_ssl stream_return sni
	socket_ssl ngx_expr_module/)->has_daemon('openssl')->plan(16);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    expr hit str_in $proxy_protocol_addr 192.0.2.1;

    when hit {
        proxy_timeout 1s;
    }

    proxy_timeout 100ms;

    upstream retry {
        server 127.0.0.1:8090 max_fails=0;
        server 127.0.0.1:8091 backup;
    }

    upstream delayed_retry {
        server 127.0.0.1:8092 max_fails=0;
        server 127.0.0.1:8089 backup;
    }

    server {
        listen      127.0.0.1:8080 proxy_protocol;
        proxy_pass  127.0.0.1:8088;
    }

    server {
        listen      127.0.0.1:8081 proxy_protocol;
        proxy_pass  127.0.0.1:8089;
        proxy_ssl   on;
        proxy_ssl_session_reuse off;

        when hit {
            proxy_connect_timeout 1s;
        }

        proxy_connect_timeout 100ms;
    }

    server {
        listen      127.0.0.1:8082 proxy_protocol;
        proxy_pass  retry;

        when hit {
            proxy_next_upstream on;
        }

        proxy_next_upstream off;
    }

    server {
        listen      127.0.0.1:8083 proxy_protocol;
        proxy_pass  retry;
        proxy_next_upstream on;

        when hit {
            proxy_next_upstream_tries 2;
        }

        proxy_next_upstream_tries 1;
    }

    server {
        listen      127.0.0.1:8084 proxy_protocol;
        proxy_pass  delayed_retry;
        proxy_ssl   on;
        proxy_ssl_session_reuse off;
        proxy_timeout 1s;
        proxy_next_upstream on;

        when hit {
            proxy_next_upstream_timeout 1s;
        }

        proxy_next_upstream_timeout 100ms;
    }

    server {
        listen      127.0.0.1:8085 proxy_protocol;
        proxy_pass  127.0.0.1:8093;
        proxy_ssl   on;
        proxy_ssl_server_name on;
        proxy_ssl_session_reuse off;

        when hit {
            proxy_ssl_name hit.example;
        }

        proxy_ssl_name default.example;
    }

    server {
        listen      127.0.0.1:8086 proxy_protocol;
        proxy_pass  127.0.0.1:8093;
        proxy_ssl   on;
        proxy_ssl_name named.example;
        proxy_ssl_session_reuse off;

        when hit {
            proxy_ssl_server_name on;
        }

        proxy_ssl_server_name off;
    }

    server {
        listen      127.0.0.1:8087 proxy_protocol;
        proxy_pass  127.0.0.1:8088;

        proxy_timeout 100ms;

        when hit {
            proxy_timeout 1s;
        }
    }

    server {
        listen  127.0.0.1:8093 ssl;
        return  $ssl_server_name;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;
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

$t->run_daemon(\&slow_daemon, port(8088));
$t->run_daemon(\&delayed_ssl_daemon, port(8089));
$t->run_daemon(\&echo_daemon, port(8091));
$t->run_daemon(\&close_daemon, port(8092));
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8088));
$t->waitforsocket('127.0.0.1:' . port(8089));
$t->waitforsocket('127.0.0.1:' . port(8091));
$t->waitforsocket('127.0.0.1:' . port(8092));

###############################################################################

pass('all condition-aware stream proxy directives accepted');

is(pp_stream(8080, '192.0.2.1'), 'SEE-THIS',
	'proxy_timeout condition');
is(pp_stream(8080, '198.51.100.1'), '', 'proxy_timeout default');

is(pp_stream(8081, '192.0.2.1'), 'SSL-OK',
	'proxy_connect_timeout condition');
is(pp_stream(8081, '198.51.100.1'), '',
	'proxy_connect_timeout default');

is(pp_stream(8082, '192.0.2.1'), 'SEE-THIS',
	'proxy_next_upstream condition');
is(pp_stream(8082, '198.51.100.1'), '',
	'proxy_next_upstream default');

is(pp_stream(8083, '192.0.2.1'), 'SEE-THIS',
	'proxy_next_upstream_tries condition');
is(pp_stream(8083, '198.51.100.1'), '',
	'proxy_next_upstream_tries default');

is(pp_stream(8084, '192.0.2.1'), 'SSL-OK',
	'proxy_next_upstream_timeout condition');
is(pp_stream(8084, '198.51.100.1'), '',
	'proxy_next_upstream_timeout default');

is(pp_stream(8085, '192.0.2.1'), 'hit.example',
	'proxy_ssl_name condition');
is(pp_stream(8085, '198.51.100.1'), 'default.example',
	'proxy_ssl_name default');

is(pp_stream(8086, '192.0.2.1'), 'named.example',
	'proxy_ssl_server_name condition');
is(pp_stream(8086, '198.51.100.1'), '',
	'proxy_ssl_server_name default');

is(pp_stream(8087, '192.0.2.1'), '',
	'configuration order takes priority');

###############################################################################

sub pp_stream {
	my ($port, $addr) = @_;
	my $peer = '127.0.0.1:' . port($port);
	my $header = "PROXY TCP4 $addr 127.0.0.1 12345 "
		. port($port) . "\r\n";

	return stream($peer)->io($header . 'X', read_timeout => 2);
}

sub slow_daemon {
	my ($port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		$client->sysread(my $buffer, 1) or next;
		select undef, undef, undef, 0.35;
		$client->syswrite('SEE-THIS');
		close $client;
	}
}

sub delayed_ssl_daemon {
	my ($port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		select undef, undef, undef, 0.35;

		eval {
			IO::Socket::SSL->start_SSL($client,
				SSL_server => 1,
				SSL_cert_file => "$d/localhost.crt",
				SSL_key_file => "$d/localhost.key",
				SSL_error_trap => sub { die $_[1] }
			);
		};
		next if $@;

		$client->sysread(my $buffer, 1) or next;
		$client->syswrite('SSL-OK');
		close $client;
	}
}

sub echo_daemon {
	my ($port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		$client->sysread(my $buffer, 1) or next;
		$client->syswrite('SEE-THIS');
		close $client;
	}
}

sub close_daemon {
	my ($port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	while (my $client = $server->accept()) {
		$client->sysread(my $buffer, 1) or next;
		select undef, undef, undef, 0.35;
		close $client;
	}
}

###############################################################################
