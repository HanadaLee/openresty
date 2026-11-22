#!/usr/bin/perl

# TLS sessions on new TCP connections to dynamically selected upstream peers.

use warnings;
use strict;

use IO::Socket::INET;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http http_ssl proxy stream stream_ssl
	stream_return stream_map/)->has_daemon('openssl');
my $d = $t->testdir();

$t->write_file('openssl.cnf', <<'EOF');
[req]
distinguished_name = dn
[dn]
EOF
local $ENV{OPENSSL_CONF} = "$d/openssl.cnf";

system("openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=one.test "
	. "-keyout $d/origin.key -out $d/origin.crt >$d/openssl.log 2>&1") == 0
	or die "openssl req: $?";

my ($http, $stream) = ('', '');
for my $v (2, 3) {
	$http .= <<"END";
	server {
	    listen 127.0.0.1:80${v}0;
	    proxy_ssl_protocols TLSv1.$v;
	    proxy_ssl_server_name on;
	    proxy_ssl_name \$host;
	    proxy_set_header Connection close;
	    location / { proxy_pass https://dynamic; }
	    location /retry {
	        proxy_next_upstream http_503;
	        proxy_pass https://dynamic;
	    }
	    location /off {
	        proxy_ssl_session_reuse off;
	        proxy_pass https://dynamic;
	    }
	    location /verify {
	        proxy_ssl_verify on;
	        proxy_ssl_trusted_certificate origin.crt;
	        proxy_pass https://dynamic;
	    }
	    location /optional {
	        error_log %%TESTDIR%%/optional.log error;
	        proxy_ssl_certificate \$test_cert;
	        proxy_ssl_certificate_key \$test_key;
	        proxy_pass https://dynamic;
	    }
	    location /cert {
	        proxy_ssl_certificate origin.crt;
	        proxy_ssl_certificate_key origin.key;
	        proxy_pass https://dynamic;
	    }
	    location /callback {
	        proxy_ssl_certificate_by_lua_block { ngx.ctx.cert_called = true }
	        proxy_pass https://dynamic;
	    }
	}
END
	$stream .= <<"END";
	server {
	    listen 127.0.0.1:80${v}1 proxy_protocol;
	    proxy_ssl on;
	    proxy_ssl_protocols TLSv1.$v;
	    proxy_ssl_server_name on;
	    proxy_ssl_name \$name;
	    proxy_ssl_alpn \$alpn;
	    proxy_pass dynamic;
	}
	server {
	    listen 127.0.0.1:80${v}2 proxy_protocol;
	    proxy_ssl on;
	    proxy_ssl_protocols TLSv1.$v;
	    proxy_ssl_certificate_by_lua_block { ngx.ctx.cert_called = true }
	    proxy_pass dynamic;
	}
END
}

for my $size (0, 2) {
	my $peers = <<"END";
	upstream capacity_$size {
	    server 0.0.0.1:1;
	    balancer_ssl_session_cache $size;
	    balancer_by_lua_block {
	        assert(require("ngx.balancer").set_current_peer("127.0.0.1", BACKEND))
	    }
	}
END
	(my $http_peers = $peers) =~ s/BACKEND/%%PORT_8090%%/;
	$http_peers =~ s/    server 0/    balancer_keepalive 1;\n\t    server 0/;
	(my $stream_peers = $peers) =~ s/BACKEND/%%PORT_8091%%/;
	$http .= $http_peers . <<"END";
	server {
	    listen 127.0.0.1:804$size;
	    proxy_ssl_protocols TLSv1.2;
	    proxy_ssl_server_name on;
	    proxy_ssl_name \$host;
	    location / { proxy_pass https://capacity_$size; }
	}
END
	$stream .= $stream_peers . <<"END";
	server {
	    listen 127.0.0.1:805$size proxy_protocol;
	    proxy_ssl_protocols TLSv1.2;
	    proxy_ssl_server_name on;
	    proxy_ssl_name \$name;
	    proxy_ssl_alpn \$alpn;
	    proxy_ssl on;
	    proxy_pass capacity_$size;
	}
END
}

$t->write_file_expand('nginx.conf', <<"END");
%%TEST_GLOBALS%%
daemon off;
worker_processes 1;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    map \$http_x_test_cert \$test_cert { on origin.crt; default ""; }
    map \$http_x_test_cert \$test_key { on origin.key; default "not-opened"; }
    upstream dynamic {
        server 0.0.0.1:1;
        balancer_by_lua_block {
            local b = require "ngx.balancer"
            local port = ngx.var.http_x_test_peer == "second" and %%PORT_8092%% or %%PORT_8090%%
            if ngx.var.uri == "/retry" and not ngx.ctx.retried then
                ngx.ctx.retried = true
                assert(b.set_more_tries(1))
                port = %%PORT_8093%%
            end
            assert(b.set_current_peer("127.0.0.1", port))
        }
    }
    $http
    log_format session_status "\$ssl_session_reused";
    server {
        listen 127.0.0.1:8093 ssl;
        ssl_certificate origin.crt;
        ssl_certificate_key origin.key;
        ssl_session_cache shared:retry_origin:1m;
        access_log %%TESTDIR%%/retry.log session_status;
        return 503;
    }
    server {
        listen 127.0.0.1:8090 ssl;
        listen 127.0.0.1:8092 ssl;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_certificate origin.crt;
        ssl_certificate_key origin.key;
        ssl_session_cache shared:http_origin:1m;
        ssl_verify_client optional_no_ca;
        keepalive_timeout 0;
        return 200 "\$ssl_session_reused:\$connection";
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    map \$proxy_protocol_addr \$alpn { 192.0.2.3 h2; default http/1.1; }
    map \$proxy_protocol_addr \$name { 192.0.2.2 two.test; default one.test; }
    upstream dynamic {
        server 0.0.0.1:1;
        balancer_by_lua_block {
            local b = require "ngx.balancer"
            assert(b.set_current_peer("127.0.0.1", %%PORT_8091%%))
        }
    }
    $stream
    server {
        listen 127.0.0.1:8091 ssl;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_certificate origin.crt;
        ssl_certificate_key origin.key;
        ssl_session_cache shared:stream_origin:1m;
        ssl_verify_client optional_no_ca;
        ssl_alpn http/1.1 h2;
        return "\$ssl_session_reused:\$connection";
    }
}
END
$t->run();

my %seen;
sub result {
	my ($reply, $expected, $label) = @_;
	my ($status, $connection) = ($reply // '') =~ /([.r]):(\d+)\s*$/;
	is($status, $expected, $label);
	ok(defined $connection && !$seen{$connection}++, "$label - new TCP connection");
}

for my $v (2, 3) {
	my $tls = "TLS 1.$v";
	for my $case (
		['/', 'one.test', '.', 'cold'],
		['/', 'one.test', 'r', 'warm'],
		['/', 'two.test', '.', 'different SNI'],
		['/', 'one.test', 'r', 'first SNI retained'],
		['/', 'one.test', '.', 'different peer port', 'X-Test-Peer: second'],
		['/verify', 'one.test', '.', 'first verified handshake'],
		['/verify', 'one.test', 'r', 'same verification policy'],
		['/retry', 'one.test', '.', 'retry selects a new peer'],
		['/retry', 'one.test', 'r', 'retry restores the selected peer'],
		['/off', 'one.test', '.', 'disabled'],
		['/off', 'one.test', '.', 'still disabled'],
		['/optional', 'one.test', '.', 'empty certificate'],
		['/optional', 'one.test', 'r', 'empty certificate can resume'],
		['/optional', 'one.test', '.', 'request with certificate', 'X-Test-Cert: on'],
		['/optional', 'one.test', 'r', 'empty certificate after mTLS'],
		['/cert', 'one.test', '.', 'client certificate'],
		['/cert', 'one.test', '.', 'client certificate not cached'],
		['/callback', 'one.test', '.', 'certificate callback'],
		['/callback', 'one.test', '.', 'callback still active'],
	) {
		my ($uri, $host, $want, $label, $header) = @$case;
		$header = defined $header ? "$header\r\n" : '';
		my $reply = http("GET $uri HTTP/1.0\r\nHost: $host\r\n$header\r\n",
			PeerAddr => '127.0.0.1:' . port("80${v}0"));
		result($reply, $want, "$tls HTTP $label");
	}
	my $bad = http("GET /verify HTTP/1.0\r\nHost: two.test\r\n\r\n",
		PeerAddr => '127.0.0.1:' . port("80${v}0"));
	like($bad, qr/HTTP\/1\.[01] 502/, "$tls wrong verification name");

	for my $case ([1, '.', 'cold'], [1, 'r', 'warm'],
		[2, '.', 'different SNI'], [3, '.', 'different ALPN'],
		[3, 'r', 'same ALPN'], [1, 'r', 'first offer retained'],
		[1, '.', 'certificate callback', 2], [1, '.', 'callback again', 2],
		[1, '.', 'callback remains active', 2])
	{
		my ($ip, $want, $label, $listener) = @$case;
		$listener ||= 1;
		my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
			PeerPort => port("80$v$listener"), Timeout => 5) or die $!;
		print $s "PROXY TCP4 192.0.2.$ip 127.0.0.1 12345 443\r\n";
		result(scalar <$s>, $want, "$tls Stream $label");
		close $s;
	}
}

for my $size (0, 2) {
	my @cases = $size ? ([1, '.'], [2, '.'], [1, 'r'], [3, '.'], [1, 'r'], [2, '.'])
		: ([1, '.'], [1, '.']);
	for my $case (@cases) {
		my ($id, $want) = @$case;
		my $reply = http("GET / HTTP/1.0\r\nHost: cap-$id.test\r\n\r\n",
			PeerAddr => '127.0.0.1:' . port("804$size"));
		result($reply, $want, "HTTP capacity $size peer $id");

		my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
			PeerPort => port("805$size"), Timeout => 5) or die $!;
		print $s "PROXY TCP4 192.0.2.$id 127.0.0.1 12345 443\r\n";
		result(scalar <$s>, $want, "Stream capacity $size peer $id");
		close $s;
	}
}

my $evict = sub {
	my ($id) = @_;
	my $reply = http("GET / HTTP/1.0\r\nHost: evict-$id.test\r\n\r\n",
		PeerAddr => '127.0.0.1:' . port(8020));
	my ($status) = $reply =~ /([.r]):\d+$/;
	return $status // '';
};

my $cold = 0;
for my $id (0 .. 256) {
	$cold++ if $evict->($id) eq '.';
}
is($cold, 257, 'distinct identities start cold');
is($evict->(256), 'r', 'most recent session retained');
is($evict->(0), '.', 'least recently used session evicted');

$t->stop();
is($t->read_file('retry.log'), ".\nr\n.\nr\n", 'first peer retains its own session across retries');
is($t->read_file('optional.log'), '', 'empty certificate emits no error log');
undef $t;
done_testing();
