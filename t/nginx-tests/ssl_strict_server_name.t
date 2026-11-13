#!/usr/bin/perl

# Strict SNI validation in the combined post-read phase chain.

use warnings;
use strict;

use Digest::MD5 qw/ md5_hex /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite realip
	ngx_expr_module ngx_http_auth_internal_module ngx_http_phase_control_module
	ngx_http_server_redirect_module ngx_http_ssl_strict_server_name_module
	socket_ssl_sni/)->has_daemon('openssl')->plan(18);
my $d = $t->testdir();

$t->write_file('openssl.conf', "[req]\ndistinguished_name = dn\n[dn]\n");
system('openssl req -x509 -newkey rsa:2048 -nodes -days 2 '
	. "-config $d/openssl.conf -subj /CN=origin.test/ -out $d/cert.pem "
	. "-keyout $d/key.pem >>$d/openssl.out 2>&1") == 0 or die "openssl: $?";

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate cert.pem;
    ssl_certificate_key key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_strict_server_name on;

    set_real_ip_from 127.0.0.1;
    real_ip_header X-Real-IP;

    server {
        listen 127.0.0.1:8443 ssl default_server;
        server_name origin.test;

        return 200 "origin:$host:$server_redirect_original_host";
    }

    server {
        listen 127.0.0.1:8443 ssl;
        server_name protected.test;

        auth_internal on;
        auth_internal_empty_deny on;
        auth_internal_failure_deny on;
        auth_internal_timeout 60s;

        expr socket_peer str_eq $realip_remote_addr 127.0.0.1;
        when socket_peer {
            auth_internal_secret primary;
        }
        auth_internal_secret fallback;

        expr exempt_client str_eq $remote_addr 192.0.2.10;
        when exempt_client {
            ssl_strict_server_name off;
        }
        ssl_strict_server_name on;

        return 200 "protected:$auth_internal_result:$remote_addr";
    }

    server {
        listen 127.0.0.1:8443 ssl;
        server_name redirect.test;

        server_redirect origin.test;
        return 200 redirect;
    }

    server {
        listen 127.0.0.1:8443 ssl;
        server_name skip.test;

        skip_post_read on;
        auth_internal on;
        auth_internal_secret primary;
        auth_internal_empty_deny on;
        server_redirect origin.test;

        return 200 "skipped:$host:$remote_addr";
    }
}
EOF

$t->run();

for my $tls (qw/TLSv1_2 TLSv1_3/) {
	my $time = sprintf('%08x', time());
	my $token = $time . md5_hex('primary' . $time);

	like(request($tls, 'origin.test', 'origin.test'),
		qr/200 OK/, "$tls: matching names pass");
	like(request($tls, 'origin.test', 'protected.test'),
		qr/403 Forbidden/, "$tls: authentication precedes SNI validation");
	like(request($tls, 'origin.test', 'protected.test',
		'X-Fingerprint' => $token), qr/421 Misdirected Request/,
		"$tls: authenticated request still requires matching SNI");
	like(request($tls, 'origin.test', 'protected.test',
		'X-Fingerprint' => $token, 'X-Real-IP' => '192.0.2.10'),
		qr/200 OK.*\r\n\r\nprotected:success:192\.0\.2\.10$/s,
		"$tls: authenticated SNI policy uses real IP");
	like(request($tls, 'origin.test', 'protected.test',
		'X-Fingerprint' => $token, 'X-Real-IP' => '192.0.2.11'),
		qr/421 Misdirected Request/, "$tls: other real IP is not exempt");
	like(request($tls, 'origin.test', 'protected.test',
		'X-Fingerprint' => 'invalid', 'X-Real-IP' => '192.0.2.10'),
		qr/403 Forbidden/, "$tls: SNI exemption does not bypass authentication");
	like(request($tls, 'origin.test', 'redirect.test'),
		qr/421 Misdirected Request/, "$tls: SNI validation precedes server redirect");
	like(request($tls, 'redirect.test', 'redirect.test'),
		qr/200 OK.*\r\n\r\norigin:origin\.test:redirect\.test$/s,
		"$tls: server redirect does not repeat SNI validation");
	like(request($tls, 'origin.test', 'skip.test',
		'X-Real-IP' => '192.0.2.10'),
		qr/200 OK.*\r\n\r\nskipped:skip\.test:127\.0\.0\.1$/s,
		"$tls: phase control skips the entire post-read chain");
}

$t->stop();

sub request {
	my ($tls, $sni, $host, %headers) = @_;
	my $request = "GET / HTTP/1.0\r\nHost: $host\r\n";

	for my $name (sort keys %headers) {
		$request .= "$name: $headers{$name}\r\n";
	}

	return http($request . "\r\n", SSL => 1,
		PeerAddr => '127.0.0.1:' . port(8443),
		SSL_hostname => $sni, SSL_version => $tls);
}
