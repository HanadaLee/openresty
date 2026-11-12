#!/usr/bin/perl

# Conditional TLS handshake rejection and asynchronous delay.

use warnings;
use strict;

use IO::Socket::SSL;
use Time::HiRes qw/ time sleep /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite stream stream_ssl
	stream_return stream_map socket_ssl_sni/)->has_daemon('openssl');
my $d = $t->testdir();
my $expr = $t->has_module('ngx_expr_module');
my $var = $t->has_module('ngx_var_module');
my $fingerprint = $t->has_module('ngx_ssl_fingerprint_module');
my $realip = $t->has_module('stream_realip');
my $lua = $t->has_module('lua');
my $quic = $t->has_module('http_v3') && $t->has_feature('cryptx');
if ($quic) { require Test::Nginx::HTTP3; }

$t->write_file('openssl.conf', "[req]\ndistinguished_name = dn\n[dn]\n");
system('openssl req -x509 -newkey rsa:2048 -nodes -days 2 '
	. "-config $d/openssl.conf -subj /CN=test/ -out $d/cert.pem "
	. "-keyout $d/key.pem >>$d/openssl.out 2>&1") == 0 or die "openssl: $?";

for my $scope (qw/http stream/) {
	for my $case (
		['ssl_delay_handshake 1ms;', 1, 'literal delay'],
		['ssl_delay_handshake -1;', 0, 'negative delay'],
		['ssl_delay_handshake invalid;', 0, 'invalid delay'],
		['ssl_delay_handshake 1ms; ssl_delay_handshake 2ms;', 0, 'duplicate delay'],
		['ssl_reject_handshake on; ssl_delay_handshake 1ms;', 1, 'reject without certificate'],
	) {
		my ($setting, $expected, $label) = @$case;
		my $reject = $label eq 'reject without certificate';
		my ($ok, $output) = config_test($scope, $setting, !$reject);
		is($ok, $expected, "$scope: $label") or diag $output;
	}
	if ($expr) {
		my ($ok, $output) = config_test($scope,
			'expr matched str_eq $ssl_server_name reject.test; '
			. 'when matched { ssl_reject_handshake on; }', 0);
		ok(!$ok, "$scope: conditional rejection needs a certificate") or diag $output;
		like($output, qr/no "ssl_certificate"/, "$scope: certificate diagnostic");
		($ok, $output) = config_test($scope,
			'expr matched str_eq $ssl_server_name reject.test; '
			. 'when matched { ssl_reject_handshake on; } ssl_reject_handshake on;', 0);
		ok($ok, "$scope: unconditional rejection fallback permits no certificate") or diag $output;
		($ok, $output) = config_test($scope,
			'expr matched str_eq $ssl_server_name allow.test; '
			. 'when matched { ssl_reject_handshake off; } ssl_reject_handshake on;', 0);
		ok(!$ok, "$scope: conditional acceptance needs a certificate") or diag $output;
		($ok, $output) = config_test($scope,
			'expr matched str_eq $ssl_server_name allow.test; '
			. 'ssl_reject_handshake on; when matched { ssl_reject_handshake off; }', 0);
		ok($ok, "$scope: unreachable acceptance permits no certificate") or diag $output;
	}
}

my $common = <<'EOF';
    ssl_certificate cert.pem;
    ssl_certificate_key key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    map $ssl_server_name $wait {
        default 0;
        delay.test 250ms;
        both.test 250ms;
        invalid.test invalid;
        slow.test 800ms;
    }
EOF
if ($fingerprint) { $common .= "ssl_fingerprint on;\n"; }
if ($expr) {
	$common .= <<'EOF';
    expr rejected str_in $ssl_server_name reject.test both.test;
    expr wait str_in $ssl_server_name conditional.test;
    when rejected { ssl_reject_handshake on; }
    when wait { ssl_delay_handshake 250ms; }
EOF
}
if ($var) { $common .= "var \$policy_delay set \$wait;\n"; }
$common .= 'ssl_delay_handshake ' . ($var ? '$policy_delay' : '$wait') . ";\n";

my ($http, $stream) = ('', '');
for my $scope (qw/http stream/) {
	my $p = $scope eq 'http' ? 18491 : 18492;
	my $reply = $scope eq 'http' ? 'return 200 "$ssl_server_name:$ssl_protocol";'
		: 'return "$ssl_server_name:$ssl_protocol";';
	my $timeouts = $scope eq 'http' ? 'client_header_timeout 100ms;' : 'ssl_handshake_timeout 100ms;';
	my $q = $quic && $scope eq 'http' ? 'listen 127.0.0.1:%%PORT_18493_UDP%% quic;' : '';
	my $body = "$common\nssl_session_cache shared:$scope:1m;\n"
		. "server { listen 127.0.0.1:$p ssl; $q\n"
		. "server_name default.test delay.test invalid.test slow.test conditional.test; $reply }\n";
	if (!$expr) {
		$body .= "server { listen 127.0.0.1:$p ssl; server_name reject.test both.test; "
			. "ssl_reject_handshake on; $reply }\n";
	}
	$body .= "server { listen 127.0.0.1:$p ssl; server_name override.test; "
		. "ssl_delay_handshake 0; ssl_reject_handshake off; $reply }\n";
	$body .= "server { listen 127.0.0.1:" . ($p + 10) . " ssl; "
		. "$timeouts ssl_delay_handshake 1s; $reply }\n";
	$body .= "server { listen 127.0.0.1:$p ssl; "
		. 'server_name ~^(?<delay_part>250ms)\.capture\.test$; '
		. 'ssl_delay_handshake $delay_part; ' . "$reply }\n";
	$body .= "server { listen 127.0.0.1:$p ssl; "
		. 'server_name ~^(250ms)\.numeric\.test$; '
		. 'ssl_delay_handshake $1; ' . "$reply }\n";
	if ($expr) {
		$body .= "server { listen 127.0.0.1:$p ssl; server_name both.test reject.test; $reply }\n";
		$body .= "server { listen 127.0.0.1:$p ssl; server_name first.test; "
			. 'expr yes str_eq $ssl_server_name first.test; '
			. 'when yes { ssl_delay_handshake 0; ssl_reject_handshake off; } '
			. 'ssl_delay_handshake 1s; ssl_reject_handshake on; '
			. "$reply }\n";
		if ($fingerprint) {
			$body .= "server { listen 127.0.0.1:$p ssl; server_name fingerprint.test; "
				. 'expr fingerprint !is_empty $ssl_fingerprint_ja3_hash; '
				. 'when fingerprint { ssl_delay_handshake 250ms; ssl_reject_handshake on; } '
				. "$reply }\n";
		}
	}
	if ($scope eq 'http') { $http = $body; } else { $stream = $body; }
}
if ($realip) {
	$stream .= <<'EOF';
    map $realip_remote_addr $peer_delay {
        127.0.0.1 250ms;
        default 0;
    }
    server {
        listen 127.0.0.1:18496 ssl proxy_protocol;
        set_real_ip_from 127.0.0.1;
        ssl_delay_handshake $peer_delay;
        return "$remote_addr:$realip_remote_addr";
    }
EOF
}
if ($lua) {
	my $path = $ENV{TEST_NGINX_RESTY_LUALIB} || '/usr/local/openresty/lualib';
	$http .= "lua_package_path '$path/?.lua;;';\n";
	$http .= <<'EOF';
    server {
        listen 127.0.0.1:18494 ssl;
        ssl_delay_handshake 250ms;
        ssl_client_hello_by_lua_block { ngx.sleep(0.05) }
        return 200 ok;
    }
    server {
        listen 127.0.0.1:18494 ssl;
        server_name lua-reject.test;
        ssl_delay_handshake 250ms;
        ssl_client_hello_by_lua_block { ngx.exit(ngx.ERROR) }
        return 200 unexpected;
    }
EOF
	if ($quic) {
		$http =~ s/listen 127\.0\.0\.1:18494 ssl;/listen 127.0.0.1:18494 ssl; listen 127.0.0.1:%%PORT_18495_UDP%% quic;/g;
	}
}
write_config("http { %%TEST_GLOBALS_HTTP%% access_log off; $http }\n"
	. "stream { %%TEST_GLOBALS_STREAM%% $stream }\n");
unlink "$d/nginx.pid";
$t->run();
BAIL_OUT('nginx did not start') unless -s "$d/nginx.pid";

for my $p (18491, 18492) {
	for my $tls (qw/TLSv1_2 TLSv1_3/) {
		for my $case (
			['default.test', 1, 0], [undef, 1, 0], ['delay.test', 1, 1],
			['reject.test', 0, 0], ['both.test', 0, 1], ['override.test', 1, 0],
			['invalid.test', 0, 0],
			['250ms.capture.test', 1, 1], ['250ms.numeric.test', 1, 1],
			($expr ? (['conditional.test', 1, 1], ['first.test', 1, 0]) : ()),
			($expr && $fingerprint ? (['fingerprint.test', 0, 1]) : ()),
		) {
			my ($name, $accepted, $delayed) = @$case;
			my $label = "$p $tls " . ($name // 'no SNI');
			my ($ok, $elapsed, $body) = connect_tls($p, $name, $tls);
			is($ok, $accepted, "$label: handshake") or diag $body;
			if ($delayed) { cmp_ok($elapsed, '>=', 0.22, "$label: delayed"); }
			if ($accepted) { like($body, qr/TLSv1\.[23]/, "$label: post-handshake variables"); }
		}
	}
	my $saved;
	for my $resumed (0, 1) {
		my ($ok, $elapsed, undef, $reused, $s) = connect_tls($p, 'delay.test',
			'TLSv1_2', SSL_session_cache_size => 4,
			($saved ? (SSL_reuse_ctx => $saved) : ()));
		$saved = $s;
		ok($ok, "$p: session connection $resumed accepted");
		is($reused, $resumed, "$p: session reuse $resumed");
		cmp_ok($elapsed, '>=', 0.22, "$p: session connection $resumed delayed");
	}
	$saved->close() if $saved;
	my ($ok, $elapsed) = connect_tls($p + 10, 'timeout.test', 'TLSv1_2');
	ok(!$ok, "$p: handshake timeout cancels delay");
	cmp_ok($elapsed, '<', 0.8, "$p: original handshake deadline retained");

	# Send a ClientHello then leave the connection waiting while another connects.
	my $waiting = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => port($p));
	IO::Socket::SSL->start_SSL($waiting, SSL_startHandshake => 0,
		SSL_verify_mode => 0, SSL_hostname => 'slow.test');
	$waiting->blocking(0);
	$waiting->connect_SSL();
	sleep 0.03;
	($ok, $elapsed) = connect_tls($p, 'default.test', 'TLSv1_2');
	ok($ok, "$p: another handshake proceeds during delay");
	cmp_ok($elapsed, '<', 0.6, "$p: worker is not blocked by delay");
	$waiting->close(SSL_no_shutdown => 1);
	sleep 0.85;
	($ok) = connect_tls($p, 'default.test', 'TLSv1_2');
	ok($ok, "$p: worker survives client disconnect during delay");
}

SKIP: {
	skip 'requires stream_realip', 3 unless $realip;
	my ($ok, $elapsed, $body) = connect_tls(18496, 'realip.test', 'TLSv1_3',
		proxy_protocol => "PROXY TCP4 198.51.100.1 127.0.0.1 12345 18496\r\n");
	ok($ok, 'Stream realip: handshake accepted');
	cmp_ok($elapsed, '>=', 0.22, 'Stream realip: original peer used during handshake');
	is($body, '198.51.100.1:127.0.0.1', 'Stream realip: session context preserved');
}

SKIP: {
	skip 'requires ngx_http_lua_module', 4 unless $lua;
	for my $case (['lua.test', 1, 0.28], ['lua-reject.test', 0, 0.22]) {
		my ($ok, $elapsed) = connect_tls(18494, $case->[0], 'TLSv1_3');
		is($ok, $case->[1], "$case->[0]: native retry reaches Lua callback");
		cmp_ok($elapsed, '>=', $case->[2], "$case->[0]: native delay precedes Lua");
	}
}

SKIP: {
	skip 'requires HTTP/3, CryptX and expr', 6 unless $quic && $expr;
	for my $case (['default.test', 1, 0], ['conditional.test', 1, 1], ['both.test', 0, 1]) {
		my ($name, $accept, $delay) = @$case;
		my $start = time();
		my $s = Test::Nginx::HTTP3->new(18493, sni => $name, probe => !$accept);
		my $frames;
		if ($accept) {
			my $sid = $s->new_stream({ host => $name });
			$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
		} else {
			$frames = $s->read(all => [{ type => 'CONNECTION_CLOSE' }]);
		}
		my $elapsed = time() - $start;
		if ($accept) {
			my ($headers) = grep { $_->{type} eq 'HEADERS' } @$frames;
			is($headers->{headers}{':status'}, '200', "QUIC $name: accepted");
		} else {
			my ($close) = grep { $_->{type} eq 'CONNECTION_CLOSE' } @$frames;
			is($close->{error}, 0x100 + 112, "QUIC $name: rejected");
		}
		cmp_ok($elapsed, '>=', $delay ? 0.22 : 0, "QUIC $name: delay");
	}
}

SKIP: {
	skip 'requires HTTP/3, CryptX and Lua', 4 unless $quic && $lua;
	for my $case (['lua.test', 1], ['lua-reject.test', 0]) {
		my ($name, $accept) = @$case;
		my $start = time();
		my $s = Test::Nginx::HTTP3->new(18495, sni => $name, probe => !$accept);
		if ($accept) {
			my $sid = $s->new_stream({ host => $name });
			my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
			my ($headers) = grep { $_->{type} eq 'HEADERS' } @$frames;
			is($headers->{headers}{':status'}, '200', "QUIC $name: Lua yield after native delay");
		} else {
			my $frames = $s->read(all => [{ type => 'CONNECTION_CLOSE' }]);
			my ($close) = grep { $_->{type} eq 'CONNECTION_CLOSE' } @$frames;
			cmp_ok($close->{error} // 0, '>=', 0x100, "QUIC $name: Lua rejection");
		}
		cmp_ok(time() - $start, '>=', 0.22, "QUIC $name: native delay before Lua");
	}
}

$t->stop();
unlike($t->read_file('error.log'), qr/AddressSanitizer|runtime error:|exited on signal/,
	'no memory errors or worker crashes');
done_testing();

sub connect_tls {
	my ($p, $name, $tls, %options) = @_;
	my $start = time();
	my $proxy = delete $options{proxy_protocol};
	my %ssl = (SSL_hostname => $name, SSL_verify_mode => 0,
		SSL_version => $tls, Timeout => 3, %options);
	my $s;
	if (defined $proxy) {
		$s = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
			PeerPort => port($p), Timeout => 3) or die "connect: $!";
		print $s $proxy;
		$s = IO::Socket::SSL->start_SSL($s, %ssl);
	} else {
		$s = IO::Socket::SSL->new(PeerAddr => '127.0.0.1',
			PeerPort => port($p), %ssl);
	}
	my $elapsed = time() - $start;
	return (0, $elapsed, IO::Socket::SSL::errstr()) unless $s;
	if ($p == 18491 || $p == 18494) {
		print $s "GET / HTTP/1.0\r\nHost: " . ($name // 'localhost') . "\r\n\r\n";
	}
	my $body = '';
	$s->sysread($body, 4096);
	my $reused = $s->get_session_reused() ? 1 : 0;
	$s->close() unless $options{SSL_session_cache_size};
	return (1, $elapsed, $body, $reused, $s);
}

sub write_config {
	my ($body) = @_;
	$body =~ s/127\.0\.0\.1:(\d+)/127.0.0.1:%%PORT_$1%%/g;
	$t->write_file_expand('nginx.conf', "%%TEST_GLOBALS%%\ndaemon off;\n"
		. "events { worker_connections 256; }\n$body");
}

sub config_test {
	my ($scope, $setting, $cert) = @_;
	my $paths = $cert ? 'ssl_certificate cert.pem; ssl_certificate_key key.pem;' : '';
	my $reply = $scope eq 'http' ? 'return 200 ok;' : 'return ok;';
	my $logging = $scope eq 'http' ? 'access_log off;' : '';
	write_config("$scope { $logging server { listen 127.0.0.1:18491 ssl; $paths $setting $reply } }");
	my $pid = open(my $pipe, '-|');
	die "fork: $!" unless defined $pid;
	if (!$pid) {
		open STDERR, '>&', \*STDOUT or die "dup: $!";
		exec($Test::Nginx::NGINX, '-t', '-p', "$d/", '-c', 'nginx.conf', '-e', 'error.log');
		die "exec: $!";
	}
	my $output = do { local $/; <$pipe> };
	close $pipe;
	return ($? == 0 ? 1 : 0, $output);
}
