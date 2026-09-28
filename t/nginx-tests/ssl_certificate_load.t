#!/usr/bin/perl

# Runtime loading of constant certificate paths in HTTP/Stream and upstreams.

use warnings;
use strict;

use File::Copy qw/ copy /;
use IO::Socket::SSL;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http http_ssl http_v2 rewrite proxy
	grpc uwsgi stream stream_ssl stream_return stream_map/)->has_daemon('openssl');
my $d = $t->testdir();

# Runtime defers missing-file errors but still rejects a missing key directive.
my @targets = qw/http stream proxy grpc uwsgi stream-proxy/;
for my $target (@targets) {
	for my $case (
		[ '', 'missing.crt', 'missing.key', 0, 'implicit default loads constant paths' ],
		[ 'default', 'missing.crt', 'missing.key', 0, 'explicit default' ],
		[ 'runtime', 'missing.crt', 'missing.key', 1, 'runtime defers files' ],
		[ 'default', '$cert.crt', 'missing.key', 1, 'variable certificate wins' ],
		[ 'default', 'missing.crt', '$cert.key', 1, 'variable key wins' ],
		[ 'runtime', 'missing.crt', undef, 0, 'missing key directive' ],
		[ 'invalid', 'missing.crt', 'missing.key', 0, 'invalid mode' ],
		[ 'runtime; %LOAD% default', 'missing.crt', 'missing.key', 0,
			'duplicate directive' ],
	) {
		my ($mode, $cert, $key, $expected, $name) = @$case;
		config_case($target, $mode, $cert, $key);
		my ($ok, $output) = config_test();
		is($ok, $expected, "$target: $name") or diag $output;
	}
	config_case($target, 'default', 'missing.crt', 'missing.key', 1);
	my ($ok, $output) = config_test();
	ok(!$ok, "$target: default overrides inherited runtime") or diag $output;
	config_case($target, 'runtime', 'missing.crt', 'missing.key', 'default');
	($ok, $output) = config_test();
	ok($ok, "$target: runtime overrides inherited default") or diag $output;
}

$t->write_file('openssl.conf', <<'EOF');
[req]
distinguished_name = dn
[dn]
EOF
for my $name (qw/one two encrypted/) {
	my $password = $name eq 'encrypted' ? '-passout pass:secret' : '-nodes';
	system("openssl req -x509 -newkey rsa:2048 -days 2 $password "
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0 or die "openssl: $?";
}
$t->write_file('password', "secret\n");

my @modes = qw/runtime default cache variable-cert variable-key encrypted late/;
my %ports;
my $http = '';
my $stream = '';
my $next_port = 18090;

# Switching only load mode must not reuse a sibling's incompatible SSL_CTX.
for my $target (qw/http stream/) {
	deploy($target, 'one');
	for my $mode (@modes) {
		my $p = $ports{"$target/$mode"} = $next_port++;
		my $extra = cert_options('ssl', $target, $mode);
		my $server = "server {\n listen 127.0.0.1:$p ssl;\n$extra";
		$server .= $target eq 'http' ? "return 200 ok;\n" : "return ok;\n";
		$server .= "}\n";
		if ($target eq 'http') { $http .= $server; }
		else { $stream .= $server; }
	}

	my $p = $ports{"$target/sni"} = $next_port++;
	my $reply = $target eq 'http' ? 'return 200 ok;' : 'return ok;';
	my $servers = "server { listen 127.0.0.1:$p ssl;\n"
		. "server_name default.example; ssl_certificate_load default;\n"
		. "ssl_certificate one.crt; ssl_certificate_key one.key; $reply }\n"
		. "server { listen 127.0.0.1:$p ssl;\n"
		. "server_name runtime.example; ssl_certificate $target.crt;\n"
		. "ssl_certificate_key $target.key; $reply }\n";
	if ($target eq 'http') { $http .= $servers; }
	else { $stream .= $servers; }
}

my $upstreams = '';
for my $target (qw/proxy grpc uwsgi/) {
	deploy($target, 'one');
	$upstreams .= "$target" . "_ssl_certificate_load runtime;\n"
		. "$target" . "_ssl_certificate $target.crt;\n"
		. "$target" . "_ssl_certificate_key $target.key;\n"
		. "$target" . "_ssl_session_reuse off;\n";
	for my $mode (@modes) {
		my $pass = $target eq 'proxy' ? 'https' :
			$target eq 'grpc' ? 'grpcs' : 'suwsgi';
		my $extra = cert_options($target . '_ssl', $target, $mode, 1);
		$http .= "server {\n listen 127.0.0.1:"
			. ($ports{"$target/$mode"} = $next_port++) . ";\n"
			. "location / {\n$extra"
			. $target . "_pass $pass://127.0.0.1:18081;\n}\n}\n";
	}
}

deploy('stream-proxy', 'one');
for my $mode (@modes) {
	my $p = $ports{"stream-proxy/$mode"} = $next_port++;
	my $extra = cert_options('proxy_ssl', 'stream-proxy', $mode, 1);
	$stream .= "server {\n listen 127.0.0.1:$p;\n$extra"
		. "proxy_ssl on;\nproxy_pass 127.0.0.1:18081;\n}\n";
}

write_config(<<EOF);
%%TEST_GLOBALS%%
daemon off;
worker_processes 1;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    map "" \$http_path { default http; }
    map "" \$proxy_path { default proxy; }
    map "" \$grpc_path { default grpc; }
    map "" \$uwsgi_path { default uwsgi; }
    ssl_certificate_load runtime;
    ssl_session_cache off;
    ssl_session_tickets off;
    $upstreams
    $http
    server {
        listen 127.0.0.1:18081 ssl;
        http2 on;
        ssl_certificate_load default;
        ssl_certificate one.crt;
        ssl_certificate_key one.key;
        ssl_verify_client optional_no_ca;
        add_header X-Client \$ssl_client_s_dn always;
        return 200 ok;
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    map "" \$stream_path { default stream; }
    map "" \$stream_proxy_path { default stream-proxy; }
    ssl_certificate_load runtime;
    ssl_session_cache off;
    ssl_session_tickets off;
    proxy_ssl_certificate_load runtime;
    proxy_ssl_certificate stream-proxy.crt;
    proxy_ssl_certificate_key stream-proxy.key;
    proxy_ssl_session_reuse off;
    $stream
}
EOF

# The late files do not exist yet; startup must nevertheless succeed.
$t->run();
for my $target (@targets) {
	for my $mode (@modes) {
		my $expected = $mode eq 'late' ? '' :
			$mode eq 'encrypted' ? 'encrypted' : 'one';
		is(subject($target, $mode), $expected, "$target: initial $mode");
	}
	deploy("$target-late", 'two');
	is(subject($target, 'late'), 'two', "$target: files deployed after startup");
}

for my $target (@targets) {
	unlink("$d/$target.crt", "$d/$target.key") == 2 or die "unlink: $!";
	for my $mode (qw/runtime default cache variable-cert variable-key/) {
		is(subject($target, $mode),
			$mode eq 'default' || $mode eq 'cache' ? 'one' : '',
			"$target: $mode after files removed");
	}
	deploy($target, 'two');
	for my $mode (qw/runtime default cache variable-cert variable-key/) {
		is(subject($target, $mode),
			$mode eq 'default' || $mode eq 'cache' ? 'one' : 'two',
			"$target: $mode after certificate replacement");
	}
	if ($target eq 'http' || $target eq 'stream') {
		is(subject($target, 'sni', 'default.example'), 'one',
			"$target: default SNI certificate");
		is(subject($target, 'sni', 'runtime.example'), 'two',
			"$target: runtime SNI certificate");
	}
}

$t->stop();
unlike($t->read_file('error.log'), qr/\[alert\]|Sanitizer/,
	'no alerts or sanitizer errors');
undef $t;
done_testing();

sub deploy {
	my ($path, $name) = @_;
	copy("$d/$name.crt", "$d/$path.crt") or die "copy cert: $!";
	copy("$d/$name.key", "$d/$path.key") or die "copy key: $!";
}

sub cert_options {
	my ($prefix, $target, $mode, $inherited) = @_;
	my $cert = "$target.crt";
	my $key = "$target.key";
	my $extra = '';

	$extra .= $prefix . "_certificate_load default;\n"
		if $mode =~ /^(default|variable-)/;
	$extra .= $prefix . "_certificate_cache max=20 valid=1h inactive=1h;\n"
		if $mode eq 'cache';

	(my $var = $target) =~ s/-/_/g;
	$cert = '$' . $var . '_path.crt' if $mode eq 'variable-cert';
	$key = '$' . $var . '_path.key' if $mode eq 'variable-key';
	if ($mode eq 'encrypted') {
		$cert = 'encrypted.crt';
		$key = 'encrypted.key';
		$extra .= $prefix . "_password_file password;\n";
	}
	if ($mode eq 'late') {
		$cert = "$target-late.crt";
		$key = "$target-late.key";
	}
	# Leave these inherited to exercise SSL context sharing across siblings.
	unless ($inherited && $mode =~ /^(runtime|default|cache)$/) {
		$extra .= $prefix . "_certificate $cert;\n"
			. $prefix . "_certificate_key $key;\n";
	}
	return $extra;
}

sub subject {
	my ($target, $mode, $host) = @_;
	my $p = port($ports{"$target/$mode"});
	if ($target eq 'http' || $target eq 'stream') {
		my $s = IO::Socket::SSL->new(
			PeerAddr => "127.0.0.1:$p", Timeout => 3,
			SSL_verify_mode => 0, SSL_hostname => $host // 'localhost',
		) or return '';
		my $name = $s->peer_certificate('cn');
		$s->close();
		return $name // '';
	}
	my $response = http_get('/', PeerAddr => "127.0.0.1:$p") // '';
	return $response =~ /X-Client:.*?CN=([a-z]+)/i ? $1 : '';
}

sub config_case {
	my ($target, $mode, $cert, $key, $inherit) = @_;
	my $is_stream = $target =~ /^stream/;
	my $upstream = $target ne 'http' && $target ne 'stream';
	my $module = $target eq 'stream-proxy' ? 'proxy' : $target;
	my $prefix = $upstream ? $module . '_ssl' : 'ssl';
	my $load = $prefix . '_certificate_load';
	$mode =~ s/%LOAD%/$load/g;
	my $extra = $mode eq '' ? '' : "$load $mode;\n";
	my $paths = $prefix . "_certificate $cert;\n";
	$paths .= $prefix . "_certificate_key $key;\n" if defined $key;
	my $parent_mode = $inherit && $inherit eq 'default' ? 'default' : 'runtime';
	my $parent = $inherit ? "$load $parent_mode;\n$paths" : '';
	$extra .= $paths unless $inherit;
	my $pass = '';
	if ($upstream) {
		$pass = $target eq 'stream-proxy'
			? 'proxy_ssl on; proxy_pass 127.0.0.1:18081;'
			: $module . "_pass "
				. ($module eq 'proxy' ? 'https' :
					$module eq 'grpc' ? 'grpcs' : 'suwsgi')
				. '://127.0.0.1:18081;';
		$extra = "location / { $extra $pass }" unless $is_stream;
	} else {
		$pass = $is_stream ? 'return ok;' : 'return 200 ok;';
	}
	my $scope = $is_stream ? 'stream' : 'http';
	my $globals = $is_stream ? '%%TEST_GLOBALS_STREAM%%' : '%%TEST_GLOBALS_HTTP%%';
	my $listen = $upstream ? '' : ' ssl';
	my $body = $upstream && !$is_stream ? $extra : "$extra $pass";
	write_config(<<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
$scope {
    $globals
    map "" \$cert { default missing; }
    $parent
    server {
        listen 127.0.0.1:18080$listen;
        $body
    }
}
EOF
}

sub write_config {
	my ($config) = @_;
	$config =~ s/127\.0\.0\.1:(\d+)/127.0.0.1:%%PORT_$1%%/g;
	$t->write_file_expand('nginx.conf', $config);
}

sub config_test {
	my $pid = open(my $pipe, '-|');
	die "fork: $!" unless defined $pid;
	if (!$pid) {
		open STDERR, '>&', \*STDOUT or die "dup: $!";
		exec($Test::Nginx::NGINX, '-t', '-p', "$d/", '-c', 'nginx.conf',
			'-e', 'error.log');
		die "exec: $!";
	}
	my $output = do { local $/; <$pipe> };
	close $pipe;
	return ($? == 0 ? 1 : 0, $output);
}
