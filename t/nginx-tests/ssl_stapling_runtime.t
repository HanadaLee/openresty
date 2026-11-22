#!/usr/bin/perl

# Tests for OCSP stapling of certificates loaded during the handshake.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/sha256_hex/;
use IO::Socket::SSL;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite stream stream_ssl
	stream_map stream_return socket_ssl/)->has_daemon('openssl');

plan(skip_all => 'no OCSP support in the TLS client')
	unless defined &IO::Socket::SSL::SSL_OCSP_TRY_STAPLE
	&& defined &Net::SSLeay::OCSP_response_results;
plan(skip_all => 'no OCSP stapling') if $t->has_module('BoringSSL');
plan(skip_all => 'nginx extensions are disabled') if $t->has_module('--without-ext');

my $d = $t->testdir();
my $ocsp_port = port(8080);
my $client = '';
my $compression = $t->has_module('built with OpenSSL (?:3\.(?:[2-9]|[1-9]\d+)\.|[4-9]\.)')
    ? 'ssl_certificate_compression on;' : '';

if (!$t->has_module('--without-client')) {
	$client = <<'EOF';
    ssl_stapling_http_client @ocsp;

    server {
        server_name @ocsp;
        client;

        location / {
            proxy_pass http://127.0.0.1:8080;
        }
    }
EOF
}

my $stream_client = $client eq '' ? '' : 'ssl_stapling_http_client @ocsp;';

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    $compression
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate ca.crt;
    ssl_session_cache off;
    ssl_session_tickets off;

    $client

    map "" \$certificate {
        default variable.crt;
    }

    server {
        listen 127.0.0.1:8443 ssl;
        server_name ocsp.test;
        ssl_certificate_load runtime;
        ssl_certificate_cache max=10 valid=0;
        ssl_certificate active.crt;
        ssl_certificate_key rsa.key;
        ssl_certificate ec.crt;
        ssl_certificate_key ec.key;
        return 200 ok;
    }

    server {
        listen 127.0.0.1:8444 ssl;
        server_name ocsp.test;
        ssl_certificate \$certificate;
        ssl_certificate_key rsa.key;
        return 200 ok;
    }

    server {
        listen 127.0.0.1:8445 ssl;
        server_name ocsp.test;
        ssl_certificate no-aia.crt;
        ssl_certificate_key rsa.key;
        ssl_certificate_load runtime;
        return 200 ok;
    }

    server {
        listen 127.0.0.1:8449 ssl;
        server_name ocsp.test;
        ssl_stapling off;
        ssl_certificate_load runtime;
        ssl_certificate chain.crt;
        ssl_certificate_key rsa.key;
        return 200 ok;
    }

    server {
        listen 127.0.0.1:8080;
        access_log responder.log combined;
        root %%TESTDIR%%;
        default_type application/ocsp-response;

        location /a/ { try_files /a.der =404; }
        location /b/ { try_files /b.der =404; }
        location /ec/ { try_files /ec.der =404; }
        location /bad/ { try_files /a.der =404; }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    $compression
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate ca.crt;
    ssl_session_cache off;
    ssl_session_tickets off;

    $stream_client

    map "" \$key {
        default rsa.key;
    }

    server {
        listen 127.0.0.1:8446 ssl;
        server_name ocsp.test;
        ssl_certificate_load runtime;
        ssl_certificate_cache max=10 valid=0;
        ssl_certificate stream.crt;
        ssl_certificate_key rsa.key;
        return ok;
    }

    server {
        listen 127.0.0.1:8447 ssl;
        server_name ocsp.test;
        ssl_certificate b.crt;
        ssl_certificate_key \$key;
        return ok;
    }

    server {
        listen 127.0.0.1:8448 ssl;
        server_name ocsp.test;
        ssl_certificate_load runtime;
        ssl_certificate bad.crt;
        ssl_certificate_key rsa.key;
        return ok;
    }
}
EOF

$t->write_file('openssl.cnf', <<'EOF');
[req]
distinguished_name = dn
[dn]
EOF
local $ENV{OPENSSL_CONF} = "$d/openssl.cnf";

openssl('req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=ca '
	. '-addext basicConstraints=critical,CA:TRUE '
	. '-addext keyUsage=critical,keyCertSign,cRLSign -keyout ca.key -out ca.crt');
openssl('req -new -newkey rsa:2048 -nodes -subj /CN=ocsp.test '
	. '-keyout rsa.key -out rsa.csr');
openssl('ecparam -name prime256v1 -genkey -noout -out ec.key');
openssl('req -new -key ec.key -subj /CN=ocsp.test -out ec.csr');

my @certificates = (
	[ 'a', 'rsa', '01' ], [ 'b', 'rsa', '02' ], [ 'ec', 'ec', '03' ],
	[ 'bad', 'rsa', '04' ], [ 'no-aia', 'rsa', '05' ],
);

my @db;
for my $cert (@certificates) {
	my ($name, $key, $serial) = @$cert;
	my $ext = "basicConstraints=critical,CA:FALSE\n";
	$ext .= "authorityInfoAccess=OCSP;URI:http://127.0.0.1:$ocsp_port/$name\n"
		unless $name eq 'no-aia';
	$t->write_file('leaf.ext', $ext);
	openssl("x509 -req -in $key.csr -CA ca.crt -CAkey ca.key -set_serial 0x$serial "
		. "-days 1 -extfile leaf.ext -out $name.leaf");
	$t->write_file("$name.crt", $t->read_file("$name.leaf") . $t->read_file('ca.crt'));
	push @db, "V\t491231235959Z\t\t$serial\tunknown\t/CN=ocsp.test\n";
}

$t->write_file('index', join('', @db));
$t->write_file('index.attr', "unique_subject = no\n");
for my $name (qw/a b ec/) {
	openssl('ocsp -index index -CA ca.crt -rsigner ca.crt -rkey ca.key '
		. "-issuer ca.crt -cert $name.leaf -no_nonce -ndays 1 -respout $name.der");
}

for my $name (qw/active variable stream/) {
	$t->write_file("$name.crt", $t->read_file('a.crt'));
}

$t->write_file('chain.crt', $t->read_file('a.crt'));
if ($compression) {
    openssl('req -x509 -key ca.key -days 2 -subj /CN=ca -set_serial 12345 '
        . '-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign '
        . '-out alternate.crt');
    openssl("x509 -in $_.crt -outform DER -out $_.der") for qw/ca alternate/;
}

$t->plan(20 + ($compression ? 18 : 0))->run();

is(staple(8443, 'TLSv1_2'), '1 no staple', 'runtime HTTP cold handshake');
is(warm(8443, 'TLSv1_2'), '1 good', 'runtime HTTP TLS 1.2');
is(staple(8444, 'TLSv1_3'), '1 no staple', 'variable certificate cold handshake');
is(warm(8444, 'TLSv1_3'), '1 good', 'variable certificate without file cache');
is(staple(8446, 'TLSv1_2'), '1 no staple', 'runtime Stream cold handshake');
is(warm(8446, 'TLSv1_2'), '1 good', 'runtime Stream TLS 1.2');
is(staple(8447, 'TLSv1_3'), '2 no staple', 'variable key cold handshake');
is(warm(8447, 'TLSv1_3'), '2 good', 'variable key in Stream');
is(staple(8443, 'TLSv1_2', 'ECDSA'), '3 no staple', 'cold ECDSA beside warm RSA');
is(warm(8443, 'TLSv1_2', 'ECDSA'), '3 good', 'ECDSA has its own staple');
is(staple(8443, 'TLSv1_3'), '1 good', 'RSA staple unchanged by ECDSA');

if ($compression) {
    for my $alg (1 .. 3) {
        compressed(8443, $alg, 1, 'a', 'RSA', "HTTP stapled algorithm $alg");
        compressed(8446, $alg, 1, 'a', 'RSA', "Stream stapled algorithm $alg");
        compressed(8443, $alg, 0, '', 'RSA', "no unsolicited staple $alg");
    }
    compressed(8443, 2, 1, 'ec', 'ECDSA', 'ECDSA uses its own chain and staple');
    compressed(8443, 0, 1, 'a', 'RSA', 'client without compression receives staple');
    compressed(8444, 3, 1, 'a', 'RSA', 'variable certificate without a file cache');
    compressed(8449, 2, 0, '', 'RSA', 'original intermediate', 'ca');
    $t->write_file('chain.crt', $t->read_file('a.leaf') . $t->read_file('alternate.crt'));
    compressed(8449, 2, 0, '', 'RSA', 'changed intermediate starts cold', 'alternate', 0);
    compressed(8449, 2, 0, '', 'RSA', 'changed intermediate is compressed', 'alternate');
}

rotate($_) for qw/active variable stream/;
sleep 1;
is(staple(8443, 'TLSv1_3'), '2 no staple', 'HTTP rotation drops the old staple');
is(warm(8443, 'TLSv1_3'), '2 good', 'HTTP rotation fetches the new staple');
is(warm(8444, 'TLSv1_3'), '2 good', 'variable certificate reuses new staple');
is(staple(8446, 'TLSv1_3'), '2 no staple', 'Stream rotation drops the old staple');
is(warm(8446, 'TLSv1_3'), '2 good', 'Stream rotation fetches the new staple');
is(staple(8445, 'TLSv1_3'), '5 no staple', 'certificate without AIA handshakes');
is(staple(8448, 'TLSv1_3'), '4 no staple', 'wrong OCSP cert ID cold handshake');
is(warm(8448, 'TLSv1_3'), '4 no staple', 'wrong OCSP cert ID is not stapled');

if ($compression) {
    compressed(8443, 2, 1, 'b', 'RSA', 'HTTP rotation replaces the stapled message');
    compressed(8446, 2, 1, 'b', 'RSA', 'Stream rotation replaces the stapled message');
    compressed(8443, 2, 0, '', 'RSA', 'rotated chain without unsolicited staple');
}

my $requests = $t->read_file('responder.log');
is(scalar(() = $requests =~ m{"GET /bad/}g), 1, 'wrong response retries are throttled');

undef $t;

###############################################################################

sub openssl {
	my ($args) = @_;
	system("cd $d && openssl $args >>openssl.log 2>&1") == 0
		or die "openssl $args: " . $t->read_file('openssl.log');
}

sub staple {
	my ($port, $version, $cipher) = @_;
	my $out = '';
	$cipher //= 'RSA';

	my $s = IO::Socket::SSL->new(
		PeerAddr => '127.0.0.1:' . port($port),
		SSL_hostname => 'ocsp.test', SSL_verify_mode => 0,
		SSL_version => $version, SSL_cipher_list => $cipher,
		SSL_create_ctx_callback => sub {
			my $algorithms = $cipher eq 'RSA' ? 'RSA+SHA256:PSS+SHA256'
				: 'ECDSA+SHA256';
			Net::SSLeay::CTX_ctrl($_[0], 98, 0, $algorithms)
				or die 'cannot set signature algorithms';
		},
		SSL_ocsp_mode => IO::Socket::SSL::SSL_OCSP_TRY_STAPLE(),
		SSL_ocsp_staple_callback => sub {
			my ($sock, $resp) = @_;
			my $ssl = $sock->_get_ssl_object();
			my $cert = Net::SSLeay::get_peer_certificate($ssl);
			my $serial = Net::SSLeay::P_ASN1_INTEGER_get_dec(
				Net::SSLeay::X509_get_serialNumber($cert));
			$out = "$serial no staple";
			if ($resp) {
				my $id = Net::SSLeay::OCSP_cert2ids($ssl, $cert);
				my @res = Net::SSLeay::OCSP_response_results($resp, $id);
				$out = "$serial " . (@res && $res[0][2]
					&& $res[0][2]->{statusType} == 0 ? 'good' : 'wrong staple');
			}
			Net::SSLeay::X509_free($cert);
			return 1;
		},
	);

	return "handshake failed: $IO::Socket::SSL::SSL_ERROR" unless $s;
	close $s;
	return $out;
}

sub warm {
	my $out;
	for (1 .. 20) {
		select undef, undef, undef, 0.05;
		$out = staple(@_);
		last if $out !~ /no staple$/;
	}
	return $out;
}

sub compressed {
    my ($listener, $alg, $status, $name, $type, $label, $issuer, $expected) = @_;
    $expected //= $alg;
    my $sig = $type eq 'RSA' ? 'rsa_pss_rsae_sha256' : 'ecdsa_secp256r1_sha256';
    my $want = $name ? sha256_hex($t->read_file("$name.der")) : '-';
    $want .= ' ' . sha256_hex($t->read_file("$issuer.der")) if defined $issuer;
    my $result = '';

    # Use the same OpenSSL build as nginx for certificate compression.
    local $ENV{LD_LIBRARY_PATH} = join ':',
        grep { defined && length } @ENV{qw/TEST_NGINX_OPENSSL_LIB LD_LIBRARY_PATH/}
        if $ENV{TEST_NGINX_OPENSSL_LIB};

    for (1 .. 15) {
        open my $probe, '-|', 'python3', '../ssl/cert_compression.py',
            port($listener), "$d/ca.crt", $alg, $status, $sig,
            (defined $issuer ? 'issuer' : ()) or die "python3: $!";
        $result = <$probe> // '';
        close $probe or last;
        chomp $result;
        last if $result eq "$expected $want";
        last if $result ne "0 $want";
        select undef, undef, undef, 0.05;
    }

    is($result, "$expected $want", $label);
}

sub rotate {
	my ($name) = @_;
	$t->write_file("$name.new", $t->read_file('b.crt'));
	rename "$d/$name.new", "$d/$name.crt" or die "rename: $!";
}
