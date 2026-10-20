#!/usr/bin/perl

# TCP fingerprints coexist with SSL fingerprints without RTT callbacks.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::HTTP2;
use Test::Nginx::Stream qw/ stream /;

plan(skip_all => 'Linux TCP_SAVE_SYN is required') unless $^O eq 'linux';

my $t = Test::Nginx->new()->has(qw/http http_ssl http_v2 rewrite stream
    stream_ssl stream_return socket_ssl ngx_tcp_fingerprint_module
    ngx_ssl_fingerprint_module/)->has_daemon('openssl')->plan(203);

$t->write_file('openssl.conf', "[req]\ndistinguished_name=dn\n[dn]\n");
my $d = $t->testdir();
system("openssl req -x509 -newkey rsa:2048 -nodes -config $d/openssl.conf "
    . "-subj /CN=localhost/ -keyout $d/localhost.key "
    . "-out $d/localhost.crt >>$d/openssl.out 2>&1") == 0
    or die "certificate generation failed";

my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    tcp_fingerprint HTTP_ENABLED;
    ssl_fingerprint SSL_ENABLED;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;
    log_format fp "$tcpfp_signature|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4";
    server {
        listen 127.0.0.1:8080;
        listen 127.0.0.1:8443 ssl;
        http2 on;
        location / {
            return 200 "$tcpfp_signature|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4";
        }
        location /log {
            access_log %%TESTDIR%%/http-fp.log fp;
            return 200 "logged";
        }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    tcp_fingerprint STREAM_ENABLED;
    ssl_fingerprint SSL_ENABLED;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;
    log_format fp "$tcpfp_signature|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4";
    server {
        listen 127.0.0.1:8081;
        listen 127.0.0.1:8444 ssl;
        return "$tcpfp_signature|$ssl_fingerprint_ja3_hash|$ssl_fingerprint_ja4";
    }
    server {
        listen 127.0.0.1:8445 ssl;
        access_log %%TESTDIR%%/stream-fp.log fp;
        return "logged";
    }
}
EOF

for my $case ([qw/on on on/], [qw/off on on/], [qw/on off on/],
    [qw/off off on/], [qw/on on off/])
{
    my ($http, $stream, $ssl) = @$case;
    my $name = "http=$http stream=$stream ssl=$ssl";
    my $conf = $config;
    $conf =~ s/HTTP_ENABLED/$http/g;
    $conf =~ s/STREAM_ENABLED/$stream/g;
    $conf =~ s/SSL_ENABLED/$ssl/g;
    $t->write_file_expand('nginx.conf', $conf)->run();

    fingerprints(http_content(http_get('/')), $http, 'off',
        "$name plain HTTP");
    fingerprints(stream('127.0.0.1:' . port(8081))->io(''), $stream, 'off',
        "$name plain Stream");

    for my $version ('TLSv1_2', 'TLSv1_3') {
        my %options = (SSL => 1, SSL_hostname => 'localhost',
            SSL_version => $version);
        fingerprints(http_content(http_get('/', %options)), $http, $ssl,
            "$name HTTP $version");
        fingerprints(stream(PeerAddr => '127.0.0.1:' . port(8444),
            %options)->io(''), $stream, $ssl, "$name Stream $version");
    }

    my $h2 = Test::Nginx::HTTP2->new(port(8443), SSL => 1, alpn => 'h2');
    my @bodies;
    for (1 .. 2) {
        my $sid = $h2->new_stream();
        my $frames = $h2->read(all => [{ sid => $sid, fin => 1 }]);
        push @bodies, join '', map { $_->{data} }
            grep { $_->{type} eq 'DATA' && $_->{sid} == $sid } @$frames;
    }
    fingerprints($bodies[0], $http, $ssl, "$name HTTP/2");
    is($bodies[1], $bodies[0], "$name reused HTTP/2 connection");
    undef $h2;

    $t->write_file('http-fp.log', '');
    $t->write_file('stream-fp.log', '');
    is(http_content(http_get('/log', SSL => 1)), 'logged',
        "$name HTTP log-only request");
    is(stream(PeerAddr => '127.0.0.1:' . port(8445), SSL => 1)->io(''),
        'logged', "$name Stream log-only session");
    $t->stop();
    for my $entry (['http', $http], ['stream', $stream]) {
        my $line = $t->read_file("$entry->[0]-fp.log");
        chomp $line;
        $line =~ s/(^|\|)-(?=\||$)/$1/g;
        fingerprints($line, $entry->[1], $ssl, "$name $entry->[0] access log");
    }
}

for my $subsystem ('http', 'stream') {
    for my $variable ('tcpfp_tcp_rtt', 'tcpfp_tls_rtt') {
        my $return = $subsystem eq 'http' ? "return 200 \"\$$variable\";"
            : "return \"\$$variable\";";
        $t->write_file_expand('removed.conf', <<EOF);
%%TEST_GLOBALS%%
events {}
$subsystem {
    tcp_fingerprint on;
    server {
        listen 127.0.0.1:8080;
        $return
    }
}
EOF
        my $nginx = $ENV{TEST_NGINX_BINARY};
        my $output = qx{"$nginx" -p "$d" -c removed.conf -t 2>&1};
        isnt($?, 0, "$subsystem rejects removed \$$variable");
        like($output, qr/unknown "$variable" variable/,
            "$subsystem no longer registers \$$variable");
    }
}

sub fingerprints {
    my ($body, $tcp, $ssl, $name) = @_;
    my @fields = split /\|/, $body, -1;
    is(scalar @fields, 3, "$name fields");
    if ($tcp eq 'on') {
        like($fields[0], qr/^4:\d+\+\d+:\d+:\d+:[^:]+:[^:]*:[^:]*:[0+]$/,
            "$name TCP SYN fingerprint");
    } else {
        is($fields[0], '', "$name TCP fingerprint disabled");
    }
    if ($ssl eq 'on') {
        like($fields[1], qr/^[0-9a-f]{32}$/, "$name JA3 hash");
        like($fields[2], qr/^t1[23][di]\d{4}\w{2}_[0-9a-f]{12}_[0-9a-f]{12}$/,
            "$name JA4");
    } else {
        is($fields[1], '', "$name no JA3");
        is($fields[2], '', "$name no JA4");
    }
}
