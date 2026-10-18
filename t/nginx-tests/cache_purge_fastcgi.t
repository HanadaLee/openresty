#!/usr/bin/perl

# cache-purge's private FastCGI layout must match the nginx-ext layout.

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my @cases;
my $locations = '';
for my $strict (0, 1) {
    for my $syntax ('same', 'separate') {
        for my $inherit ('default', 'on', 'off') {
            my $name = "c$strict-$syntax-$inherit";
            my $key = $strict ? '$cache_purge_key' : '$uri';
            my $params = $inherit eq 'default' ? ''
                : "fastcgi_param_inherit $inherit;";
            my $purge = $syntax eq 'same'
                ? 'fastcgi_cache_purge PURGE from 127.0.0.1;'
                : 'fastcgi_cache_purge off;';
            my $namespace = $strict ? 'cache_purge_key objects $uri;' : '';
            push @cases, { name => $name, strict => $strict, syntax => $syntax };

            $locations .= <<EOF;
        location /$name/ {
            $params
            $namespace
            fastcgi_pass 127.0.0.1:8081;
            fastcgi_param REQUEST_URI \$uri;
            fastcgi_cache NAME;
            fastcgi_cache_key $key;
            fastcgi_cache_valid 200 1h;
            $purge
            add_header X-Cache \$upstream_cache_status always;
        }
EOF
            if ($syntax eq 'separate') {
                my $purge_key = $strict ? '$cache_purge_key' : "/$name\$1";
                my $purge_namespace = $strict
                    ? "cache_purge_key objects /$name\$1;" : '';
                $locations .= <<EOF;
        location ~ ^/purge/$name(/.*)\$ {
            $params
            $purge_namespace
            fastcgi_cache_purge NAME $purge_key;
        }
EOF
            }
        }
    }
}

my $t = Test::Nginx->new()->has(qw/http fastcgi cache rewrite
    ngx_http_cache_purge_module/)->plan(25 * scalar(@cases) + 1);

my $config = <<'EOF';
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    fastcgi_cache_path %%TESTDIR%%/cache levels=1:2 keys_zone=NAME:2m;
    cache_purge_namespace objects 1m %%TESTDIR%%/purge-state;
    cache_purge_background_queue off;

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location = /health { return 200 "ready\n"; }
        %%LOCATIONS%%
    }
}
EOF

$config =~ s/%%LOCATIONS%%/$locations/;
$t->write_file_expand('nginx.conf', $config);
$t->run_daemon(\&fastcgi_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

for my $case (@cases) {
    my $name = $case->{name};
    my $purge_uri = $case->{syntax} eq 'same' ? "/$name" : "/purge/$name";
    my $code = $case->{strict} ? 'invalidated' : 'purged';
    my $empty_code = $case->{strict} ? 'invalidated' : 'no_match';

    # This exercises the misaligned complex value before any cache is warmed.
    my $response = purge("$purge_uri/missing");
    like($response, qr/200 OK/, "$name: empty cache PURGE completes")
        or BAIL_OUT('FastCGI PURGE failed before cache warmup');
    like($response, qr/^Cache-Purge-Code: $empty_code\r?$/mi,
        "$name: empty cache outcome");

    for my $key ('items/first', 'items/second', 'other') {
        $response = http_get("/$name/$key");
        like($response, qr/200 OK/, "$name $key: upstream responds");
        like($response, qr/\r\n\r\nfastcgi body\n\z/,
            "$name $key: FastCGI response decoded");
        like($response, qr/^X-Cache: MISS\r?$/mi, "$name $key: cache filled");
        like(http_get("/$name/$key"), qr/^X-Cache: HIT\r?$/mi,
            "$name $key: native cache hit");
    }

    $response = purge("$purge_uri/items/first");
    like($response, qr/200 OK/, "$name: exact PURGE completes");
    like($response, qr/^Cache-Purge-Code: $code\r?$/mi, "$name: exact outcome");
    like(http_get("/$name/items/first"), qr/^X-Cache: MISS\r?$/mi,
        "$name: exact entry invalidated");
    like(http_get("/$name/items/second"), qr/^X-Cache: HIT\r?$/mi,
        "$name: exact purge preserves sibling");
    like(http_get("/$name/other"), qr/^X-Cache: HIT\r?$/mi,
        "$name: exact purge preserves unrelated entry");

    $response = purge("$purge_uri/items/*");
    like($response, qr/200 OK/, "$name: prefix PURGE completes");
    like($response, qr/^Cache-Purge-Code: $code\r?$/mi, "$name: prefix outcome");
    like(http_get("/$name/items/first"), qr/^X-Cache: MISS\r?$/mi,
        "$name: prefix invalidates first entry");
    like(http_get("/$name/items/second"), qr/^X-Cache: MISS\r?$/mi,
        "$name: prefix invalidates second entry");
    like(http_get("/$name/other"), qr/^X-Cache: HIT\r?$/mi,
        "$name: prefix preserves unrelated entry");
    like(http_get('/health'), qr/200 OK/, "$name: server remains available");
}

$t->stop();
unlike($t->read_file('error.log'), qr/\[(?:alert|emerg)\]|exited on signal/,
    'no worker crashes or critical configuration errors');

sub purge {
    my ($uri) = @_;
    return http("PURGE $uri HTTP/1.0\r\nHost: localhost\r\n\r\n");
}

# A minimal responder keeps this regression independent of the FCGI Perl module.
sub fastcgi_daemon {
    my $listener = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
        LocalPort => port(8081), Listen => 16, ReuseAddr => 1) or die $!;
    local $SIG{PIPE} = 'IGNORE';

    while (my $client = $listener->accept()) {
        $client->autoflush(1);
        while (my $header = read_exact($client, 8)) {
            my (undef, $type, $id, $length, $padding) = unpack('CCnnCC', $header);
            last if $length + $padding && !defined read_exact($client, $length + $padding);
            next unless $type == 5 && $length == 0; # End of FCGI_STDIN.

            my $body = "Content-Type: text/plain\r\n\r\nfastcgi body\n";
            print {$client} pack('CCnnCC', 1, 6, $id, length($body), 0, 0), $body,
                pack('CCnnCC', 1, 6, $id, 0, 0, 0),
                pack('CCnnCC', 1, 3, $id, 8, 0, 0), "\0" x 8;
            last;
        }
        close $client;
    }
}

sub read_exact {
    my ($socket, $length) = @_;
    my $data = '';
    while (length($data) < $length) {
        my $read = sysread($socket, $data, $length - length($data), length($data));
        return undef unless $read;
    }
    return $data;
}
