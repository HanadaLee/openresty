#!/usr/bin/perl

# Indexed FastCGI purge with inherited conditional parameter configuration.

use warnings;
use strict;
use Test::More;
use IO::Socket::INET;
use JSON::PP qw/decode_json/;
use Time::HiRes qw/time sleep/;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http fastcgi cache rewrite
    ngx_http_cache_purge_module/);
plan 'no_plan';

my @cases;
my $locations = '';
for my $syntax ('same', 'separate') {
    for my $inherit ('default', 'on', 'off') {
        my $name = "$syntax-$inherit";
        my $params = $inherit eq 'default' ? '' : "fastcgi_param_inherit $inherit;";
        push @cases, { name => $name, syntax => $syntax };
        $locations .= <<EOF;
        location /$name/ {
            $params
            fastcgi_pass 127.0.0.1:8081;
            fastcgi_param REQUEST_URI \$uri;
            fastcgi_cache NAME;
            fastcgi_cache_key \$cache_key_full;
            fastcgi_cache_valid 200 1h;
            fastcgi_cache_purge on;
            add_header X-Cache \$upstream_cache_status always;
        }
EOF
        if ($syntax eq 'separate') {
            $locations .= <<EOF;
        location ~ ^/purge/$name(/.*)\$ {
            $params
            fastcgi_cache_purge on;
            cache_purge_key_url http://cache.test/$name\$1;
        }
EOF
        }
    }
}

my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
master_process on;
worker_processes 1;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    fastcgi_cache_path %%TESTDIR%%/cache keys_zone=NAME:2m;
    cache_purge_index_store %%TESTDIR%%/index;
    cache_purge_state_zone zone=purge:1m;
    cache_key_host cache.test;
    cache_purge_key_url $cache_key_url;
    cache_purge_key_misc $cache_key_misc;
    cache_purge_key_namespace $cache_key_namespace;
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        location /management/ { cache_purge_api; }
        %%LOCATIONS%%
    }
}
EOF
$config =~ s/%%LOCATIONS%%/$locations/;
$t->write_file_expand('nginx.conf', $config);
$t->run_daemon(\&fastcgi_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
wait_for(sub { json_get('/management/capabilities')->{ready} }, 'index ready');

my $id = 0;
for my $case (@cases) {
    my $name = $case->{name};
    my $purge_uri = $case->{syntax} eq 'same' ? "/$name" : "/purge/$name";
    for my $key ('items/first', 'items/second', 'other') {
        my $response = http_get("/$name/$key");
        like($response, qr/200 OK/, "$name $key: upstream responds");
        like($response, qr/\r\n\r\nfastcgi body\n\z/, "$name $key: response decoded");
        wait_for(sub { http_get("/$name/$key") =~ /^X-Cache: HIT\r?$/mi },
            "$name $key: cache fill settled");
    }
    # Native timestamps deliberately use one-second precision.
    sleep 1.05;
    submit("$purge_uri/items/first", 'url', "fastcgi-" . ++$id);
    like(http_get("/$name/items/first"), qr/^X-Cache: MISS\r?$/mi,
        "$name: exact entry deleted");
    like(http_get("/$name/items/second"), qr/^X-Cache: HIT\r?$/mi,
        "$name: exact purge preserves sibling");
    like(http_get("/$name/other"), qr/^X-Cache: HIT\r?$/mi,
        "$name: exact purge preserves unrelated entry");
    wait_for(sub { http_get("/$name/items/first") =~ /^X-Cache: HIT\r?$/mi },
        "$name: replacement fill settled");
    sleep 1.05;
    submit("$purge_uri/items/", 'prefix', "fastcgi-" . ++$id);
    for my $key ('first', 'second') {
        like(http_get("/$name/items/$key"), qr/^X-Cache: MISS\r?$/mi,
            "$name: prefix deletes $key");
    }
    like(http_get("/$name/other"), qr/^X-Cache: HIT\r?$/mi,
        "$name: prefix preserves unrelated entry");
}

$t->stop();
unlike($t->read_file('error.log'), qr/\[(?:alert|emerg)\]|exited on signal/,
    'no worker crashes or critical errors');

sub json_get {
    my ($uri) = @_;
    my $response = http_get($uri);
    return {} unless $response =~ /200 OK/;
    return decode_json((split /\r\n\r\n/, $response, 2)[1]);
}

sub wait_for {
    my ($check, $description) = @_;
    my $deadline = time() + 10;
    while (time() < $deadline) {
        if ($check->()) { pass($description); return; }
        sleep 0.02;
    }
    BAIL_OUT($description . ' timed out');
}

sub submit {
    my ($uri, $type, $identifier) = @_;
    my $response = http("PURGE $uri HTTP/1.0\r\nHost: localhost\r\n"
        . "X-Cache-Purge-Type: $type\r\nX-Cache-Purge-Action: delete\r\n"
        . "X-Cache-Purge-Operation-Id: $identifier\r\n"
        . 'X-Cache-Purge-Issued-At: ' . int(time() * 1000) . "\r\n\r\n");
    like($response, qr/202 Accepted/, "$identifier: task accepted");
    wait_for(sub {
        my $status = json_get("/management/operations/$identifier");
        return $status->{cleanup} && $status->{cleanup}->{state} eq 'done';
    }, "$identifier: cleanup complete");
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
