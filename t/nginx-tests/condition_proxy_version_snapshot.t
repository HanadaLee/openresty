#!/usr/bin/perl

# Protocol dispatch, framing and Host must share one selected HTTP version.

use warnings;
use strict;
use IO::Socket::INET;
use Test::More;
use Test::Nginx;

my @cases;
for my $before ('1.0', '1.1', '2') {
    for my $after ('1.0', '1.1', '2') {
        my $path = "v${before}_to_$after";
        push @cases, [$path, $before, $after, $before];
    }
}
push @cases, ['inherit', '1.1', '2', '1.1'],
    ['included', '1.0', '2', '1.0'], ['retry', '1.1', '2', '1.1'],
    ['redirected', '1.1', '2', '2'];

my $t = Test::Nginx->new()
    ->has(qw/http http_v2 proxy rewrite ngx_expr_module/)
    ->plan(4 * scalar(@cases) + 1);

$t->write_file('version-snapshot.inc', 'proxy_http_version 2;');
my $locations = '';
for my $case (@cases) {
    my ($path, $before, $after) = @$case;
    my $rules = "when after_body { proxy_http_version $after; }
        proxy_http_version $before;";
    my $backend = 'http://127.0.0.1:8081';
    if ($path eq 'inherit') {
        $rules = 'when never { proxy_http_version 1.0; }';
    } elsif ($path eq 'included') {
        $rules = 'when after_body { include version-snapshot.inc; }
            proxy_http_version 1.0;';
    } elsif ($path eq 'retry') {
        $backend = 'http://retry_backend';
        $rules .= ' proxy_next_upstream http_503 non_idempotent;
            proxy_next_upstream_tries 2;
            add_header X-Final-Length $request_length always;
            add_header X-Attempts $upstream_status always;';
    } elsif ($path eq 'redirected') {
        $backend = 'http://127.0.0.1:8082';
        $rules .= ' proxy_intercept_errors on; error_page 503 = @again;';
    }
    $locations .= "location /$path {
        $rules
        proxy_pass $backend;
    }\n";
}

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr after_body num_gt \$request_length 1024;
    expr never str_eq 0 1;
    upstream retry_backend {
        server 127.0.0.1:8082 max_fails=0;
        server 127.0.0.1:8081 backup;
    }
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        when after_body { proxy_http_version 2; }
        proxy_http_version 1.1;
        proxy_request_buffering on;
        proxy_set_header Host "";
        proxy_set_header Expect "";
        proxy_set_header X-Selected-Host "[\$proxy_http_host]";
        proxy_read_timeout 3s;
        add_header X-Final-Length \$request_length always;
        $locations
        location \@again {
            when after_body { proxy_http_version 2; }
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:8081;
        }
    }
    server {
        listen 127.0.0.1:8081;
        http2 on;
        server_name backend;
        return 200 "\$server_protocol|\$http_host|\$http_x_selected_host\n";
    }
    server {
        listen 127.0.0.1:8082;
        http2 on;
        server_name retry;
        return 503;
    }
}
EOF

$t->run();
for my $case (@cases) {
    my ($path, undef, undef, $selected) = @$case;
    my ($interim, $r) = upload($path);
    like($interim, qr/^HTTP\/1\.1 100 Continue\r\n\r\n$/,
        "$path body withheld until handler selected");
    like($r, qr/^HTTP\/1\.[01] 200 /, "$path successful upstream exchange");
    my $protocol = $selected eq '2' ? 'HTTP/2.0' : "HTTP/$selected";
    my $host = $selected eq '1.0' ? '' : $path eq 'retry'
        ? 'retry_backend' : '127.0.0.1:' . port(8081);
    like($r, qr/\Q$protocol|$host|[$host]\E\n/,
        "$path selected protocol and Host agree");
    my ($length) = $r =~ /^X-Final-Length: (\d+)/mi;
    cmp_ok($length // 0, '>', 1024, "$path condition input changed after body");
    like($r, qr/^X-Attempts: 503, 200\r?$/mi,
        'retry keeps the selected protocol') if $path eq 'retry';
}
$t->stop();

sub upload {
    my ($path) = @_;
    my ($interim, $response) = ('', '');
    my $client;
    eval {
        local $SIG{ALRM} = sub { die "upload timeout\n" };
        local $SIG{PIPE} = 'IGNORE';
        alarm 6;
        $client = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
            PeerPort => port(8080), Proto => 'tcp') or die "connect: $!";
        $client->autoflush(1);
        my $body = 'x' x 2048;
        print $client "POST /$path HTTP/1.1\r\nHost: localhost\r\n"
            . 'Content-Length: ' . length($body)
            . "\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n";
        # Waiting for 100 Continue guarantees that proxy's handler has run,
        # without a timing-dependent sleep or pre-reading the request body.
        while ($interim !~ /\r\n\r\n\z/) {
            my $n = sysread($client, my $byte, 1);
            die "closed before continue\n" unless $n;
            $interim .= $byte;
        }
        print $client $body;
        while (sysread($client, my $chunk, 4096)) {
            $response .= $chunk;
        }
        alarm 0;
    };
    alarm 0;
    close $client if $client;
    return ($interim, $response);
}
