#!/usr/bin/perl

# Conditional cookie lists for all four upstream protocols, including cache.

use warnings;
use strict;
use IO::Socket::INET;
use Test::More;
use Test::Nginx;

my @protocols = qw/proxy fastcgi scgi uwsgi/;
my @cookies = ('parent=1', 'server=1', 'a1=1', 'b1=1', 'a2=1',
    'always=1', 'keep=1', 'off=1', 'dup=one', 'dup=two',
    'MiXeD=1', ' spaced =1', '=empty');
my @names = qw/parent server a1 b1 a2 always keep off dup dup mixed spaced/;
push @names, '';

# path, A, B, server condition, parent condition, hidden names
my @cases;
for my $path (qw/combined ordered included/) {
    for my $a (0, 1) {
        for my $b (0, 1) {
            my @hidden = ($a ? ('a1', 'a2') : (), $b ? ('b1') : ());
            @hidden = ('parent') if !$a && !$b;
            push @cases, [$path, $a, $b, 0, 1, \@hidden];
        }
    }
}
push @cases,
    ['inherit', 0, 0, 0, 1, ['parent']],
    ['inherit', 0, 0, 1, 1, ['server']],
    ['inherit', 0, 0, 0, 0, []],
    ['ordered', 0, 0, 1, 1, ['server']],
    ['ordered', 1, 1, 1, 1, ['a1', 'b1', 'a2']],
    ['unconditional', 0, 0, 0, 1, ['always']],
    ['unconditional', 1, 0, 0, 1, ['always', 'a1']],
    ['miss', 1, 0, 1, 1, []],
    ['miss', 0, 0, 0, 1, ['parent']],
    ['case', 0, 0, 0, 1, ['mixed', 'spaced', '']],
    ['duplicates', 1, 0, 0, 1, ['dup']],
    ['duplicates', 0, 0, 0, 1, ['parent']],
    ['literal', 0, 0, 0, 1, ['off']],
    ['late', 0, 0, 0, 1, ['b1']],
    ['nested/child', 0, 0, 0, 1, ['parent']],
    ['nested/child', 0, 1, 1, 1, ['b1']],
    ['nested/child', 1, 1, 1, 1, ['a1']];

my $t = Test::Nginx->new()
    ->has(qw/http proxy fastcgi scgi uwsgi cache rewrite ngx_expr_module/)
    ->plan(4 * (3 * scalar(@cases) + 16));

my ($main, $servers) = ('', '');
my $port = 8081;
my @backends;
for my $proto (@protocols) {
    my $hide = $proto . '_hide_cookie';
    my $pass = $proto . '_pass';
    my $cache = $proto . '_cache';
    my $params = $proto eq 'fastcgi' ? 'fastcgi_param REQUEST_METHOD GET;'
        : $proto eq 'scgi' ? 'scgi_param SCGI 1;' : '';
    my $address = ($proto eq 'proxy' ? 'http://' : '') . "127.0.0.1:$port";
    my $forward = "$params $pass $address;";

    $main .= "$cache" . "_path %%TESTDIR%%/cache-$proto keys_zone=$proto:1m;\n";
    $main .= "when p { $hide parent; }\n";
    $t->write_file("$proto.inc", "$hide a2;");

    my %locations = (
        combined => "when a { $hide a1; $hide a2; } when b { $hide b1; }",
        ordered => "when a { $hide a1; } when b { $hide b1; } when a { $hide a2; }",
        included => "when a { $hide a1; include $proto.inc; } when b { $hide b1; }",
        inherit => '',
        unconditional => "when a { $hide a1; } $hide always;",
        miss => "when a { $hide absent; }",
        case => "$hide mixed; $hide spaced; $hide \"\";",
        duplicates => "when a { $hide dup; } when a { $hide dup; }",
        literal => "$hide off;",
        late => "when late { $hide b1; }",
    );

    my $body = '';
    for my $path (sort keys %locations) {
        $body .= "location /$proto/$path { $forward $locations{$path} }\n";
    }
    $body .= "location /$proto/nested/ {
        when b { $hide b1; }
        location /$proto/nested/child { $forward when a { $hide a1; } }
    }\n";
    $body .= "location /$proto/cache {
        $forward
        $cache $proto;
        $cache" . "_key \"\$scheme\$host\$uri\";
        $cache" . "_valid 200 1m;
        $cache" . "_types *;
        $proto" . "_ignore_headers Set-Cookie;
        add_header X-Cache \$upstream_cache_status always;
        when c { $cache" . "_hide_cookies on; }
        $cache" . "_hide_cookies off;
        when a { $hide a1; }
        when b { $hide b1; }
        when a { $hide a2; }
    }\n";
    $servers .= "server {
        listen 127.0.0.1:8080;
        server_name $proto;
        when s { $hide server; }
        $body
    }\n";
    push @backends, [$proto, port($port)];
    $port++;
}

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr a str_eq \$http_x_a 1;
    expr b str_eq \$http_x_b 1;
    expr s str_eq \$http_x_s 1;
    expr p str_eq \$http_x_p 1;
    expr c str_eq \$http_x_c 1;
    expr late str_eq \$upstream_http_x_policy yes;
    $main
    $servers
}
EOF

for my $backend (@backends) {
    $t->run_daemon(\&backend, @$backend);
    $t->waitforsocket('127.0.0.1:' . $backend->[1]);
}
$t->run();

for my $proto (@protocols) {
    for my $case (@cases) {
        my ($path, $a, $b, $s, $p, $hidden) = @$case;
        check_response(request($proto, $path, $a, $b, $s, $p, 0),
            $hidden, "$proto $path a=$a b=$b s=$s p=$p");
    }
    check_response(request($proto, 'cache', 1, 1, 0, 1, 1),
        ['a1', 'a2', 'b1'], "$proto cache warm", 'MISS');
    check_response(request($proto, 'cache', 0, 0, 0, 1, 0),
        ['parent'], "$proto cache conditional fallback", 'HIT');
    check_response(request($proto, 'cache', 0, 0, 0, 1, 1),
        \@names, "$proto cache_hide_cookies precedes name rules", 'HIT');
    check_response(request($proto, 'cache', 1, 0, 0, 1, 0),
        ['a1', 'a2'], "$proto cached headers remain unmodified", 'HIT');
}
$t->stop();

sub request {
    my ($proto, $path, $a, $b, $s, $p, $c) = @_;
    return http("GET /$proto/$path HTTP/1.0\r\nHost: $proto\r\n"
        . "X-A: $a\r\nX-B: $b\r\nX-S: $s\r\nX-P: $p\r\nX-C: $c\r\n\r\n");
}

sub check_response {
    my ($response, $hidden, $label, $cache) = @_;
    my %hidden = map { $_ => 1 } @$hidden;
    my @wanted = grep { !exists $hidden{$_} } @names;
    my @seen = $response =~ /^Set-Cookie:[ \t]*([^=;\r\n]*?)[ \t]*=/img;
    @seen = map { lc $_ } @seen;
    like($response, qr/^HTTP\/1\.[01] 200 /, "$label status");
    is_deeply(\@seen, \@wanted, "$label cookie fields and duplicates");
    like($response, qr/\r\n\r\nok\n\z/, "$label body");
    like($response, qr/^X-Cache: \Q$cache\E\r?$/m, "$label cache status")
        if defined $cache;
}

sub read_exact {
    my ($socket, $length) = @_;
    my $result = '';
    while (length($result) < $length) {
        my $count = sysread($socket, my $part, $length - length($result));
        return undef if !defined($count) || !$count;
        $result .= $part;
    }
    return $result;
}

sub backend {
    my ($proto, $port) = @_;
    my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
        LocalPort => $port, Listen => 16, ReuseAddr => 1, Proto => 'tcp')
        or die "listen $proto: $!";

    while (my $client = $server->accept()) {
        $client->autoflush(1);
        binmode $client;
        eval {
            local $SIG{ALRM} = sub { die "backend timeout\n" };
            alarm 5;
            my $id = 1;
            if ($proto eq 'proxy') {
                my $request = '';
                while ($request !~ /\r\n\r\n\z/) {
                    my $byte = read_exact($client, 1);
                    die "closed\n" unless defined $byte;
                    $request .= $byte;
                }
            } elsif ($proto eq 'fastcgi') {
                while (1) {
                    my $header = read_exact($client, 8);
                    die "closed\n" unless defined $header;
                    my ($version, $type, $request_id, $length, $padding)
                        = unpack('CCnnCC', $header);
                    $id = $request_id;
                    die "closed\n" unless defined read_exact($client, $length + $padding);
                    last if $type == 5 && $length == 0;
                }
            } elsif ($proto eq 'uwsgi') {
                my $header = read_exact($client, 4);
                die "closed\n" unless defined $header;
                my (undef, $length) = unpack('CvC', $header);
                die "closed\n" unless defined read_exact($client, $length);
            } else {
                my $length = '';
                while (1) {
                    my $byte = read_exact($client, 1);
                    die "closed\n" unless defined $byte;
                    last if $byte eq ':';
                    die "invalid netstring\n" unless $byte =~ /\d/;
                    $length .= $byte;
                }
                die "closed\n" unless defined read_exact($client, $length + 1);
            }
            my $response = ($proto eq 'proxy' ? "HTTP/1.0 200 OK\r\n" : "Status: 200 OK\r\n")
                . "Content-Type: text/plain\r\nContent-Length: 3\r\nX-Policy: yes\r\n"
                . join('', map { "Set-Cookie: $_\r\n" } @cookies)
                . "\r\nok\n";
            if ($proto eq 'fastcgi') {
                print $client pack('CCnnCC', 1, 6, $id, length($response), 0, 0), $response;
                print $client pack('CCnnCC', 1, 6, $id, 0, 0, 0);
                print $client pack('CCnnCC', 1, 3, $id, 8, 0, 0), pack('NCxxx', 0, 0);
            } else {
                print $client $response;
            }
            alarm 0;
        };
        alarm 0;
        close $client;
    }
}
