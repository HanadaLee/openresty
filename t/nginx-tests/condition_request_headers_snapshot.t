#!/usr/bin/perl

# One decision must size and serialize each upstream request header block.

use warnings;
use strict;
use IO::Select;
use IO::Socket::INET;
use Test::More;
use Test::Nginx;

my @protocols = qw/fastcgi scgi uwsgi/;
my @cases;
for my $layout (qw/combined split included/) {
    push @cases, ["off_on_$layout", '!str_regex_match', $layout, 0, 0],
        ["on_off_$layout", 'str_regex_match', $layout, 1, 1];
}
push @cases, ['literal_on', '', '', 1, 1], ['literal_off', '', '', 0, 1],
    ['inherit', '', '', 1, 1], ['override', '', '', 0, 1];

my $t = Test::Nginx->new()
    ->has(qw/http fastcgi scgi uwsgi rewrite ngx_expr_module/)
    ->plan(3 * scalar(@cases) * 5);

my ($servers, @backends);
$servers = '';
my $port = 8081;
for my $proto (@protocols) {
    my $headers = "${proto}_pass_request_headers";
    my $hide = "${proto}_hide_cookie";
    my $params = "${proto}_param TEST fixed;"
        . " ${proto}_param HTTP_X_SHADOW configured;";
    $params .= ' scgi_param SCGI 1;' if $proto eq 'scgi';
    $t->write_file("$proto-snapshot.inc", "$hide marker;");
    my $locations = '';
    for my $case (@cases) {
        my ($path, $operator, $layout, $forward) = @$case;
        my $rules;
        if ($operator) {
            # The location starts with $1 = xa.  The first successful regex
            # changes it to a; repeating the predicate changes its result.
            $rules = "expr flip $operator \$1 ^x(a)\$;\n";
            if ($layout eq 'combined') {
                $rules .= "when flip { $headers on; $hide marker; }";
            } elsif ($layout eq 'split') {
                $rules .= "when flip { $headers on; } when flip { $hide marker; }";
            } else {
                $rules .= "when flip { $headers on; include $proto-snapshot.inc; }";
            }
            $rules .= " $headers off;";
        } elsif ($path eq 'inherit' || $path eq 'override') {
            $rules = "when disable { $headers off; }";
        } else {
            $rules = "$headers " . ($forward ? 'on' : 'off') . ';';
        }
        $locations .= "location ~ ^/$path/(xa)\$ {
            $params
            ${proto}_pass 127.0.0.1:$port;
            ${proto}_read_timeout 2s;
            $rules
        }\n";
    }
    $servers .= "server {
        listen 127.0.0.1:8080;
        server_name $proto;
        $headers on;
        $locations
    }\n";
    push @backends, [$proto, port($port++)];
}

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr disable str_eq \$http_x_disable yes;
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
        my ($path, undef, undef, $forward, $cookie) = @$case;
        my $disable = $path eq 'override' ? 'yes' : 'no';
        my $r = http("GET /$path/xa HTTP/1.0\r\nHost: $proto\r\n"
            . 'X-Probe: ' . ('p' x 2048) . "\r\nX-Shadow: incoming\r\n"
            . "X-Repeat: one\r\nX-Repeat: two\r\nX-Disable: $disable\r\n\r\n");
        my $label = "$proto $path";
        like($r, qr/^HTTP\/1\.[01] 200 /, "$label valid framing");
        like($r, qr/^probe=@{[$forward ? 'ok' : 'absent']}$/m,
            "$label selected header decision");
        like($r, qr/^shadow=configured$/m, "$label explicit parameter retained");
        like($r, qr/^repeat=@{[$forward ? 'one, two' : 'absent']}$/m,
            "$label duplicate header sizing");
        is(scalar(() = $r =~ /^Set-Cookie: marker=1\r?$/gmi), $cookie,
            "$label response condition evaluated independently");
    }
}
$t->stop();

sub read_exact {
    my ($socket, $length) = @_;
    my $data = '';
    while (length($data) < $length) {
        my $n = sysread($socket, my $chunk, $length - length($data));
        die "short packet\n" unless $n;
        $data .= $chunk;
    }
    return $data;
}

sub take {
    my ($data, $length) = @_;
    die "truncated parameter\n" if length($$data) < $length;
    return substr($$data, 0, $length, '');
}

sub fcgi_length {
    my ($data) = @_;
    my $first = ord(take($data, 1));
    return $first unless $first & 0x80;
    return unpack('N', pack('C', $first) . take($data, 3)) & 0x7fffffff;
}

sub decode_params {
    my ($proto, $data) = @_;
    my %params;
    if ($proto eq 'scgi') {
        die "missing parameter terminator\n" unless $data =~ /\0\z/;
        my @pairs = split /\0/, $data, -1;
        pop @pairs;
        die "odd parameter list\n" if @pairs % 2;
        while (@pairs) {
            my ($key, $value) = splice @pairs, 0, 2;
            die "duplicate parameter\n" if exists $params{$key};
            $params{$key} = $value;
        }
    } else {
        while (length($data)) {
            my ($key, $value);
            if ($proto eq 'fastcgi') {
                my $key_len = fcgi_length(\$data);
                my $value_len = fcgi_length(\$data);
                $key = take(\$data, $key_len);
                $value = take(\$data, $value_len);
            } else {
                my $key_len = unpack('v', take(\$data, 2));
                $key = take(\$data, $key_len);
                my $value_len = unpack('v', take(\$data, 2));
                $value = take(\$data, $value_len);
            }
            die "duplicate parameter\n" if exists $params{$key};
            $params{$key} = $value;
        }
    }
    die "missing explicit parameter\n" unless ($params{TEST} // '') eq 'fixed';
    return \%params;
}

sub backend {
    my ($proto, $port) = @_;
    my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
        LocalPort => $port, Listen => 16, ReuseAddr => 1, Proto => 'tcp')
        or die "listen $proto: $!";
    local $SIG{PIPE} = 'IGNORE';
    while (my $client = $server->accept()) {
        $client->autoflush(1);
        binmode $client;
        eval {
            local $SIG{ALRM} = sub { die "backend timeout\n" };
            alarm 3;
            my ($data, $id) = ('', 1);
            if ($proto eq 'fastcgi') {
                while (1) {
                    my ($version, $type, $request_id, $length, $padding)
                        = unpack('CCnnCC', read_exact($client, 8));
                    die "invalid record\n" unless $version == 1
                        && ($type == 1 || $type == 4 || $type == 5);
                    $id = $request_id;
                    my $record = read_exact($client, $length);
                    read_exact($client, $padding);
                    $data .= $record if $type == 4;
                    last if $type == 5 && !$length;
                }
            } elsif ($proto eq 'uwsgi') {
                my (undef, $length) = unpack('CvC', read_exact($client, 4));
                $data = read_exact($client, $length);
                # There is no body in these requests: excess bytes mean the
                # packet was serialized using a different header decision.
                if (IO::Select->new($client)->can_read(0.05)) {
                    my $n = sysread($client, my $extra, 1);
                    die "bytes outside declared packet\n" if $n;
                }
            } else {
                my $length = '';
                while (1) {
                    my $byte = read_exact($client, 1);
                    last if $byte eq ':';
                    die "invalid netstring\n" unless $byte =~ /\d/;
                    $length .= $byte;
                    die "excessive netstring length\n" if length($length) > 6;
                }
                die "empty netstring length\n" unless length($length);
                $data = read_exact($client, $length);
                die "bad netstring boundary\n" unless read_exact($client, 1) eq ',';
            }
            my $params = decode_params($proto, $data);
            my $probe = !exists $params->{HTTP_X_PROBE} ? 'absent'
                : $params->{HTTP_X_PROBE} eq ('p' x 2048) ? 'ok' : 'corrupt';
            my $body = "probe=$probe\nshadow=" . ($params->{HTTP_X_SHADOW} // '')
                . "\nrepeat=" . ($params->{HTTP_X_REPEAT} // 'absent') . "\n";
            my $response = "Status: 200 OK\r\nContent-Type: text/plain\r\n"
                . 'Content-Length: ' . length($body)
                . "\r\nSet-Cookie: marker=1\r\n\r\n$body";
            if ($proto eq 'fastcgi') {
                print $client pack('CCnnCC', 1, 6, $id, length($response), 0, 0),
                    $response, pack('CCnnCC', 1, 6, $id, 0, 0, 0),
                    pack('CCnnCC', 1, 3, $id, 8, 0, 0), pack('NCxxx', 0, 0);
            } else {
                print $client $response;
            }
            alarm 0;
        };
        alarm 0;
        close $client;
    }
}
