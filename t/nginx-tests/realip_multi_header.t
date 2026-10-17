#!/usr/bin/perl

# Ordered realip sources: fallback, trust boundaries and upstream chain semantics.

use warnings;
use strict;

use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw/ SOCK_STREAM /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http realip rewrite unix/)->plan(53);

my %rules = (
    ordered => 'real_ip_header X-Real-IP X-CDN-IP X-Forwarded-For proxy_protocol;',
    custom => 'real_ip_header X-CDN-IP X-Real-IP X-Forwarded-For proxy_protocol;',
    xff => 'real_ip_header X-Forwarded-For X-CDN-IP;',
    proxy => 'real_ip_header proxy_protocol X-Real-IP X-CDN-IP;',
    chain_off => 'real_ip_header X-CDN-IP X-Fallback; real_ip_recursive off;',
    chain_on => 'real_ip_header X-CDN-IP X-Fallback; real_ip_recursive on;',
    xff_off => 'real_ip_header X-Forwarded-For X-Fallback; real_ip_recursive off;',
    xff_on => 'real_ip_header X-Forwarded-For X-Fallback; real_ip_recursive on;',
    xreal_on => 'real_ip_header X-Real-IP X-Fallback; real_ip_recursive on;',
    repeated => 'real_ip_header X-Real-IP; real_ip_header X-CDN-IP X-Forwarded-For;',
    growth => 'real_ip_header X-One X-Two X-Three X-Four X-Five X-Real-IP X-Forwarded-For proxy_protocol;',
    untrusted => 'real_ip_header X-CDN-IP X-Forwarded-For proxy_protocol;',
    inherited => '',
);

my $servers = '';
for my $name (sort keys %rules) {
    my $trusted = $name eq 'untrusted' ? '192.0.2.0/24' : '127.0.0.1';
    $servers .= <<EOF;
    server {
        listen 127.0.0.1:8080;
        listen 127.0.0.1:8081 proxy_protocol;
        server_name $name;
        set_real_ip_from $trusted;
        set_real_ip_from 10.0.1.0/24;
        $rules{$name}
        return 204;
    }
EOF
}

my $config = <<'EOF';
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    underscores_in_headers on;
    real_ip_header X-HTTP-IP X-HTTP-Fallback;
    add_header X-Address "$remote_addr|$remote_port|$realip_remote_addr|$realip_remote_port";
    add_header X-Xff $http_x_forwarded_for;

    %%REALIP_SERVERS%%

    server {
        listen 127.0.0.1:8080;
        server_name location;

        # No trusted peers at server scope: selection runs in preaccess.
        location = /addr {
            set_real_ip_from 127.0.0.1;
            real_ip_header X-CDN-IP X-Fallback;
            alias %%TESTDIR%%/ok;
        }
    }

    server {
        listen unix:%%TESTDIR%%/realip.sock;
        server_name unix;
        set_real_ip_from unix:;
        real_ip_header X-CDN-IP X-Fallback;
        return 204;
    }
}
EOF

$config =~ s/%%REALIP_SERVERS%%/$servers/;
$t->write_file_expand('nginx.conf', $config);
$t->write_file('ok', 'ok');
$t->run();

###############################################################################

check('first valid source wins', 'ordered',
    [ 'X-Real-IP: 198.51.100.1', 'X-CDN-IP: 198.51.100.2' ], '198.51.100.1');
check('missing first source', 'ordered',
    [ 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('invalid first source', 'ordered',
    [ 'X-Real-IP: invalid', 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('empty first source', 'ordered',
    [ 'X-Real-IP:', 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('whitespace-only first source', 'ordered',
    [ 'X-Real-IP:   ', 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('invalid custom source falls back to X-Real-IP', 'custom',
    [ 'X-CDN-IP: invalid', 'X-Real-IP: 198.51.100.3' ], '198.51.100.3');
check('two invalid sources fall back to XFF', 'ordered',
    [ 'X-Real-IP: invalid', 'X-CDN-IP: invalid',
      'X-Forwarded-For: 198.51.100.4' ], '198.51.100.4');
check('XFF first and missing', 'xff',
    [ 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('XFF first and invalid', 'xff',
    [ 'X-Forwarded-For: invalid', 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('XFF first and empty', 'xff',
    [ 'X-Forwarded-For:', 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('all sources missing', 'ordered', [], '127.0.0.1', 'peer');
check('all sources invalid', 'ordered',
    [ 'X-Real-IP: invalid', 'X-CDN-IP: invalid',
      'X-Forwarded-For: invalid' ], '127.0.0.1', 'peer');
check('custom header names are case-insensitive', 'custom',
    [ 'x-cDn-iP: 198.51.100.2' ], '198.51.100.2');
check('IPv4 with port', 'custom',
    [ 'X-CDN-IP: 198.51.100.2:4567' ], '198.51.100.2', '4567');
check('invalid port falls back', 'custom',
    [ 'X-CDN-IP: 198.51.100.2:65536', 'X-Real-IP: 198.51.100.3' ],
    '198.51.100.3');
check('unix is not a client address in a header', 'custom',
    [ 'X-CDN-IP: unix:', 'X-Real-IP: 198.51.100.3' ], '198.51.100.3');
check('untrusted reported client is still selected', 'ordered',
    [ 'X-Real-IP: 203.0.113.9', 'X-CDN-IP: 10.0.1.1' ], '203.0.113.9');
check('untrusted direct peer cannot use any candidate', 'untrusted',
    [ 'X-CDN-IP: 10.0.1.1', 'X-Forwarded-For: 198.51.100.4' ],
    '127.0.0.1', 'peer');
check('repeated directives preserve declaration order', 'repeated',
    [ 'X-Real-IP: invalid', 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('candidate array grows beyond four entries', 'growth',
    [ 'X-One: invalid', 'X-Real-IP: 198.51.100.3' ], '198.51.100.3');
check('http-level candidates are inherited', 'inherited',
    [ 'X-HTTP-IP: invalid', 'X-HTTP-Fallback: 198.51.100.5' ], '198.51.100.5');
check('server candidates replace http-level candidates', 'ordered',
    [ 'X-HTTP-IP: 198.51.100.5', 'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');
check('location candidates replace inherited candidates in preaccess', 'location',
    [ 'X-HTTP-IP: 198.51.100.5', 'X-CDN-IP: invalid',
      'X-Fallback: 198.51.100.6' ], '198.51.100.6');

# Candidate order is left-to-right; an individual address chain is right-to-left.
for my $source ([ 'chain', 'X-CDN-IP' ], [ 'xff', 'X-Forwarded-For' ]) {
    my ($host, $header) = @$source;
    check("$header recursive off takes last address", "${host}_off",
        [ "$header: 198.51.100.1, 10.0.1.1", 'X-Fallback: 198.51.100.6' ],
        '10.0.1.1');
    check("$header recursive on skips trusted proxy", "${host}_on",
        [ "$header: 198.51.100.1, 10.0.1.1", 'X-Fallback: 198.51.100.6' ],
        '198.51.100.1');
    check("$header stops at untrusted address without falling back", "${host}_on",
        [ "$header: 10.0.1.9, 198.51.100.1, 10.0.1.1",
          'X-Fallback: 198.51.100.6' ], '198.51.100.1');
    check("$header retains a partially parsed chain", "${host}_on",
        [ "$header: invalid, 10.0.1.1", 'X-Fallback: 198.51.100.6' ],
        '10.0.1.1');
    check("$header invalid rightmost address falls back", "${host}_on",
        [ "$header: 198.51.100.1, invalid", 'X-Fallback: 198.51.100.6' ],
        '198.51.100.6');
}
check('X-Real-IP retains recursive chain parsing', 'xreal_on',
    [ 'X-Real-IP: 198.51.100.1, 10.0.1.1' ], '198.51.100.1');

check('XFF later in the list keeps multiple header-line semantics', 'custom',
    [ 'X-Forwarded-For: 198.51.100.1', 'X-Forwarded-For: 198.51.100.4' ],
    '198.51.100.4');
my $response = check('XFF recursively traverses multiple header lines', 'xff_on',
    [ 'X-Forwarded-For: 198.51.100.1', 'X-Forwarded-For: 10.0.1.1' ],
    '198.51.100.1');
like($response, qr/^X-Xff: 198\.51\.100\.1, 10\.0\.1\.1\x0d?$/mi,
    'XFF header links are restored after traversal');
check('invalid final XFF line falls back to next candidate', 'xff_on',
    [ 'X-Forwarded-For: 198.51.100.1', 'X-Forwarded-For: invalid',
      'X-Fallback: 198.51.100.6' ], '198.51.100.6');
check('invalid earlier XFF line retains parsed address', 'xff_on',
    [ 'X-Forwarded-For: invalid', 'X-Forwarded-For: 10.0.1.1',
      'X-Fallback: 198.51.100.6' ], '10.0.1.1');
check('ordinary repeated headers retain first-line behavior', 'chain_on',
    [ 'X-CDN-IP: invalid', 'X-CDN-IP: 198.51.100.2',
      'X-Fallback: 198.51.100.6' ], '198.51.100.6');
check('custom header lookup spans list parts', 'custom',
    [ (map { "X-Padding-$_: padding" } 1 .. 40),
      'X-CDN-IP: 198.51.100.2' ], '198.51.100.2');

my $proxy4 = "PROXY TCP4 192.0.2.9 127.0.0.1 4321 80\r\n";
check('PROXY protocol in later position supplies address and port', 'custom',
    [ 'X-CDN-IP: invalid' ], '192.0.2.9', '4321', proxy => $proxy4);
check('valid earlier header wins over PROXY protocol', 'ordered',
    [ 'X-Real-IP: 198.51.100.1:4567' ], '198.51.100.1', '4567', proxy => $proxy4);
check('PROXY protocol first takes priority', 'proxy',
    [ 'X-Real-IP: 198.51.100.1' ], '192.0.2.9', '4321', proxy => $proxy4);
check('missing PROXY protocol falls back to header', 'proxy',
    [ 'X-Real-IP: 198.51.100.1' ], '198.51.100.1');
check('PROXY UNKNOWN falls back to header', 'proxy',
    [ 'X-Real-IP: 198.51.100.1' ], '198.51.100.1', '',
    proxy => "PROXY UNKNOWN\r\n");
check('invalid PROXY source address falls back to header', 'proxy',
    [ 'X-Real-IP: 198.51.100.1' ], '198.51.100.1', '',
    proxy => "PROXY TCP4 999.999.999.999 127.0.0.1 4321 80\r\n");
check('untrusted direct peer cannot bypass trust using PROXY data', 'untrusted',
    [ 'X-CDN-IP: invalid' ], '127.0.0.1', 'peer', proxy => $proxy4);
check('proxy_protocol token never reads an HTTP header', 'custom',
    [ 'proxy_protocol: 198.51.100.7' ], '127.0.0.1', 'peer');

check('IPv6 with port', 'custom',
    [ 'X-CDN-IP: [2001:db8::2]:4567' ], '2001:db8::2', '4567');
check('PROXY IPv6 in later position', 'custom', [], '2001:db8::9', '4321',
    proxy => "PROXY TCP6 2001:db8::9 2001:db8::1 4321 80\r\n");

check('unix socket trusted peer supports fallback', 'unix',
    [ 'X-CDN-IP: invalid', 'X-Fallback: 198.51.100.6' ], '198.51.100.6', '',
    unix => 1);

$t->stop();
unlike($t->read_file('error.log'), qr/\[(?:alert|crit)\]/,
    'no worker or request lifecycle errors');

# check() captures $t; run its cleanup assertions before Test::More exits.
undef $t;

###############################################################################

sub check {
    my ($name, $host, $headers, $address, $remote_port, %opts) = @_;
    $remote_port = '' unless defined $remote_port;

    my ($socket, $peer_address, $peer_port);
    if ($opts{unix}) {
        $socket = IO::Socket::UNIX->new(
            Type => SOCK_STREAM, Peer => $t->testdir() . '/realip.sock');
        $peer_address = 'unix:';
        $peer_port = '';
    } else {
        $socket = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1', PeerPort => port($opts{proxy} ? 8081 : 8080),
            Proto => 'tcp', Timeout => 8);
        $peer_address = '127.0.0.1';
        $peer_port = $socket->sockport() if $socket;
    }
    die "connect for $name: $!" unless $socket;

    $remote_port = $peer_port if $remote_port eq 'peer';
    my $request = ($opts{proxy} || '') . join("\r\n",
        'GET /addr HTTP/1.0', "Host: $host", @$headers, '', '');
    my $response = http($request, socket => $socket);
    my ($actual) = $response =~ /^X-Address: (.*?)\x0d?$/mi;
    is($actual, join('|', $address, $remote_port, $peer_address, $peer_port),
        $name) or diag $response;
    return $response;
}
