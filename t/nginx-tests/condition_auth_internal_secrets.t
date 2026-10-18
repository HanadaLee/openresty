#!/usr/bin/perl

# Same-level secret lists, block equivalence and conditional inheritance.

use warnings;
use strict;
use Digest::MD5 qw/md5_hex/;
use Test::More;
use Test::Nginx;

my @cases;
for my $host (qw/combined split included/) {
    for my $a (0, 1) {
        for my $b (0, 1) {
            for my $secret (qw/a1 a2 b1 parent1 parent2 wrong/) {
                my $valid = ($a && $secret =~ /^a/)
                    || ($b && $secret eq 'b1')
                    || (!$a && !$b && $secret =~ /^parent/);
                push @cases, [$host, $a, $b, 1, $secret,
                    $valid ? 'success' : '403'];
            }
        }
    }
}
push @cases,
    ['unconditional', 1, 0, 1, 'always', 'success'],
    ['unconditional', 1, 0, 1, 'a1', 'success'],
    ['unconditional', 0, 0, 1, 'a1', '403'],
    ['unconditional', 0, 0, 1, 'parent1', '403'],
    ['inherit', 0, 0, 1, 'parent1', 'success'],
    ['inherit', 0, 0, 1, 'parent2', 'success'],
    ['inherit', 0, 0, 0, 'parent1', 'secrets_not_configured'],
    ['split', 0, 0, 0, 'a1', 'secrets_not_configured'],
    ['split', 1, 0, 0, 'parent1', '403'],
    ['relaxed', 1, 0, 1, 'parent1', 'failure'],
    ['relaxed', 0, 0, 1, 'parent1', 'success'],
    ['empty-secret', 0, 0, 1, '', 'success'],
    ['empty-secret', 0, 0, 1, 'parent1', '403'],
    ['split', 1, 1, 1, undef, '403'];

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_expr_module
    ngx_http_auth_internal_module/)->plan(scalar @cases);

$t->write_file('a2.inc', 'auth_internal_secret a2;');
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr a str_eq $http_x_a 1;
    expr b str_eq $http_x_b 1;
    expr p str_eq $http_x_p 1;
    auth_internal on;
    auth_internal_empty_deny on;
    auth_internal_timeout 60s;
    when p {
        auth_internal_secret parent1;
        auth_internal_secret parent2;
    }

    server {
        listen 127.0.0.1:8080;
        server_name combined;
        when a { auth_internal_secret a1; auth_internal_secret a2; }
        when b { auth_internal_secret b1; }
        location / { return 200 "$auth_internal_result"; }
    }
    server {
        listen 127.0.0.1:8080;
        server_name split;
        when a { auth_internal_secret a1; }
        when b { auth_internal_secret b1; }
        when a { auth_internal_secret a2; }
        location / { return 200 "$auth_internal_result"; }
    }
    server {
        listen 127.0.0.1:8080;
        server_name included;
        when a { auth_internal_secret a1; include a2.inc; }
        when b { auth_internal_secret b1; }
        location / { return 200 "$auth_internal_result"; }
    }
    server {
        listen 127.0.0.1:8080;
        server_name unconditional;
        when a { auth_internal_secret a1; }
        auth_internal_secret always;
        location / { return 200 "$auth_internal_result"; }
    }
    server {
        listen 127.0.0.1:8080;
        server_name inherit;
        location / { return 200 "$auth_internal_result"; }
    }
    server {
        listen 127.0.0.1:8080;
        server_name relaxed;
        when a { auth_internal_secret a1; }
        auth_internal_failure_deny off;
        location / { return 200 "$auth_internal_result"; }
    }
    server {
        listen 127.0.0.1:8080;
        server_name empty-secret;
        auth_internal_secret "";
        location / { return 200 "$auth_internal_result"; }
    }
}
EOF

$t->run();
for my $case (@cases) {
    my ($host, $a, $b, $p, $secret, $expected) = @$case;
    my $request = "GET / HTTP/1.0\r\nHost: $host\r\n"
        . "X-A: $a\r\nX-B: $b\r\nX-P: $p\r\n";
    if (defined $secret) {
        my $hex = sprintf('%08x', time());
        $request .= "X-Fingerprint: " . $hex . md5_hex($secret . $hex) . "\r\n";
    }
    my $response = http($request . "\r\n");
    my $label = "$host a=$a b=$b p=$p secret="
        . (defined $secret ? $secret : '(missing)');
    my $pattern = $expected eq '403' ? qr/^HTTP\/1\.[01] 403 /
        : qr/^HTTP\/1\.[01] 200 .*\r\n\r\n\Q$expected\E\z/s;
    like($response, $pattern, $label);
}
$t->stop();
