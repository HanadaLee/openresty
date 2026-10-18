#!/usr/bin/perl

# Native off conflicts must survive when splitting and include expansion.

use warnings;
use strict;
use Test::More;
use Test::Nginx;

my @directives = (
    ['proxy_redirect', 'http://origin.test/ /new/'],
    ['proxy_cookie_domain', 'origin.test new.test'],
    ['proxy_cookie_path', '/old/ /new/'],
    ['proxy_cookie_flags', 'sid secure'],
    ['proxy_cookie_value', 'sid old new'],
    ['proxy_cookie_max_age', 'sid 10s'],
);
my $t = Test::Nginx->new()->has(qw/http proxy ngx_expr_module/);
my @cases;
for my $item (@directives) {
    my ($d, $args) = @$item;
    my $rule = "$d $args;";
    my $off = "$d off;";
    $t->write_file("$d-rule.inc", $rule);
    $t->write_file("$d-off.inc", $off);
    push @cases,
        [$d, 'unconditional off first', "$off $rule", 0],
        [$d, 'unconditional off last', "$rule $off", 0],
        [$d, 'combined off first', "when a { $off $rule }", 0],
        [$d, 'combined off last', "when a { $rule $off }", 0],
        [$d, 'split off first', "when a { $off } when a { $rule }", 0],
        [$d, 'split off last', "when a { $rule } when a { $off }", 0],
        [$d, 'included rule', "when a { $off include $d-rule.inc; }", 0],
        [$d, 'included off', "when a { $rule include $d-off.inc; }", 0],
        [$d, 'repeated off', "when a { $off } when a { $off }", 0],
        [$d, 'same negation', "when !a { $off } when !a { $rule }", 0],
        [$d, 'same terms', "when a !b { $off } when a !b { $rule }", 0],
        [$d, 'interleaved conflict',
            "when a { $off } when b { $rule } when a { $rule }", 0],
        [$d, 'different conditions', "when a { $off } when b { $rule }", 1],
        [$d, 'mutually exclusive', "when a { $off } when !a { $rule }", 1],
        [$d, 'unconditional off fallback', "when a { $rule } $off", 1],
        [$d, 'ordinary multiple rules', "when a { $rule } when a { $rule }", 1];
}
$t->plan(2 * @cases + 8);

for my $case (@cases) {
    my ($directive, $name, $body, $valid) = @$case;
    write_config($body);
    my $output = $t->dump_config();
    my $status = $?;
    if ($valid) {
        is($status, 0, "$directive $name accepted");
        unlike($output, qr/is duplicate/, "$directive $name remains distinct");
    } else {
        isnt($status, 0, "$directive $name rejected");
        like($output, qr/"\Q$directive\E" directive is duplicate/,
            "$directive $name duplicate diagnosis");
    }
}
for my $case (
    ['default after proxy_pass',
        'proxy_pass http://127.0.0.1:8081/base/;
         when a { proxy_redirect default; }', 1, qr/is duplicate/],
    ['default before proxy_pass',
        'when a { proxy_redirect default; }
         proxy_pass http://127.0.0.1:8081/base/;', 0, qr/should be placed after/],
    ['default with variable proxy_pass',
        'proxy_pass http://$host;
         when a { proxy_redirect default; }', 0, qr/cannot be used.*variables/],
    ['default conflicts with off',
        'proxy_pass http://127.0.0.1:8081/base/;
         when a { proxy_redirect default; } when a { proxy_redirect off; }',
        0, qr/is duplicate/],
) {
    my ($name, $body, $valid, $diagnosis) = @$case;
    write_config($body);
    my $output = $t->dump_config();
    my $status = $?;
    if ($valid) {
        is($status, 0, "$name accepted");
        unlike($output, $diagnosis, "$name no conflict");
    } else {
        isnt($status, 0, "$name rejected");
        like($output, $diagnosis, "$name diagnosis");
    }
}

# Finish the harness checks before Test::More evaluates the test plan.  The
# named configuration helper otherwise retains $t until global destruction.
undef $t;

sub write_config {
    my ($body) = @_;
    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr a bool true;
    expr b bool false;
    server {
        listen 127.0.0.1:8080;
        location / { $body }
    }
}
EOF
}
