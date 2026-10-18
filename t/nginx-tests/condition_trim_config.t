#!/usr/bin/perl

# Reject complex values at configuration time, even in an unmatched when.

use warnings;
use strict;
use Test::More;
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http trim_filter ngx_expr_module/);
my @cases;

for my $directive (qw/trim trim_js trim_css/) {
    $t->write_file("$directive.inc", "$directive on;");
    for my $context (qw/http server location/) {
        for my $wrapped (0, 1) {
            for my $value ('on', 'off', 'ON', '"off"', '$arg_enable',
                'on$arg_enable', '"$arg_enable"', 'yes', '1', '""')
            {
                my $valid = $value =~ /^(?:on|off|ON|"off")$/;
                my $line = "$directive $value;";
                $line = "when missed { $line }" if $wrapped;
                push @cases, ["$directive $context when=$wrapped $value",
                    $context, $line, $valid, qr/must be "on" or "off"/];
            }
        }
    }
    for my $spec (
        ['duplicate literal', "$directive on; $directive off;", 0],
        ['duplicate in one block', "when a { $directive on; $directive off; }", 0],
        ['duplicate in split blocks',
            "when a { $directive on; } when a { $directive off; }", 0],
        ['duplicate through include',
            "when a { $directive off; include $directive.inc; }", 0],
        ['different conditions',
            "when a { $directive on; } when missed { $directive off; }", 1],
        ['unconditional fallback', "when a { $directive on; } $directive off;", 1],
        ['missing argument', "$directive;", 0],
        ['extra argument', "$directive on off;", 0],
    ) {
        my ($name, $line, $valid) = @$spec;
        push @cases, ["$directive $name", 'location', $line, $valid,
            $name =~ /argument/ ? qr/invalid number of arguments/ : qr/is duplicate/];
    }
}
push @cases, ['trim_types in when', 'location',
    'when a { trim_types text/plain; }', 0, qr/is not allowed here/];
$t->plan(2 * @cases);

for my $case (@cases) {
    my ($name, $context, $line, $valid, $diagnosis) = @$case;
    my $main = $context eq 'http' ? $line : '';
    my $server = $context eq 'server' ? $line : '';
    my $location = $context eq 'location' ? $line : '';
    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr a bool true;
    expr missed bool false;
    $main
    server {
        listen 127.0.0.1:8080;
        $server
        location / { $location }
    }
}
EOF
    my $output = $t->dump_config();
    my $status = $?;
    if ($valid) {
        is($status, 0, "$name accepted");
        unlike($output, qr/\[emerg\]/, "$name no configuration error");
    } else {
        isnt($status, 0, "$name rejected");
        like($output, $diagnosis, "$name diagnosis");
    }
}

undef $t;
