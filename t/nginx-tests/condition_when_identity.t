#!/usr/bin/perl

# Splitting or including when blocks must preserve conditional slot identity.

use warnings;
use strict;

use Test::More;
use lib 'lib';
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @cases = (
    ['duplicate in one block',
        'when a { proxy_connect_timeout 1s; proxy_connect_timeout 2s; }', 0],
    ['duplicate in split blocks',
        'when a { proxy_connect_timeout 1s; }
         when a { proxy_connect_timeout 2s; }', 0],
    ['duplicate through include',
        'when a { proxy_connect_timeout 1s; include second.inc; }', 0],
    ['duplicate across included block',
        'when a { proxy_connect_timeout 1s; } include block.inc;', 0],
    ['duplicate with negation',
        'when !a { proxy_connect_timeout 1s; }
         when !a { proxy_connect_timeout 2s; }', 0],
    ['duplicate with multiple terms',
        'when a !b { proxy_connect_timeout 1s; }
         when a !b { proxy_connect_timeout 2s; }', 0],
    ['different polarity',
        'when a { proxy_connect_timeout 1s; }
         when !a { proxy_connect_timeout 2s; }', 1],
    ['different expression',
        'when a { proxy_connect_timeout 1s; }
         when b { proxy_connect_timeout 2s; }', 1],
    ['different term order',
        'when a b { proxy_connect_timeout 1s; }
         when b a { proxy_connect_timeout 2s; }', 1],
    ['different term count',
        'when a { proxy_connect_timeout 1s; }
         when a b { proxy_connect_timeout 2s; }', 1],
    ['different fields in one block',
        'when a { proxy_connect_timeout 1s; proxy_next_upstream_tries 2; }', 1],
    ['different fields in split blocks',
        'when a { proxy_connect_timeout 1s; }
         when a { proxy_next_upstream_tries 2; }', 1],
);

my $t = Test::Nginx->new()
    ->has(qw/http proxy stream ngx_expr_module/)->plan(4 * scalar @cases);

$t->write_file('second.inc', 'proxy_connect_timeout 2s;');
$t->write_file('block.inc', 'when a { proxy_connect_timeout 2s; }');

for my $context (qw/http stream/) {
    for my $case (@cases) {
        my ($name, $body, $valid) = @$case;
        my $globals = '';
        my $server;

        if ($context eq 'http') {
            $globals = '%%TEST_GLOBALS_HTTP%%';
            $server = "server { listen 127.0.0.1:8080; location / {
                $body
                proxy_pass http://127.0.0.1:8081;
            } }";
        } else {
            $server = "server { listen 127.0.0.1:8080;
                $body
                proxy_pass 127.0.0.1:8081;
            }";
        }

        $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
$context {
    $globals
    expr a bool true;
    expr b bool true;
    $server
}
EOF

        my $output = $t->dump_config();
        my $status = $?;
        my $label = "$context $name";

        if ($valid) {
            is($status, 0, "$label is accepted");
            unlike($output, qr/is duplicate/, "$label keeps distinct slots");
        } else {
            isnt($status, 0, "$label is rejected");
            like($output, qr/"proxy_connect_timeout" directive is duplicate/,
                "$label retains duplicate checking");
        }
    }
}
