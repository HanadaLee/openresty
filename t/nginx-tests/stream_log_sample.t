#!/usr/bin/perl

# Stream uses the same per-destination integer sampling semantics as HTTP.

use strict;
use warnings;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

my $t = Test::Nginx->new()->has(qw/stream stream_return stream_map/);
my $expr = $t->has_module('ngx_expr_module');
my $conditional = $expr ? 'when yes { access_log %%TESTDIR%%/child.log values sample=0; }'
    : 'access_log %%TESTDIR%%/child.log values sample=0;';
my $definition = $expr ? 'expr yes bool true;' : '';
$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
stream {
    %%TEST_GLOBALS_STREAM%%
    log_format values '\$server_port';
    map \$remote_addr \$one { default 1; }
    map \$remote_addr \$zero { default 0; }
    map \$remote_addr \$sample { default 20; }
    map \$remote_addr \$bad { default invalid; }
    $definition
    access_log %%TESTDIR%%/parent.log values;
    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/all.log values sample=1 buffer=4k flush=1s;
        access_log %%TESTDIR%%/none.log values sample=0;
        access_log %%TESTDIR%%/random.log values sample=20;
        access_log %%TESTDIR%%/variable.log values sample=\$sample;
        access_log %%TESTDIR%%/variable-one.log values sample=\$one;
        access_log %%TESTDIR%%/composite.log values sample=\$zero\$one;
        access_log %%TESTDIR%%/variable-zero.log values sample=\$zero;
        access_log %%TESTDIR%%/plain.log values;
        return ok;
    }
    server {
        listen 127.0.0.1:8081;
        access_log %%TESTDIR%%/invalid.log values sample=\$bad;
        access_log %%TESTDIR%%/other.log values;
        access_log %%TESTDIR%%/filtered.log values if=0 sample=\$bad;
        return ok;
    }
    server { listen 127.0.0.1:8082; $conditional return ok; }
}
EOF
$t->run();
my $ok = 0;
for (1 .. 2000) {
    $ok++ if stream('127.0.0.1:' . port(8080))->read() eq 'ok';
}
is($ok, 2000, 'all stream sessions complete');
is(stream('127.0.0.1:' . port(8081))->read(), 'ok', 'invalid sample session completes');
is(stream('127.0.0.1:' . port(8082))->read(), 'ok', 'sampled-out child completes');
$t->stop();
sub contents {
    my ($name) = @_;
    return -e $t->testdir() . "/$name.log" ? $t->read_file("$name.log") : '';
}
my $all = (port(8080) . "\n") x 2000;
is(contents($_), $all, "$_ retains every session") for qw/all plain variable-one composite/;
is(contents($_), '', "$_ skips without parent fallback")
    for qw/none variable-zero invalid filtered child parent/;
for my $name (qw/random variable/) {
    my $count = () = contents($name) =~ /\n/g;
    cmp_ok($count, '>', 40, "$name sampling retains a subset");
    cmp_ok($count, '<', 180, "$name approximates one in twenty");
}
is(contents('other'), port(8081) . "\n", 'invalid variable preserves another destination');
my $errors = $t->read_file('error.log');
my $invalid = () = $errors =~ /invalid access_log sample value/g;
is($invalid, 1, 'only the evaluated invalid sample is diagnosed');
undef $t;

$t = Test::Nginx->new();
for my $case (
    ['sample=0', 1], ['sample=1', 1], ['sample=20', 1],
    ['sample=2147483647', 1], ['sample=$server_port', 1],
    ['sample=', 0], ['sample=-1', 0], ['sample=0.5', 0],
    ['sample=20%', 0], ['sample=1/20', 0], ['sample=abc', 0],
    ['sample=2147483648', 0], ['sample=999999999999999999999999', 0],
    ['sample=1 sample=2', 0], ['sample=$server_port sample=1', 0],
) {
    my ($parameters, $valid) = @$case;
    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
events {}
stream {
    %%TEST_GLOBALS_STREAM%%
    log_format values '\$server_port';
    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/validate.log values $parameters;
        return ok;
    }
}
EOF
    my $output = $t->dump_config();
    is($? == 0 ? 1 : 0, $valid, "$parameters configuration validation");
    like($output, qr/(?:invalid access_log sample value|duplicate sample parameter)/,
        "$parameters diagnosis") unless $valid;
}
undef $t;
done_testing();
