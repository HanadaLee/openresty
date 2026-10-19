#!/usr/bin/perl

# Integer and variable sampling, filtering, level selection and validation.

use strict;
use warnings;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite map /);
my $expr = $t->has_module('ngx_expr_module');
my $conditional = $expr ? <<'EOF' : '';
        location /conditional {
            when selected { access_log %%TESTDIR%%/conditional.log values sample=0; }
            proxy_pass http://127.0.0.1:8081;
        }
EOF
my $definitions = $expr ? 'expr selected str_eq $arg_selected yes;' : '';
$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    log_format values '\$arg_id';
    map \$arg_n \$sample { default \$arg_n; }
    $definitions
    access_log %%TESTDIR%%/parent.log values;
    upstream retry_backend {
        server 127.0.0.1:8999;
        server 127.0.0.1:8081 backup;
    }
    server {
        listen 127.0.0.1:8081;
        access_log off;
        return 200 ok;
    }
    server {
        listen 127.0.0.1:8080;
        location /literal {
            access_log %%TESTDIR%%/all.log values sample=1 buffer=4k flush=1s;
            access_log %%TESTDIR%%/none.log values sample=0;
            access_log %%TESTDIR%%/random.log values sample=20;
            access_log %%TESTDIR%%/plain.log values;
            proxy_pass http://127.0.0.1:8081;
        }
        location /variable {
            access_log %%TESTDIR%%/variable.log values sample=\$sample;
            access_log %%TESTDIR%%/other.log values;
            proxy_pass http://127.0.0.1:8081;
        }
        location /composite {
            access_log %%TESTDIR%%/composite.log values sample=1\$arg_suffix;
            proxy_pass http://127.0.0.1:8081;
        }
        location /filtered {
            access_log %%TESTDIR%%/filtered.log values sample=\$sample if=\$arg_gate;
            proxy_pass http://127.0.0.1:8081;
        }
        location /retry {
            access_log %%TESTDIR%%/retry.log values sample=\$sample;
            proxy_next_upstream error;
            proxy_next_upstream_tries 2;
            proxy_pass http://retry_backend;
        }
        $conditional
    }
}
EOF
$t->run();

my @cases = (
    ['/variable?n=1&id=one', 'one'],
    ['/variable?n=0&id=zero', ''],
    ['/variable?n=01&id=leading', 'leading'],
    ['/variable?n=2147483647&id=maximum', ''],
    ['/variable?n=bad&id=invalid', ''],
    ['/variable?n=-1&id=negative', ''],
    ['/variable?n=0.5&id=fraction', ''],
    ['/variable?n=2147483648&id=overflow', ''],
    ['/variable?n=999999999999999999999999999999&id=huge', ''],
    ['/variable?id=empty', ''],
);
my ($variable, $other) = ('', '');
for my $case (@cases) {
    like(http_get($case->[0]), qr/^HTTP\/1\.1 200 /, $case->[0]);
    $variable .= "$case->[1]\n" if length $case->[1];
    $case->[0] =~ /id=(\w+)/;
    $other .= "$1\n";
}
like(http_get('/composite?id=composite'), qr/^HTTP\/1\.1 200 /,
    'complex value with literal prefix');
like(http_get('/filtered?n=bad&gate=0&id=filtered'), qr/^HTTP\/1\.1 200 /,
    'if= evaluated before sample variable');
like(http_get('/filtered?n=1&gate=1&id=allowed'), qr/^HTTP\/1\.1 200 /,
    'if= and sample both permit logging');
like(http_get('/retry?n=1&id=retry'), qr/^HTTP\/1\.1 200 /, 'retry sampled in');
like(http_get('/retry?n=0&id=retry-zero'), qr/^HTTP\/1\.1 200 /, 'retry sampled out');
if ($expr) {
    like(http_get('/conditional?selected=yes&id=selected'), qr/^HTTP\/1\.1 200 /,
        'matching when with sample=0');
    like(http_get('/conditional?id=fallback'), qr/^HTTP\/1\.1 200 /,
        'unmatched when uses parent');
}

my ($literal_ok, $variable_ok) = (0, 0);
for my $i (1 .. 2000) {
    $literal_ok++ if http_get("/literal?id=$i") =~ /^HTTP\/1\.1 200 /;
    $variable_ok++ if http_get("/variable?n=20&id=random-$i") =~ /^HTTP\/1\.1 200 /;
}
is($literal_ok, 2000, 'literal sample requests complete');
is($variable_ok, 2000, 'variable sample requests complete');
$t->stop();

sub contents {
    my ($name) = @_;
    return -e $t->testdir() . "/$name.log" ? $t->read_file("$name.log") : '';
}
is(contents('all'), join('', map { "$_\n" } 1 .. 2000), 'sample=1 and buffering');
is(contents('plain'), contents('all'), 'omitted sample retains all entries');
is(contents('none'), '', 'sample=0 skips entries');
my $random = () = contents('random') =~ /\n/g;
cmp_ok($random, '>', 40, 'literal sample=20 retains a random subset');
cmp_ok($random, '<', 180, 'literal sample=20 approximates one in twenty');
my $variable_log = contents('variable');
like($variable_log, qr/^\Q$variable\E/, 'variable 0, 1 and leading zeros');
$variable_log =~ s/^\Q$variable\E//;
$variable_log =~ s/^maximum\n//m;
unlike($variable_log, qr/^(?!random-)\w/m, 'invalid variable values skip only their entries');
$random = () = $variable_log =~ /\n/g;
cmp_ok($random, '>', 40, 'variable sample=20 retains a random subset');
cmp_ok($random, '<', 180, 'variable sample=20 approximates one in twenty');
is(contents('other'), $other . join('', map { "random-$_\n" } 1 .. 2000),
    'invalid values and sample misses preserve other destinations');
is(contents('composite'), "composite\n", 'complex sample value is evaluated');
is(contents('filtered'), "allowed\n", 'if= combines with sampling');
is(contents('retry'), "retry\n" x 1, 'sampling applies to each completed request');
if ($expr) {
    is(contents('conditional'), '', 'sample misses do not write child');
    is(contents('parent'), "fallback\n", 'sample misses never fall back to parent');
}
my $errors = $t->read_file('error.log');
my $invalid = () = $errors =~ /invalid access_log sample value/g;
is($invalid, 6, 'invalid dynamic values diagnosed, filtered value is not evaluated');
undef $t;

my @parameters = (
    ['sample=0', 1], ['sample=1', 1], ['sample=20', 1],
    ['sample=2147483647', 1], ['sample=$arg_n', 1], ['sample=1$arg_n', 1],
    ['sample=', 0], ['sample=-1', 0], ['sample=0.5', 0],
    ['sample=20%', 0], ['sample=1/20', 0], ['sample=abc', 0],
    ['sample=2147483648', 0], ['sample=999999999999999999999999', 0],
    ['sample=1 sample=2', 0], ['sample=$arg_n sample=1', 0],
);
$t = Test::Nginx->new();
for my $case (@parameters) {
    my ($parameters, $valid) = @$case;
    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    log_format values '\$uri';
    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/validate.log values $parameters;
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
