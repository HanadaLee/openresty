#!/usr/bin/perl

# Conditional sink inheritance is selected before aggregation or output.

use strict;
use warnings;
use FindBin;
use JSON::PP qw/ decode_json /;

BEGIN {
    unshift @INC, "$ENV{NGINX_TESTS}/lib" if $ENV{NGINX_TESTS};
    chdir $FindBin::Bin;
}

use Test::More;
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

my @requests = (
    ['/fallback', ['parent']],
    ['/fallback?server=yes', ['server']],
    ['/select?child=yes', ['child']],
    ['/select', ['parent']],
    ['/off?child=yes', []],
    ['/off', ['parent']],
    ['/ordered?child=yes', ['before']],
    ['/ordered', ['before', 'after']],
    ['/shared', ['shared_a', 'shared_b']],
    ['/nested/deep', ['parent']],
    ['/nested/deep?server=yes', ['server']],
    ['/nested/deep?child=yes', ['child']],
    ['/nested/deep?child=yes&leaf=yes', ['leaf']],
    ['/parent-off/child', []],
    ['/parent-off/child?child=yes', ['off_child']],
    ['/redefine?server=yes', ['parent']],
    ['/invalid?metric=bad', ['invalid'], 0],
    ['/fallback', ['parent']],
);
my @destinations = qw/parent server child shared_a shared_b before after leaf
    off_child unused invalid/;
my @sessions = (
    ['', ['parent']],
    ['when no { stat_log %%TESTDIR%%/stream-child.json child format=json; }',
        ['parent']],
    ['when yes { stat_log %%TESTDIR%%/stream-child.json child format=json; }',
        ['child']],
    ['when yes { stat_log off; }', []],
    ['when no { stat_log off; }', ['parent']],
    ['stat_log %%TESTDIR%%/stream-before.json before format=json;
      when yes { stat_log off; }
      stat_log %%TESTDIR%%/stream-after.json after format=json;', ['before']],
    ['stat_log %%TESTDIR%%/stream-before.json before format=json;
      when no { stat_log off; }
      stat_log %%TESTDIR%%/stream-after.json after format=json;',
        ['before', 'after']],
    ['when yes { stat_log %%TESTDIR%%/stream-shared_a.json shared format=json; }
      when yes { stat_log %%TESTDIR%%/stream-shared_b.json shared format=json; }',
        ['shared_a', 'shared_b']],
    ['expr inherited bool false;
      when no { stat_log %%TESTDIR%%/stream-child.json child format=json; }', []],
    ['expr inherited bool false;
      when yes { stat_log %%TESTDIR%%/stream-child.json child format=json; }',
        ['child']],
);
my @stream_destinations = qw/parent child before after shared_a shared_b/;

my $t = Test::Nginx->new()->has(qw/http rewrite stream stream_return
    ngx_expr_module/);
my @modules = grep { $_ } ($ENV{NGX_STAT_TEST_MODULE} || '',
    $ENV{NGX_STAT_TEST_STREAM_MODULE} || '');
$t->has('ngx_stat_module') unless @modules;
$t->plan(@requests + @sessions + @destinations + @stream_destinations + 2);
my $load = join '', map { "load_module $_;\n" } @modules;

my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    stat_interval 3600s;
    log_format values '$arg_id';
    access_log %%TESTDIR%%/http-access.log values;
    %%HTTP_FIELDS%%
    expr yes bool true;
    expr no bool false;
    expr server_selected str_eq $arg_server yes;
    expr child_selected str_eq $arg_child yes;
    expr leaf_selected str_eq $arg_leaf yes;
    stat_log %%TESTDIR%%/parent.json parent format=json;

    server {
        listen 127.0.0.1:8080;
        when server_selected { stat_log %%TESTDIR%%/server.json server format=json; }
        location /fallback {
            when no { stat_log %%TESTDIR%%/unused.json unused format=json; }
            return 200 ok;
        }
        location /select {
            when child_selected { stat_log %%TESTDIR%%/child.json child format=json; }
            return 200 ok;
        }
        location /off {
            when child_selected { stat_log off; }
            return 200 ok;
        }
        location /ordered {
            stat_log %%TESTDIR%%/before.json before format=json;
            when child_selected { stat_log off; }
            stat_log %%TESTDIR%%/after.json after format=json;
            return 200 ok;
        }
        location /shared {
            when yes { stat_log %%TESTDIR%%/shared_a.json shared format=json; }
            when yes { stat_log %%TESTDIR%%/shared_b.json shared format=json; }
            return 200 ok;
        }
        location /nested {
            when child_selected { stat_log %%TESTDIR%%/child.json child format=json; }
            location /nested/deep {
                when leaf_selected { stat_log %%TESTDIR%%/leaf.json leaf format=json; }
                return 200 ok;
            }
        }
        location /parent-off {
            stat_log off;
            location /parent-off/child {
                when child_selected {
                    stat_log %%TESTDIR%%/off_child.json off_child format=json;
                }
                return 200 ok;
            }
        }
        location /redefine {
            expr server_selected bool false;
            when no { stat_log %%TESTDIR%%/unused.json unused format=json; }
            return 200 ok;
        }
        location /invalid {
            when yes { stat_log %%TESTDIR%%/invalid.json invalid format=json; }
            return 200 ok;
        }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    stat_interval 3600s;
    log_format values '$server_port';
    access_log %%TESTDIR%%/stream-access.log values;
    %%STREAM_FIELDS%%
    expr yes bool true;
    expr no bool false;
    expr inherited bool true;
    when inherited { stat_log %%TESTDIR%%/stream-parent.json parent format=json; }
    stat_log off;
    %%STREAM_SERVERS%%
}
EOF

my ($http_fields, $stream_fields, $servers) = ('', '', '');
for my $name (qw/parent server child shared before after leaf off_child unused/) {
    $http_fields .= "stat_group_field $name id \$arg_id;\n"
        . "stat_metric_field $name requests 1;\n";
}
$http_fields .= "stat_group_field invalid id \$arg_id;\n"
    . "stat_metric_field invalid requests \$arg_metric;\n";
for my $name (qw/parent child shared before after/) {
    $stream_fields .= "stat_group_field $name id \$server_port;\n"
        . "stat_metric_field $name requests 1;\n";
}
for my $i (0 .. $#sessions) {
    my $port = 8100 + $i;
    $servers .= "server { listen 127.0.0.1:$port; $sessions[$i][0] return ok; }\n";
}
$config =~ s/%%HTTP_FIELDS%%/$http_fields/;
$config =~ s/%%STREAM_FIELDS%%/$stream_fields/;
$config =~ s/%%STREAM_SERVERS%%/$servers/;
$t->write_file_expand('nginx.conf', $load . $config);
$t->run();

my (%expected, $http_access, $stream_access);
for my $i (0 .. $#requests) {
    my ($uri, $sinks, $metric) = @{$requests[$i]};
    $metric = 1 unless defined $metric;
    $uri .= ($uri =~ /\?/ ? '&' : '?') . "id=$i";
    like(http_get($uri), qr/^HTTP\/1\.1 200 /, "HTTP $uri");
    $http_access .= "$i\n";
    push @{$expected{$_}}, { id => "$i", requests => $metric } for @$sinks;
}
for my $i (0 .. $#sessions) {
    my $port = port(8100 + $i);
    is(stream("127.0.0.1:$port")->read(), 'ok', "Stream case $i");
    $stream_access .= "$port\n";
    push @{$expected{"stream-$_"}}, { id => "$port", requests => 1 }
        for @{$sessions[$i][1]};
}
$t->stop();

for my $name (@destinations, map { "stream-$_" } @stream_destinations) {
    my @actual;
    if (-e $t->testdir() . "/$name.json") {
        @actual = map { decode_json($_) }
            grep { length } split /\n/, $t->read_file("$name.json");
    }
    is_deeply([sort { $a->{id} <=> $b->{id} } @actual],
        [sort { $a->{id} <=> $b->{id} } @{$expected{$name} || []}],
        "$name receives only its selected requests, counted once");
}
is($t->read_file('http-access.log'), $http_access,
    'HTTP stat_log does not change access_log inheritance');
is($t->read_file('stream-access.log'), $stream_access,
    'Stream stat_log does not change access_log inheritance');
