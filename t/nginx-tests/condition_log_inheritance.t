#!/usr/bin/perl

# Select the nearest active logging level, before applying per-entry if=.

use strict;
use warnings;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

my @requests = (
    ['/fallback', ['parent']],
    ['/fallback?server=yes', ['server']],
    ['/select?child=yes&gate=1', ['child']],
    ['/select?child=yes&gate=0', []],
    ['/select?child=yes', []],
    ['/select?child=yes&gate=00&second=yes', ['child', 'second']],
    ['/select?second=yes', ['second']],
    ['/select', ['parent']],
    ['/off?child=yes', []],
    ['/off', ['parent']],
    ['/ordered?child=yes', ['before']],
    ['/ordered', ['before', 'after']],
    ['/local?gate=0', []],
    ['/local?gate=1', ['child']],
    ['/nested/deep', ['parent']],
    ['/nested/deep?server=yes', ['server']],
    ['/nested/deep?child=yes', ['child']],
    ['/nested/deep?child=yes&leaf=yes', ['leaf']],
    ['/parent-off/child', []],
    ['/parent-off/child?child=yes', ['off_child']],
    ['/redefine?server=yes', ['parent']],
    ['/only-access?child=yes', ['only_access'], ['parent']],
    ['/only-upstream?child=yes', ['parent'], ['only_upstream']],
    ['/redirect?child=yes&gate=1', ['child']],
    ['/retry', ['parent'], ['retry', 'parent']],
    ['/fallback', ['parent']],
);
my @destinations = qw/parent server child second before after leaf off_child
    unused only_access only_upstream retry/;
my @sessions = (
    ['', ['parent']],
    ['when no { access_log %%TESTDIR%%/stream-child.log values; }', ['parent']],
    ['when yes { access_log %%TESTDIR%%/stream-child.log values; }', ['child']],
    ['when yes { access_log %%TESTDIR%%/stream-child.log values if=0; }', []],
    ['when yes { access_log %%TESTDIR%%/stream-child.log values if=; }', []],
    ['when yes { access_log off; }', []],
    ['when no { access_log off; }', ['parent']],
    ['access_log %%TESTDIR%%/stream-before.log values;
      when yes { access_log off; }
      access_log %%TESTDIR%%/stream-after.log values;', ['before']],
    ['access_log %%TESTDIR%%/stream-before.log values;
      when no { access_log off; }
      access_log %%TESTDIR%%/stream-after.log values;', ['before', 'after']],
    ['when yes { access_log %%TESTDIR%%/stream-child.log values; }
      when yes { access_log %%TESTDIR%%/stream-second.log values; }',
      ['child', 'second']],
    ['expr inherited bool false;
      when no { access_log %%TESTDIR%%/stream-child.log values; }', []],
    ['expr inherited bool false;
      when yes { access_log %%TESTDIR%%/stream-child.log values; }', ['child']],
);
my @stream_destinations = qw/parent child second before after/;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite stream stream_return
    ngx_expr_module ngx_http_upstream_log_module/)
    ->plan(@requests + @sessions + 2 * @destinations + @stream_destinations);

my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    log_format values '$arg_id';
    expr server_selected str_eq $arg_server yes;
    expr child_selected str_eq $arg_child yes;
    expr second_selected str_eq $arg_second yes;
    expr leaf_selected str_eq $arg_leaf yes;
    expr failed_attempt str_eq $upstream_status 502;
    expr no bool false;
    both_log parent;

    upstream retry_backend {
        server 127.0.0.1:8999;
        server 127.0.0.1:8081 backup;
    }
    server {
        listen 127.0.0.1:8081;
        access_log off;
        upstream_log off;
        return 200 ok;
    }
    server {
        listen 127.0.0.1:8080;
        when server_selected { both_log server; }

        location /fallback {
            when no { both_log unused; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /select {
            when child_selected { both_log child if=$arg_gate; }
            when second_selected { both_log second; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /off {
            when child_selected { access_log off; upstream_log off; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /ordered {
            both_log before;
            when child_selected { access_log off; upstream_log off; }
            both_log after;
            proxy_pass http://127.0.0.1:8081;
        }
        location /local {
            both_log child if=$arg_gate;
            proxy_pass http://127.0.0.1:8081;
        }
        location /nested {
            when child_selected { both_log child; }
            proxy_pass http://127.0.0.1:8081;
            location /nested/deep {
                when leaf_selected { both_log leaf; }
            }
        }
        location /parent-off {
            access_log off;
            upstream_log off;
            proxy_pass http://127.0.0.1:8081;
            location /parent-off/child {
                when child_selected { both_log off_child; }
            }
        }
        location /redefine {
            expr server_selected bool false;
            when no { both_log unused; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /only-access {
            when child_selected {
                access_log %%TESTDIR%%/access-only_access.log values;
            }
            proxy_pass http://127.0.0.1:8081;
        }
        location /only-upstream {
            when child_selected {
                upstream_log %%TESTDIR%%/upstream-only_upstream.log values;
            }
            proxy_pass http://127.0.0.1:8081;
        }
        location /redirect { rewrite ^ /select last; }
        location /retry {
            when failed_attempt { both_log retry; }
            proxy_next_upstream error;
            proxy_next_upstream_tries 2;
            proxy_pass http://retry_backend;
        }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    log_format values '$server_port';
    expr yes bool true;
    expr no bool false;
    expr inherited bool true;
    when inherited { access_log %%TESTDIR%%/stream-parent.log values; }
    access_log off;
    %%STREAM_SERVERS%%
}
EOF

# Expand identical HTTP access/upstream configurations to compare their rules.
$config =~ s{both_log ([a-z_]+)([^;]*);}{
    "access_log %%TESTDIR%%/access-$1.log values$2;\n"
    . "upstream_log %%TESTDIR%%/upstream-$1.log values$2;"
}ge;
my $servers = '';
for my $i (0 .. $#sessions) {
    my $port = 8100 + $i;
    $servers .= "server { listen 127.0.0.1:$port; $sessions[$i][0] return ok; }\n";
}
$config =~ s/%%STREAM_SERVERS%%/$servers/;
$t->write_file_expand('nginx.conf', $config);
$t->run();

my %expected;
for my $i (0 .. $#requests) {
    my ($uri, $access, $upstream) = @{$requests[$i]};
    $upstream = $access unless defined $upstream;
    $uri .= ($uri =~ /\?/ ? '&' : '?') . "id=$i";
    like(http_get($uri), qr/^HTTP\/1\.1 200 /, "HTTP $uri");
    $expected{"access-$_"} .= "$i\n" for @$access;
    $expected{"upstream-$_"} .= "$i\n" for @$upstream;
}
for my $i (0 .. $#sessions) {
    my $port = port(8100 + $i);
    is(stream("127.0.0.1:$port")->read(), 'ok', "Stream case $i");
    $expected{"stream-$_"} .= "$port\n" for @{$sessions[$i][1]};
}
$t->stop();

for my $kind (qw/access upstream/) {
    for my $name (@destinations) {
        my $file = "$kind-$name.log";
        my $actual = -e $t->testdir() . "/$file" ? $t->read_file($file) : '';
        is($actual, $expected{"$kind-$name"} || '', "$kind $name inheritance");
    }
}
for my $name (@stream_destinations) {
    is($t->read_file("stream-$name.log"), $expected{"stream-$name"} || '',
        "Stream $name inheritance");
}
