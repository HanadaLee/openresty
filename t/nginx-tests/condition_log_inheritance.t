#!/usr/bin/perl

# HTTP and Stream access_log select the nearest active logging level.

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
    ['/redirect?child=yes&gate=1', ['child']],
    ['/retry', ['parent']],
    ['/fallback', ['parent']],
);
my @destinations = qw/parent server child second before after leaf off_child
    unused retry/;
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
    ngx_expr_module/)
    ->plan(@requests + @sessions + @destinations + @stream_destinations);

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
    access_log %%TESTDIR%%/access-parent.log values;

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
        when server_selected { access_log %%TESTDIR%%/access-server.log values; }

        location /fallback {
            when no { access_log %%TESTDIR%%/access-unused.log values; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /select {
            when child_selected { access_log %%TESTDIR%%/access-child.log values if=$arg_gate; }
            when second_selected { access_log %%TESTDIR%%/access-second.log values; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /off {
            when child_selected { access_log off; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /ordered {
            access_log %%TESTDIR%%/access-before.log values;
            when child_selected { access_log off; }
            access_log %%TESTDIR%%/access-after.log values;
            proxy_pass http://127.0.0.1:8081;
        }
        location /local {
            access_log %%TESTDIR%%/access-child.log values if=$arg_gate;
            proxy_pass http://127.0.0.1:8081;
        }
        location /nested {
            when child_selected { access_log %%TESTDIR%%/access-child.log values; }
            proxy_pass http://127.0.0.1:8081;
            location /nested/deep {
                when leaf_selected { access_log %%TESTDIR%%/access-leaf.log values; }
                proxy_pass http://127.0.0.1:8081;
            }
        }
        location /parent-off {
            access_log off;
            proxy_pass http://127.0.0.1:8081;
            location /parent-off/child {
                when child_selected { access_log %%TESTDIR%%/access-off_child.log values; }
                proxy_pass http://127.0.0.1:8081;
            }
        }
        location /redefine {
            expr server_selected bool false;
            when no { access_log %%TESTDIR%%/access-unused.log values; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /redirect { rewrite ^ /select last; }
        location /retry {
            when failed_attempt { access_log %%TESTDIR%%/access-retry.log values; }
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
    my ($uri, $access) = @{$requests[$i]};
    $uri .= ($uri =~ /\?/ ? '&' : '?') . "id=$i";
    like(http_get($uri), qr/^HTTP\/1\.1 200 /, "HTTP $uri");
    $expected{"access-$_"} .= "$i\n" for @$access;
}
for my $i (0 .. $#sessions) {
    my $port = port(8100 + $i);
    is(stream("127.0.0.1:$port")->read(), 'ok', "Stream case $i");
    $expected{"stream-$_"} .= "$port\n" for @{$sessions[$i][1]};
}
$t->stop();

for my $name (@destinations) {
    my $file = "access-$name.log";
    my $actual = -e $t->testdir() . "/$file" ? $t->read_file($file) : '';
    is($actual, $expected{"access-$name"} || '', "access $name inheritance");
}
for my $name (@stream_destinations) {
    is($t->read_file("stream-$name.log"), $expected{"stream-$name"} || '',
        "Stream $name inheritance");
}
