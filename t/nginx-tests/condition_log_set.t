#!/usr/bin/perl

# Conditional log_set inheritance in HTTP and Stream.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @http = (
    ['/selected?case=1', 'http'],
    ['/selected?case=2&server=yes', 'server'],
    ['/selected?case=3&server=yes&child=yes', 'child'],
    ['/selected?case=4&child=yes', 'child'],
    ['/selected/nested?case=5', 'http'],
    ['/selected/nested?case=6&server=yes', 'server'],
    ['/selected/nested?case=7&child=yes', 'child'],
    ['/selected/nested?case=8&nested=yes', 'nested'],
    ['/local?case=9&server=yes', 'local'],
    ['/first?case=10&child=yes', 'first'],
    ['/selected?case=11', 'http'],
);
my @stream = (
    [8081, 'parent'],
    [8082, 'child'],
    [8083, 'first'],
    [8084, 'parent'],
);

my $t = Test::Nginx->new()->has(qw/http rewrite stream stream_return
    ngx_expr_module ngx_http_log_set_module ngx_stream_log_set_module/)
    ->plan(2 * (@http + @stream));

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}

http {
    %%TEST_GLOBALS_HTTP%%
    log_format values '$uri|$arg_case|$field|$other';
    log_set $field http;
    log_set $other keep;
    expr server_selected str_eq $arg_server yes;
    expr child_selected str_eq $arg_child yes;
    expr nested_selected str_eq $arg_nested yes;

    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/http-values.log values;
        when server_selected { log_set $field server; }

        location /selected {
            when child_selected { log_set $field child; }
            location /selected/nested {
                when nested_selected { log_set $field nested; }
                return 200 ok;
            }
            return 200 ok;
        }
        location /local {
            log_set $field local;
            return 200 ok;
        }
        location /first {
            log_set $field first;
            when child_selected { log_set $field unreachable; }
            return 200 ok;
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%
    log_format values '$server_port|$field|$other';
    expr selected bool true;
    expr missed bool false;
    when selected { log_set $field parent; }
    log_set $field fallback;
    log_set $other keep;

    server {
        listen 127.0.0.1:8081;
        access_log %%TESTDIR%%/stream-values.log values;
        when missed { log_set $field child; }
        return ok;
    }
    server {
        listen 127.0.0.1:8082;
        access_log %%TESTDIR%%/stream-values.log values;
        when selected { log_set $field child; }
        return ok;
    }
    server {
        listen 127.0.0.1:8083;
        access_log %%TESTDIR%%/stream-values.log values;
        log_set $field first;
        when selected { log_set $field unreachable; }
        return ok;
    }
    server {
        listen 127.0.0.1:8084;
        access_log %%TESTDIR%%/stream-values.log values;
        return ok;
    }
}
EOF

$t->run();
for my $case (@http) {
    like(http_get($case->[0]), qr/^HTTP\/1\.1 200 /, $case->[0]);
}
for my $case (@stream) {
    is(stream('127.0.0.1:' . port($case->[0]))->read(), 'ok',
        "Stream session $case->[0]");
}
$t->stop();

my $http_log = $t->read_file('http-values.log');
for my $case (@http) {
    my ($uri, $value) = @$case;
    my ($path, $id) = $uri =~ m{^([^?]+)\?case=(\d+)};
    like($http_log, qr/^\Q$path|$id|$value|keep\E$/m,
        "HTTP inherited value for $uri");
}
my $stream_log = $t->read_file('stream-values.log');
for my $case (@stream) {
    my $port = port($case->[0]);
    like($stream_log, qr/^\Q$port|$case->[1]|keep\E$/m,
        "Stream inherited value for $case->[0]");
}
