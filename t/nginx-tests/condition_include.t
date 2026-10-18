#!/usr/bin/perl

# include preserves when context, including nested includes and globs.

use warnings;
use strict;

use Test::More;
use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
    ->has(qw/http rewrite stream stream_return ngx_expr_module/)->plan(24);

for my $name (qw/http server location stream stream-server/) {
    $t->write_file_expand("$name.inc",
        "include %%TESTDIR%%/$name-leaf-*.inc;\n");
    $t->write_file_expand("$name-leaf-1.inc",
        "access_log %%TESTDIR%%/$name.log included;\n");
    $t->write_file_expand("$name-leaf-2.inc",
        "access_log %%TESTDIR%%/$name-copy.log included;\n");
}
$t->write_file('empty.inc', "# no directives\n");
$t->write_file_expand('outside.inc',
    "access_log %%TESTDIR%%/outside.log included;\n");

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    log_format included '$arg_hit';
    expr selected str_eq $arg_hit yes;
    when selected { include http.inc; }
    server {
        listen 127.0.0.1:8080;
        location / { return 204; }
    }
    server {
        listen 127.0.0.1:8081;
        when selected { include server.inc; }
        location / { return 204; }
    }
    server {
        listen 127.0.0.1:8082;
        location / {
            when selected {
                include location.inc;
                include empty.inc;
                include missing-*.inc;
            }
            include outside.inc;
            return 204;
        }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    log_format included '$server_port';
    expr selected bool true;
    when selected { include stream.inc; }
    server {
        listen 127.0.0.1:8083;
        return ok;
    }
    server {
        listen 127.0.0.1:8084;
        expr selected bool false;
        when selected { include stream-server.inc; }
        return ok;
    }
}
EOF

$t->run();
for my $port (8080 .. 8082) {
    for my $hit (qw/yes no/) {
        like(http("GET /?hit=$hit HTTP/1.0\r\n\r\n",
            PeerAddr => '127.0.0.1:' . port($port)), qr/^HTTP\/1\.1 204/,
            "HTTP include $port $hit");
    }
}
for my $port (8083 .. 8084) {
    is(stream('127.0.0.1:' . port($port))->read(), 'ok',
        "Stream include $port");
}
$t->stop();

for my $name (qw/http server location/) {
    is($t->read_file("$name.log"), "yes\n", "$name retains when ID");
    is($t->read_file("$name-copy.log"), "yes\n", "$name glob retains when ID");
}
is($t->read_file('outside.log'), "yes\nno\n", 'when context is restored');
is($t->read_file('stream.log'), port(8083) . "\n", 'stream main include');
is($t->read_file('stream-server.log'), '', 'stream server false include');

for my $case (
    ['http', 'return 204;', qr/"return" directive is not allowed here/],
    ['stream', 'return ok;', qr/"return" directive is not allowed here/],
    ['http', 'when selected {}', qr/"when" directive is not allowed here/],
) {
    my ($context, $body, $error) = @$case;
    $t->write_file('invalid.inc', $body);
    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
$context {
    expr selected bool true;
    when selected { include invalid.inc; }
}
EOF
    my $output = $t->dump_config();
    my $status = $?;
    isnt($status, 0, "$context invalid included directive rejected");
    like($output, $error, "$context included directive keeps restrictions");
}

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    expr selected bool false;
    when selected { include absent.inc; }
}
EOF
my $output = $t->dump_config();
like($output, qr/absent\.inc.*failed/, 'false when still loads include at parse time');
