#!/usr/bin/perl

# Standard if= remains available with expr; when and if= are ANDed.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @cases = (
    ['hit', '1', 1],
    ['hit', '0', 0],
    ['hit', '', 0],
    ['miss', '1', 1],
    ['hit', '00', 1],
    ['hit', 'false', 1],
);
my $t = Test::Nginx->new()->has(qw/http proxy rewrite stream stream_return
    ngx_expr_module/)->plan(25);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    log_format values '$arg_mode|$arg_gate';
    expr selected str_eq $arg_mode hit;

    server {
        listen 127.0.0.1:8080;
        access_log %%TESTDIR%%/access-plain.log values if=$arg_gate;
        when selected {
            access_log %%TESTDIR%%/access-when.log values if=$arg_gate;
        }
        location / { proxy_pass http://127.0.0.1:8081; }
    }
    server {
        listen 127.0.0.1:8081;
        access_log off;
        return 200 ok;
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    log_format values '$server_port';
    expr selected bool true;
    expr missed bool false;
    server {
        listen 127.0.0.1:8082;
        access_log %%TESTDIR%%/stream-plain.log values if=1;
        when selected {
            access_log %%TESTDIR%%/stream-hit.log values if=1;
            access_log %%TESTDIR%%/stream-zero.log values if=0;
            access_log %%TESTDIR%%/stream-empty.log values if=;
            access_log %%TESTDIR%%/stream-nonzero.log values if=00;
        }
        when missed {
            access_log %%TESTDIR%%/stream-miss.log values if=1;
        }
        return ok;
    }
}
EOF

$t->run();
my ($plain, $combined) = ('', '');
for my $case (@cases) {
    my ($mode, $gate, $enabled) = @$case;
    like(http_get("/?mode=$mode&gate=$gate"), qr/^HTTP\/1\.1 200 /,
        "HTTP mode=$mode gate=$gate");
    $plain .= "$mode|$gate\n" if $enabled;
    $combined .= "$mode|$gate\n" if $enabled && $mode eq 'hit';
}
is(stream('127.0.0.1:' . port(8082))->read(), 'ok', 'Stream if= session');
$t->stop();

is($t->read_file('access-plain.log'), $plain, 'access standard truth values');
is($t->read_file('access-when.log'), $combined, 'access when AND if=');
for my $name (qw/plain hit nonzero/) {
    is($t->read_file("stream-$name.log"), port(8082) . "\n", "Stream $name logs");
}
for my $name (qw/zero empty miss/) {
    is($t->read_file("stream-$name.log"), '', "Stream $name skips logging");
}

# Check both ordinary and when contexts. Do not accept if!= syntax.
for my $spec (
    ['http', 'access_log', '%%TESTDIR%%/invalid.log combined'],
    ['stream', 'access_log', '%%TESTDIR%%/invalid.log values'],
) {
    my ($context, $directive, $arguments) = @$spec;
    for my $wrapped (0, 1) {
        my $line = "$directive $arguments if!=1;";
        $line = "when selected { $line }" if $wrapped;
        my $format = "log_format values '\$remote_addr';";
        $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
$context {
    $format
    expr selected bool true;
    $line
}
EOF
        my $output = $t->dump_config();
        my $status = $?;
        isnt($status, 0, "$context $directive if!= rejected, when=$wrapped");
        like($output, qr/invalid parameter "if!=1"/,
            "$context $directive reports unsupported parameter");
    }
}

# Standard if= must also remain accepted when no when block is configured.
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    log_format values '$remote_addr';
    access_log %%TESTDIR%%/only-if.log combined if=1;
}
stream {
    log_format values '$remote_addr';
    access_log %%TESTDIR%%/only-stream-if.log values if=1;
}
EOF
my $output = $t->dump_config();
is($?, 0, 'if= configuration without any when is accepted');
unlike($output, qr/\[emerg\]/, 'if= does not require a when definition');
