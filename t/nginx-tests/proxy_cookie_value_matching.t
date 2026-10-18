#!/usr/bin/perl

# Cookie value rules match both name and value; no expr module is required.

use warnings;
use strict;
use Test::More;
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(12);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    proxy_cookie_value sid ~.* parent;
    server {
        listen 127.0.0.1:8080;
        location /literal {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_value sid absent wrong;
            proxy_cookie_value sid old new;
        }
        location /regex {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_value ~^sid$ ~^absent$ wrong;
            proxy_cookie_value ~^sid$ ~^ol(d)$ $1;
        }
        location /name-miss {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_value other ~.* wrong;
            proxy_cookie_value sid old new;
        }
        location /case {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_value SID ~^absent$ wrong;
            proxy_cookie_value SID ~^old$ new;
        }
        location /miss {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_value sid ~^absent$ wrong;
            proxy_cookie_value sid ~^missing$ wrong;
        }
        location /no-cascade {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_value sid old first;
            proxy_cookie_value sid first second;
        }
        location /empty {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_value sid ~^absent$ wrong;
            proxy_cookie_value sid ~^$ filled;
        }
        location /off {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_value off;
        }
        location /inherit {
            proxy_pass http://127.0.0.1:8081;
        }
    }
    server {
        listen 127.0.0.1:8081;
        add_header Set-Cookie "sid=$http_x_value; Path=/; HttpOnly" always;
        add_header Set-Cookie "other=keep; Path=/" always;
        return 200 ok;
    }
}
EOF

$t->run();
for my $case (
    ['literal', 'old', 'new'],
    ['literal', 'old-tail', 'new-tail'],
    ['regex', 'old', 'd'],
    ['regex', 'old-tail', 'old-tail'],
    ['name-miss', 'old', 'new'],
    ['case', 'old', 'new'],
    ['miss', 'old', 'old'],
    ['no-cascade', 'old', 'first'],
    ['empty', '', 'filled'],
    ['off', 'old', 'old'],
    ['inherit', 'old', 'parent'],
) {
    my ($path, $value, $expected) = @$case;
    my $response = http("GET /$path HTTP/1.0\r\nX-Value: $value\r\n\r\n");
    like($response, qr/^Set-Cookie: sid=\Q$expected\E; Path=\/; HttpOnly\r?$/mi,
        "$path value=$value");
}
my $response = http("GET /literal HTTP/1.0\r\nX-Value: old\r\n\r\n");
like($response, qr/^Set-Cookie: other=keep; Path=\/\r?$/mi,
    'non-matching Cookie stays intact');
$t->stop();
