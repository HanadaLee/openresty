#!/usr/bin/perl

# Nameless response cookies use an empty name for all proxy cookie controls.

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my @cases = (
    [bare_named => 'proxy_cookie_value sid ~^$ changed;', 'sid', ['sid']],
    [bare_value => 'proxy_cookie_value "" sid changed;', 'sid', ['changed']],
    [explicit_value => 'proxy_cookie_value "" sid changed;', '=sid', ['=changed']],
    [named_empty => 'proxy_cookie_value sid ~^$ changed;', 'sid=', ['sid=changed']],
    [empty_name_miss => 'proxy_cookie_value "" sid changed;', 'sid=', ['sid=']],
    [bare_regex => 'proxy_cookie_value ~^$ ~^s(.+)$ new-$1;', 'sid', ['new-id']],
    [bare_remove => 'proxy_cookie_value "" sid "";', 'sid', ['=']],
    [flags_name => 'proxy_cookie_flags sid secure;', 'sid', ['sid']],
    [flags_empty => 'proxy_cookie_flags "" secure;', 'sid', ['sid; Secure']],
    [age_name => 'proxy_cookie_max_age sid 1m;', 'sid', ['sid']],
    [age_empty => 'proxy_cookie_max_age "" 1m;', 'sid', ['sid; Max-Age=60']],
    [hide_name => 'proxy_hide_cookie sid;', 'sid', ['sid']],
    [hide_empty => 'proxy_hide_cookie "";', 'sid', []],
    [hide_explicit => 'proxy_hide_cookie "";', '=sid', []],
    [hide_named_empty => 'proxy_hide_cookie "";', 'sid=', ['sid=']],
    [attrs => 'proxy_cookie_path /old /new; proxy_cookie_value "" sid changed; '
        . 'proxy_cookie_flags "" secure; proxy_cookie_max_age "" 1m;',
        'sid; Path=/old', ['changed; Path=/new; Max-Age=60; Secure']],
);
my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite pcre/);
my ($locations, $backend) = ('', '');
for my $case (@cases) {
    my ($name, $rules, $input) = @$case;
    $locations .= "location /$name { $rules proxy_pass http://127.0.0.1:8081; }\n";
    $backend .= "location /$name { add_header Set-Cookie '$input'; return 200 ok; }\n";
}
$t->write_file('locations.conf', $locations);
$t->write_file('backend.conf', $backend);
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        include locations.conf;
    }
    server {
        listen 127.0.0.1:8082;
        proxy_http_version 2;
        include locations.conf;
    }
    server {
        listen 127.0.0.1:8081;
        http2 on;
        include backend.conf;
    }
}
EOF
$t->plan(4 * @cases)->run();
for my $port (8080, 8082) {
    for my $case (@cases) {
        my $response = http_get("/$case->[0]",
            PeerAddr => '127.0.0.1:' . port($port));
        like($response, qr/^HTTP\/1\.[01] 200 /, "$port $case->[0] response");
        my @cookies = $response =~ /^Set-Cookie:[ \t]*(.*?)\r?$/gmi;
        is_deeply(\@cookies, $case->[3], "$port $case->[0]");
    }
}
