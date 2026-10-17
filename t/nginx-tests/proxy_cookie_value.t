#!/usr/bin/perl

# Tests for proxy cookie value rewriting, including cookies without '='.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite pcre/);

my $attrs = '; Domain=old.example; Path=/old';
my $changed = '; Domain=new.example; Path=/new; Max-Age=60; Secure';
my $attr_rules = <<'EOF';
    proxy_cookie_domain old.example new.example;
    proxy_cookie_path /old /new;
    proxy_cookie_max_age sid 1m;
    proxy_cookie_flags sid secure;
EOF

# name, directives, arguments, expected values for absent/empty/present.

my @cases = (
    [ 'plain_empty', 'proxy_cookie_value sid "" filled;', '',
        [ 'sid=filled', 'sid=filled', 'sid=filledx' ] ],
    [ 'plain_nonempty', 'proxy_cookie_value sid x new;', '',
        [ 'sid', 'sid=', 'sid=new' ] ],
    [ 'regex_empty', 'proxy_cookie_value sid ~^$ filled;', '',
        [ 'sid=filled', 'sid=filled', 'sid=x' ] ],
    [ 'regex_nonempty', 'proxy_cookie_value sid ~^x$ new;', '',
        [ 'sid', 'sid=', 'sid=new' ] ],
    [ 'capture', 'proxy_cookie_value sid ~^(.*)$ pre-$1-post;', '',
        [ 'sid=pre--post', 'sid=pre--post', 'sid=pre-x-post' ] ],
    [ 'named_capture',
        'proxy_cookie_value sid ~^(?<cookie_value>.*)$ pre-$cookie_value-post;',
        '', [ 'sid=pre--post', 'sid=pre--post', 'sid=pre-x-post' ] ],
    [ 'plain_remove', 'proxy_cookie_value sid "" "";', '',
        [ 'sid=', 'sid=', 'sid=x' ] ],
    [ 'regex_remove', 'proxy_cookie_value sid ~^$ "";', '',
        [ 'sid=', 'sid=', 'sid=x' ] ],
    [ 'variable_empty',
        'proxy_cookie_value sid $arg_match $arg_replacement;',
        '?replacement=filled', [ 'sid=filled', 'sid=filled', 'sid=filledx' ] ],
    [ 'variable_nonempty',
        'proxy_cookie_value sid $arg_match $arg_replacement;',
        '?match=x&replacement=new', [ 'sid', 'sid=', 'sid=new' ] ],
    [ 'name_regex', 'proxy_cookie_value ~^sid$ ~^$ filled;', '',
        [ 'sid=filled', 'sid=filled', 'sid=x' ] ],
    [ 'name_miss', 'proxy_cookie_value other ~^$ filled;', '',
        [ 'sid', 'sid=', 'sid=x' ] ],
    [ 'first_name',
        'proxy_cookie_value sid ~^x$ first; proxy_cookie_value sid ~^$ second;',
        '', [ 'sid', 'sid=', 'sid=first' ] ],
    [ 'attrs_miss', 'proxy_cookie_value sid ~^x$ new;' . $attr_rules, '',
        [ 'sid', 'sid=', 'sid=new' ], $changed ],
    [ 'attrs_fill', 'proxy_cookie_value sid ~^$ filled;' . $attr_rules, '',
        [ 'sid=filled', 'sid=filled', 'sid=x' ], $changed ],
    [ 'attrs_only', $attr_rules, '',
        [ 'sid', 'sid=', 'sid=x' ], $changed ],
);

my $locations = '';

for my $case (@cases) {
    my ($name, $rules) = @$case;

    $locations .= <<EOF;
    location /$name/ {
        proxy_pass http://127.0.0.1:8081/;
        $rules
    }
EOF
}

$t->write_file_expand('locations.conf', $locations);
$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_http_version 1.1;
        include locations.conf;
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        proxy_http_version 2;
        include locations.conf;
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        http2 on;

        location = /absent {
            add_header Set-Cookie "sid; Domain=old.example; Path=/old";
            return 200 ok;
        }

        location = /empty {
            add_header Set-Cookie "sid=; Domain=old.example; Path=/old";
            return 200 ok;
        }

        location = /present {
            add_header Set-Cookie "sid=x; Domain=old.example; Path=/old";
            return 200 ok;
        }

        location = /multiple {
            add_header Set-Cookie sid;
            add_header Set-Cookie sid=;
            add_header Set-Cookie sid=x;
            add_header Set-Cookie other;
            return 200 ok;
        }
    }
}

EOF

$t->plan(scalar(@cases) * 3 * 2 * 2 + 4)->run();

###############################################################################

my @inputs = qw/absent empty present/;

for my $backend ([ 8080, 'HTTP/1.1' ], [ 8082, 'HTTP/2' ]) {
    my ($port, $protocol) = @$backend;

    for my $case (@cases) {
        my ($name, $rules, $args, $expected, $suffix) = @$case;
        $suffix = $attrs unless defined $suffix;

        for my $i (0 .. $#inputs) {
            my $label = "$protocol $name $inputs[$i]";
            my $response = http_get("/$name/$inputs[$i]$args",
                PeerAddr => '127.0.0.1:' . port($port));

            like($response, qr/^HTTP\/1\.[01] 200 /, "$label response");
            my @cookies = $response =~ /^Set-Cookie:[ \t]*(.*?)\r?$/gmi;
            is_deeply(\@cookies, [ $expected->[$i] . $suffix ], $label);
        }
    }

    my $response = http_get('/regex_empty/multiple',
        PeerAddr => '127.0.0.1:' . port($port));

    like($response, qr/^HTTP\/1\.[01] 200 /, "$protocol multiple response");
    my @cookies = $response =~ /^Set-Cookie:[ \t]*(.*?)\r?$/gmi;
    is_deeply(\@cookies, [ 'sid=filled', 'sid=filled', 'sid=x', 'other' ],
        "$protocol independent cookie values");
}

###############################################################################
