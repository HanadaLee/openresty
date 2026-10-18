#!/usr/bin/perl

# Implicit proxy_redirect defaults after conditional inheritance.

use warnings;
use strict;
use Test::More;
use Test::Nginx;

my @variants = (
    ['none', 'none'],
    ['http', 'match'], ['server', 'match'],
    ['http', 'miss'], ['server', 'miss'],
    ['http', 'off'], ['server', 'off'],
);
my %rules = (
    match => 'when p { proxy_redirect ~^http://.* http://parent.test/item; }',
    miss => 'when p { proxy_redirect http://absent.test/ /unused/; }',
    off => 'when p { proxy_redirect off; }',
    none => '',
);

# Path, local condition, parent condition, expected rule.
my @cases = (
    ['default', 0, 0, 'default'],
    ['conditional', 0, 0, 'default'],
    ['conditional', 1, 0, 'upstream'],
    ['explicit', 1, 0, 'default'],
    ['explicit', 0, 0, 'default'],
    ['off', 1, 0, 'upstream'],
    ['off', 0, 0, 'default'],
    ['default', 0, 1, 'parent'],
    ['conditional', 0, 1, 'parent'],
    ['conditional', 1, 1, 'upstream'],
    ['explicit', 1, 1, 'default'],
    ['explicit', 0, 1, 'parent'],
    ['off', 1, 1, 'upstream'],
    ['always', 0, 0, 'upstream'],
    ['always-off', 0, 0, 'upstream'],
    ['nested/child', 0, 0, 'default'],
    ['nested/child', 0, 1, 'parent'],
    ['sibling', 0, 0, 'default'],
    ['default', 0, 0, 'default'],
    ['variable', 0, 0, 'upstream'],
    ['variable', 0, 1, 'variable-parent'],
);

plan tests => scalar(@variants) * (2 * scalar(@cases) * 4 + 2);

for my $variant (@variants) {
    my ($scope, $mode) = @$variant;
    my $t = Test::Nginx->new()
        ->has(qw/http http_v2 proxy rewrite ngx_expr_module/);
    my $http_rule = $scope eq 'http' ? $rules{$mode} : '';
    my $server_rule = $scope eq 'server' ? $rules{$mode} : '';
    my $locations = '';

    for my $version ('1.1', '2') {
        my $prefix = $version eq '2' ? 'h2' : 'h1';
        $locations .= "
        location /$prefix/ {
            proxy_http_version $version;
            location /$prefix/default/ {
                proxy_pass http://127.0.0.1:8081/base/;
            }
            location /$prefix/conditional/ {
                proxy_pass http://127.0.0.1:8081/base/;
                when a { proxy_redirect http://absent.test/ /unused/; }
            }
            location /$prefix/explicit/ {
                proxy_pass http://127.0.0.1:8081/base/;
                when a { proxy_redirect default; }
            }
            location /$prefix/off/ {
                proxy_pass http://127.0.0.1:8081/base/;
                when a { proxy_redirect off; }
            }
            location /$prefix/always/ {
                proxy_pass http://127.0.0.1:8081/base/;
                proxy_redirect http://absent.test/ /unused/;
            }
            location /$prefix/always-off/ {
                proxy_pass http://127.0.0.1:8081/base/;
                proxy_redirect off;
            }
            location /$prefix/nested/ {
                location /$prefix/nested/child/ {
                    proxy_pass http://127.0.0.1:8081/base/;
                    when a { proxy_redirect http://absent.test/ /unused/; }
                }
            }
            location /$prefix/sibling/ {
                proxy_pass http://127.0.0.1:8081/other/;
            }
            location /$prefix/variable/ {
                set \$backend http://127.0.0.1:8081;
                proxy_pass \$backend/base/;
            }
        }\n";
    }

    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr a str_eq \$http_x_a 1;
    expr p str_eq \$http_x_p 1;
    $http_rule
    server {
        listen 127.0.0.1:8080;
        absolute_redirect off;
        $server_rule
        $locations
    }
    server {
        listen 127.0.0.1:8081;
        http2 on;
        add_header X-Protocol \$server_protocol always;
        add_header Location \$http_x_location always;
        add_header Refresh "0; url=\$http_x_location" always;
        return 200 ok;
    }
}
EOF
    $t->run();

    for my $version ('1.1', '2') {
        my $prefix = $version eq '2' ? 'h2' : 'h1';
        my $protocol = $version eq '2' ? 'HTTP/2.0' : 'HTTP/1.1';

        for my $case (@cases) {
            my ($path, $a, $p, $rule) = @$case;
            my $base = $path eq 'sibling' ? 'other' : 'base';
            my $upstream = 'http://127.0.0.1:' . port(8081) . "/$base/item";
            my $want = $upstream;

            if ($rule eq 'default'
                || ($rule eq 'parent' && $scope eq 'none'))
            {
                $want = "/$prefix/$path/item";

            } elsif (($rule eq 'parent' || $rule eq 'variable-parent')
                     && $mode eq 'match')
            {
                $want = 'http://parent.test/item';
            }

            my $response = http("GET /$prefix/$path/item HTTP/1.0\r\n"
                . "Host: localhost\r\nX-A: $a\r\nX-P: $p\r\n"
                . "X-Location: $upstream\r\n\r\n");
            my $label = "$scope $mode $prefix/$path a=$a p=$p";

            like($response, qr/^HTTP\/1\.[01] 200 /, "$label status");
            is(header($response, 'X-Protocol'), $protocol, "$label protocol");
            is(header($response, 'Location'), $want, "$label Location");
            is(header($response, 'Refresh'), "0; url=$want", "$label Refresh");
        }
    }

    $t->stop();
}

sub header {
    my ($response, $name) = @_;
    my ($value) = $response =~ /^\Q$name\E: (.*?)\r?$/mi;
    return $value;
}
