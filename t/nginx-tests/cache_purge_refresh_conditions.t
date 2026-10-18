#!/usr/bin/perl

# REFRESH profiles must validate the effective conditional proxy settings.

use warnings;
use strict;

use Test::More;
use JSON::PP qw/decode_json/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @cases = (
    { name => 'default' },
    { name => 'literal', method => 'proxy_method HEAD;' },
    { name => 'variable', method => 'proxy_method $refresh_method;' },
    { name => 'get', method => 'proxy_method GET;', rejected => 1 },
    { name => 'empty', method => 'proxy_method "";', rejected => 1 },
    { name => 'variable-get', method => 'proxy_method $refresh_method;',
      variable => 'GET', rejected => 1 },
    { name => 'method-match', mode => 'active',
      method => 'when active { proxy_method HEAD; } proxy_method GET;' },
    { name => 'method-fallback', rejected => 1,
      method => 'when active { proxy_method HEAD; } proxy_method GET;' },
    { name => 'method-miss', method => 'when active { proxy_method GET; }' },
    { name => 'inherited', parent => 'proxy_method HEAD;',
      method => 'when active { proxy_method GET; }' },
    { name => 'inherited-match', parent => 'proxy_method HEAD;',
      method => 'when active { proxy_method GET; }',
      mode => 'active', rejected => 1 },
    { name => 'headers-on', mode => 'active', rejected => 1,
      headers => 'when active { proxy_pass_request_headers on; }'
                 . ' proxy_pass_request_headers off;' },
    { name => 'headers-off', mode => 'active',
      headers => 'when active { proxy_pass_request_headers off; }'
                 . ' proxy_pass_request_headers on;' },
    { name => 'headers-miss',
      headers => 'when active { proxy_pass_request_headers on; }'
                 . ' proxy_pass_request_headers off;' },
    { name => 'body-on', mode => 'active', rejected => 1,
      body => 'when active { proxy_pass_request_body on; }'
              . ' proxy_pass_request_body off;' },
    { name => 'body-off', mode => 'active',
      body => 'when active { proxy_pass_request_body off; }'
              . ' proxy_pass_request_body on;' },
    { name => 'body-miss',
      body => 'when active { proxy_pass_request_body on; }'
              . ' proxy_pass_request_body off;' },
    { name => 'flags-inherited',
      parent => 'proxy_pass_request_headers off; proxy_pass_request_body off;',
      headers => 'when active { proxy_pass_request_headers on; }',
      body => 'when active { proxy_pass_request_body on; }' },
);

my $t = Test::Nginx->new()
    ->has(qw/http proxy cache ngx_expr_module ngx_http_cache_purge_module/)
    ->plan(7 * scalar @cases);

my $locations = '';
for my $case (@cases) {
    my $name = $case->{name};
    my $method = $case->{method} // '';
    my $headers = $case->{headers} // 'proxy_pass_request_headers off;';
    my $body = $case->{body} // 'proxy_pass_request_body off;';
    my $probe = "/probe-$name";
    $probe = "/$name/probe" if $case->{parent};

    $locations .= <<EOF;
        location = /refresh-$name {
            cache_purge_key objects /cache/$name;
            proxy_cache_refresh NAME \$cache_purge_key;
            cache_purge_refresh_profile $probe /cache;
        }
EOF
    $locations .= "location /$name/ { $case->{parent}\n" if $case->{parent};
    $locations .= <<EOF;
        location = $probe {
            internal;
            proxy_cache off;
            proxy_cache_purge off;
            proxy_intercept_errors off;
            $method
            $headers
            $body
            proxy_set_header Host origin.test;
            proxy_set_header If-None-Match \$cache_purge_refresh_etag;
            proxy_set_header If-Modified-Since \$cache_purge_refresh_last_modified;
            proxy_pass http://127.0.0.1:8081/origin\$cache_purge_refresh_uri;
        }
EOF
    $locations .= "}\n" if $case->{parent};
}

my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache levels=1:2 keys_zone=NAME:1m;
    cache_purge_namespace objects 1m %%TESTDIR%%/purge-state;
    cache_purge_key objects $uri;

    map $http_x_method $refresh_method {
        default HEAD;
        GET     GET;
    }

    log_format probe '$request_method $uri "$http_x_leak"';

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        expr active str_in $http_x_mode active;

        location /cache/ {
            proxy_cache NAME;
            proxy_cache_key $cache_purge_key;
            proxy_cache_valid 200 1h;
            proxy_set_header Host origin.test;
            proxy_pass http://127.0.0.1:8081/origin/;
            add_header X-Cache $upstream_cache_status always;
        }

        %%LOCATIONS%%
    }

    server {
        listen 127.0.0.1:8081;
        server_name origin.test;
        access_log %%TESTDIR%%/origin.log probe;
        root %%TESTDIR%%;
    }
}
EOF

$config =~ s/%%LOCATIONS%%/$locations/;
$t->write_file_expand('nginx.conf', $config);
mkdir $t->testdir() . '/origin';
for my $case (@cases) {
    $t->write_file('origin/' . $case->{name}, "cached body\n");
}

$t->run();

for my $case (@cases) {
    my $name = $case->{name};
    my $mode = $case->{mode} // 'inactive';
    my $method = $case->{variable} // 'HEAD';

    like(http_get("/cache/$name"), qr/200 OK/, "$name: warm cache");
    like(http_get("/cache/$name"), qr/X-Cache: HIT/i,
        "$name: cache candidate is available");

    my $response = http(<<EOF);
REFRESH /refresh-$name HTTP/1.0
Host: localhost
X-Mode: $mode
X-Method: $method
X-Leak: private-client-header

EOF
    like($response, qr/200 OK/, "$name: refresh completed");
    my ($body) = $response =~ /\x0d\x0a\x0d\x0a(.*)/s;
    my $result = eval { decode_json($body // '') };
    diag($@ || $response) if !$result;
    my $results = $result ? ($result->{results} // []) : [];
    is(scalar @$results, 1, "$name: checked one cached object");
    is($results->[0] ? $results->[0]{result} : undef,
        $case->{rejected} ? 'skipped_profile' : 'kept',
        "$name: effective settings determine profile safety");
    like(http_get("/cache/$name"), qr/X-Cache: HIT/i,
        "$name: cached object retained");
}

$t->stop();

my $origin_log = $t->read_file('origin.log');
for my $case (@cases) {
    my $name = $case->{name};
    my @requests = $origin_log =~ /^(\S+ \/origin\/\Q$name\E "[^"]*")$/mg;
    my @expected = (qq{GET /origin/$name "-"});
    push @expected, qq{HEAD /origin/$name "-"} unless $case->{rejected};
    is_deeply(\@requests, \@expected,
        "$name: only safe HEAD probes reach origin without client headers");
}
