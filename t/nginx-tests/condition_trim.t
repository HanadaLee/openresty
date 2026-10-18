#!/usr/bin/perl

# Literal trim switches, conditional selection, and per-switch inheritance.

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my $raw = '<p>hello   world</p><!-- html -->'
    . '<script>/* js */var x=  1;</script>'
    . '<style>/* css */p { color: red; }</style>'
    . '<pre>a   b</pre><textarea>c   d</textarea>';

# Each expected mask is trim/trim_js/trim_css.  JS and CSS never enable HTML
# filtering by themselves.  Every response is compared in full.
my @cases = (
    ['default', '', [['', '000'], ['h=1', '111'], ['s=1', '111']]],
    ['fixed', 'trim on; trim_js on; trim_css on;', [['', '111']]],
    ['off', 'trim off; trim_js off; trim_css off;', [['h=1&s=1', '000']]],
    ['html', 'trim on;', [['', '100']]],
    ['js', 'trim on; trim_js on;', [['', '110']]],
    ['css', 'trim on; trim_css on;', [['', '101']]],
    ['js_css_only', 'trim_js on; trim_css on;', [['', '011']]],
    ['conditional', 'when a { trim on; trim_js on; trim_css on; }',
        [['', '000'], ['a=1', '111'], ['h=1', '111']]],
    ['disable', 'when a { trim off; trim_js off; trim_css off; }',
        [['a=1&h=1', '000'], ['a=0&h=1', '111'], ['a=0', '000']]],
    ['independent', 'trim on; when a { trim_js on; }'
        . ' when b { trim_css on; }',
        [['', '100'], ['a=1', '110'], ['b=1', '101'], ['a=1&b=1', '111']]],
    ['first', 'when a { trim off; } when b { trim on; }',
        [['a=1&b=1', '000'], ['b=1', '100'], ['', '000']]],
    ['fallback', 'when a { trim on; } trim off;',
        [['a=1', '100'], ['h=1', '000']]],
    ['unconditional_first', 'trim off; when a { trim on; }',
        [['a=1', '000']]],
    ['negation', 'when !a { trim on; }', [['', '100'], ['a=1', '000']]],
    ['conjunction', 'when a !b { trim on; }',
        [['a=1', '100'], ['a=1&b=1', '000'], ['', '000']]],
    ['combined', 'when a { trim on; trim_js on; trim_css on; }',
        [['a=1', '111'], ['', '000']]],
    ['split', 'when a { trim on; } when a { trim_js on; }'
        . ' when a { trim_css on; }', [['a=1', '111'], ['', '000']]],
    ['included', 'when a { include switches.inc; }',
        [['a=1', '111'], ['', '000']]],
    ['redefined', 'expr a str_eq $arg_b 1; when a { trim on; }',
        [['a=1', '000'], ['b=1', '100']]],
    ['inherited_expr', 'expr h str_eq $arg_b 1;',
        [['h=1', '000'], ['b=1', '111']]],
    ['case_insensitive', 'trim ON; trim_js On; trim_css oN;', [['', '111']]],
);

my @parent_cases = (
    ['inherit', '', [['', '111']]],
    ['disable_html', 'when a { trim off; }',
        [['a=1', '000'], ['', '111']]],
    ['disable_js', 'when a { trim_js off; }',
        [['a=1', '101'], ['', '111']]],
    ['disable_css', 'when a { trim_css off; }',
        [['a=1', '110'], ['', '111']]],
    ['fixed_children', 'trim_js off; trim_css off;', [['', '100']]],
);

my $requests = 0;
$requests += @{$_->[2]} for (@cases, @parent_cases);
my $t = Test::Nginx->new()->has(qw/http rewrite proxy trim_filter
    ngx_expr_module/)->plan($requests * 2 + 18);

my $locations = locations(\@cases);
my $parent_locations = locations(\@parent_cases);
$t->write_file('switches.inc', 'trim on; trim_js on; trim_css on;');
$t->write_file('body.html', $raw);
$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    default_type text/html;
    log_format sizes '\$uri|\$trim_bytes|\$trim_original_bytes';
    expr a str_eq \$arg_a 1;
    expr b str_eq \$arg_b 1;
    expr h str_eq \$arg_h 1;
    expr s str_eq \$arg_s 1;
    when h { trim on; trim_js on; trim_css on; }
    server {
        listen 127.0.0.1:8080;
        when s { trim on; trim_js on; trim_css on; }
        $locations
        location /plain {
            default_type text/plain;
            trim on;
            return 200 '$raw';
        }
        location /plain_enabled {
            default_type text/plain;
            trim_types text/plain;
            trim on;
            return 200 '$raw';
        }
        location /encoded {
            trim on;
            proxy_pass http://127.0.0.1:8082;
        }
        location /error { trim on; return 404 '$raw'; }
        location /empty { trim on; return 200 ''; }
        location /file {
            alias %%TESTDIR%%/body.html;
            trim on;
            sendfile on;
            access_log %%TESTDIR%%/sizes.log sizes;
        }
        location /proxy {
            trim on;
            trim_js on;
            trim_css on;
            proxy_buffering off;
            proxy_pass http://127.0.0.1:8082;
        }
    }
    server {
        listen 127.0.0.1:8081;
        trim on;
        trim_js on;
        trim_css on;
        $parent_locations
        location /nested/ {
            when a { trim_js off; }
            location /nested/child {
                when b { trim_css off; }
                return 200 '$raw';
            }
        }
    }
    server {
        listen 127.0.0.1:8082;
        trim off;
        location / { return 200 '$raw'; }
        location /encoded {
            add_header Content-Encoding gzip;
            return 200 '$raw';
        }
    }
}
EOF

$t->run();
for my $group ([8080, \@cases], [8081, \@parent_cases]) {
    my ($listen, $specs) = @$group;
    for my $case (@$specs) {
        my ($name, undef, $queries) = @$case;
        for my $query (@$queries) {
            my ($args, $mask) = @$query;
            my $response = get("/$name?$args", $listen);
            like($response, qr/^HTTP\/1\.1 200 /, "$name $args status");
            is(body($response), expected($mask), "$name $args body");
        }
    }
}

for my $case (['', '111'], ['a=1', '101'], ['b=1', '110'], ['a=1&b=1', '100']) {
    is(body(get('/nested/child?' . $case->[0], 8081)), expected($case->[1]),
        'nested per-switch inheritance ' . $case->[0]);
}
is(body(get('/fixed?http_trim=off')), $raw, 'query bypass is preserved');
is(body(get('/fixed?http_trim=on')), expected('111'), 'query on does not bypass');
is(body(get('/off?http_trim=on')), $raw, 'query on does not enable trim');
is(body(get('/plain')), $raw, 'unlisted content type bypasses trim');
is(body(get('/plain_enabled')), expected('100'), 'trim_types still adds MIME types');
is(body(get('/encoded')), $raw, 'encoded response bypasses trim');
my $error = get('/error');
like($error, qr/^HTTP\/1\.1 404 /, 'error status preserved');
is(body($error), $raw, 'non-200 bypasses trim');
is(body(get('/empty')), '', 'empty response');
is(body(http("HEAD /fixed HTTP/1.0\r\nHost: localhost\r\n\r\n")), '', 'HEAD response');
is(body(get('/file')), expected('100'), 'static sendfile response');
is(body(get('/proxy')), expected('111'), 'unbuffered proxy response');
is(body(get('/conditional?a=1')), expected('111'), 'hit after a miss in same worker');
$t->stop();
is($t->read_file('sizes.log'), '/file|' . (length($raw) - length(expected('100'))) . '|'
    . length($raw) . "\n", 'trim statistics remain available');

undef $t;

sub locations {
    my ($specs) = @_;
    return join "\n", map {
        "location /$_->[0] { $_->[1] return 200 '$raw'; }"
    } @$specs;
}

sub get {
    my ($uri, $listen) = @_;
    return http("GET $uri HTTP/1.0\r\nHost: localhost\r\n\r\n",
        PeerAddr => '127.0.0.1:' . port($listen || 8080));
}

sub body {
    my ($response) = @_;
    return (split /\r\n\r\n/, $response, 2)[1] // '';
}

sub expected {
    my ($mask) = @_;
    return $raw unless substr($mask, 0, 1);
    return '<p>hello world</p><script>'
        . (substr($mask, 1, 1) ? 'var x=1;' : '/* js */var x=  1;')
        . '</script><style>'
        . (substr($mask, 2, 1) ? 'p{color:red;}' : '/* css */p { color: red; }')
        . '</style><pre>a   b</pre><textarea>c   d</textarea>';
}
