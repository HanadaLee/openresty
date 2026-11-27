#!/usr/bin/perl

# Targeted CDN cache policy and independent header/directive overrides.

use warnings;
use strict;
use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite/);
plan skip_all => 'requires nginx extensions' if $t->has_module('--without-ext');

# name, origin response fields in wire order, edge configuration, second lookup
my @cases = (
    ['plain', ['Cache-Control: no-store'], '', 'MISS'],
    ['preferred', ['Cache-Control: no-store', 'CDN-Cache-Control: max-age=50'], '', 'HIT'],
    ['reverse', ['CDN-Cache-Control: max-age=50', 'Cache-Control: no-store'], '', 'HIT'],
    ['deny', ['Cache-Control: max-age=50', 'CDN-Cache-Control: no-store'], '', 'MISS'],
    ['empty', ['Cache-Control: no-store', 'CDN-Cache-Control:'], '', 'MISS'],
    ['blank', ['Cache-Control: no-store', "CDN-Cache-Control: \t"], '', 'MISS'],
    ['empty_then_set', ['Cache-Control: no-store', 'CDN-Cache-Control:', 'CDN-Cache-Control: max-age=60'], '', 'HIT'],
    ['unknown', ['Cache-Control: no-store', 'CDN-Cache-Control: future'], '', 'HIT'],
    ['age', ['Age: 123', 'Cache-Control: no-store'], '', 'MISS'],
    ['duplicate', ['CDN-Cache-Control: max-age=0', 'CDN-Cache-Control: max-age=50'], '', 'HIT'],
    ['ignore_cdn', ['Cache-Control: no-store', 'CDN-Cache-Control: max-age=50'], 'proxy_ignore_headers CDN-Cache-Control;', 'MISS'],
    ['ignore_cc', ['Cache-Control: no-store', 'CDN-Cache-Control: no-store'], 'proxy_ignore_headers Cache-Control;', 'MISS'],
    ['ignore_both', ['Cache-Control: no-store', 'CDN-Cache-Control: no-store'], 'proxy_ignore_headers Cache-Control CDN-Cache-Control;', 'HIT'],
    ['mask', ['Cache-Control: no-store', 'CDN-Cache-Control: s-maxage=0, max-age=50'], 'proxy_ignore_cache_control s-maxage;', 'HIT'],
    ['all_masked', ['Cache-Control: no-store', 'Expires: Thu, 01 Jan 1970 00:00:01 GMT', 'CDN-Cache-Control: no-store'], 'proxy_ignore_cache_control no-store;', 'HIT'],
    ['pragma_cdn', ['Pragma: no-cache', 'CDN-Cache-Control: max-age=50'], '', 'HIT'],
    ['cdn_pragma', ['CDN-Cache-Control: max-age=50', 'Pragma: no-cache'], '', 'HIT'],
    ['pragma_blank_cdn', ['Pragma: no-cache', "CDN-Cache-Control: \t"], '', 'EXPIRED'],
    ['pragma_ignored_cdn', ['CDN-Cache-Control: max-age=50', 'Pragma: no-cache'],
        'proxy_ignore_headers CDN-Cache-Control;', 'EXPIRED'],
    ['pragma_masked_cdn', ['CDN-Cache-Control: no-cache', 'Pragma: no-cache'],
        'proxy_ignore_cache_control no-cache;', 'HIT'],
    ['pragma_after', ['Cache-Control: max-age=50', 'Pragma: no-cache'], '', 'EXPIRED'],
    ['pragma_expires', ['Pragma: no-cache', 'Expires: Tue, 19 Jan 2038 03:14:00 GMT'], '', 'EXPIRED'],
    ['pragma_list', ['Pragma: extension', "Pragma: x,\tNo-CaChE \t, y"], '', 'EXPIRED'],
    ['pragma_other', ['Pragma: x-no-cache, no-cache=1, no-cache-x, "no-cache"'], '', 'HIT'],
    ['pragma_quote', ['Pragma: ext="x, no-cache, y"'], '', 'HIT'],
    ['pragma_ignored', ['Pragma: no-cache'], 'proxy_ignore_headers Pragma;', 'HIT'],
    ['pragma_mask', ['Pragma: no-cache'], 'proxy_ignore_cache_control no-cache;', 'EXPIRED'],
    ['pragma_private', ['Cache-Control: private', 'Pragma: no-cache'], '', 'MISS'],
    ['pragma_cookie', ['Set-Cookie: a=b', 'Pragma: no-cache'], '', 'MISS'],
    ['pragma_accel', ['Pragma: no-cache', 'X-Accel-Expires: 50'], '', 'HIT'],
    ['accel_pragma', ['X-Accel-Expires: 50', 'Pragma: no-cache'], '', 'HIT'],
    ['pragma_accel_zero', ['Pragma: no-cache', 'X-Accel-Expires: 0'], '', 'MISS'],
    ['pragma_same_expiry', ['Expires: Tue, 19 Jan 2038 03:14:07 GMT',
        'X-Accel-Expires: @2147483647', 'Pragma: no-cache'], '', 'HIT'],
    ['pragma_accel_bad', ['Cache-Control: max-age=50', 'X-Accel-Expires: bad', 'Pragma: no-cache'], '', 'EXPIRED'],
    ['pragma_accel_ignored', ['X-Accel-Expires: 50', 'Cache-Control: max-age=50', 'Pragma: no-cache'], 'proxy_ignore_headers X-Accel-Expires;', 'EXPIRED'],
    ['set_cookie_accel', ['Set-Cookie: a=b', 'CDN-Cache-Control: max-age=50', 'X-Accel-Expires: 50'], '', 'MISS'],
    ['underscore', ['Cache-Control: no-store', 'CDN-Cache-Control: max-age=50', 'CDN_Cache_Control: no-store'], '', 'HIT'],
    ['cookie', ['Set-Cookie: a=b', 'CDN-Cache-Control: max-age=50'], '', 'MISS'],
    ['expires', ['Expires: Thu, 01 Jan 1970 00:00:01 GMT', 'CDN-Cache-Control: public'], '', 'HIT'],
    ['accel_first', ['X-Accel-Expires: 60', 'X-Accel-Expires: 0'], '', 'HIT'],
    ['accel_first_zero', ['X-Accel-Expires: 0', 'X-Accel-Expires: 60'], '', 'MISS'],
    ['expires_first', ['Expires: Thu, 01 Jan 1970 00:00:01 GMT',
                       'Expires: Tue, 19 Jan 2038 03:14:00 GMT'], '', 'MISS'],
    ['ordinary_exp', ['Expires: Thu, 01 Jan 1970 00:00:01 GMT'], '', 'MISS'],
    ['list', ['CDN-Cache-Control: private="X-User"'], '', 'MISS'],
);

# These inputs follow the native parser, including its header-order semantics.
# Compare the two names directly instead of prescribing a parser behavior.
my @pairs = (
    ['Cache-Control: max-age=50,'],
    ['Cache-Control: private=?0'],
    ['Cache-Control: x="no-store", max-age=40'],
    ['Cache-Control: max-age=0', 'Cache-Control: max-age=60'],
    ['Cache-Control: max-age=bad', 'X-Accel-Expires: 60'],
    ['X-Accel-Expires: 60', 'Cache-Control: max-age=bad'],
    ['Cache-Control: max-age=60', 'X-Accel-Expires: bad', 'Cache-Control: no-store'],
    ['Pragma: no-cache', 'X-Accel-Expires: 60', 'Cache-Control: private'],
);

# An absolute expiry in the past tests stale reuse without waiting for a timer.
my $expired = 'X-Accel-Expires: @1';
my $recent = 'X-Accel-Expires: @' . (time() - 60);
my @stale = (
    ['cc_first', ['Cache-Control: no-cache', $expired], 503],
    ['cc_last', [$expired, 'Cache-Control: no-cache'], 200],
    ['cc_must_revalidate', [$expired, 'Cache-Control: must-revalidate'], 503],
    ['cdn_proxy_revalidate', [$expired, 'CDN-Cache-Control: proxy-revalidate'], 503],
    ['header_no_stale', [$recent, 'Cache-Control: max-age=60'], 502],
    ['header_stale', [$recent, 'Cache-Control: max-age=60, stale-if-error=86400'], 200],
    ['pragma_first', ['Pragma: no-cache', $expired], 503],
    ['pragma_last', [$expired, 'Pragma: no-cache'], 200],
    ['pragma_both', ['Pragma: no-cache', $expired, 'Pragma: no-cache'], 503],
    ['pragma_late_match', ['Pragma: other', $expired, 'Pragma: no-cache'], 200],
);

my $conditions = '';
if ($t->has_module('ngx_expr_module')) {
    $conditions = 'expr local_test str_eq $host localhost;';
    push @cases,
        ['when_header', ['Cache-Control: no-store', 'CDN-Cache-Control: max-age=60'],
            'when local_test { proxy_ignore_headers CDN-Cache-Control; }', 'MISS'],
        ['when_directive', ['Cache-Control: no-store', 'CDN-Cache-Control: no-store'],
            'when local_test { proxy_ignore_cache_control no-store; }', 'HIT'];
}

$t->plan(2 * @cases + 3 * @pairs + 2 * @stale + 9);
my $edge = '';
my %headers = map { "validate_" . $_->[0] => join("\r\n", @{$_->[1]}) } @stale;
for my $case (@cases) {
    my ($name, $fields, $conf) = @$case;
    $edge .= "location = /$name { $conf proxy_pass http://127.0.0.1:8081; }\n";
    $headers{$name} = join("\r\n", @$fields);
}

for my $i (0 .. $#pairs) {
    my @cdn = @{$pairs[$i]};
    s/^Cache-Control:/CDN-Cache-Control:/ for @cdn;
    $headers{"cc_$i"} = join("\r\n", @{$pairs[$i]});
    $headers{"cdn_$i"} = join("\r\n", @cdn);
}

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    $conditions
    proxy_cache_path %%TESTDIR%%/cache keys_zone=z:1m;
    server {
        listen 127.0.0.1:8080;
        proxy_cache z;
        proxy_cache_valid 200 1m;
        add_header X-Cache \$upstream_cache_status;
        location /validate_header_ {
            proxy_cache_revalidate on;
            proxy_pass http://127.0.0.1:8081;
        }
        location /validate_ {
            proxy_cache_revalidate on;
            proxy_cache_use_stale http_503 updating;
            proxy_pass http://127.0.0.1:8081;
        }
        location / { proxy_pass http://127.0.0.1:8081; }
        $edge
    }
}
EOF
$t->run_daemon(\&origin, port(8081));
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->run();
for my $case (@cases) {
    my ($name, $fields, $conf, $status) = @$case;
    like(http_get("/$name"), qr/^X-Cache: MISS\r?$/mi, "$name first lookup");
    like(http_get("/$name"), qr/^X-Cache: $status\r?$/mi, "$name second lookup");
}
for my $i (0 .. $#pairs) {
    my @status;
    for my $name ("cc_$i", "cdn_$i") {
        like(http_get("/$name"), qr/^X-Cache: MISS\r?$/mi, "$name first lookup");
        push @status, (http_get("/$name") =~ /^X-Cache: (\w+)\r?$/mi);
    }
    ok(@status == 2 && $status[0] eq $status[1], "same cache decision for pair $i")
        or diag(join('; ', @{$pairs[$i]}), ': ', join(' / ', @status));
}
like(http_get('/cdn_pragma'), qr/^Pragma: no-cache\r?$/mi, 'cached response forwards Pragma');
my $r = http_get('/preferred');
like($r, qr/^Cache-Control: no-store\r?$/mi, 'downstream ordinary policy');
like($r, qr/^CDN-Cache-Control: max-age=50\r?$/mi, 'downstream CDN policy');
like(http_get('/age'), qr/^Age: 123\r?$/mi, 'ordinary Age is forwarded');

for my $path (qw/validate_etag validate_error/) {
    like(http_get("/$path"), qr/^X-Cache: MISS\b.*\r\n\r\nok\z/ms,
        "$path stores the initial response");
}
for (1 .. 2) {
    like(http_get('/validate_etag'), qr/^X-Cache: REVALIDATED\b.*\r\n\r\nok\z/ms,
        "reuse after ETag validation $_");
}
like(http_get('/validate_error'), qr{^HTTP/1\.[01] 503 },
    'an origin failure cannot reuse the stale response');

for my $case (@stale) {
    my ($name, $fields, $status) = @$case;
    my $uri = "/validate_$name";
    like(http_get($uri), qr/^X-Cache: MISS\b/m, "$name stores the response");
    my $expected = $status == 200 ? qr/^X-Cache: STALE\b/m : qr{^HTTP/1\.[01] $status };
    like(http_get($uri), $expected, "$name on origin failure");
}

sub origin {
    my ($port) = @_;
    my $server = IO::Socket::INET->new(
        Proto => 'tcp', LocalAddr => '127.0.0.1', LocalPort => $port,
        Listen => 8, ReuseAddr => 1
    ) or die "listen: $!";

    while (my $c = $server->accept()) {
        my $req = <$c>;
        next unless defined $req && $req =~ m{^GET /([^ ]+) };
        my $name = $1;
        my $validated = 0;
        while (<$c>) {
            last if /^\r?\n$/;
            $validated = 1 if /^If-None-Match: "v1"\r?$/i;
        }
        my $fields = $headers{$name};
        if ($name =~ /^validate_/) {
            $fields //= "Pragma: no-cache\r\n"
                     . "Cache-Control: max-age=60, stale-while-revalidate=120, stale-if-error=120";
            $fields = "ETag: \"v1\"\r\n$fields";
            if ($validated) {
                # Exercise stale-if-error on a failed connection.
                next if $name =~ /^validate_header_/;
                my $status = $name eq 'validate_etag' ? '304 Not Modified' : '503 Unavailable';
                print $c "HTTP/1.1 $status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                next;
            }
        }
        print $c "HTTP/1.1 200 OK\r\n$fields\r\nContent-Length: 2\r\n",
                 "Connection: close\r\n\r\nok";
    }
}
