#!/usr/bin/perl

# Ordered conditional proxy rewrites, including off, inheritance and defaults.

use warnings;
use strict;
use Test::More;
use Test::Nginx;
use Time::Local qw/timegm/;

my @kinds = qw/redirect domain path flags value max_age/;
my %directive = map { $_ => 'proxy_cookie_' . $_ } @kinds;
$directive{redirect} = 'proxy_redirect';
my %flags = (a => 'httponly', b => 'secure', c => 'samesite=strict',
    parent => 'secure httponly', server => 'samesite=lax',
    always => 'samesite=none');
my %age = (a => 101, b => 202, c => 303, parent => 404,
    server => 505, always => 606);

my $t = Test::Nginx->new()
    ->has(qw/http http_v2 proxy rewrite cache ngx_expr_module/);
my ($global, $servers) = ('', '');
my @checks;

for my $kind (@kinds) {
    my $d = $directive{$kind};
    $global .= 'when p { ' . rule($kind, '*', 'parent') . " }\n";
    my $locations = '';
    for my $version ('1.1', '2') {
        my $prefix = $version eq '2' ? 'h2' : 'h1';
        my $a1 = rule($kind, 'first', 'a');
        my $a2 = rule($kind, 'second', 'c');
        my $b1 = rule($kind, 'second', 'b');
        my $third = rule($kind, 'third', 'b');
        my $always = rule($kind, 'second', 'always');
        my $all = rule($kind, '*', 'a');
        my %config = (
            combined => "when a { $a1 $a2 } when b { $third }",
            split => "when a { $a1 } when a { $a2 } when b { $third }",
            included => "when a { $a1 include $kind.inc; } when b { $third }",
            ordered => "when a { $a1 } when b { $b1 } when a { $a2 }",
            unconditional => "when a { $a1 } $always when a { $a2 }",
            middle_off => "when a { $a1 } when b { $d off; } when c { $a2 }",
            first_off => "when b { $d off; } when a { $a2 }",
            last_off => "when a { $all } when b { $d off; }",
            fallback_off => "when a { $a2 } $d off;",
            miss => "when a { $a1 }",
            inherit => '',
            late => "proxy_set_header X-Early \$policy; when late { $a2 } $d off;",
            early => "proxy_set_header X-Early \$policy; when early { $a2 } $d off;",
            cache => "when a { $a1 } when b { $b1 } when a { $a2 }",
        );
        $t->write_file("$kind.inc", $a2);
        for my $name (sort keys %config) {
            my $cache = $name eq 'cache' ? q{
                proxy_cache rewrites;
                proxy_cache_key "$host$uri";
                proxy_cache_valid 200 1m;
                proxy_ignore_headers Set-Cookie;
                add_header X-Cache $upstream_cache_status always;
            } : '';
            $locations .= "location /$prefix/$name {
                proxy_http_version $version;
                proxy_pass http://127.0.0.1:8081;
                $cache
                $config{$name}
            }\n";
        }
        $locations .= "location /$prefix/nested/ {
            when b { $b1 }
            location /$prefix/nested/child {
                proxy_http_version $version;
                proxy_pass http://127.0.0.1:8081;
                when a { $a1 }
            }
        }\n";
        $locations .= "location /$prefix/parent_off/ {
            $d off;
            location /$prefix/parent_off/child {
                proxy_http_version $version;
                proxy_pass http://127.0.0.1:8081;
                when a { $a2 }
            }
        }\n";
        $locations .= "location /$prefix/retry {
            proxy_http_version $version;
            proxy_pass http://retry_backend;
            proxy_next_upstream http_503;
            proxy_next_upstream_tries 2;
            add_header X-Attempts \$upstream_status always;
            when late { $a2 }
            $d off;
        }
        location /$prefix/redirected {
            proxy_http_version $version;
            proxy_pass http://127.0.0.1:8082;
            proxy_intercept_errors on;
            error_page 503 = \@$prefix;
            when early { $all }
            $d off;
        }
        location \@$prefix {
            proxy_http_version $version;
            proxy_pass http://127.0.0.1:8081;
            when late { $a2 }
            $d off;
        }\n";

        # A/B truth table and combined/split/include equivalence.
        for my $layout (qw/combined split included ordered/) {
            for my $a (0, 1) {
                for my $b (0, 1) {
                    for my $target (qw/first second third/) {
                        my $want = '_';
                        if (!$a && !$b) {
                            $want = 'parent';
                        } elsif ($target eq 'first' && $a) {
                            $want = 'a';
                        } elsif ($target eq 'second') {
                            $want = $layout eq 'ordered' && $b ? 'b'
                                : $a ? 'c' : '_';
                        } elsif ($target eq 'third' && $b && $layout ne 'ordered') {
                            $want = 'b';
                        }
                        push @checks, [$kind, "$prefix/$layout", $target,
                            $a, $b, 0, 0, 1, $want];
                    }
                }
            }
        }
        # path, target, A, B, C, server condition, parent condition, result
        for my $case (
            ['unconditional', 'second', 1, 1, 0, 1, 1, 'always'],
            ['unconditional', 'first', 0, 0, 0, 1, 1, '_'],
            ['middle_off', 'first', 1, 1, 1, 1, 1, 'a'],
            ['middle_off', 'second', 1, 1, 1, 1, 1, '_'],
            ['middle_off', 'second', 1, 0, 1, 1, 1, 'c'],
            ['middle_off', 'second', 0, 0, 0, 0, 1, 'parent'],
            ['first_off', 'second', 1, 1, 0, 1, 1, '_'],
            ['first_off', 'second', 1, 0, 0, 1, 1, 'c'],
            ['last_off', 'second', 1, 1, 0, 1, 1, 'a'],
            ['last_off', 'second', 0, 1, 0, 1, 1, '_'],
            ['fallback_off', 'second', 1, 0, 0, 1, 1, 'c'],
            ['fallback_off', 'second', 0, 0, 0, 1, 1, '_'],
            ['miss', 'second', 1, 0, 0, 1, 1, '_'],
            ['miss', 'second', 0, 0, 0, 1, 1, 'server'],
            ['inherit', 'second', 0, 0, 0, 0, 1, 'parent'],
            ['inherit', 'second', 0, 0, 0, 1, 1, 'server'],
            ['inherit', 'second', 0, 0, 0, 0, 0, '_'],
            ['nested/child', 'second', 0, 1, 0, 1, 1, 'b'],
            ['nested/child', 'second', 1, 1, 0, 1, 1, '_'],
            ['nested/child', 'second', 0, 0, 0, 0, 1, 'parent'],
            ['parent_off/child', 'second', 0, 0, 0, 1, 1, '_'],
            ['parent_off/child', 'second', 1, 0, 0, 1, 1, 'c'],
            ['late', 'second', 0, 0, 0, 0, 0, 'c'],
            ['early', 'second', 0, 0, 0, 0, 0, '_'],
            ['retry', 'second', 0, 0, 0, 0, 0, 'c'],
            ['redirected', 'second', 0, 0, 0, 0, 0, 'c'],
        ) {
            my ($path, @args) = @$case;
            push @checks, [$kind, "$prefix/$path", @args];
        }
    }
    $servers .= "server {
        listen 127.0.0.1:8080;
        server_name $kind;
        absolute_redirect off;
        when s { " . rule($kind, '*', 'server') . " }
        $locations
    }\n";
}

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    expr a str_eq \$http_x_a 1;
    expr b str_eq \$http_x_b 1;
    expr c str_eq \$http_x_c 1;
    expr s str_eq \$http_x_s 1;
    expr p str_eq \$http_x_p 1;
    # A volatile map makes the intended response-phase dependency explicit.
    map \$upstream_http_x_policy \$policy {
        volatile;
        default "";
        yes yes;
    }
    expr late str_eq \$policy yes;
    expr early str_eq \$policy "";
    proxy_cache_path %%TESTDIR%%/cache keys_zone=rewrites:1m;
    upstream retry_backend {
        server 127.0.0.1:8082 max_fails=0;
        server 127.0.0.1:8081 backup;
    }
    $global
    $servers

    server {
        listen 127.0.0.1:8082;
        http2 on;
        add_header X-Policy no always;
        return 503;
    }
    server {
        listen 127.0.0.1:8081;
        http2 on;
        add_header X-Protocol \$server_protocol always;
        add_header X-Policy yes always;
        add_header Location \$http_x_location always;
        add_header Refresh "0; url=\$http_x_location" always;
        add_header Set-Cookie "\$http_x_target=old; Domain=\$http_x_target.test; Path=/\$http_x_target/; Max-Age=60; Expires=Thu, 01-Jan-37 00:00:00 GMT" always;
        add_header Set-Cookie "keep=old; Path=/keep/; Max-Age=60" always;
        return 200 ok;
    }
    server {
        listen 127.0.0.1:8080;
        server_name special;
        absolute_redirect off;

        location /value {
            proxy_pass http://127.0.0.1:8081;
            when a { proxy_cookie_value second ~^different\$ a; }
            when b { proxy_cookie_value second ~^old\$ b; }
        }
        location /flags {
            proxy_pass http://127.0.0.1:8081;
            when a { proxy_cookie_flags second ""; }
            when b { proxy_cookie_flags second secure; }
        }
        location /value_off {
            proxy_pass http://127.0.0.1:8081;
            when a { proxy_cookie_value second ~^different\$ a; }
            when b { proxy_cookie_value off; }
            when c { proxy_cookie_value second ~^old\$ c; }
        }
        location /independent {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_path off;
            proxy_cookie_domain second.test rewritten.test;
            proxy_cookie_flags second secure;
        }
        location /default/ {
            proxy_pass http://127.0.0.1:8081/base/;
        }
        location /explicit/ {
            proxy_pass http://127.0.0.1:8081/base/;
            when a { proxy_redirect default; }
            when b { proxy_redirect ~^http://.* http://replacement.test/b; }
        }
        location /no-default/ {
            proxy_pass http://127.0.0.1:8081/base/;
            when a { proxy_redirect http://absent.test/ /unused/; }
        }
    }
}
EOF

my $tests = 19;
for my $check (@checks) {
    $tests += 2 + rewrite_assertions($check->[0]);
    $tests++ if $check->[1] =~ /\/retry$/;
}
for my $kind (@kinds) {
    $tests += 6 * (1 + rewrite_assertions($kind));
}
$t->plan($tests)->run();
for my $check (@checks) {
    my ($kind, $path, $target, $a, $b, $c, $s, $p, $want) = @$check;
    my $response = request($kind, $path, $target, $a, $b, $c, $s, $p);
    my $label = "$kind $path target=$target a=$a b=$b c=$c s=$s p=$p";
    like($response, qr/^HTTP\/1\.[01] 200 /, "$label status");
    my $protocol = $path =~ /^h2/ ? 'HTTP/2.0' : 'HTTP/1.1';
    like($response, qr/^X-Protocol: \Q$protocol\E\r?$/mi, "$label backend protocol");
    if ($path =~ /\/retry$/) {
        is(header($response, 'X-Attempts'), '503, 200', "$label retried upstream");
    }
    check_rewrite($response, $kind, $target, $want, $label);
}
for my $kind (@kinds) {
    for my $prefix (qw/h1 h2/) {
        for my $case ([1, 1, 'b', 'MISS'], [1, 0, 'c', 'HIT'],
                     [0, 0, 'parent', 'HIT']) {
            my ($a, $b, $want, $cache) = @$case;
            my $response = request($kind, "$prefix/cache", 'second', $a, $b, 0, 0, 1);
            like($response, qr/^X-Cache: $cache\r?$/mi, "$kind $prefix $cache");
            check_rewrite($response, $kind, 'second', $want, "$kind $prefix cached headers");
        }
    }
}
my $response = request('special', 'value', 'second', 1, 1, 0, 0, 0);
check_rewrite($response, 'value', 'second', 'b', 'value mismatch tries next matching rule');
for my $case ([1, 1, 1, '_'], [1, 0, 1, 'c'], [1, 0, 0, '_'], [0, 0, 1, 'c']) {
    my ($a, $b, $c, $want) = @$case;
    $response = request('special', 'value_off', 'second', $a, $b, $c, 0, 1);
    check_rewrite($response, 'value', 'second', $want,
        "value mismatch and off a=$a b=$b c=$c");
}
$response = request('special', 'flags', 'second', 1, 1, 0, 0, 0);
check_rewrite($response, 'flags', 'second', '_', 'empty flags on selected name stop');
$response = request('special', 'independent', 'second', 0, 0, 0, 0, 0);
like($response, qr/Domain=rewritten\.test; Path=\/second\//, 'path off leaves domain independent');
like($response, qr/; Secure\r?$/mi, 'path off leaves flags independent');

my $upstream = 'http://127.0.0.1:' . port(8081) . '/base/item';
for my $case (['default/item', 0, 0, '/default/item'],
              ['explicit/item', 1, 1, '/explicit/item'],
              ['explicit/item', 0, 1, 'http://replacement.test/b'],
              ['no-default/item', 1, 0, $upstream],
              ['no-default/item', 0, 0, '/no-default/item']) {
    my ($path, $a, $b, $want) = @$case;
    $response = request('special', $path, 'second', $a, $b, 0, 0, 0, $upstream);
    is(header($response, 'Location'), $want, "redirect $path a=$a b=$b");
}
$t->stop();

sub rewrite_assertions {
    my ($kind) = @_;
    return $kind eq 'max_age' ? 3 : 2;
}

sub rule {
    my ($kind, $target, $label) = @_;
    my $all = $target eq '*';
    return 'proxy_redirect ' . ($all ? '~^http://origin.test/.*$'
        : "http://origin.test/$target") . " http://replacement.test/$label;"
        if $kind eq 'redirect';
    return 'proxy_cookie_domain ' . ($all ? '~.*' : "$target.test")
        . " $label.test;" if $kind eq 'domain';
    return 'proxy_cookie_path ' . ($all ? '~.*' : "/$target/")
        . " /$label/;" if $kind eq 'path';
    $target = '~.*' if $all;
    return "proxy_cookie_flags $target $flags{$label};" if $kind eq 'flags';
    return "proxy_cookie_value $target ~^old\$ $label;" if $kind eq 'value';
    return "proxy_cookie_max_age $target $age{$label}s;" if $kind eq 'max_age';
    die "unknown kind $kind";
}

sub request {
    my ($host, $path, $target, $a, $b, $c, $s, $p, $location) = @_;
    $location //= "http://origin.test/$target";
    return http("GET /$path HTTP/1.0\r\nHost: $host\r\nX-Target: $target\r\n"
        . "X-A: $a\r\nX-B: $b\r\nX-C: $c\r\nX-S: $s\r\nX-P: $p\r\n"
        . "X-Location: $location\r\n\r\n");
}

sub header {
    my ($response, $name) = @_;
    my ($value) = $response =~ /^\Q$name\E: (.*?)\r?$/mi;
    return $value;
}

sub check_rewrite {
    my ($response, $kind, $target, $want, $label) = @_;
    if ($kind eq 'redirect') {
        my $expected = $want eq '_' ? "http://origin.test/$target"
            : "http://replacement.test/$want";
        is(header($response, 'Location'), $expected, "$label Location");
        is(header($response, 'Refresh'), "0; url=$expected", "$label Refresh");
        return;
    }
    my ($cookie) = $response =~ /^Set-Cookie: (\Q$target\E=.*?)\r?$/mi;
    $cookie //= '';
    like($cookie, qr/^\Q$target\E=/, "$label retains the Cookie");
    my ($actual, $expected);
    if ($kind eq 'domain' || $kind eq 'path') {
        ($actual) = $cookie =~ /;\s*\Q$kind\E=([^;]+)/i;
        my $value = $want eq '_' ? $target : $want;
        $expected = $kind eq 'domain' ? "$value.test" : "/$value/";
    } elsif ($kind eq 'flags') {
        my @actual = $cookie =~ /;\s*(secure|httponly|samesite=[^;]+)/ig;
        $actual = join ' ', sort map { lc } @actual;
        $expected = $want eq '_' ? '' : join ' ', sort split / /, $flags{$want};
    } elsif ($kind eq 'value') {
        ($actual) = $cookie =~ /^[^=]+=([^;]*)/;
        $expected = $want eq '_' ? 'old' : $want;
    } else {
        ($actual) = $cookie =~ /;\s*Max-Age=([^;]+)/i;
        $expected = $want eq '_' ? 60 : $age{$want};
        my ($expires) = $cookie =~ /;\s*Expires=([^;]+)/i;
        if ($want eq '_') {
            is($expires, 'Thu, 01-Jan-37 00:00:00 GMT', "$label original Expires");
        } else {
            my %month;
            @month{qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/} = (0 .. 11);
            my ($day, $mon, $year, $h, $m, $s) = ($expires // '') =~
                /^[A-Za-z]+, (\d+)-([A-Za-z]+)-(\d+) (\d+):(\d+):(\d+) GMT$/;
            my $epoch = defined $year
                ? eval { timegm($s, $m, $h, $day, $month{$mon},
                    $year < 100 ? 2000 + $year : $year) } : undef;
            ok(defined $epoch && abs($epoch - time() - $expected) <= 5,
                "$label Expires uses the same selected age");
        }
    }
    is($actual, $expected, "$label $kind");
}
