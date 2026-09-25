#!/usr/bin/perl

# Tests for condition-aware http proxy cache directives.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy cache ngx_expr_module/)
	->plan(36);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache levels=1:2 keys_zone=NAME:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        expr methods str_in $http_x_case methods;
        expr range str_in $http_x_case range;
        expr stale str_in $http_x_case stale;
        expr background str_in $http_x_case background;
        expr min_uses str_in $http_x_case min_uses;
        expr min_length str_in $http_x_case min_length;
        expr max_length str_in $http_x_case max_length;
        expr vary str_in $http_x_case vary;
        expr cache_hide str_in $http_x_case cache_hide;
        expr hide str_in $http_x_case hide;
        expr ignore_control str_in $http_x_case ignore_control;

        location /methods/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_types *;
            add_header X-Cache $upstream_cache_status always;

            when methods {
                proxy_cache_methods POST;
            }
        }

        location /range/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_types *;
            add_header X-Cache $upstream_cache_status always;

            when range {
                proxy_cache_max_range_offset 2;
            }

            proxy_cache_max_range_offset 0;
        }

        location /stale/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_key $uri;
            proxy_cache_types *;
            add_header X-Cache $upstream_cache_status always;

            when stale {
                proxy_cache_use_stale http_500;
            }

            proxy_cache_use_stale off;
        }

        location /background/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            add_header X-Cache $upstream_cache_status always;

            when background {
                proxy_cache_background_update on;
            }

            proxy_cache_background_update off;
        }

        location /min-uses/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_types *;
            add_header X-Cache $upstream_cache_status always;

            when min_uses {
                proxy_cache_min_uses 2;
            }

            proxy_cache_min_uses 1;
        }

        location /min-length/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_types *;
            add_header X-Cache $upstream_cache_status always;

            when min_length {
                proxy_cache_min_length 10;
            }

            proxy_cache_min_length 0;
        }

        location /max-length/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_types *;
            add_header X-Cache $upstream_cache_status always;

            when max_length {
                proxy_cache_max_length 4;
            }

            proxy_cache_max_length 0;
        }

        location /vary/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_types *;
            add_header X-Cache $upstream_cache_status always;

            when vary {
                proxy_cache_vary X-Ignored;
            }

            proxy_cache_vary X-Variant;
        }

        location /cache-hide/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_types *;
            proxy_ignore_headers Set-Cookie;
            add_header X-Cache $upstream_cache_status always;

            when cache_hide {
                proxy_cache_hide_cookies on;
            }

            proxy_cache_hide_cookies off;
        }

        location /hide/ {
            proxy_pass http://127.0.0.1:8081;

            when hide {
                proxy_hide_cookie secret;
            }
        }

        location /ignore-control/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_types *;
            add_header X-Cache $upstream_cache_status always;

            when ignore_control {
                proxy_ignore_cache_control no-store;
            }
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location /methods/ {
            add_header Cache-Control "max-age=60";
            return 200 method;
        }

        location /range/ {
            rewrite ^ /range.html break;
            add_header X-Range $http_range;
        }

        location /stale/ {
            if ($http_x_fail) {
                return 500;
            }

            add_header Cache-Control "max-age=1";
            return 200 stale-body;
        }

        location /background/ {
            rewrite ^ /background.html break;
            add_header Cache-Control "max-age=1, stale-while-revalidate=10";
        }

        location /min-uses/ {
            add_header Cache-Control "max-age=60";
            return 200 min-uses;
        }

        location /min-length/ {
            add_header Cache-Control "max-age=60";
            return 200 short;
        }

        location /max-length/ {
            add_header Cache-Control "max-age=60";
            return 200 short;
        }

        location /vary/ {
            add_header Cache-Control "max-age=60";
            add_header Vary X-Variant;
            return 200 $http_x_variant;
        }

        location /cache-hide/ {
            add_header Cache-Control "max-age=60";
            add_header Set-Cookie "secret=backend";
            return 200 cookie;
        }

        location /hide/ {
            add_header Set-Cookie "secret=one";
            add_header Set-Cookie "public=two";
            return 200 cookie;
        }

        location /ignore-control/ {
            add_header Cache-Control "no-store";
            return 200 ignored;
        }
    }
}

EOF

$t->write_file('range.html', 'SEE-THIS');
$t->write_file('background.html', 'OLD');
$t->run();

###############################################################################

like(post('/methods/on', methods => 1), qr/^X-Cache: MISS\x0d?$/mi,
	'proxy_cache_methods condition miss');
like(post('/methods/on', methods => 1), qr/^X-Cache: HIT\x0d?$/mi,
	'proxy_cache_methods condition hit');
unlike(post('/methods/off'), qr/^X-Cache:/mi,
	'proxy_cache_methods default first');
unlike(post('/methods/off'), qr/^X-Cache:/mi,
	'proxy_cache_methods default second');

like(range('/range/off', 'bytes=1-'), qr/^X-Range: bytes=1-\x0d?$/mi,
	'proxy_cache_max_range_offset default');
unlike(range('/range/on', 'bytes=1-', range => 1), qr/^X-Range:/mi,
	'proxy_cache_max_range_offset condition');
like(range('/range/on', 'bytes=1-', range => 1),
	qr/^X-Cache: HIT\x0d?$/mi, 'proxy_cache_max_range_offset cached');

like(request('/stale/on'), qr/^X-Cache: MISS\x0d?$/mi,
	'proxy_cache_use_stale condition primed');
like(request('/stale/off'), qr/^X-Cache: MISS\x0d?$/mi,
	'proxy_cache_use_stale default primed');
sleep 2;
like(request('/stale/on', stale => 1, fail => 1),
	qr/^X-Cache: STALE\x0d?.*stale-body/ms,
	'proxy_cache_use_stale condition');
like(request('/stale/off', fail => 1), qr/500 Internal Server Error/,
	'proxy_cache_use_stale default');

like(request('/background/on', background => 1),
	qr/^X-Cache: MISS\x0d?.*OLD/ms, 'proxy_cache_background_update primed');
like(request('/background/off'), qr/^X-Cache: MISS\x0d?.*OLD/ms,
	'proxy_cache_background_update default primed');
sleep 2;
$t->write_file('background.html', 'NEW');

like(request('/background/on', background => 1),
	qr/^X-Cache: STALE\x0d?.*OLD/ms,
	'proxy_cache_background_update condition');
select undef, undef, undef, 0.2;
like(request('/background/on', background => 1),
	qr/^X-Cache: HIT\x0d?.*NEW/ms,
	'proxy_cache_background_update refreshed');
like(request('/background/off'), qr/^X-Cache: EXPIRED\x0d?.*NEW/ms,
	'proxy_cache_background_update default');

like(request('/min-uses/default'), qr/^X-Cache: MISS\x0d?$/mi,
	'proxy_cache_min_uses default miss');
like(request('/min-uses/default'), qr/^X-Cache: HIT\x0d?$/mi,
	'proxy_cache_min_uses default hit');
like(request('/min-uses/condition', min_uses => 1),
	qr/^X-Cache: MISS\x0d?$/mi, 'proxy_cache_min_uses condition first');
like(request('/min-uses/condition', min_uses => 1),
	qr/^X-Cache: MISS\x0d?$/mi, 'proxy_cache_min_uses condition second');
like(request('/min-uses/condition', min_uses => 1),
	qr/^X-Cache: HIT\x0d?$/mi, 'proxy_cache_min_uses condition hit');

request('/min-length/default');
like(request('/min-length/default'), qr/^X-Cache: HIT\x0d?$/mi,
	'proxy_cache_min_length default');
request('/min-length/condition', min_length => 1);
like(request('/min-length/condition', min_length => 1),
	qr/^X-Cache: MISS\x0d?$/mi, 'proxy_cache_min_length condition');

request('/max-length/default');
like(request('/max-length/default'), qr/^X-Cache: HIT\x0d?$/mi,
	'proxy_cache_max_length default');
request('/max-length/condition', max_length => 1);
like(request('/max-length/condition', max_length => 1),
	qr/^X-Cache: MISS\x0d?$/mi, 'proxy_cache_max_length condition');

request('/vary/default', variant => 'A');
like(request('/vary/default', variant => 'B'),
	qr/^X-Cache: MISS\x0d?.*^B$/ms,
	'proxy_cache_vary default');
request('/vary/condition', vary => 1, variant => 'A');
like(request('/vary/condition', vary => 1, variant => 'B'),
	qr/^X-Cache: HIT\x0d?.*^A$/ms,
	'proxy_cache_vary condition');

request('/cache-hide/default');
like(request('/cache-hide/default'),
	qr/^Set-Cookie: secret=backend\x0d?$/mi,
	'proxy_cache_hide_cookies default');
request('/cache-hide/condition', cache_hide => 1);
my $hidden = request('/cache-hide/condition', cache_hide => 1);
like($hidden, qr/^X-Cache: HIT\x0d?$/mi,
	'proxy_cache_hide_cookies condition cached');
unlike($hidden, qr/^Set-Cookie:/mi,
	'proxy_cache_hide_cookies condition');

like(request('/hide/default'), qr/^Set-Cookie: secret=one\x0d?$/mi,
	'proxy_hide_cookie default');
my $hide = request('/hide/condition', hide => 1);
unlike($hide, qr/^Set-Cookie: secret=one\x0d?$/mi,
	'proxy_hide_cookie condition');
like($hide, qr/^Set-Cookie: public=two\x0d?$/mi,
	'proxy_hide_cookie preserves other cookies');

request('/ignore-control/default');
like(request('/ignore-control/default'), qr/^X-Cache: MISS\x0d?$/mi,
	'proxy_ignore_cache_control default');
request('/ignore-control/condition', ignore_control => 1);
like(request('/ignore-control/condition', ignore_control => 1),
	qr/^X-Cache: HIT\x0d?$/mi, 'proxy_ignore_cache_control condition');

pass('all non-lock proxy cache directives accepted in when');

###############################################################################

sub post {
	my ($uri, %headers) = @_;
	return request($uri, %headers, method => 'POST');
}

sub range {
	my ($uri, $value, %headers) = @_;
	$headers{range_header} = $value;
	return request($uri, %headers);
}

sub request {
	my ($uri, %extra) = @_;
	my $method = delete $extra{method} || 'GET';
	my $headers = '';

	$headers .= "X-Case: $_\r\n" for grep { $extra{$_} }
		qw/methods range stale background min_uses min_length max_length vary
		cache_hide hide ignore_control/;
	$headers .= "X-Fail: 1\r\n" if $extra{fail};
	$headers .= "X-Variant: $extra{variant}\r\n"
		if defined $extra{variant};
	$headers .= "Range: $extra{range_header}\r\n"
		if $extra{range_header};
	$headers .= "Content-Length: 0\r\n" if $method eq 'POST';

	return http("$method $uri HTTP/1.1\r\nHost: localhost\r\n"
		. $headers . "Connection: close\r\n\r\n");
}

###############################################################################
