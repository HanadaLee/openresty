#!/usr/bin/perl

# Tests for condition-aware proxy cookie directives.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite pcre
	ngx_condition_module/)->plan(23);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    condition http_cookie str_in $arg_case http;

    when http_cookie {
        proxy_cookie_domain old.example http.example;
        proxy_cookie_path /old /http;
        proxy_cookie_flags id secure;
        proxy_cookie_value id old http;
        proxy_cookie_max_age id 10m;
    }

    proxy_cookie_domain off;
    proxy_cookie_path off;
    proxy_cookie_flags off;
    proxy_cookie_value off;
    proxy_cookie_max_age off;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        condition domain str_in $arg_case domain;
        condition path str_in $arg_case path;
        condition flags str_in $arg_case flags;
        condition value str_in $arg_case value;
        condition max_age str_in $arg_case max_age;
        condition all str_in $arg_case all;
        condition regex str_in $arg_case regex;
        condition disabled str_in $arg_case disabled;
        condition vars str_in $arg_case vars;
        condition multi str_in $arg_case multi;

        location /http/ {
            proxy_pass http://127.0.0.1:8081/;
        }

        location /basic/ {
            proxy_pass http://127.0.0.1:8081/;

            when domain {
                proxy_cookie_domain old.example new.example;
            }
            when path {
                proxy_cookie_path /old /new;
            }
            when flags {
                proxy_cookie_flags id secure httponly samesite=strict;
            }
            when value {
                proxy_cookie_value id old new;
            }
            when max_age {
                proxy_cookie_max_age id 1h;
            }

            proxy_cookie_domain off;
            proxy_cookie_path off;
            proxy_cookie_flags off;
            proxy_cookie_value off;
            proxy_cookie_max_age off;
        }

        location /combined/ {
            proxy_pass http://127.0.0.1:8081/;

            when all {
                proxy_cookie_domain old.example new.example;
                proxy_cookie_path /old /new;
                proxy_cookie_flags id secure httponly samesite=strict;
                proxy_cookie_value id old new;
                proxy_cookie_max_age id 1h;
            }

            proxy_cookie_domain off;
            proxy_cookie_path off;
            proxy_cookie_flags off;
            proxy_cookie_value off;
            proxy_cookie_max_age off;
        }

        location /regex/ {
            proxy_pass http://127.0.0.1:8081/;

            when regex {
                proxy_cookie_domain ~^(.+)\.example$ $1.changed;
                proxy_cookie_path ~*^/old/(.+)$ /path/$1;
                proxy_cookie_flags ~^token$ secure;
                proxy_cookie_value ~^token$ ~*^old-(.+)$ new-$1;
                proxy_cookie_max_age ~^token$ 2h;
            }

            proxy_cookie_domain off;
            proxy_cookie_path off;
            proxy_cookie_flags off;
            proxy_cookie_value off;
            proxy_cookie_max_age off;
        }

        location /off/ {
            proxy_pass http://127.0.0.1:8081/;

            when disabled {
                proxy_cookie_domain off;
                proxy_cookie_path off;
                proxy_cookie_flags off;
                proxy_cookie_value off;
                proxy_cookie_max_age off;
            }

            proxy_cookie_domain old.example enabled.example;
            proxy_cookie_path /old /enabled;
            proxy_cookie_flags id secure;
            proxy_cookie_value id old enabled;
            proxy_cookie_max_age id 5m;
        }

        location /order/ {
            proxy_pass http://127.0.0.1:8081/;

            proxy_cookie_domain old.example first.example;
            proxy_cookie_path /old /first;
            proxy_cookie_flags id secure;
            proxy_cookie_value id old first;
            proxy_cookie_max_age id 1m;

            when all {
                proxy_cookie_domain old.example second.example;
                proxy_cookie_path /old /second;
                proxy_cookie_flags id httponly;
                proxy_cookie_value id old second;
                proxy_cookie_max_age id 2m;
            }
        }

        location /inherit/ {
            when all {
                proxy_cookie_domain old.example inherited.example;
                proxy_cookie_path /old /inherited;
                proxy_cookie_flags id httponly;
                proxy_cookie_value id old inherited;
                proxy_cookie_max_age id 15m;
            }

            proxy_cookie_domain off;
            proxy_cookie_path off;
            proxy_cookie_flags off;
            proxy_cookie_value off;
            proxy_cookie_max_age off;

            location /inherit/child/ {
                proxy_pass http://127.0.0.1:8081/;
            }
        }

        location /vars/ {
            proxy_pass http://127.0.0.1:8081/;

            when vars {
                proxy_cookie_domain old.example $arg_domain;
                proxy_cookie_path /old $arg_path;
                proxy_cookie_flags id $arg_flag;
                proxy_cookie_value id old $arg_value;
                proxy_cookie_max_age id 30m;
            }

            proxy_cookie_domain off;
            proxy_cookie_path off;
            proxy_cookie_flags off;
            proxy_cookie_value off;
            proxy_cookie_max_age off;
        }

        location /multi/ {
            proxy_pass http://127.0.0.1:8081/;

            when multi {
                proxy_cookie_domain other.example ignored.example;
                proxy_cookie_domain old.example multi.example;
                proxy_cookie_path /other /ignored;
                proxy_cookie_path /old /multi;
                proxy_cookie_flags other httponly;
                proxy_cookie_flags id secure;
                proxy_cookie_value other old ignored;
                proxy_cookie_value id old multi;
                proxy_cookie_max_age other 1m;
                proxy_cookie_max_age id 45m;
            }

            proxy_cookie_domain off;
            proxy_cookie_path off;
            proxy_cookie_flags off;
            proxy_cookie_value off;
            proxy_cookie_max_age off;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        condition server_cookie str_in $arg_case server;

        when server_cookie {
            proxy_cookie_domain old.example server.example;
            proxy_cookie_path /old /server;
            proxy_cookie_flags id httponly;
            proxy_cookie_value id old server;
            proxy_cookie_max_age id 20m;
        }

        proxy_cookie_domain off;
        proxy_cookie_path off;
        proxy_cookie_flags off;
        proxy_cookie_value off;
        proxy_cookie_max_age off;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location = /base {
            add_header Set-Cookie
                "id=old; Domain=old.example; Path=/old";
            return 200 base;
        }

        location = /suffix {
            add_header Set-Cookie "id=old-tail";
            return 200 suffix;
        }

        location = /aged {
            add_header Set-Cookie
                "id=old; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
            return 200 aged;
        }

        location = /regex {
            add_header Set-Cookie
                "ToKeN=OlD-VALUE; Domain=Sub.Example; Path=/OLD/item";
            return 200 regex;
        }
    }
}

EOF

$t->run();

###############################################################################

my $base = 'id=old; Domain=old.example; Path=/old';

is(cookie('/basic/base'), $base, 'cookie conditions default');
is(cookie('/basic/base?case=domain'),
	'id=old; Domain=new.example; Path=/old',
	'proxy_cookie_domain condition');
is(cookie('/basic/base?case=path'),
	'id=old; Domain=old.example; Path=/new',
	'proxy_cookie_path condition');
is(cookie('/basic/base?case=flags'),
	'id=old; Domain=old.example; Path=/old; Secure; HttpOnly; SameSite=Strict',
	'proxy_cookie_flags condition');
is(cookie('/basic/base?case=value'),
	'id=new; Domain=old.example; Path=/old',
	'proxy_cookie_value condition');
is(cookie('/basic/suffix?case=value'), 'id=new-tail',
	'proxy_cookie_value prefix condition');
is(cookie('/basic/base?case=max_age'),
	'id=old; Domain=old.example; Path=/old; Max-Age=3600',
	'proxy_cookie_max_age condition adds attribute');

is(cookie('/basic/aged'),
	'id=old; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
	'proxy_cookie_max_age default');

my $aged = cookie('/basic/aged?case=max_age');
like($aged, qr/^id=old; Max-Age=3600; Expires=/,
	'proxy_cookie_max_age condition rewrites attributes');
unlike($aged, qr/Expires=Thu, 01 Jan 1970 00:00:00 GMT/,
	'proxy_cookie_max_age condition rewrites expires');

is(cookie('/combined/base?case=all'),
	'id=new; Domain=new.example; Path=/new; Max-Age=3600; Secure; '
	. 'HttpOnly; SameSite=Strict', 'cookie conditions combined');

is(cookie('/regex/regex'),
	'ToKeN=OlD-VALUE; Domain=Sub.Example; Path=/OLD/item',
	'cookie regex conditions default');
is(cookie('/regex/regex?case=regex'),
	'ToKeN=new-VALUE; Domain=Sub.changed; Path=/path/item; '
	. 'Max-Age=7200; Secure', 'cookie regex conditions');

is(cookie('/off/base'),
	'id=enabled; Domain=enabled.example; Path=/enabled; Max-Age=300; Secure',
	'cookie condition off fallback');
is(cookie('/off/base?case=disabled'), $base, 'cookie condition off');

is(cookie('/order/base?case=all'),
	'id=first; Domain=first.example; Path=/first; Max-Age=60; Secure',
	'cookie configuration order takes priority');

is(cookie('/inherit/child/base?case=all'),
	'id=inherited; Domain=inherited.example; Path=/inherited; '
	. 'Max-Age=900; HttpOnly', 'cookie conditions inherited');

is(cookie('/http/base'), $base, 'http cookie conditions default');
is(cookie('/http/base?case=http'),
	'id=http; Domain=http.example; Path=/http; Max-Age=600; Secure',
	'http cookie conditions');

is(cookie('/base', 8082), $base, 'server cookie conditions default');
is(cookie('/base?case=server', 8082),
	'id=server; Domain=server.example; Path=/server; Max-Age=1200; HttpOnly',
	'server cookie conditions');

is(cookie('/vars/base?case=vars&domain=vars.example&path=/vars'
	. '&flag=secure&value=vars'),
	'id=vars; Domain=vars.example; Path=/vars; Max-Age=1800; Secure',
	'cookie condition complex values');

is(cookie('/multi/base?case=multi'),
	'id=multi; Domain=multi.example; Path=/multi; Max-Age=2700; Secure',
	'multiple cookie rules in one condition');

###############################################################################

sub cookie {
	my ($uri, $listen) = @_;
	$listen = 8080 unless defined $listen;

	http_get($uri, PeerAddr => '127.0.0.1:' . port($listen))
		=~ /^Set-Cookie:\s*(.+?)\x0d?$/mi;
	return $1;
}

###############################################################################
