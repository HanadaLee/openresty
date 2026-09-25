#!/usr/bin/perl

# Tests for condition-aware proxy cookie directives with HTTP/2 backend.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite
	ngx_expr_module/);

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

        expr cookies str_in $arg_case cookies;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 2;

            when cookies {
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
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->waitforsocket('127.0.0.1:' . port(8081));

$t->try_run('no proxy_http_version 2')->plan(2);

###############################################################################

is(cookie('/'), 'id=old; Domain=old.example; Path=/old',
	'HTTP/2 cookie conditions default');
is(cookie('/?case=cookies'),
	'id=new; Domain=new.example; Path=/new; Max-Age=3600; Secure; '
	. 'HttpOnly; SameSite=Strict', 'HTTP/2 cookie conditions');

###############################################################################

sub cookie {
	my ($uri) = @_;
	http_get($uri) =~ /^Set-Cookie:\s*(.+?)\x0d?$/mi;
	return $1;
}

sub http_daemon {
	my $client;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	while ($client = $server->accept()) {
		$client->autoflush(1);
		$client->sysread(my $buf, 24) == 24 or next; # preface

		my $c = Test::Nginx::HTTP2->new(1, socket => $client,
			pure => 1, preface => "") or next;

		$c->h2_settings(0);
		$c->h2_settings(1);

		my $frames = $c->read(all => [{ fin => 4 }]);
		my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
		my $sid = $frame->{sid};

		$c->new_stream({ headers => [
			{ name => ':status', value => '200' },
			{ name => 'set-cookie',
				value => 'id=old; Domain=old.example; Path=/old' },
		]}, $sid);
	}
}

###############################################################################
