#!/usr/bin/perl

# (C) Hanada

# Extended rewrite conditions must size the runtime stack at configuration time.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(28);
my $locations = '';

for my $count (10, 11, 64) {
	for my $op ('&&', '||') {
		my $name = $op eq '&&' ? 'and' : 'or';
		my $expr = join " $op ", ('$arg_a') x $count;
		$locations .= "location /$name$count { if ($expr) { return 204; } }\n";
	}

	# Comparisons need one temporary slot in addition to their result.
	my $expr = join ' && ', ('$arg_a = 1') x $count;
	$locations .= "location /compare$count { if ($expr) { return 204; } }\n";
}

my $deep = '$arg_a = 1';
for (1 .. 32) {
	$deep = "\$arg_a && ($deep)";
}
$locations .= "location /deep { if ($deep) { return 204; } }\n";
$locations .= "location \@deep { if ($deep) { return 204; } return 403; }\n";
$locations .= "location /named { goto \@deep; }\n";
$locations .= "location /elif { if (\$arg_a = 2) { return 202; }"
	. " elif ($deep) { return 204; } else { return 403; } }\n";

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        $locations
    }
    server {
        listen 127.0.0.1:8081;
        server_name localhost;
        if ($deep) { return 204; }
        return 403;
    }
}
EOF

$t->run();

for my $count (10, 11, 64) {
	for my $name ('and', 'or', 'compare') {
		like(http_get("/$name$count?a=1"), qr/ 204 /, "$name $count true");
		like(http_get("/$name$count?a=0"), qr/ 404 /, "$name $count false");
	}
}
for my $name ('deep', 'named', 'elif') {
	like(http_get("/$name?a=1"), qr/ 204 /, "$name true");
	my $status = $name eq 'deep' ? 404 : 403;
	like(http_get("/$name?a=0"), qr/ $status /, "$name false");
}
like(http_get('/elif?a=2'), qr/ 202 /, 'elif keeps first branch');
like(http_get('/?a=1', PeerAddr => '127.0.0.1:' . port(8081)),
	qr/ 204 /, 'server stack true');
like(http_get('/?a=0', PeerAddr => '127.0.0.1:' . port(8081)),
	qr/ 403 /, 'server stack false');
like(http_get('/compare11?a=1'), qr/ 204 /, 'worker survives repeated evaluation');
