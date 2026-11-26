#!/usr/bin/perl

# Read a replacement cache file before its shared node has been updated.

use warnings;
use strict;

use Test::More;
use Digest::MD5 qw/md5_hex/;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite/);
plan skip_all => 'requires nginx extensions' if $t->has_module('--without-ext');
plan skip_all => 'requires rename over an existing file' if $^O eq 'MSWin32';

$t->plan(6)->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/old keys_zone=old:1m;
    proxy_cache_path %%TESTDIR%%/new keys_zone=new:1m;

    server {
        listen 127.0.0.1:8080;
        proxy_cache_key fixture;
        proxy_cache_valid 200 1m;
        add_header X-Cache $upstream_cache_status;

        location /old {
            proxy_cache old;
            proxy_pass http://127.0.0.1:8081;
        }

        location /new {
            proxy_cache new;
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen 127.0.0.1:8081;

        location /old { return 200 old; }
        location /new {
            add_header X-Extra header;
            return 200 new;
        }
    }
}
EOF

$t->run();
like(http_get('/old'), qr/\r\n\r\nold\z/, 'warm the original entry');
like(http_get('/new'), qr/\r\n\r\nnew\z/, 'warm a replacement with a longer header');

# Both files have the same cache key.  This supplies exactly the disk and
# shared-memory state visible between rename() and the publisher's node update.
my $key = md5_hex('fixture');
my $dir = $t->testdir();
rename("$dir/new/$key", "$dir/old/$key") or die "rename cache file: $!";

my $r = http_get('/old');
like($r, qr/^X-Cache: HIT\r?$/mi, 'replacement is read without contacting the origin');
like($r, qr/^X-Extra: header\r?$/mi, 'replacement header');
like($r, qr/\r\n\r\nnew\z/, 'replacement body');
unlike($t->read_file('error.log'), qr/has too long header/, 'no stale header size error');
