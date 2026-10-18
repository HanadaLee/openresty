#!/usr/bin/perl

# Select a rule group once, retaining the current location's filter options.

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http rewrite sub ngx_expr_module/)->plan(21);
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    default_type text/html;
    expr no bool false;
    expr yes bool true;
    expr selected str_eq $arg_mode yes;
    sub_filter TOKEN PARENT;
    server {
        listen 127.0.0.1:8080;
        when no { sub_filter TOKEN INACTIVE; }
        location = /absent { return 200 "TOKEN TOKEN"; }
        location = /conditional {
            when selected { sub_filter TOKEN LOCAL; }
            return 200 "TOKEN TOKEN";
        }
        location = /no-match {
            when selected { sub_filter ABSENT LOCAL; }
            return 200 TOKEN;
        }
        location = /empty-search {
            when yes { sub_filter $arg_search LOCAL; }
            return 200 TOKEN;
        }
        location = /empty-replacement {
            when selected { sub_filter TOKEN ""; }
            return 200 "TOKEN-tail";
        }
        location = /mixed {
            when no { sub_filter TOKEN INACTIVE; }
            sub_filter ABSENT LOCAL;
            return 200 TOKEN;
        }
        location = /once-off {
            sub_filter_once off;
            when no { sub_filter TOKEN INACTIVE; }
            return 200 "TOKEN TOKEN";
        }
        location = /plain {
            default_type text/plain;
            when no { sub_filter TOKEN INACTIVE; }
            return 200 TOKEN;
        }
        location = /plain-enabled {
            default_type text/plain;
            sub_filter_types text/plain;
            when no { sub_filter TOKEN INACTIVE; }
            return 200 TOKEN;
        }
        location /nested/ {
            when no { sub_filter TOKEN INACTIVE; }
            location = /nested/child {
                when no { sub_filter TOKEN INACTIVE; }
                return 200 TOKEN;
            }
        }
        location = /redefined {
            expr no bool true;
            return 200 TOKEN;
        }
        location = /modified {
            sub_filter_last_modified on;
            alias %%TESTDIR%%/body;
        }
        location = /default-modified {
            alias %%TESTDIR%%/body;
        }
        location = /many-pairs {
            sub_filter_once off;
            when yes {
                sub_filter TOKEN LOCAL;
                sub_filter second SECOND;
            }
            return 200 "token second TOKEN";
        }
        location /dynamic/ {
            sub_filter $arg_search DYNAMIC;
            location = /dynamic/child {
                when no { sub_filter TOKEN INACTIVE; }
                return 200 TOKEN;
            }
        }
    }
}
EOF
$t->write_file('body', 'TOKEN');
$t->run();

# HTTP/1.0 avoids chunk framing when checking the replaced body.
sub body {
    my ($uri, $body, $label) = @_;
    like(http_get($uri), qr/\r\n\r\n\Q$body\E\z/, $label);
}
body('/absent', 'PARENT TOKEN', 'static http tables prepared before fallback');
body('/conditional', 'PARENT TOKEN', 'miss inherits static parent group');
body('/conditional?mode=yes', 'LOCAL TOKEN', 'hit selects local group only');
body('/no-match?mode=yes', 'TOKEN', 'absent body string does not trigger inheritance');
body('/no-match', 'PARENT', 'when miss does trigger inheritance');
body('/empty-search', 'TOKEN', 'active empty dynamic search blocks parent');
body('/empty-search?search=TOKEN', 'LOCAL', 'nonempty dynamic search matches');
body('/empty-replacement?mode=yes', '-tail', 'empty replacement deletes text');
body('/mixed', 'TOKEN', 'unconditional local entry selects group');
body('/once-off', 'PARENT PARENT', 'current once option applies to inherited rules');
body('/plain', 'TOKEN', 'current MIME types exclude filtering');
body('/plain-enabled', 'PARENT', 'current MIME types enable inherited rules');
body('/nested/child', 'PARENT', 'multiple inactive levels inherit');
body('/redefined', 'INACTIVE', 'inherited conditions use current definitions');
like(http_get('/modified'), qr/\r\nLast-Modified:/i,
    'current last_modified on retains timestamp');
unlike(http_get('/default-modified'), qr/\r\nLast-Modified:/i,
    'default last_modified removes timestamp');
body('/conditional', 'PARENT TOKEN', 'selection does not leak between requests');
body('/many-pairs', 'LOCAL SECOND LOCAL', 'selected pairs share native case-insensitive matching');
body('/dynamic/child?search=TOKEN', 'DYNAMIC', 'parent dynamic match set travels with its rules');
body('/dynamic/child', 'TOKEN', 'empty active parent search blocks static grandparent');
like(http_get('/empty-search'), qr/\r\nContent-Length: 5\r\n/i,
    'empty selected search leaves content metadata intact');
