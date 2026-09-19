#!/usr/bin/perl

# Tests for $modsecurity_intervention and $modsecurity_triggered_rules.

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

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format modsec '$request_uri|i=$modsecurity_intervention|r=$modsecurity_triggered_rules';
    access_log %%TESTDIR%%/access.log modsec;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /pass {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq never" "id:100,phase:2,log,pass"
            ';
        }

        location /match-logonly {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq hit" "id:200,phase:2,log,pass"
            ';
        }

        location /multi {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq hit" "id:301,phase:2,log,pass"
                SecRule ARGS "@streq hit" "id:302,phase:2,log,pass"
                SecRule ARGS "@streq hit" "id:303,phase:2,log,pass"
            ';
        }

        location /mixed-logging {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq hit" "id:701,phase:2,nolog,pass"
                SecRule ARGS "@streq hit" "id:702,phase:2,noauditlog,pass"
                SecRule ARGS "@streq hit" "id:703,phase:2,log,pass"
            ';
        }

        location /allow {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq skip" "id:800,phase:1,log,allow"
                SecRule ARGS "@streq skip" "id:801,phase:1,log,deny,status:403"
            ';
        }

        location /block {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq go" "id:400,phase:1,log,deny,status:403"
            ';
        }

        location /redirect {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq go" "id:500,phase:1,log,status:302,redirect:http://example.com/"
            ';
        }

        location /block-phase3 {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq go" "id:600,phase:3,log,deny,status:403"
            ';
        }

        location /bypass {
            modsecurity on;
            modsecurity_bypass $arg_check;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS:arg "@streq go" "id:900,phase:1,log,deny,status:403"
            ';
        }

        location /cleared-request-header {
            more_clear_input_headers X-Removed;
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Removed "@streq blocked" "id:901,phase:1,log,deny,status:403"
            ';
        }

        location /cleared-response-header {
            content_by_lua_block {
                ngx.header["X-Removed"] = "blocked"
                ngx.header["X-Removed"] = nil
                ngx.print("body")
            }
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:X-Removed "@streq blocked" "id:902,phase:3,log,deny,status:403"
            ';
        }
    }
}
EOF

$t->write_file("/block-phase3", "body");
$t->write_file("/bypass", "body");
$t->write_file("/cleared-request-header", "body");
$t->run();
$t->plan(29);

###############################################################################

# No rule matches: intervention=0, no rule list (nginx prints '-' for missing var).
http_get('/pass?arg=x');
like(log_line($t, '/pass'), qr/\|i=0\|/,      'pass: intervention=0');
like(log_line($t, '/pass'), qr/\|r=-$/,       'pass: no triggered rules');

# Rule matches but non-disruptive: intervention=0, rule id listed.
http_get('/match-logonly?arg=hit');
like(log_line($t, '/match-logonly'), qr/\|i=0\|/,  'log-only: intervention=0');
like(log_line($t, '/match-logonly'), qr/\|r=200$/, 'log-only: rule id captured');

# Multiple rules all matching: intervention=0, every id listed.
http_get('/multi?arg=hit');
like(log_line($t, '/multi'), qr/\|i=0\|/,               'multi: intervention=0');
like(log_line($t, '/multi'), qr/\|r=301,302,303$/,      'multi: all rule ids listed in order');

# Three rules with different logging actions (nolog / noauditlog / log).
http_get('/mixed-logging?arg=hit');
like(log_line($t, '/mixed-logging'), qr/\|i=0\|/,   'mixed-logging: intervention=0');
like(log_line($t, '/mixed-logging'), qr/\|r=703$/,  'mixed-logging: only the log-action rule is captured (nolog/noauditlog both clear m_saveMessage)');

# allow action: short-circuits rule evaluation but is NOT treated as an intervention.
http_get('/allow?arg=skip');
like(log_line($t, '/allow'), qr/\|i=0\|/,   'allow: intervention=0');
like(log_line($t, '/allow'), qr/\|r=800$/,  'allow: only the allow rule captured; subsequent deny short-circuited');

# Deny intervention (phase 1): intervention=1, rule id listed.
http_get('/block?arg=go');
like(log_line($t, '/block'), qr/\|i=1\|/,    'block: intervention=1');
like(log_line($t, '/block'), qr/\|r=400$/,   'block: rule id captured');

# Redirect intervention: intervention=1, rule id listed.
http_get('/redirect?arg=go');
like(log_line($t, '/redirect'), qr/\|i=1\|/,  'redirect: intervention=1');
like(log_line($t, '/redirect'), qr/\|r=500$/, 'redirect: rule id captured');

# Intervention fired from a post-access phase.
http_get('/block-phase3?arg=go');
like(log_line($t, '/block-phase3'), qr/\|i=1\|/,  'phase3 block: intervention=1');
like(log_line($t, '/block-phase3'), qr/\|r=600$/, 'phase3 block: rule id captured');

# A true predicate bypasses ModSecurity; a false predicate evaluates it.
like(http_get('/bypass?arg=go&check=1'), qr/^HTTP\/1\.1 200 /,
    'bypass: true predicate skips ModSecurity');
like(log_line($t, '/bypass'), qr/\|i=0\|/, 'bypass: no intervention');
like(log_line($t, '/bypass'), qr/\|r=-$/, 'bypass: no triggered rules');

like(http_get('/bypass?arg=go&check=0'), qr/^HTTP\/1\.1 403 /,
    'bypass: false predicate evaluates ModSecurity');
like(log_line($t, '/bypass'), qr/\|i=1\|/, 'checked: intervention=1');
like(log_line($t, '/bypass'), qr/\|r=900$/, 'checked: rule id captured');

# Header filters mark removed headers with hash=0.  They must not be copied
# into the ModSecurity transaction on either side of the request.
my $cleared_request = http(<<'EOF');
GET /cleared-request-header HTTP/1.1
Host: localhost
X-Removed: blocked
Connection: close

EOF

like($cleared_request, qr/^HTTP\/1\.1 200 /,
    'cleared request header does not trigger ModSecurity');
like(log_line($t, '/cleared-request-header'), qr/\|i=0\|/,
    'cleared request header: no intervention');
like(log_line($t, '/cleared-request-header'), qr/\|r=-$/,
    'cleared request header: no triggered rules');

my $cleared_response = http_get('/cleared-response-header');
like($cleared_response, qr/^HTTP\/1\.1 200 /,
    'cleared response header does not trigger ModSecurity');
unlike($cleared_response, qr/^X-Removed:/mi,
    'cleared response header is absent on the wire');
like(log_line($t, '/cleared-response-header'), qr/\|i=0\|/,
    'cleared response header: no intervention');
like(log_line($t, '/cleared-response-header'), qr/\|r=-$/,
    'cleared response header: no triggered rules');

###############################################################################

sub log_line {
    my ($t, $uri_prefix) = @_;
    my $path = $t->testdir() . '/access.log';
    open my $fh, '<', $path or return "open: $!";
    my @matches = grep { /^\Q$uri_prefix\E/ } <$fh>;
    close $fh;
    return $matches[-1] // '';
}

###############################################################################
