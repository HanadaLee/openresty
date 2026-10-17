#!/usr/bin/perl

# Tests for upstream cache MIME type defaults, inheritance and overrides.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy fastcgi scgi uwsgi cache gzip rewrite/);
my @modules = qw/proxy fastcgi scgi uwsgi/;
my %ports = (proxy => 8081, fastcgi => 8082, scgi => 8083, uwsgi => 8084);
my %types = (
	html => 'text/html',
	json => 'application/json',
	json_charset => 'application/json; charset=utf-8',
	png => 'image/png',
	text => 'text/plain',
	missing => undef,
	nostore => 'application/json'
);
my @types = qw/html json json_charset png text missing nostore/;

# Path, effective type restriction (undef means inherit http), virtual server.
my @cases = (
	[ 'default', undef, 'default' ],
	[ 'limited', 'text', 'default' ],
	[ 'any', '*', 'default' ],
	[ 'inherited/child', 'json', 'default' ],
	[ 'inherited/any', '*', 'default' ],
	[ 'inherited/limited', 'png', 'default' ],
	[ 'all/child', '*', 'default' ],
	[ 'all/limited', 'text', 'default' ],
	[ 'default', 'json', 'restricted' ],
	[ 'any', '*', 'restricted' ]
);

$t->plan(2 * @modules * @cases * @types * 4 + 4);

for my $module (@modules) {
	my $port = port($ports{$module});
	$t->run_daemon(\&backend, $module, $port);
	$t->waitforsocket("127.0.0.1:$port");
}

for my $phase (qw/default restricted/) {
	my ($settings, $locations, $server_types) = ('', '', '');
	for my $module (@modules) {
		$settings .= "${module}_cache_path %%TESTDIR%%/$phase-$module "
			. "keys_zone=$module:1m;\n${module}_cache $module;\n"
			. "${module}_cache_key \"$phase|\$host|\$request_uri\";\n"
			. "${module}_cache_valid 200 1m;\n";
		$settings .= "${module}_cache_types application/json;\n"
			if $phase eq 'restricted';
		$server_types .= "${module}_cache_types application/json;\n";

		my $pass = $module eq 'proxy'
			? "proxy_pass http://127.0.0.1:$ports{$module};\n"
				. 'proxy_set_header X-Test-Type $arg_type;'
			: "${module}_pass 127.0.0.1:$ports{$module};\n"
				. "${module}_param TEST_TYPE \$arg_type;";
		$pass .= "\nscgi_param SCGI 1;" if $module eq 'scgi';
		$t->write_file_expand("$module.inc", $pass);

		$locations .= <<EOF;
location /$module/default { include $module.inc; }
location /$module/limited {
    ${module}_cache_types text/plain;
    include $module.inc;
}
location /$module/any {
    ${module}_cache_types *;
    include $module.inc;
}
location /$module/inherited/ {
    ${module}_cache_types application/json;
    location /$module/inherited/child { include $module.inc; }
    location /$module/inherited/any {
        ${module}_cache_types *;
        include $module.inc;
    }
    location /$module/inherited/limited {
        ${module}_cache_types image/png;
        include $module.inc;
    }
}
location /$module/all/ {
    ${module}_cache_types *;
    location /$module/all/child { include $module.inc; }
    location /$module/all/limited {
        ${module}_cache_types text/plain;
        include $module.inc;
    }
}
EOF
	}

	$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    $settings
    add_header X-Cache \$upstream_cache_status always;
    server {
        listen 127.0.0.1:8080;
        server_name default;
        $locations
        gzip on;
        gzip_min_length 0;
        gzip_http_version 1.0;
        location /gzip-json {
            default_type application/json;
            return 200 "gzip test body";
        }
        location /gzip-html {
            default_type text/html;
            return 200 "gzip test body";
        }
    }
    server {
        listen 127.0.0.1:8080;
        server_name restricted;
        $server_types
        $locations
    }
}
EOF

	$t->run();
	for my $module (@modules) {
		for my $case (@cases) {
			my ($path, $policy, $host) = @$case;
			$policy //= $phase eq 'default' ? '*' : 'json';
			for my $type (@types) {
				my $allowed = $type ne 'nostore' && ($policy eq '*'
					|| $type eq 'html' || $policy eq $type
					|| ($policy eq 'json' && $type eq 'json_charset'));
				for my $request (1, 2) {
					my $status = $request == 2 && $allowed ? 'HIT' : 'MISS';
					my $label = "$phase $module $host $path $type $request";
					my $response = http("GET /$module/$path?type=$type HTTP/1.0\r\n"
						. "Host: $host\r\n\r\n");
					like($response, qr/\AHTTP\/1\.[01] 200 .*\r\n\r\ncache body\n\z/s,
						"$label response");
					like($response, qr/^X-Cache: $status\r?$/mi, "$label cache status");
				}
			}
		}
	}

	unlike(http("GET /gzip-json HTTP/1.0\r\nHost: default\r\n"
		. "Accept-Encoding: gzip\r\n\r\n"), qr/^Content-Encoding: gzip\r?$/mi,
		"$phase gzip still excludes JSON by default");
	like(http("GET /gzip-html HTTP/1.0\r\nHost: default\r\n"
		. "Accept-Encoding: gzip\r\n\r\n"), qr/^Content-Encoding: gzip\r?$/mi,
		"$phase gzip still includes HTML by default");
	$t->stop();
}

###############################################################################

# Minimal protocol peers keep the test independent of FCGI/SCGI Perl packages.
# All requests are bodyless; consume their complete framing before replying.

sub read_exact {
	my ($socket, $length) = @_;
	my $data = '';
	while (length($data) < $length) {
		my $n = sysread($socket, my $part, $length - length($data));
		die "short backend request\n" unless $n;
		$data .= $part;
	}
	return $data;
}

sub fcgi_length {
	my ($data) = @_;
	my $length = unpack('C', substr($$data, 0, 1, ''));
	return $length unless $length & 0x80;
	return unpack('N', pack('C', $length) . substr($$data, 0, 3, '')) & 0x7fffffff;
}

sub fcgi_record {
	my ($type, $id, $data) = @_;
	return pack('CCnnCC', 1, $type, $id, length($data), 0, 0) . $data;
}

sub backend {
	my ($module, $port) = @_;
	my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
		LocalPort => $port, Listen => 16, ReuseAddr => 1) or die $!;
	local $SIG{PIPE} = 'IGNORE';
	while (my $socket = $server->accept()) {
		eval {
			my (%params, $type, $data, $id);
			if ($module eq 'proxy') {
				$data = '';
				$data .= read_exact($socket, 1) until $data =~ /\r\n\r\n\z/;
				($type) = $data =~ /^X-Test-Type:\s*(\w+)/mi;
			} elsif ($module eq 'fastcgi') {
				$data = '';
				while (1) {
					my (undef, $record, $request, $length, $padding)
						= unpack('CCnnCC', read_exact($socket, 8));
					$id = $request;
					my $content = read_exact($socket, $length);
					read_exact($socket, $padding);
					$data .= $content if $record == 4;
					last if $record == 5 && $length == 0;
				}
				while (length($data)) {
					my $name_length = fcgi_length(\$data);
					my $value_length = fcgi_length(\$data);
					my $name = substr($data, 0, $name_length, '');
					$params{$name} = substr($data, 0, $value_length, '');
				}
			} elsif ($module eq 'scgi') {
				my $length = '';
				while ((my $char = read_exact($socket, 1)) ne ':') { $length .= $char; }
				$data = read_exact($socket, $length);
				die "invalid SCGI terminator\n" unless read_exact($socket, 1) eq ',';
				my @params = split /\0/, $data, -1;
				pop @params;
				%params = @params;
			} else {
				my (undef, $length) = unpack('CvC', read_exact($socket, 4));
				$data = read_exact($socket, $length);
				while (length($data)) {
					my $name_length = unpack('v', substr($data, 0, 2, ''));
					my $name = substr($data, 0, $name_length, '');
					my $value_length = unpack('v', substr($data, 0, 2, ''));
					$params{$name} = substr($data, 0, $value_length, '');
				}
			}
			$type //= $params{TEST_TYPE};
			die "missing test MIME type\n" unless defined $type && exists $types{$type};
			my $body = "cache body\n";
			my $response = $module eq 'proxy' ? "HTTP/1.1 200 OK\r\n" : "Status: 200 OK\r\n";
			$response .= "Content-Type: $types{$type}\r\n" if defined $types{$type};
			$response .= "Cache-Control: no-store\r\n" if $type eq 'nostore';
			$response .= 'Content-Length: ' . length($body) . "\r\n\r\n$body";
			if ($module eq 'fastcgi') {
				$response = fcgi_record(6, $id, $response) . fcgi_record(6, $id, '')
					. fcgi_record(3, $id, pack('NCxxx', 0, 0));
			}
			$socket->autoflush(1);
			print $socket $response;
		};
		close $socket;
	}
}
