#!/usr/bin/perl

# (C) Hanada

# Extended rewrite expression parsing, precedence and malformed input.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my @cases = (
	['and-or', '$arg_a && $arg_b || $arg_c', sub { $_[0] && $_[1] || $_[2] }],
	['or-and', '$arg_a || $arg_b && $arg_c', sub { $_[0] || $_[1] && $_[2] }],
	['group-tail', '($arg_a || $arg_b) && $arg_c', sub { ($_[0] || $_[1]) && $_[2] }],
	['group-or', '($arg_a && $arg_b) || $arg_c', sub { ($_[0] && $_[1]) || $_[2] }],
	['group-right', '$arg_a && ($arg_b || $arg_c)', sub { $_[0] && ($_[1] || $_[2]) }],
	['nested', '(($arg_a) || ($arg_b)) && ($arg_c)', sub { ($_[0] || $_[1]) && $_[2] }],
);
my @literals = (
	['literal-and', '$http_x_value = "&&"', '&&'],
	['literal-or', '$http_x_value = "||"', '||'],
	['literal-and-chain', '$http_x_value = "&&" && $arg_a', '&&'],
	['literal-op-value', '$http_x_value = "=" && $arg_a', '='],
	['group-equal', '($http_x_value = "abc") && $arg_a', 'abc'],
	['group-regex', '($http_x_value ~ "^(abc)$") && $arg_a', 'abc'],
	['group-regex-parens', '($http_x_value ~ "^(abc)") && $arg_a', 'abc'],
	['group-file', '(-f %%TESTDIR%%/file) && $arg_a', 'unused'],
);
my @invalid = (
	'()', '( )', '$arg_a &&', '&& $arg_a',
	'$arg_a || || $arg_b', '($arg_a) $arg_b',
	'($arg_a', '$arg_a && ()', '($arg_a && $arg_b))',
);

my $t = Test::Nginx->new()->has(qw/http rewrite/)
	->plan(@cases * 9 + @literals * 3 + @invalid);
my $locations = '';
my %valid;

$t->write_file('file', 'test');

for my $case (@cases, @literals) {
	my ($name, $expr) = @$case;
	my $location = "location /$name { if ($expr) { return 204; } }\n";
	write_config($location);
	my ($ok, $output) = config_test();
	ok($ok, "$name configuration accepted") or diag $output;
	$valid{$name} = $ok;
	$locations .= $location if $ok;
}

for my $expr (@invalid) {
	write_config("location /invalid { if ($expr) { return 204; } }");
	my ($ok, $output) = config_test();
	ok(!$ok && $output =~ /\[emerg\]/ && $output !~ /Sanitizer/,
		"invalid condition rejected: $expr") or diag $output;
}

write_config($locations);
unlink $t->testdir() . '/nginx.pid';
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8080)) or die 'nginx not listening';

for my $case (@cases) {
	my ($name, $expr, $expected) = @$case;
	SKIP: {
		skip "$name configuration rejected", 8 unless $valid{$name};
		for my $bits (0 .. 7) {
			my ($a, $b, $c) = map { ($bits >> $_) & 1 } (2, 1, 0);
			my $status = $expected->($a, $b, $c) ? 204 : 404;
			like(http_get("/$name?a=$a&b=$b&c=$c"), qr/ $status /,
				"$name truth table $a$b$c");
		}
	}
}
for my $case (@literals) {
	my ($name, $expr, $value) = @$case;
	SKIP: {
		skip "$name configuration rejected", 2 unless $valid{$name};
		like(http("GET /$name?a=1 HTTP/1.0\r\nX-Value: $value\r\n\r\n"),
			qr/ 204 /, "$name matches");
		my $args = $name eq 'group-file' ? 'a=0' : 'a=1';
		like(http("GET /$name?$args HTTP/1.0\r\nX-Value: mismatch\r\n\r\n"),
			qr/ 404 /, "$name mismatch");
	}
}

$t->stop();
undef $t;

sub write_config {
	my ($locations) = @_;
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
}
EOF
}

sub config_test {
	my $pid = open(my $pipe, '-|');
	die "fork failed: $!" unless defined $pid;
	if (!$pid) {
		open STDERR, '>&', \*STDOUT or die "dup stderr: $!";
		exec($Test::Nginx::NGINX, '-t', '-p', $t->testdir(), '-c', 'nginx.conf',
			'-e', 'error.log');
		die "exec failed: $!";
	}
	my $output = do { local $/; <$pipe> };
	close $pipe;
	return ($? == 0, $output);
}
