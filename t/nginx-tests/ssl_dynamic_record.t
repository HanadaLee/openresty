#!/usr/bin/perl

# Dynamic TLS record directive names and configuration parsing.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http http_ssl/);
my $d = $t->testdir();

my @directives = (
	[ 'ssl_dynamic_record', 'ssl_dyn_rec', 'on', 'off', 'invalid' ],
	[ 'ssl_dynamic_record_timeout', 'ssl_dyn_rec_timeout', '1s', '250ms', '-1' ],
	[ 'ssl_dynamic_record_low_size', 'ssl_dyn_rec_size_lo', '1369', '2k', '-1' ],
	[ 'ssl_dynamic_record_high_size', 'ssl_dyn_rec_size_hi', '4229', '8k', '-1' ],
	[ 'ssl_dynamic_record_threshold', 'ssl_dyn_rec_threshold', '40', '80', '-1' ],
);

for my $directive (@directives) {
	my ($name, $old, $value, $override, $invalid) = @$directive;
	for my $scope (qw/http server/) {
		my ($ok, $output) = config_test($scope, "$name $value;");
		ok($ok, "$name: accepted in $scope") or diag $output;

		($ok, $output) = config_test($scope, "$old $value;");
		ok(!$ok, "$old: rejected in $scope") or diag $output;
		like($output, qr/unknown directive "\Q$old\E"/,
			"$old: no compatibility alias");

		($ok, $output) = config_test($scope, "$name $value; $name $override;");
		ok(!$ok, "$scope: duplicate $name rejected") or diag $output;
		like($output, qr/"\Q$name\E" directive is duplicate/,
			"$scope: duplicate diagnostic");
	}

	my ($ok, $output) = config_test('server', "$name $invalid;");
	ok(!$ok, "$name: invalid value rejected") or diag $output;
	like($output, qr/invalid (?:value|number)/,
		"$name: value validation retained");

	for my $arguments ('', "$value $override") {
		($ok, $output) = config_test('server', "$name $arguments;");
		ok(!$ok, "$name: incorrect argument count rejected") or diag $output;
		like($output, qr/invalid number of arguments/,
			"$name: argument count diagnostic");
	}

	($ok, $output) = config_test('location', "$name $value;");
	ok(!$ok, "$name: location context rejected") or diag $output;
	like($output, qr/"\Q$name\E" directive is not allowed here/,
		"$name: context diagnostic");

	($ok, $output) = config_test('server', "$name $override;", "$name $value;");
	ok($ok, "$name: server can override http setting") or diag $output;
}

my $settings = join "\n", map { "$_->[0] $_->[2];" } @directives;
my ($ok, $output) = config_test('http', $settings);
ok($ok, 'new directive family accepted together') or diag $output;

# Zero keeps its existing disabling/phase-skipping meaning for these knobs.
for my $directive (@directives[1, 4]) {
	my $name = $directive->[0];
	($ok, $output) = config_test('server', "$name 0;");
	ok($ok, "$name: zero remains valid") or diag $output;
}

done_testing();

sub config_test {
	my ($scope, $setting, $parent) = @_;
	my $http = defined $parent ? $parent : '';
	my $server = '';

	if ($scope eq 'http') {
		$http .= "\n$setting";
	} elsif ($scope eq 'server') {
		$server = $setting;
	} else {
		$server = "location / { $setting }";
	}

	$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    $http
    server {
        listen 127.0.0.1:%%PORT_8080%%;
        $server
    }
}
EOF

	my $pid = open(my $pipe, '-|');
	die "fork: $!" unless defined $pid;
	if (!$pid) {
		open STDERR, '>&', \*STDOUT or die "dup: $!";
		exec($Test::Nginx::NGINX, '-t', '-p', "$d/", '-c', 'nginx.conf',
			'-e', 'error.log');
		die "exec: $!";
	}
	my $output = do { local $/; <$pipe> };
	close $pipe;
	return ($? == 0 ? 1 : 0, $output);
}
