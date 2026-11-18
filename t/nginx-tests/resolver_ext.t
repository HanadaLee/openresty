#!/usr/bin/perl

# Copyright (C) Hanada

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->has_daemon('python3');
$t->write_file('error.log', '');

for my $suite (qw/configuration ttl-tcp retries cache stale protocols lifecycle lua-api/) {
	subtest $suite => sub {
		open my $output, '-|', 'python3', "../resolver/$suite.py"
			or die "python3: $!";
		while (my $line = <$output>) {
			chomp $line;
			if ($line =~ s/^PASS //) {
				pass($line);
			} elsif (length $line) {
				diag $line;
			}
		}
		close $output;
		is($? >> 8, 0, "$suite completed");
		done_testing();
	};
}

undef $t;
done_testing();
