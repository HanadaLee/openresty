#!/usr/bin/perl

# Tests for the patched OpenResty installation prefix.

###############################################################################

use warnings;
use strict;

use Test::More tests => 2;

###############################################################################

my $nginx = $ENV{TEST_NGINX_BINARY}
	or die "TEST_NGINX_BINARY is not set";
my $output = qx{"$nginx" -V 2>&1};

like($output, qr/--prefix=\/usr\/local\/openresty(?:\s|$)/,
	'configured prefix is the OpenResty root');
unlike($output, qr/--prefix=\/usr\/local\/openresty\/nginx(?:\s|$)/,
	'configured prefix does not retain the nested nginx directory');

###############################################################################
