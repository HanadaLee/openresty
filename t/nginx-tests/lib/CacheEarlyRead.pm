package CacheEarlyRead;

# Copyright (C) Hanada

use strict;
use warnings;
use Exporter 'import';
use Digest::MD5 qw/md5_hex/;
use Fcntl qw/:flock SEEK_SET/;
use IO::Select;
use IO::Socket::INET;
use POSIX ();
use Time::HiRes qw/sleep time/;
use Test::More;
use Test::Nginx qw/:DEFAULT http_start/;

our @EXPORT = qw/start_cache origin_body release_fill origin_hits socket_for
    send_req headers read_body fetch wait_for legacy_guard finish_cache/;

# Each request to the origin records its Range and writes a prefix. A file in
# the test directory releases the remainder, including across worker reloads.
sub origin_body {
	my ($path, $version, $range) = @_;
	if ($path =~ m{^/(obj|range|slice|saved)/}) {
		my $s = join('', map { pack('N', $_) } 0 .. 32767);
		return ($range || '') =~ /^bytes=131072-/ ? scalar reverse($s) : $s;
	}
	my $s = chr($version) x 131072;
	return $s unless $path eq '/multipart';
	return "--part\r\nContent-Range: bytes 0-65535/524288\r\n\r\n"
		. substr($s, 0, 65536)
		. "\r\n--part\r\nContent-Range: bytes 458752-524287/524288\r\n\r\n"
		. substr($s, -65536) . "\r\n--part--\r\n";
}

sub wait_for {
	my ($test, $why, $timeout) = @_;
	my $end = time + ($timeout // 6);
	until ($test->()) {
		die "timed out waiting for $why\n" if time >= $end;
		sleep 0.01;
	}
}

sub release_fill { $_[0]->write_file(md5_hex($_[1]) . '.go', '1'); }

sub origin_hits {
	my ($t, $path) = @_;
	my $file = $t->testdir() . '/' . md5_hex($path) . '.hits';
	return [] unless -e $file;
	open my $fh, '<', $file or die "open $file: $!";
	flock($fh, LOCK_SH) or die "flock: $!";
	chomp(my @hits = <$fh>);
	return \@hits;
}

sub serve {
	my ($c, $dir) = @_;
	my $request = <$c> || return;
	my ($path) = $request =~ /^GET (\/\S*) / or return;
	my $range = '';
	while (<$c>) {
		last if /^\r?\n$/;
		$range = $1 if /^Range:\s*(\S+)/i;
	}
	my $key = "$dir/" . md5_hex($path);
	open my $hits, '+>>', "$key.hits" or die "open $key.hits: $!";
	flock($hits, LOCK_EX) or die "flock: $!";
	seek($hits, 0, SEEK_SET) or die "seek: $!";
	my @previous = <$hits>;
	my $n = @previous + 1;
	print {$hits} "$range\n"; close $hits or die "close hits: $!";
	my $partial = $range && $path =~ m{^/(range|slice|saved)/};
	my $body = origin_body($path, $n, $range);
	my $status = $partial || $path eq '/multipart' ? '206 Partial Content' : '200 OK';
	my $cc = $path eq '/private' ? 'private' : $path =~ m{^/stale/} ? 'max-age=1' : 'max-age=300';
	my $ct = $path eq '/multipart' ? 'Multipart/ByteRanges; boundary=part' : 'application/octet-stream';
	print $c "HTTP/1.1 $status\r\nContent-Length: " . length($body)
		. "\r\nContent-Type: $ct\r\nETag: \"one\"\r\nCache-Control: $cc\r\n";
	print $c "Content-Range: bytes $1/262144\r\n" if $partial && $range =~ /^bytes=(\d+-\d+)$/;
	print $c "Vary: Accept-Language\r\n" if $path =~ m{^/(excluded-vary/|vary$)};
	print $c "Set-Cookie: a=b\r\n" if $path eq '/set-cookie';
	print $c "Content-Encoding: identity\r\n" if $path eq '/encoded';
	print $c "Connection: close\r\n\r\n", substr($body, 0, 32768);
	if (($n == ($path =~ m{^/stale/} ? 2 : 1) || $path =~ m{/independent$})
		&& !($path =~ m{^/slice/multi} && $range eq 'bytes=0-131071'))
	{
		wait_for(sub { -e "$key.go" }, "release of $path", 20);
	}
	print $c substr($body, 32768) unless $n == 1 && $path =~ m{^/short/};
}

sub origin {
	my ($dir) = @_;
	my $server = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
		LocalPort => port(8081), Listen => 32, ReuseAddr => 1) or die "listen: $!";
	$SIG{CHLD} = 'IGNORE';
	while (my $c = $server->accept()) {
		my $pid = fork(); die "fork: $!" unless defined $pid;
		if (!$pid) {
			close $server;
			$c->autoflush(1); serve($c, $dir);
			close $c;
			POSIX::_exit(0);
		}
		close $c;
	}
}

sub start_cache {
	my ($t, $http, $server) = @_;
	my $dir = $t->testdir();
	chmod 0755, $dir or die "chmod: $!";
	for (qw/cache other state store/) { mkdir "$dir/$_" or die "mkdir: $!"; chmod 0777, "$dir/$_" or die "chmod: $!"; }
	$t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%
daemon off;
worker_processes 2;
events { worker_connections 512; }
http {
    %%TEST_GLOBALS_HTTP%%
    sendfile on;
    $http
    server {
        listen 127.0.0.1:8080 reuseport;
        location = /pid { return 200 \$pid; }
        add_header X-Pid \$pid always;
        add_header X-Cache \$upstream_cache_status always;
        $server
    }
}
EOF
	$t->run_daemon(\&origin, $dir);
	$t->waitforsocket('127.0.0.1:' . port(8081));
	$t->run();
}

sub socket_for {
	my ($other) = @_;
	for (1 .. 100) {
		my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1:' . port(8080),
			Proto => 'tcp', Timeout => 5) or die "connect: $!";
		return $s unless defined $other;
		my $r = send_req($s, '/pid');
		headers($r);
		return $s if read_body($r) != $other;
	}
	die 'could not select another worker';
}

sub send_req {
	my ($s, $path, $extra, $method) = @_;
	$method ||= 'GET';
	$extra ||= '';
	http_start("$method $path HTTP/1.1\r\nHost: localhost\r\n$extra\r\n", socket => $s)
		or die "could not send $method $path";
	return { socket => $s, buf => '', h => {} };
}

sub receive {
	my ($r) = @_;
	my $s = $r->{socket};
	die 'response timed out' unless IO::Select->new($s)->can_read(5);
	my $n = sysread($s, my $buf, 16384);
	die "read: $!" unless defined $n;
	$r->{buf} .= $buf;
	return $n;
}

sub headers {
	my ($r) = @_;
	my $end;
	while (($end = index($r->{buf}, "\r\n\r\n")) < 0) { receive($r) or die 'EOF in headers'; }
	my ($status, @fields) = split /\r\n/, substr($r->{buf}, 0, $end + 4, '');
	($r->{status}) = $status =~ m{^HTTP/\S+ (\d+)} or die "bad status: $status";
	for (@fields) { my ($k, $v) = split /:\s*/, $_, 2; $r->{h}{lc $k} = $v; }
	$r->{left} = $r->{h}{'content-length'} // die 'missing Content-Length';
	return $r;
}

sub read_body {
	my ($r, $want, $allow_eof) = @_;
	$want //= $r->{left};
	while (length($r->{buf}) < $want) {
		next if receive($r);
		die 'short response' unless $allow_eof;
		last;
	}
	my $out = substr($r->{buf}, 0, $want, ''); $r->{left} -= length($out);
	return $out;
}

sub fetch {
	my ($path, $extra, $method) = @_;
	my $r = headers(send_req(socket_for(), $path, $extra, $method));
	$r->{body} = read_body($r);
	return $r;
}

sub legacy_guard {
	my ($t) = @_;
	return $t->read_file('error.log') =~ /no in-flight invalidation handler/;
}

sub finish_cache {
	my ($t, @killed) = @_;
	$t->stop();
	my $log = $t->read_file('error.log');
	my @alerts = $log =~ /^(.*\[alert\].*)$/mg;
	for my $pid (@killed) { @alerts = grep { !/worker process $pid exited on signal 9\b/ } @alerts; }
	is(join("\n", @alerts), '', 'no unexpected alerts');
	unlike($log, qr/AddressSanitizer|runtime error:/, 'no sanitizer errors');
}

1;
