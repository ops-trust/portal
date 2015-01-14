#!/usr/bin/env perl

# This file is part of the Ops-T Portal.
#
#   Copyright 2014 Operations Security Administration, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#


use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin;
use common;
use Fcntl qw(:flock LOCK_EX LOCK_NB);

my $dbh = &common::get_dbh();

my $mll = {};
#
# Find all Mailing-lists, generate any missing keys.
foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT lhs,descr,trustgroup,pubkey,seckey FROM mailinglist
}, { Slice=>{} } )}) {
	my $ml = &common::email_ml_lhs($row->{trustgroup}, $row->{lhs});
	$mll->{$ml} = $row;
	if (!&common::gpg_mlkey_present($dbh,$row->{lhs},$row->{trustgroup})){
		&generate_ml_key($dbh,$ml,$row);
	}
}

my $lf = undef;
open($lf, $common::ml_keys) || die "open $common::ml_keys: $!";
flock($lf, LOCK_EX | LOCK_NB) || die "flock $common::ml_keys: $!";

#
# Find all list/keys already on disk.
my $ml_keys = {};
my $mlkdir = undef;
opendir($mlkdir, $common::ml_keys) || die "opendir: $!";
while ($_ = readdir($mlkdir)) {
	next if $_ eq '.' || $_ eq '..';
	next if $_ eq 'random_seed';
	if (! /\.(gpg|secring)~?$/) {
		print "mystery file: $_\n";
	} elsif (-z $_) {
		print "zero length file: $_\n";
	} else {
		$ml_keys->{$`} = undef;
	}
}
closedir($mlkdir);

#
# Removing old/stale files for keys.
foreach my $ml_key (keys %{$ml_keys}) {
	next if $ml_key eq 'trustdb' ||
		$ml_key eq 'pubring' ||
		$ml_key eq 'secring';
	if (!exists $mll->{$ml_key}) {
		print "removing listless list key: $ml_key\n";
		unlink $common::ml_keys.'/'.$ml_key.'.gpg';
		unlink $common::ml_keys.'/'.$ml_key.'.gpg~';
		unlink $common::ml_keys.'/'.$ml_key.'.secring';
		next;
	}
}

flock $lf, LOCK_UN;
close $lf;
$lf = undef;

exit 0;

sub generate_ml_key() {
	my ($dbh,$ml,$row) = @_;
	print "generating list key for: $ml\n";
	my $gpg = undef;
	open($gpg, "| /usr/bin/gpg --homedir $common::ml_keys " .
		'--batch --no-secmem-warning ' .
		'--no-permission-warning ' .
		'--gen-key 2>&1') || die;
	print {$gpg} join("\n",
		qq{Key-Type: DSA},
		qq{Key-Length: 1024},
		qq{Subkey-Type: ELG-E},
		qq{Subkey-Length: 2048},
		qq{Name-Real: $row->{lhs}},
		qq{Name-Comment: $row->{descr}},
		qq{Name-Email: $ml\@$common::domain},
		qq{Expire-Date: 0},
		qq{\%pubring $common::ml_keys/$ml.gpg},
		qq{\%secring $common::ml_keys/$ml.secring});
	close($gpg);
	unlink $common::ml_keys.'/pubring.gpg';
	chown $common::www_uid, $common::www_gid,
		$common::ml_keys.'/'.$ml.'.gpg',
		$common::ml_keys.'/'.$ml.'.secring';
	my $secring_fh = undef;
	open($secring_fh,'gpg --export-secret-keys --armor '.
		'--homedir '.$common::ml_keys.
		' --secret-keyring '.$common::ml_keys."/$ml.secring |");
	my $seckey = '';
	while (read($secring_fh, my $buffer, 4096)) {
		$seckey .= $buffer;
	}
	close($secring_fh);
	my $db_sec = $dbh->quote($seckey);
	my $pubring_fh = undef;
	open($pubring_fh,'gpg --export --armor --homedir '.
		$common::ml_keys.' --keyring '.
		$common::ml_keys."/$ml.gpg |");
	my $pubkey = "";
	while (read($pubring_fh, my $buffer, 4096)) {
		$pubkey .= $buffer;
	}
	close($pubring_fh);
	my $db_pub = $dbh->quote($pubkey);
	my $db_tg = $dbh->quote($row->{trustgroup});
	my $db_lhs = $dbh->quote($row->{lhs});

	$dbh->do( qq{
		UPDATE mailinglist 
		   SET seckey = $db_sec, 
		       pubkey = $db_pub,
		       key_update_at = now() 
		 WHERE trustgroup = $db_tg 
		   AND lhs = $db_lhs});
}
