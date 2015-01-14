#! /usr/bin/env perl

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

$| = 1;
my $dbh = &common::get_dbh();

my ($ident) = @ARGV;
die "usage: $0 ident" unless defined $ident && length $ident;
my $db_ident = $dbh->quote($ident);

my $row = $dbh->selectrow_hashref(qq{
	SELECT m.descr
	  FROM member m
	 WHERE m.ident = $db_ident
});
die "no such member $db_ident" unless defined $row;
print "Found member: $db_ident ($row->{descr})\n", "\n";

foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT mt.trustgroup, mt.email
	  FROM member_trustgroup mt
	 WHERE mt.member = $db_ident
	   AND mt.state = 'vetted'
}, {Slice => {}} )}) {
	my $tg_ident = $row->{trustgroup};
	my $email = $row->{email};
	my $tg = &common::get_tg($dbh, $tg_ident);
	print "Approve in trustgroup $$tg->{db_ident} (y/n)? ";
	my $yesno = <STDIN>;
	if ($yesno) {
		my $stmt = qq{
			UPDATE member_trustgroup
			   SET state = 'approved'
			 WHERE ROW(member, trustgroup) =
				ROW($db_ident, $tg->{db_ident})
		};
		my $rc = $dbh->do($stmt);
		print "{$stmt} ==> $rc\n";
		if ($rc == 1) {
			&common::notify_newlyapproved($ident, $email, $tg);
		}
	}
}

exit 0;
