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

$| = 1;
my $dbh = &common::get_dbh();

my ($search) = @ARGV;
die "usage: $0 search_string" unless defined $search && length $search;
my $db_search = $dbh->quote($search);

my $save_ident = '';
foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT m.ident, m.descr, m.uuid, mt.email, mt.trustgroup, mt.state,
	       m.login_attempts, sf.type AS sft
	  FROM member m
	  JOIN member_trustgroup mt ON (mt.member = m.ident)
	  JOIN second_factors sf ON (sf.member = m.ident)
	 WHERE m.ident ~* $db_search
	    OR m.descr ~* $db_search
	    OR mt.email ~* $db_search
	ORDER BY m.ident
}, {Slice => {}} )}) {
	if ($row->{ident} ne $save_ident) {
		$save_ident = $row->{ident};
		print "[$save_ident] '$row->{descr}' $row->{uuid} " .
		      "LA: $row->{login_attempts} SF: $row->{sft}\n";
	}
	my $db_ident = $dbh->quote($save_ident);
	my $db_trustgroup = $dbh->quote($row->{trustgroup});
	my ($vouchor, $vouch_age) =
	    $dbh->selectrow_array(qq{
		SELECT mt.member, DATE_TRUNC('days', AGE(mv.entered))
		  FROM member_vouch mv
		  JOIN member m ON (m.ident = mv.vouchor)
		  JOIN member_trustgroup mt ON ROW(mt.member, mt.trustgroup) =
						ROW(m.ident, $db_trustgroup)
		  JOIN member_email me ON ROW(me.member, me.email) =
						ROW(mt.member, mt.email)
		 WHERE ROW(mv.vouchee, mv.trustgroup) =
			ROW($db_ident, $db_trustgroup)
		   AND mv.positive
		   AND me.pgpkey_id IS NOT NULL
		ORDER BY mv.entered
		LIMIT 1
	});
	printf "  [%s] <%s> %s (%s, %s)\n",
		$row->{trustgroup}, $row->{email}, $row->{state},
		$vouchor || '""', $vouch_age || '0';
}

exit 0;
