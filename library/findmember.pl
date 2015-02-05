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
	SELECT m.ident, mt.email, mt.trustgroup, mt.state, me.pgpkey_id
	  FROM member m
	  JOIN member_trustgroup mt ON (mt.member = m.ident)
    INNER JOIN member_email me ON (mt.email = me.email)
	 WHERE m.ident ~* $db_search
	    OR m.descr ~* $db_search
	    OR mt.email ~* $db_search
        GROUP BY mt.trustgroup, m.ident, mt.email, mt.state, me.pgpkey_id
	ORDER BY m.ident, mt.trustgroup
}, {Slice => {}} )}) {
	if ($row->{ident} ne $save_ident) {
		$save_ident = $row->{ident};
		my $q_ident = $dbh->quote($save_ident);

		my ($login_attempts, $descr, $uuid) = $dbh->selectrow_array(qq{
				SELECT login_attempts, descr, uuid
				FROM member
				WHERE ident = $q_ident
				});

		my $sft = '';
		foreach my $sfts (@{$dbh->selectall_arrayref(qq{
				SELECT sf.type AS sft, COUNT(*) AS cnt
				FROM member m
				JOIN second_factors sf ON (sf.member = m.ident)
				WHERE m.ident = $q_ident
				GROUP BY sf.type
				}, , {Slice => {}} )}) {
			$sft .= $sfts->{cnt}."x".$sfts->{sft}." ";
		}
		$sft = common::trim($sft);

		printf "[%s] '%s' %s LA: %s, SF: %s\n",
			$save_ident, $descr, $uuid,
			$login_attempts || "none",
			$sft || "none";
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
		ORDER BY mv.entered
		LIMIT 1
	});
	printf "  [%s] <%s> %s %s (%s, %s)\n",
		$row->{trustgroup}, $row->{email}, $row->{state},
		$row->{pgpkey_id} || 'NO-PGP',
		$vouchor || '""', $vouch_age || '0';
}

exit 0;
