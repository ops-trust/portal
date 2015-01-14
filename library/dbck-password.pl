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
use Text::Wrap;

my $dbh = &common::get_dbh();

foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT m.ident, mt.trustgroup, mt.email
	  FROM member m
	  JOIN member_trustgroup mt ON (mt.member = m.ident)
	  JOIN member_state ms ON (ms.ident = mt.state)
	 WHERE m.password IS NULL
	   AND ms.can_login
	GROUP BY m.ident, mt.trustgroup, mt.email
}, {Slice => {}})}) {
	my $db_trustgroup = $dbh->quote($row->{trustgroup});
	my $db_ident = $dbh->quote($row->{ident});
	my $tg = &common::get_tg($dbh, $row->{trustgroup});
	my ($vouchor_email, $vouchor_uuid, $pgpkey_id) =
	    $dbh->selectrow_array(qq{
		SELECT mt.email, m.uuid, me.pgpkey_id
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
	my $password = join('',
		('.', '/', '0'..'9', 'A'..'Z', 'a'..'z')
		[rand 64, rand 64, rand 64, rand 64,
		 rand 64, rand 64, rand 64, rand 64]);
	my $db_newcrypt = $dbh->quote(&common::mkpw_portal($password));
	my $stmt = qq{	UPDATE member
			   SET password = $db_newcrypt
			 WHERE ident = $db_ident	};
	$dbh->do($stmt);
#debug	print "$row->{ident}: $vouchor_email ($vouchor_uuid) [$pgpkey_id]\n";
	my ($size, $error) = &common::email_send_pgp($tg, $common::hostmaster,
		$vouchor_email,				# recip email
		$vouchor_uuid,				# recip uuid
		$pgpkey_id,				# pgpkey id
		undef,					# cc
		undef,					# reply-to
		"New password for $row->{ident}",	# subject
		Text::Wrap::fill('', '', (
qq{A new password has been assigned for $row->{ident} and as the vouchor
or oldest nominator having a PGP key, you are hereby deputized to inform
$row->{ident} of this password.  Please use a non-plaintext delivery method
such as in-person, telephone, or encrypted e-mail.  Also please remind
$row->{ident} that since you know their current password, they should set a
new one, and ask them to review their contact information including their own
PGP key as well as their portrait, closest airport, and so on.  The web portal
is located at $common::domain as before.

The new (temporary) password for $row->{ident} is: $password

Please do not print or save this e-mail.

Sincerely yours,

$tg->{descr} HOSTMASTER
}		))					# body
	);
	# we don't look at $size since $error is always empty when
	# there has been no failure, but we want to see warnings.
	print STDERR $error if defined $error;
}

exit 0;
