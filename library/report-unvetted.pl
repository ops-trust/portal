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
use lib '!library!';
use common;

$ENV{PATH} .= ':/usr/local/sbin';

my $tgname = $ARGV[0] || 'main';

my $dbh = &common::get_dbh();
my $tg = &common::get_tg($dbh, $tgname);
my $db_tgname = $dbh->quote($tgname);

my $report1 = '';
foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT m.ident, m.affiliation,
		(NOW()::DATE - mt.entered::DATE) AS days
	FROM member m
	JOIN member_trustgroup mt ON (ROW(mt.member, mt.trustgroup) =
					ROW(m.ident, $db_tgname))
	WHERE mt.state = 'nominated'
	ORDER BY mt.entered;
}, {Slice => {}})}) {
	$report1 .= sprintf "    %3d     %s (%s)\n",
		$row->{days}, $row->{ident}, $row->{affiliation};
}
if (length $report1) {
	$report1 =
qq[The following members have been nominated but remain unvetted due to
lack of sufficient vouching from the membership.

  #/days  nominee

$report1
]	;
}

my $report2 = '';
foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT mv.vouchor, mv.vouchee
	  FROM member_vouch mv
	 WHERE mv.positive
	   AND mv.trustgroup = $db_tgname
	   AND mv.entered > (NOW() - '1 day'::INTERVAL)
	ORDER BY mv.entered;
}, {Slice => {}})}) {
	$report2 .= sprintf "  %-35s  %-35s\n",
		$row->{vouchor}, $row->{vouchee};
}
if (length $report2) {
	$report2 =
qq[The following vouches were recorded in the past 24 hours:

  vouchor                              vouchee

$report2
]	;
}

if (length $report1 || length $report2) {
	my ($vet_email, $vet_comment) = &common::email_addr($tg, 'vetting');
	$_ = &common::email_send($tg, $common::hostmaster,	# from
		$vet_email,					# to
		undef,						# cc
		"$vet_email ($vet_comment)",			# reply-to
		"nominations report",				# subject
\qq{$report1
$report2
Please visit the $common::portal_url web portal if you can vouch
for any of these, or reply to this e-mail if you have any questions
});
	print "$_\n" if defined $_;
}

exit 0;
