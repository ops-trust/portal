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

# notify-unvetted -- send e-mail to vettors for each nominee who is
#			still unvetted and/or have no pgp key

use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin;
use common;
use Text::Wrap;

$ENV{PATH} .= ':/usr/local/sbin';

my $tgname = $ARGV[0] || 'main';

my $dbh = &common::get_dbh();
my $tg = &common::get_tg($dbh, $tgname);
my $db_tgname = $dbh->quote($tgname);

foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT m.ident, m.descr
	FROM member m
	JOIN member_trustgroup mt ON (mt.member = m.ident)
	WHERE mt.state = 'nominated'
	  AND mt.trustgroup = $db_tgname
}, {Slice => {}})}) {
	&notify($dbh, $tg, @$row{qw[ident descr]});
}

exit 0;

sub notify {
	my ($dbh, $tg, $ident, $descr) = @_;

	$descr =~ s/"//go;
	my $db_ident = $dbh->quote($ident);
	my ($vouchor, $vouchor_descr, $vouchor_email, $howlong) =
		$dbh->selectrow_array(qq{
			SELECT mv.vouchor, m.descr, mt.email,
				DATE_TRUNC('days', AGE(mv.entered))
			FROM member_vouch mv
			JOIN member m ON (mv.vouchor = m.ident)
			JOIN member_trustgroup mt ON
				ROW(mt.member, mt.trustgroup) =
					ROW(m.ident, $tg->{db_ident})
			WHERE ROW(mv.vouchee, mv.trustgroup) =
					ROW($db_ident, $db_tgname)
				AND mv.positive
			ORDER BY mv.entered
			LIMIT 1
		});
	return unless defined $vouchor;

	$_ = &common::email_send($tg, $common::hostmaster,	# tg, from
		$vouchor_email,					# to
		undef,						# cc
		undef,						# reply-to
		"nomination status for $ident ($descr)",	# subject
		Text::Wrap::fill('', '', (
qq{$ident ($descr) was nominated by $vouchor ($vouchor_descr) $howlong ago
but the membership process is incomplete.

Not enough members have vouched yet.  $vouchor should try to get other
members vouch for this candidate.
}		))						# body
	);
	print "$_\n" if defined $_;
}
