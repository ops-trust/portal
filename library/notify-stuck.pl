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

# -s: -debug
our $debug = $debug if defined $debug;

# notify-stuck -- send e-mail to nominator for each nominee who is
#			still approved (and therefore not yet active)

use strict;
use warnings;
use lib '!library!';
use common;
use Text::Wrap;

$ENV{PATH} .= ':/usr/local/sbin';

my $dbh = &common::get_dbh();
my %tgh = ();

foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT mt.trustgroup, m.ident, m.descr, mt.state, me.email,
		DATE_TRUNC('days', AGE(mt.entered)) AS entered_age,
		DATE_TRUNC('days', AGE(mt.activity)) AS activity_age,
		me.pgpkey_id IS NOT NULL AS haspgp,
		COALESCE(invouch.num, 0) AS inv,
		COALESCE(outvouch.num, 0) AS outv
	FROM member m
	JOIN member_trustgroup mt ON mt.member = m.ident
	JOIN member_email me
		ON ROW(me.member, me.email) = ROW(mt.member, mt.email)
	LEFT OUTER JOIN (
		SELECT mv.vouchee, mv.trustgroup, COUNT(mv.vouchee) AS num
		  FROM member_vouch mv
		 WHERE mv.positive
		GROUP BY mv.vouchee, mv.trustgroup
	) AS invouch
		ON ROW(invouch.vouchee, invouch.trustgroup) =
			ROW(m.ident, mt.trustgroup)
	LEFT OUTER JOIN (
		SELECT mv.vouchor, mv.trustgroup, COUNT(mv.vouchor) AS num
		  FROM member_vouch mv
		 WHERE mv.positive
		GROUP BY mv.vouchor, mv.trustgroup
	) AS outvouch
		ON ROW(outvouch.vouchor, outvouch.trustgroup) =
			ROW(m.ident, mt.trustgroup)
	WHERE mt.state IN ('nominated', 'approved')
	  AND DATE_TRUNC('days', AGE(mt.entered)) > '10 days'::INTERVAL
	  AND DATE_TRUNC('days', AGE(mt.activity)) > '5 days'::INTERVAL
	ORDER BY mt.trustgroup
}, {Slice => {}})}) {
	# maintain a local cache of trustgroup refs
	my $tgname = $row->{trustgroup};
	$tgh{$tgname} = &common::get_tg($dbh, $tgname)
		unless defined $tgh{$tgname};
	die "odd trustgroup $tgname" unless defined $tgh{$tgname};
	my $tg = $tgh{$tgname};

	&notify($dbh, $tg, @$row{qw[
		ident descr state email
		entered_age activity_age
		haspgp inv outv
	]});
}

exit 0;

sub notify {
	my ($dbh, $tg, $ident, $descr, $state, $email,
		$entered_age, $activity_age,
		$haspgp, $inv, $outv) = @_;

	$descr =~ s/"//go;
	my $db_ident = $dbh->quote($ident);
	my ($vouchor, $vouchor_descr, $vouchor_email) =
		$dbh->selectrow_array(qq{
			SELECT mv.vouchor, m.descr, mt.email
			FROM member_vouch mv
			JOIN member m ON (mv.vouchor = m.ident)
			JOIN member_trustgroup mt ON
				ROW(mt.member, mt.trustgroup) =
					ROW(m.ident, $tg->{db_ident})
			WHERE ROW(mv.vouchee, mv.trustgroup) =
					ROW($db_ident, $tg->{db_ident})
				AND mv.positive
			ORDER BY mv.entered
			LIMIT 1
		});
	return unless defined $vouchor;

	my $body = Text::Wrap::fill('', '', (
qq{$ident ($descr) was nominated
$entered_age ago 
to the $tg->{descr}
by $vouchor ($vouchor_descr)
but appears to be stuck in the '$state' state
and has been stuck there for $activity_age.
}	))."\n";

	if ($tg->{pgp_required} && !$haspgp) {
		$body .= qq{\nA PGP key is required for this trust group.\n};
	}

	if ($inv < $tg->{target_invouch}) {
		my $n = $tg->{target_invouch} - $inv;
		my $s = ($n == 1) ? "" : "s";
		my $t = sprintf "%d more member%s", $n, $s;
		$body .= qq{\nAt least ${t} need to vouch for this nominee.\n};
	}

	if ($outv < $tg->{min_outvouch}) {
		my $n = $tg->{min_outvouch} - $outv;
		my $s = ($n == 1) ? "" : "s";
		my $t = sprintf "%d more member%s", $n, $s;
		$body .= qq{\nThis nominee needs to vouch for at least ${t}.\n};
	}

	my $cc = undef;
	if ($tg->{ident} ne 'main') {
		$cc = 'admin@'.$common::domain;
		$cc = $tg->{ident}.'-'.$cc unless $tg->{ident} eq 'main';
	}

	print "stuck [$tg->{ident}]: $ident ($state) [$vouchor]\n";
	if ($debug) {
		print "To: $vouchor_email, $email;\n",
			defined $cc ? "cc: $cc;\n" : '',
			"Subj: $ident (descr) is stuck in '$state'\n",
			"\n", $body, "---\n";
	} else {
		$_ = &common::email_send($tg, $common::hostmaster, # tg, from
			[$vouchor_email, $email],		# to
			$cc,					# cc
			undef,					# reply-to
			"$ident ($descr) stuck in '$state'",	# subject
			$body					# body
		);
		print "$_\n" if defined $_;
	}
}
