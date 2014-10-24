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

use strict;
use warnings;
use lib '!library!';
use common;

sub traced_do($$);

our $dbh = &common::get_dbh();
our %member_notifications = ();

my ($member) = @ARGV;
our $and_member = (defined $member)
	? 'AND (m.ident = '.$dbh->quote($member).')'
	: '';

# no state change toward: blocked nominated
foreach my $state (qw[vetted active inactive failed soonidle idle]) {
	my $rv = eval '&mon_'.$state;
	print "${state}: $rv\n" if $rv != 0;
}

my %tgh = ( );
foreach (keys %member_notifications) {
	my ($member, $trustgroup, $email) = split(/$;/, $_);
	my $new_state = $member_notifications{$_};

	# maintain a local cache of trustgroup refs
	$tgh{$trustgroup} = &common::get_tg($dbh, $trustgroup)
		unless defined $tgh{$trustgroup};
	die "odd trustgroup $trustgroup" unless defined $tgh{$trustgroup};
	my $tg = $tgh{$trustgroup};

	if ($debug) {
		printf "debug: new state for %s (%s) is %s (tg %s)\n",
			$member, $email, $new_state, $trustgroup;
	} elsif ($new_state eq 'vetted') {
		$_ = &common::notify_newlyvetted($member, $email, $tg);
	} elsif ($new_state eq 'active') {
		$_ = &common::notify_newlyactive($member, $email, $tg);
	} elsif ($new_state eq 'inactive') {
		$_ = &common::notify_newlyinactive($member, $email, $tg);
	} elsif ($new_state eq 'failed') {
		$_ = &common::notify_newlyfailed($member, $email, $tg);
	} elsif ($new_state eq 'soonidle') {
		$_ = &common::notify_soonidle($member, $email, $tg);
	} elsif ($new_state eq 'idle') {
		$_ = &common::notify_newlyidle($member, $email, $tg);
	} else {
		die "odd state '$new_state' for $member in $trustgroup";
	}
	print "$_\n" if defined $_;
}

exit 0;

#
# "vetted" means you've been invouched.
#
# nominated -> vetted (when you have enough invouches)
# 
sub mon_vetted {
	my $rv = 0;

	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		  LEFT OUTER JOIN (
			SELECT mv.vouchee, mv.trustgroup,
				COUNT(mv.vouchee) AS num
			  FROM member_vouch mv
			 WHERE mv.positive
			GROUP BY mv.vouchee, mv.trustgroup
		  ) AS invouch
			ON ROW(invouch.vouchee, invouch.trustgroup) =
				ROW(m.ident, tg.ident)
		 WHERE COALESCE(invouch.num, 0) >= tg.target_invouch
		   AND (mt.state = 'nominated')
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup mt
			   SET state = 'vetted'
			 WHERE ROW(mt.member, mt.trustgroup, mt.state) =
				ROW($db_member, $db_trustgroup, 'nominated')
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'vetted'
			unless $row->{furlough} || $row->{no_email};
		print "vetted: $row->{member} ($row->{trustgroup})\n";
	};
	return $rv;
}

#
# "active" means you've done everything you need to do and the system
#        is not sending you any annoy-o-grams about your checklist.
#
# {approved,inactive} -> active (when you've outvouched and set a pgp key)
#
# {soon,}idle -> active (when you've logged in or sent mail recently)
#

sub mon_active {
	my $rv = 0;

	#
	# {approved,inactive} -> active
	#
	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN member_email me ON ROW(me.member, me.email) =
						ROW(mt.member, mt.email)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		  LEFT OUTER JOIN (
			SELECT mv.vouchor, mv.trustgroup,
				COUNT(mv.vouchor) AS num
			  FROM member_vouch mv
			 WHERE mv.positive
			GROUP BY mv.vouchor, mv.trustgroup
		  ) AS outvouch
			ON ROW(outvouch.vouchor, outvouch.trustgroup) =
				ROW(m.ident, tg.ident)
		 WHERE mt.state IN ('inactive', 'approved')
		   AND (me.pgpkey_id IS NOT NULL
			OR NOT tg.pgp_required)
		   AND (COALESCE(outvouch.num, 0) >= tg.min_outvouch
			OR NOT tg.please_vouch)
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup mt
			   SET state = 'active'
			 WHERE ROW(mt.member, mt.trustgroup) =
				ROW($db_member, $db_trustgroup)
			   AND state IN ('inactive', 'approved')
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'active'
			unless $row->{furlough} || $row->{no_email};
		print "active: $row->{member} ($row->{trustgroup})\n";
	};

	#
	# idle -> active
	#
	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		  LEFT OUTER JOIN (
			SELECT mv.vouchor, mv.trustgroup,
				COUNT(mv.vouchor) AS num
			  FROM member_vouch mv
			 WHERE mv.positive
			GROUP BY mv.vouchor, mv.trustgroup
		  ) AS outvouch
			ON ROW(outvouch.vouchor, outvouch.trustgroup) =
				ROW(m.ident, tg.ident)
		 WHERE ((NOW() - m.activity) <= tg.max_inactivity
			OR NOT tg.can_time_out)
		   AND (mt.state = 'idle')
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup mt
			   SET state = 'active'
			 WHERE ROW(mt.member, mt.trustgroup, mt.state) =
				ROW($db_member, $db_trustgroup, 'idle')
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'active'
			unless $row->{furlough} || $row->{no_email};
		print "active: $row->{member} ($row->{trustgroup})\n";
	};

	#
	# soonidle -> active
	#
	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		  LEFT OUTER JOIN (
			SELECT mv.vouchor, mv.trustgroup,
				COUNT(mv.vouchor) AS num
			  FROM member_vouch mv
			 WHERE mv.positive
			GROUP BY mv.vouchor, mv.trustgroup
		  ) AS outvouch
			ON ROW(outvouch.vouchor, outvouch.trustgroup) =
				ROW(m.ident, tg.ident)
		 WHERE ((NOW() - m.activity) <=
				(tg.max_inactivity - tg.idle_guard)
			OR NOT tg.can_time_out)
		   AND (mt.state = 'soonidle')
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup mt
			   SET state = 'active'
			 WHERE ROW(mt.member, mt.trustgroup, mt.state) =
				ROW($db_member, $db_trustgroup, 'soonidle')
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'active'
			unless $row->{furlough} || $row->{no_email};
		print "active: $row->{member} ($row->{trustgroup})\n";
	};

	return $rv;
}

#
# "inactive" means you used to be active but lost your pgp key or deleted
# too many outvouches.
#
# active -> inactive (when a pgp key is required and you don't have one,
#	or when you no longer have enough outvouches.)
# 
sub mon_inactive {
	my $rv = 0;

	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email,
			me.pgpkey_id IS NULL AS pgpkey_null,
			COALESCE(outvouch.num, 0) AS outvouch_num
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN member_email me ON ROW(me.member, me.email) =
						ROW(mt.member, mt.email)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		  LEFT OUTER JOIN (
			SELECT vouchor, trustgroup, COUNT(vouchor) AS num
			  FROM member_vouch
			 WHERE positive
			GROUP BY vouchor, trustgroup
		  ) AS outvouch
			ON ROW(outvouch.vouchor, outvouch.trustgroup) =
				ROW(m.ident, tg.ident)
		 WHERE (mt.state = 'active'
			AND ((me.pgpkey_id IS NULL AND tg.pgp_required)
			     OR (COALESCE(outvouch.num, 0) < tg.min_outvouch
				 AND tg.please_vouch)))
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup
			   SET state = 'inactive'
			 WHERE ROW(member, trustgroup) =
				ROW($db_member, $db_trustgroup)
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'inactive'
			unless $row->{furlough} || $row->{no_email};
		printf "inactive: %s (%s) PGP %s, OutV %d\n",
			$row->{member}, $row->{trustgroup},
			$row->{pgpkey_null} ? 'Null' : 'Ok',
			$row->{outvouch_num};
	};

	return $rv;
}

#
# "failed" means it's been X days since you were nominated and you
# are still not vouched. or, if you've never been active (so, you
# can't log in and you're not blocked) and you lose all your vouches.
#
# the only way out of "failed" is if someone vouches you again.
#
sub mon_failed {
	my $rv = 0;

	#
	# nominated => failed (if you time out)
	#
	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		 WHERE ((NOW()::DATE - mt.entered::DATE) > tg.max_vouchdays)
		   AND (mt.state = 'nominated')
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup mt
			   SET state = 'failed'
			 WHERE ROW(mt.member, mt.trustgroup, mt.state) =
				ROW($db_member, $db_trustgroup, 'nominated')
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'failed'
			unless $row->{furlough} || $row->{no_email};
		print "failed: $row->{member} ($row->{trustgroup})\n";
	};

	# this is just a convenient place to do this, it could also be in
	# a new dbck-* script.  failed nominations lose all vouches.
	traced_do($dbh, qq{
		DELETE FROM member_vouch mv
		 WHERE ROW(mv.vouchee, mv.trustgroup) IN
			(SELECT mt.member, mt.trustgroup
			   FROM member_trustgroup mt
			  WHERE mt.state = 'failed')
	});

	#
	# (never logged in) => failed (if you lose all your invouches)
	#
	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		  LEFT OUTER JOIN (
			SELECT mv.vouchee, mv.trustgroup,
				COUNT(mv.vouchee) AS num
			  FROM member_vouch mv
			 WHERE mv.positive
			GROUP BY mv.vouchee, mv.trustgroup
		  ) AS invouch
			ON ROW(invouch.vouchee, invouch.trustgroup) =
				ROW(m.ident, tg.ident)
		 WHERE COALESCE(invouch.num, 0) = 0
		   AND (mt.state IN ('nominated', 'vetted', 'approved'))
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup mt
			   SET state = 'failed'
			 WHERE ROW(mt.member, mt.trustgroup) =
				ROW($db_member, $db_trustgroup)
			   AND mt.state IN ('nominated', 'vetted', 'approved')
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'failed'
			unless $row->{furlough} || $row->{no_email};
		print "failed: $row->{member} ($row->{trustgroup})\n";
	};

	return $rv;
}

#
# "soonidle" means it's been X - Y (e.g. "60" - "7 days")
#	since you either logged into the UI or sent e-mail to one of the lists.
#
# active -> soonidle (when you've been inactive too long)
# 
sub mon_soonidle {
	my $rv = 0;

	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		 WHERE (tg.can_time_out AND
			(NOW() - m.activity) >
				(tg.max_inactivity - tg.idle_guard))
		   AND (mt.state = 'active')
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup mt
			   SET state = 'soonidle'
			 WHERE ROW(mt.member, mt.trustgroup, mt.state) =
				ROW($db_member, $db_trustgroup, 'active')
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'soonidle'
			unless $row->{furlough} || $row->{no_email};
		print "soonidle: $row->{member} ($row->{trustgroup})\n";
	};
	return $rv;
}

#
# "idle" means it's been X days (imagine "60") since you either
#       logged into the UI or sent e-mail to one of the lists.
#
# {active,soonidle} -> idle (when you've been inactive too long)
# 
sub mon_idle {
	my $rv = 0;

	foreach my $row (@{$dbh->selectall_arrayref(qq{
		SELECT m.ident AS member, m.furlough, m.no_email,
			mt.trustgroup, mt.email
		  FROM member m
		  JOIN member_trustgroup mt ON (mt.member = m.ident)
		  JOIN trustgroup tg ON (tg.ident = mt.trustgroup)
		 WHERE (tg.can_time_out AND
			(NOW() - m.activity) > tg.max_inactivity)
		   AND (mt.state IN ('active', 'soonidle'))
		   $and_member
	}, {Slice => {}} )}) {
		my $db_member = $dbh->quote($row->{member});
		my $db_trustgroup = $dbh->quote($row->{trustgroup});
		$rv += traced_do($dbh, qq{
			UPDATE member_trustgroup mt
			   SET state = 'idle'
			 WHERE ROW(mt.member, mt.trustgroup) =
				ROW($db_member, $db_trustgroup)
			   AND (mt.state IN ('active', 'soonidle'))
		});
		$member_notifications{$row->{member}, $row->{trustgroup},
			$row->{email}} = 'idle'
			unless $row->{furlough} || $row->{no_email};
		print "idle: $row->{member} ($row->{trustgroup})\n";
	};
	return $rv;
}

#
# traced_do
#
sub traced_do($$) {
	my ($dbh, $stmt) = @_;
	my $rv;

	if ($debug) {
		$stmt =~ s/\n/\040/go;
		$stmt =~ s/\s+/\040/go;
		print "traced_do: $stmt\n";
		$rv = 1;
	} else {
		# XXX should we be using common::audited_do here?
		$rv = $dbh->do($stmt);
	}
	return $rv;
}
