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


# notify-idle -- send e-mail to members who are idle

use strict;
use warnings;
use lib '!library!';
use common;

$ENV{PATH} .= ':/usr/local/sbin';

my $dbh = &common::get_dbh();
my $tgs = { };

foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT mt.email, m.descr, m.ident, m.affiliation, mt.trustgroup
	  FROM member m
	  JOIN member_trustgroup mt ON (mt.member = m.ident)
	 WHERE mt.state = 'idle'
	   AND NOT m.furlough
	   AND NOT m.no_email
}, {Slice => {}})}) {
	my $tgname = $row->{trustgroup};
	$tgs->{$tgname} = &common::get_tg($dbh, $tgname)
		unless defined $tgs->{$tgname};
	&notify($tgs->{$tgname}, $dbh,
		@$row{qw[email descr ident affiliation]});
}

exit 0;

sub notify {
	my ($tg, $dbh, $email, $descr, $ident, $affiliation) = @_;

	$descr =~ s/"//go;
	my $db_email = $dbh->quote($email);
	print "notify-idle: [$tg->{ident}] $ident ($affiliation)\n";
	$_ = &common::email_send($tg, $common::hostmaster,	# from
		$email,						# to
		undef,						# cc
		undef,						# reply-to
		"[ops-t] you are idle in '$tg->{descr}'",	# subject
\qq{Your membership in the opsec trust group:

	$tg->{descr}

...has reached the 'idle' state, which means you're not receiving
any group e-mails.  You have the following options:

1. do nothing, and continue to receive mail like this periodically.
2. log into the portal or send some group e-mail, you'll become non-idle.
3. log into the portal and select 'furlough' in your profile.

Questions about this can be addressed to <!supportemail!>.
});
	print "$_\n" if defined $_;
}
