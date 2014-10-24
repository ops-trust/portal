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
use lib '!library!';
use common;

$| = 1;
my $dbh = &common::get_dbh();

my ($ident, $which) = @ARGV;
die "usage: $0 ident" unless defined $ident && length $ident;
my $db_ident = $dbh->quote($ident);
$which = 'portal' unless $which;
die "usage: $0 $ident [portal|chat]"
	unless $which eq 'portal' || $which eq 'chat';

my $row = $dbh->selectrow_hashref(qq{
	SELECT m.descr
	  FROM member m
	 WHERE m.ident = $db_ident
});
die "no such member $db_ident" unless defined $row;
print "Found member: $db_ident ($row->{descr})\n\n";

print "Enter new password: ";
my $pass1 = <STDIN>;
die unless $pass1;
chomp $pass1;

print "Re-enter new password: ";
my $pass2 = <STDIN>;
die unless $pass2;
chomp $pass2;

die "password mismatch" unless $pass1 eq $pass2;

my $dbh_newpw;
if ($pass1 eq '') {
	$dbh_newpw = 'NULL';
} else {
	my $newpw;
	$newpw = &common::mkpw_portal($pass1) if $which eq 'portal';
	$newpw = &common::mkpw_portal($pass1) if $which eq 'chat';
	die "bad which ($which)" unless $newpw;
	$dbh_newpw = $dbh->quote($newpw);
}

my $db_pwfield;
$db_pwfield = 'password' if $which eq 'portal';
$db_pwfield = 'passwd_chat' if $which eq 'chat';
die "bad which ($which)" unless $db_pwfield;
# Update the member's passwd, and set login_attempts to zero.
my $stmt = qq{
	UPDATE member
	   SET $db_pwfield = $dbh_newpw, login_attempts = 0
	 WHERE ident = $db_ident
};
my $rc = $dbh->do($stmt);
print "{$stmt} ==> $rc\n";
&common::password_synch($ident);

exit 0;
