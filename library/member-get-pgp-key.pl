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
use lib '/proj/ops-trust/library';
use common;

$| = 1;
my $dbh = &common::get_dbh();

my ($search) = @ARGV;
die "usage: $0 memberident" unless defined $search && length $search;
my $db_search = $dbh->quote($search);

foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT keyring
	  FROM member_email
	 WHERE member = $db_search AND keyring <> '';
}, {Slice => {}} )}) {
	print $row->{keyring};
}

exit 0;
