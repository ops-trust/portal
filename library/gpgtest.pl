#! /usr/bin/perl

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

my $dbh = &common::get_dbh();

my ($uuid, $email) = @ARGV;
&gpgtest($uuid, $email);
exit 0;

sub gpgtest {
	my ($uuid, $email) = @_;

	print "gpgtest($uuid):\n";

	# don't do this next line until we know how to chgrp www-data non-root
	# &common::gpg_key_present($dbh, $uuid);

	print "gpg_key_path: ", &common::gpg_key_path($uuid), "\n";
	print "gpgcmd = '", &common::gpgcmd_user($uuid), "'\n";
	print "myfiles = (", join(' ', &common::gpgcmd_myfiles($uuid)), ")\n";

	my $x = &common::gpgcmd_present($uuid);
	print "present: $x\n";
	return unless $x;

	print "mykeys = (", join(' ', &common::gpgcmd_mykeys($uuid, $email)),
			")\n";
	print "allkeys:\n", &common::gpgcmd_allkeys($uuid), "---\n";
}
