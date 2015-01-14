#!/usr/bin/env perl
#
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

use warnings;
use strict;

my $siteconfig = {};
my $file = undef;
my $filename = shift @ARGV;
open($file, "<$filename") || die "$filename: $!";
while (<$file>) {
	chomp;
	s/^\s+//go; # remove starting blanks
	s/\s+$//go; # remove ending blanks
	next if /^#/ || !length;
	die "siteconfig($_) syntax error" unless /=/o;
	$siteconfig->{$`} = eval $';
}
close($file);

while (<STDIN>) {
	my $n = 100;
	while (--$n > 0 && /\!(\w+)\!/) {
		if (!defined($siteconfig->{$1})) {
			die "Undefined siteconfig variable: $1";
		}
		$_ = $`.$siteconfig->{$1}.$';
	}
	die "expansion loop" if $n == 0;
	print;
}

exit 0;
