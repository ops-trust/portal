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
use Mail::SendEasy;
use Text::Wrap;
use Data::Dumper;
use File::Find;

sub bad_pgpfile($);
sub reset_keyid($$$);

my $debug = 0;
$Data::Dumper::Indent = 1;

our $dbh = &common::get_dbh();
our $tg = &common::get_tg($dbh, 'main');

our %notices = ( );

print "loading emails from database\n" if $debug;
my $loaded_uuid = { };
my $key_uuids = { };
my $emails = { };
foreach my $row (@{$dbh->selectall_arrayref(qq{
	SELECT m.ident, m.no_email, m.uuid, me.pgpkey_id, me.email, 
		date(me.pgpkey_expire) as pgpkey_expire, 
		date_part('epoch', me.pgpkey_expire - now()) as pgpkey_remain,
		date_part('epoch', me.keyring_update_at) as pgpkey_update
	FROM member_email me
	JOIN member m ON (m.ident = me.member)
}, {Slice => {}})}) {
	if (defined $row->{pgpkey_id}){
		if (!defined $loaded_uuid->{$row->{uuid}}) {
			&common::gpg_key_present($dbh, $row->{uuid});
			$row = &check_expired($dbh,$row);
			$loaded_uuid->{$row->{uuid}} = [ ];
			&gen_email_list($row->{uuid},\@{$loaded_uuid->{$row->{uuid}}});
		}
		if (!&key_has_email($row->{email},$loaded_uuid->{$row->{uuid}})) {
			push @{$notices{$row->{email}}},
qq{The PGP keyring file you uploaded $row->{pgpkey_id} 
does not contain an alias for your currently selected e-mail $row->{email} };
			print 'No e-mail match: '.$row->{uuid}."\n";
			print 'E-mail '.$row->{email}."\n";
			foreach my $key (@{$loaded_uuid->{$row->{uuid}}}) {
				print "\t$key\n";
			}
		}
		$key_uuids->{$row->{uuid}} = $row;
	}
	if ($row->{no_email}) {
		$emails->{$row->{email}}->{no_email} = 1;
	}
}

print "reading the pgpkeys directory\n" if $debug;
my $pgpkey_files = { };
my $pgpdir = undef;

my $paths = { };

finddepth(\&wanted, $common::pgpkeys);


print "sending notices\n" if $debug;
foreach my $notice_email (keys %notices) {
	my $body = join("\n\n", @{$notices{$notice_email}});
	my $to = $notice_email;

	if ($debug) {
		print "notice ($to)\n", $body, "---\n";
	} elsif (!$emails->{$to}->{no_email}) {
		&common::email_send($tg, $common::hostmaster,	# from
			$to,					# to
			undef,					# cc
			undef,					# reply-to
			"PGP key ring trouble",			# subject
			$body);					# body
	}
}

sub wanted {
	if (-d $File::Find::name) {
		if ($File::Find::name =~ m/^$common::pgpkeys\/([a-f0-9])\/([a-f0-9])$/){
			if (!defined $pgpkey_files->{"$1/$2"} ){
				rmdir $File::Find::name;
				print "Unused dir: $File::Find::name\n";
			}
		} elsif ($File::Find::name =~ m/^$common::pgpkeys\/([a-f0-9])$/){
			if (!defined $pgpkey_files->{$1} ){
				rmdir $File::Find::name;
				print "Unused dir: $File::Find::name\n";
			}
		} elsif ($File::Find::name =~ m/^$common::pgpkeys$/){
			#This is our root, don't act on it.
		} else {
			print "UNKNOWN DIR: $File::Find::name\n";
		}
	} else {
		if ($File::Find::name =~ m/^$common::pgpkeys\/([a-f0-9])\/([a-f0-9])\/([a-f0-9-]{36}).(gpg|gpg\~|secring|trustdb)$/) {
			my $uuid = $3;
			if (defined $key_uuids->{$uuid}){
				$pgpkey_files->{$1} = 1;
				$pgpkey_files->{"$1/$2"} = 1;
			} else {
				unlink $File::Find::name;
				print "\tKEY BAD: $uuid \n"
			}
		} else {
			print "Mystery_File: $File::Find::name\n";
		}
	}
}

sub check_expired {
	my ($dbh,$row) = @_;
	my @expire_at = &common::gpgcmd_keyexpire($row->{uuid},$row->{pgpkey_id});
	my $pgp_change = 0;
	if (@expire_at) {
		if (defined $row->{pgpkey_expire}) {
			if ($expire_at[0] ne $row->{pgpkey_expire}) {
				$pgp_change = 1;
				&update_gpgkey_expire($dbh,$row->{email},$row->{uuid},
					$row->{pgpkey_id},$expire_at[0]);
				print "PGP Key updated (change expiration):  ".$row->{uuid}."\n";
				$row->{pgpkey_expire} = $expire_at[0];
			}
		} else {
			$pgp_change = 1;
			&update_gpgkey_expire($dbh,$row->{email},$row->{uuid},
				$row->{pgpkey_id},$expire_at[0]);
			print "PGP Key updated (set expiration):  ";
			print $row->{uuid}." Expire_at: ".$expire_at[0]." was: ";
			print $row->{pgpkey_expire}."\n";
			$row->{pgpkey_expire} = $expire_at[0];
		}
	} else {
		if ($row->{expire_at}) {
			$pgp_change = 1;
			&update_gpgkey_expire($dbh,$row->{email},$row->{uuid},
				$row->{pgpkey_id},$expire_at[0]);
			print "PGP Key updated (removed expiration):  ".$row->{uuid}."\n";
		}
	}
	if (@expire_at and !$pgp_change) {
		if($row->{pgpkey_remain} < 1) {
			print "PGP Key expired: ".$row->{uuid}."\n";
			push @{$notices{$row->{email}}},
qq{PGP key ID $row->{pgpkey_id} for $row->{email} has expired. Please update your PGP key to 
receive encrypted messages.};
		} elsif ($row->{pgpkey_remain} < 2592000) {
			print "PGP Key close to expiration: ".$row->{uuid}."\n";
			push @{$notices{$row->{email}}},
qq{PGP key ID $row->{pgpkey_id} for $row->{email} is about to expire. Please update your PGP key.};
		}
	
	}
	return $row;
}

#
# update_gpgkey_expire -- Set GPG key expire date in db.
#

sub update_gpgkey_expire($$$$$) {
        my ($dbh,$email,$uuid, $key_id,$expire) = @_;
        my $db_email = $dbh->quote($email);
        my $db_uuid = $dbh->quote($uuid);
        my $db_key_id = $dbh->quote($key_id);
        my $db_expire = (defined $expire) ? $dbh->quote($expire) : 'NULL';
        my $stmt = qq{
                UPDATE member_email me
                   SET pgpkey_expire = $db_expire
                   FROM member m
                WHERE me.member = m.ident
                   AND m.uuid = $db_uuid
                   AND me.email = $db_email
                   AND me.pgpkey_id = $db_key_id
        };
        my $rv = $debug || $dbh->do($stmt);
        print "{$stmt}: $rv\n" if $debug;
        return $rv;
}

sub gen_email_list() {
	my ($uuid,$ref) = @_;
	my @keylist = split('\n',&common::gpgcmd_allkeys($uuid));
	foreach my $key (@keylist) {
		$key = lc($key);
		# XXX: misses single char usernames
		if ($key =~ m/([a-z0-9\.\_+-]+\w@[a-z0-9\.\_-]+\w)/) {
			push($ref,$1);
		}
	}
}


sub key_has_email() {
	my ($email,$ref) = @_;
	foreach my $line (@{$ref}) {
		if ($line eq $email) {
			return 1;
		}
	}
	return 0;
}

exit 0;
