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

#
# extern:
#

use strict;
use warnings;
use lib '!library!';
use common;
use Mail::SendEasy;
use MIME::Parser;
use File::Temp;

#
# forward:
#

sub cleanup();
sub crack_ml($);
sub find_mailinglist($$);
sub parse_message($$$$);
sub find_member($$$$);
sub check_headers($);
sub route($$$$$$$);
sub record($$);
sub xmit_reencrypted($$$$$$);
sub xmit_encrypted($$$$);
sub transmit($$$);
sub puke($);
sub has_pgp_encrypted($);
sub edit_header($$$);

#
# initialize:
#

$ENV{'PATH'} = '/bin:/usr/bin';
delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};

our $dbh = &common::get_dbh2();
exit(75) unless $dbh;

our $parser = new MIME::Parser;
$parser->output_under("/tmp");
$parser->decode_headers(1);

# get the mailing list recipient from the postfix environment
my $ml = $ENV{'ORIGINAL_RECIPIENT'};
puke "no mailing list recipient specified?" unless defined $ml;
$ml =~ tr/A-Z/a-z/;

#
# mainline:
#

# where's this going? (note, crack_ml calls exit 67 on any error)
my ($tg, $lhs, $ml_lhs) = crack_ml $ml;

# is there such a mailing list? (note, find_mailinglist can call exit 67)
my ($descr, $members_only, $always_crypt, $footer) =
	find_mailinglist $tg, $lhs;

&common::gpg_mlkey_present($dbh, $lhs, $tg->{ident});

# parse the input and massage headers (note, parse_message can exit 67)
my ($msg, $from) = parse_message $ml, $tg, $lhs, $descr;

# find this member's record and update it (note, this can exit 67)
my ($member) = find_member $ml, $tg, $members_only, $from;

# if they included $sender ("mailer-daemon@") in the headers, exit 67 now
check_headers $msg;

# find the list of recipients for this message
my @recips = common::find_recipients $dbh, $tg, $lhs;

# maybe pgp-crypt it, transmit the thing to the people (note, this can exit 67)
route $ml, $ml_lhs, $msg, $member, $always_crypt, $footer, \@recips;

# record this e-mail message's existence (but not currently its content) in DB
record $tg, $ml_lhs;

# finish up
cleanup();
exit 0;

sub cleanup() {
	$parser->filer->purge;
	if (defined $parser->filer->output_dir()) {
		rmdir $parser->filer->output_dir();
	}
	$parser = undef;
}

#
# subs:
#

#
# find the recipient (LHS = left hand side; TG = trust group)
#
sub crack_ml($) {
	my ($ml) = @_;

	my $lhs = undef;
	my $tg_ident = undef;
	my $ml_lhs = undef;
	my $error = 0;
	if ($ml =~ /^${common::sender}$/i) {
		$lhs = ${common::sender};
		$tg_ident = 'main';
	} elsif ($ml =~ /^(\w+)\@${common::domain}$/i) {
		$lhs = $1;
		$tg_ident = 'main';
	} elsif ($ml =~ /^(\w+)\-(\w+)\@${common::domain}$/i) {
		$lhs = $2;
		$tg_ident = $1;
	} else {
		$error++;
	}
	my $tg = &common::get_tg($dbh, $tg_ident);
	$error++ unless defined $tg;
	if ($error) {
		puke "not a valid address form: $ml";
	}
	$ml_lhs = &common::email_ml_lhs($tg_ident, $lhs);
	return ($tg, $lhs, $ml_lhs);
}

#
# find the mailing list for this recipient
#
sub find_mailinglist($$) {
	my ($tg, $lhs) = @_;
	my ($descr);

	if ($lhs.'@'.$common::domain eq $common::sender) {
		$descr = $tg->{shortname}.' mail handler';
		$members_only = 0;
		return ($descr, $members_only);
	}

	my $db_lhs = $dbh->quote($lhs);
	my $db_tgname = $dbh->quote($tg->{ident});
	my $listref = $dbh->selectrow_hashref(qq{
		SELECT ml.descr, ml.members_only,
			ml.always_crypt, ml.email_footer
		  FROM mailinglist ml
		 WHERE ROW(ml.lhs, ml.trustgroup) = ROW($db_lhs, $db_tgname)
	});
	if (!defined $listref) {
		puke "not a valid recipient: $db_lhs $db_tgname";
	}
	$descr = $tg->{shortname};
	$descr =~ tr/a-z/A-Z/;
	$descr .= ' '.$listref->{descr};
	return ($descr,
		$listref->{members_only},
		$listref->{always_crypt},
		$listref->{email_footer});
}

#
# suck in the headers, modify them a little.
#
sub parse_message($$$$) {
	my ($ml, $tg, $lhs, $descr) = @_;

	my ($msg, $error);

	# crack the headers/body
	if (<STDIN> !~ /^From\s/o) {
		puke "not a valid message form: no From_ line";
	}
	eval { $msg = $parser->parse(\*STDIN); };
	$error = ($@ || $parser->last_error);
	if ($error) {
		puke "not a valid message format: $error";
	}
	my $head = $msg->head;

	# pull out the From: and floss it
	my $from = $head->get('From');
	if (!defined $from) {
		puke "not a valid header form: no From: header";
	}
	if ($head->count('From') > 1) {
		puke "not a valid header: too many From headers";
	}
	$from = common::ExtractAddr($from);
	$from =~ tr/A-Z/a-z/;

	# remove the dangerous and ugly poisonous headers
	foreach my $poison (qw[	Sender Errors-To Disposition-Notifications-To
		Receipt-Requested-To Confirm-Reading-To Rcpt-To
		MDSend-Notifications-To Smtp-Rcpt-To Return-Receipt-To
		Read-Receipt-To X-Confirm-Reading-To X-Acknowledge-To
		Delivery-Receipt-To X-PMrqc Precedence
		List-Owner List-Help List-Post List-Unsubscribe
		List-Subscribe ])
	{
		$head->delete($poison);
	}

	# annotate the Subject: if it's not already so marked
	$_ = $head->get('Subject');
	if (defined $_ && !/\s\[$tg->{shortname} $lhs\]\s/i) {
		$head->replace('Subject', "[$tg->{shortname} $lhs] ".$_);
	}

	$head->add('Sender', $common::sender);
	$head->add('Errors-To', $common::sender);
	$head->add('List-Post', "<mailto:$ml>");
	$head->add('List-Id',
		qq{"$descr" <$lhs.$tg->{ident}.${common::domain}>});
	$head->add('Precedence', 'bulk');

	return ($msg, $from);
}

#
# does this sender exist, or is it the hostmaster@ user?  if present, update
# member's activity timers. 
#
sub find_member($$$$) {
	my ($ml, $tg, $members_only, $from) = @_;

	my $db_from = $dbh->quote($from);
	my $db_tgname = $dbh->quote($tg->{ident});
	my $member = $dbh->selectrow_hashref(qq{
		SELECT m.ident, me.email, me.pgpkey_id IS NOT NULL AS haspgp,
			m.no_email, m.furlough, m.hide_email, mt.state,
			m.affiliation
		  FROM member m
		  JOIN member_email me ON (me.member = m.ident)
		  JOIN member_trustgroup mt ON (ROW(mt.member, mt.trustgroup) =
						ROW(m.ident, $db_tgname))
		  JOIN member_state ms ON (ms.ident = mt.state)
		 WHERE me.email = $db_from
		   AND ms.can_send
	});
	if ($from !~ /^(\w+\-)?${common::hostmaster}$/ &&
	    $members_only &&
	    $from ne $ml &&
	    !defined $member)
	{
		puke "not a valid sender: $db_from";
	}
	if (defined $member) {
		puke "email is disabled in this member's profile"
			if $member->{no_email};
		puke "member is on holiday or furlough"
			if $member->{furlough};
	}
	# XXX for some reason 'defined $member' isn't enough?
	if (defined $member && defined $member->{state}) {
		my $db_ident = $dbh->quote($member->{ident});
		if ($debug) {
			print "find_member: $db_ident\n";
		} else {
			$dbh->do(qq{
				UPDATE member_trustgroup mt
				   SET activity = NOW()::TIMESTAMP
				 WHERE ROW(mt.member, mt.trustgroup) =
					ROW($db_ident, $db_tgname);
				UPDATE member m
				   SET activity = NOW()::TIMESTAMP
				 WHERE m.ident = $db_ident;
			});
		}
	}
	return ($member);
}

#
# if they've put mailer-daemon@ into their To: or Cc:, bounce it now.
# (note: mailer-daemon@ will get its own separate copy, but at least
# we can keep the rest of the thread from also Cc:'ing us.)
#
sub check_headers($) {
	my ($msg) = @_;

	sub check_header($$) {
		my ($msg, $hdr) = @_;

		$_ = $msg->head->get($hdr);
		return defined $_ && /${common::sender}/i;
	}

	puke "Please do not mention $common::sender in your To: or Cc:"
		if check_header($msg, 'To') || check_header($msg, 'Cc');
}

#
# maybe pgp this, or else add a signature, and then transmit it
#
sub route($$$$$$$) {
	my ($ml, $ml_lhs, $msg, $member, $always_crypt,
	    $footer, $recip_ref) = @_;

	# decide whether there is a PGP part in there somewhere
	# (including at the top level), stopping on the first.
	my $pgp_part = has_pgp_encrypted($msg);

	if ($debug) {
		printf "route: %s pgp\n", $pgp_part ? 'has' : 'no';
		print "\tmime version count: ",
			$msg->head->count('mime-version'),
			"\n";
		print "\tis multipart: ", $msg->is_multipart, "\n";
		printf "\t%s bodyhandle\n", $msg->bodyhandle ? 'has' : 'no';
	}

	# if there's a pgp part, decrypt it and reencrypt to each recipient
	# otherwise, add a signature, and blast it to all recipients
	if (defined $pgp_part) {
		xmit_reencrypted $ml, $ml_lhs, $msg, $pgp_part,
				 $member, $recip_ref;
	} elsif ($always_crypt) {
		xmit_encrypted $ml, $msg, $member, $recip_ref;
	} else {
		# if it's multipart, make the current part list into the
		# first leg of a multipart/mixed, and then attach a
		# signature as the second leg of same.  else, sign directly.
		#
		# note that single-part messages are considered to have
		# bodies (by MIME), but those parts might not be text and
		# we should NOT be signing them.  thus, we make multipart.

		if ($msg->head->count('mime-version') &&
		    ($msg->is_multipart || !$msg->bodyhandle)) {
#			$msg->make_multipart('mixed', {Force => 1})
#				if $msg->bodyhandle;
#			$msg->sign(Attach => 1, Remove => 0,
#				File => $common::signature_file);
		} else {
			if (defined $footer) {
				$msg->sign(Attach => 0, Remove => 0,
					Signature =>
					   Text::Wrap::fill('', '', ($footer))
					   );
			} else {
				#Apply default footer. 
				$msg->sign(Attach => 0, Remove => 0,
					File => $common::signature_file);
			}
		}
		transmit $msg, $member, $recip_ref;
	}
}

#
# record this e-mail message's existence (but not currently its content) in DB
#
sub record($$) {
	my ($tg, $ml_lhs) = @_;

	my $db_lhs = $dbh->quote($ml_lhs);
	my $db_tgname = $dbh->quote($tg->{ident});

	$dbh->do(qq{
		UPDATE mailinglist ml
		   SET activity = now()::TIMESTAMP
		 WHERE ROW(ml.lhs, ml.trustgroup) =
			ROW($db_lhs, $db_tgname);
	});
}

#
# re-encrypt this message for each recipient, transmitting to each
#
sub xmit_reencrypted($$$$$$) {
	my ($ml, $ml_lhs, $msg, $pgp_part, $member, $recip_ref) = @_;

	# the original pgp part is part of the original message and
	# so we need a dup of that message we can tear into without
	# perturbing the pgp part we need to work from.
	my $new = $msg->dup;

	# possibly rewrite From: header, maybe add Organization:
	edit_header $ml, $new->head, $member;

	# something encrypted was found.  destroy the original MIME
	# description headers, which referred to that cryptotext,
	# and drop all the attachments.
	$new->head->delete('Content-Disposition');
	$new->head->delete('Content-Type');
	$new->head->delete('Content-Transfer-Encoding');
	$new->make_multipart(
		qq{encrypted; protocol="application/pgp-encrypted"},
		{Force => 1}
	);
	$new->head->add('MIME-Version', '1.0')
		unless $new->head->count('mime-version');
	$new->parts([]);
	$new->sync_headers;

	# decrypt the pgp part.
	&common::gpg_mlkey_present($dbh, $lhs, $tg->{ident});
	my ($body, $error) =
		&common::gpg_decrypt($ml_lhs, undef,
				     $pgp_part->bodyhandle->path);
	puke $error unless defined $body && length $body;

	# if the plaintext does not start with a MIME header, add one.
	if ($body !~ /^Content\-/) {
		$body = qq{Content-Type: text/plain; charset=iso-8859-1\n\n} .
			$body;
	}

	# this part will be the same for every output operation
	my $keep = $new->attach(Type => 'application/pgp-encrypted',
				Data => 'Version: 1',
				Encoding => '7bit');

	# make a unique second attachment for each recipient, and send it
	my $crypt_fh = File::Temp->new();
	puke "File::Temp: $@" unless defined $crypt_fh;
	foreach my $recip (@$recip_ref) {
		my $uuid = $recip->{uuid};
		&common::gpg_key_present($dbh, $uuid);
		my $pgpkey_id = $recip->{pgpkey_id};
		my $size;
		($size, $error) = &common::gpg_encrypt($uuid, $pgpkey_id,
			undef, \$body, $crypt_fh);
		puke $error if $size < 0;
		$new->attach(Path => $crypt_fh->filename,
				Type => 'application/octet-stream',
				Encoding => '7bit',
				Filename => undef);
		if (length $error) {
			$new->attach(Type => 'text/plain',
				     Data => $error,
				     Encoding => '7bit');
		}
		transmit $new, $member, [ $recip ];
		$new->parts([ $keep ]);
	}

	# done here
	$crypt_fh = undef;
	$new = undef;
}

#
# encrypt this plaintext message for each recipient, transmitting to each
#
sub xmit_encrypted($$$$) {
	my ($ml, $msg, $member, $recip_ref) = @_;

	# the original message is our source so we need a dup of that
	# message we can tear into without perturbing the source.
	my $new = $msg->dup;

	# possibly rewrite From: header, maybe add Organization:
	edit_header $ml, $new->head, $member;

	# destroy the original MIME and drop all the attachments.
	$new->head->delete('Content-Disposition');
	$new->head->delete('Content-Type');
	$new->head->delete('Content-Transfer-Encoding');
	$new->make_multipart(
		qq{encrypted; protocol="application/pgp-encrypted"},
		{Force => 1}
	);
	$new->head->add('MIME-Version', '1.0')
		unless $new->head->count('mime-version');
	$new->parts([]);
	$new->sync_headers;

	# get together the text we'll be putting under the crypto.  this
	# includes the content-* headers from the original message, plus
	# the stringified body of the original message.

	my $body = '';
	if (!defined $msg->head->get('content-type')) {
		$body = qq{Content-Type: text/plain; charset=iso-8859-1\n};
	} else {
		$body = "Content-Type: ".$msg->head->get('content-type')."\n";
	}

	$_ = $msg->stringify_body;
	study $_;
	# surprise! Mail::SendEasy does not implement RFC 821 4.5.2!
	s:^\.:..:mgo;
	# nor does Mail::SendEasy ensure that line terminators are \r\n
	s:\r\n$:\n:mgo;
	s:\n$:\r\n:mgo;
	$body .= "\r\n" . $_;

	# this part will be the same for every output operation
	my $keep = $new->attach(Type => 'application/pgp-encrypted',
				Data => 'Version: 1',
				Encoding => '7bit');

	# make a unique second attachment for each recipient, and send it
	my $crypt_fh = File::Temp->new();
	puke "File::Temp: $@" unless defined $crypt_fh;
	foreach my $recip (@$recip_ref) {
		my $uuid = $recip->{uuid};
		&common::gpg_key_present($dbh, $uuid);
		my $pgpkey_id = $recip->{pgpkey_id};
		my ($size, $error) = &common::gpg_encrypt($uuid, $pgpkey_id,
			undef, \$body, $crypt_fh);
		puke $error if $size < 0;
		$new->attach(Path => $crypt_fh->filename,
				Type => 'application/octet-stream',
				Encoding => '7bit',
				Filename => undef);
		if (length $error) {
			$new->attach(Type => 'text/plain',
				     Data => $error,
				     Encoding => '7bit');
		}
		transmit $new, $member, [ $recip ];
		$new->parts([ $keep ]);
	}

	# done here
	$crypt_fh = undef;
	$new = undef;
}

#
# open a channel to the local SMTP agent, to relay this message back out again
#
sub transmit($$$) {
	my ($msg, $member, $recip_ref) = @_;
	my $smtp;

	if ($debug) {
		print "transmit()\n";
	} else {
		$smtp = Mail::SendEasy::SMTP->new('127.0.0.1', 25, 120);
		if ($smtp->MAIL("FROM:<${common::sender}>") !~ /^2/o) {
			puke "relay failed (MAIL FROM <${common::sender}>): " .
				$smtp->last_response_line;
		}
	}

	foreach my $row (@$recip_ref) {
		my $rcpt = $row->{email};

		if ($debug) {
			print "\t$rcpt\n";
		} else {
			if (!$common::test_mode) {
			    if ($smtp->RCPT("TO:<$rcpt>") !~ /^2/o) {
				puke "relay failed (RCPT TO:<$rcpt>): " .
					$smtp->last_response_line;
			    }
			}
		}
	}
	if ($common::test_mode) {
		if ($smtp->RCPT("TO:<${common::hostmaster}>") !~ /^2/o) {
			puke "relay failed (RCPT TO:<hostmaster@>): " .
				$smtp->last_response_line;
		}
	}

	if ($debug) {
		print "---\n";
	} else {
		if ($smtp->DATA !~ /^3/o) {
			puke "relay failed (DATA): " .
				$smtp->last_response_line;
		}
	}

	# possibly rewrite From: header, maybe add Organization:
	edit_header $ml, $msg->head, $member;

	$_ = $msg->stringify_header;
	# Mail::SendEasy does not ensure that line terminators are \r\n
	s:\r\n$:\n:mgo;
	s:\n$:\r\n:mgo;
	if ($debug) {
		print $_, "\n";
	} else {
		$smtp->print($_);
		if ($common::test_mode) {
			foreach my $row (@$recip_ref) {
				my $rcpt = $row->{email};

				$smtp->print("X-RCPT-To: $rcpt\n");
			}
		}
		$smtp->print("\n");
	}
	$_ = $msg->stringify_body;
	study $_;
	# surprise! Mail::SendEasy does not implement RFC 821 4.5.2!
	s:^\.:..:mgo;
	# nor does Mail::SendEasy ensure that line terminators are \r\n
	s:\r\n$:\n:mgo;
	s:\n$:\r\n:mgo;
	if ($debug) {
		print;
	} else {
		$smtp->print($_);
	}

	if ($debug) {
		print "===\n";
	} else {
		my $code = $smtp->DATAEND;
		if ($code !~ /^2/) {
			puke 'relay failed (END OF DATA ['.$code.']): ' .
				$smtp->last_response_line;
		}
		$smtp->close;
	}
}

sub puke($) {
	my ($text) = @_;

	if ($debug) {
		print "puke($text)\n";
	} else {
		print STDERR "[$text]\n";
	}
	cleanup();
	exit 67;
}

sub has_pgp_encrypted($) {
	my ($msg) = @_;

	# XXX violates several important parts of RFC 2015
	sub is_pgp_encrypted($) {
		my ($body) = @_;
		my $ret = 0;

		return 0 unless defined $body;
		my $io = $body->open('r');
		$_ = $io->getline;
		if (defined $_) {
			if (/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/o) {
				$ret++;
			} else {
				$_ = $io->getline;
				if (defined $_) {
					if (/^\-\-\-\-\-BEGIN PGP MESSAGE\-\-\-\-\-/o) {
						$ret++;
					}
				}
			}
		}
		$io->close;
		return $ret;
	}

	foreach my $part ($msg->parts_DFS) {
		return $part if is_pgp_encrypted($part->bodyhandle);
	}
	return undef;
}

sub edit_header($$$) {
	my ($ml, $head, $member) = @_;

	# if this sender does not want us using their domain name in
	# From:, then edit the headers accordingly.  note that if this
	# sender isn't a member (as some lists permit), we can't hide.
	if (defined $member && $member->{hide_email}) {
		my $from = common::ExtractAddr($head->get('from'));
		my @from = split /\@/, $from;
		my @member = split /\@/, $member->{email};
		$from[1] =~ tr/A-Z/a-z/;
		$member[1] =~ tr/A-Z/a-z/;
		if ($from[1] eq $member[1]) {
			$head->replace('From',
				sprintf("%s (%s)",
					$common::sender, $from));
			$head->add('Mail-Followup-To',
				qq{"$descr" <$ml>});
			$head->add('Comments',
				"Did not say From: $from at sender's request");
		}
	}

	# if there is not an Organization: header (RFC 1036) in the message
	# but there is an 'affiliation' attribute in the member record, then
	# make an Organization. this is really a Usenet header, but many
	# e-mail clients will display it.
	$head->add('Organization', $member->{affiliation})
		unless $head->count('Organization') > 0 ||
		       !defined($member->{affiliation});
}
