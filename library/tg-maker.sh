#! /bin/sh

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

# Note that the for loop below is questions being asked and expected type()
# of response. Valid types are:
#   s == string - this is a string
#   n == number - 12
#   i == interval - 7 days
#   b == boolean - true
#
# The end result of answering question is one large transactional sql statement.
# The caller of this script should copy/paste it into:
#   psql -U sysadmin -h <dbhost> ops-trust
#

cd !library! || exit 1

. ./funcs.sh

for v in tgname/s descr/s shortname/s min_invouch/n target_invouch/n \
        min_outvouch/n max_inactivity/i idle_guard/i pgp_required/b \
	please_vouch/b vouch_adminonly/b nom_enabled/b can_time_out/b \
	max_vouchdays/n has_wiki/b
do
	IFS=/; set $v
	read -p "$1 ($2): " v
	echo "-- $v"
	case $2 in
	s) eval $1=\"\'$v\'\" ;;
	i) eval $1=\"\'$v\'::INTERVAL\" ;;
	n) eval $1=\"`expr 0 + $v`\" ;;
	b) eval $1=\"$v\" ;;
	esac
done

initmemb=''
while read -p "Initial member ident (or ^D): " v; do
	echo "-- $v"
	initmemb="$initmemb $v"
done

echo 'BEGIN;'

cat <<:EOF:
INSERT INTO trustgroup
		(ident, descr, shortname, min_invouch, target_invouch,
		min_outvouch, max_inactivity, pgp_required, please_vouch, 
		nom_enabled, vouch_adminonly, can_time_out, max_vouchdays, 
		idle_guard, has_wiki)
	VALUES
		($tgname, $descr, $shortname, $min_invouch, $target_invouch,
		$min_outvouch, $max_inactivity, $pgp_required, $please_vouch, 
		$nom_enabled, $vouch_adminonly, $can_time_out, $max_vouchdays, 
		$idle_guard, $has_wiki);

INSERT INTO attestations
		(ident, descr, trustgroup)
	VALUES
		('met', 'I have met them in person more than once.', $tgname);
INSERT INTO attestations
		(ident, descr, trustgroup)
	VALUES
		('trust', 'I trust them to take action.', $tgname);
INSERT INTO attestations
		(ident, descr, trustgroup)
	VALUES
		('fate', 'I will share membership fate with them.', $tgname);

INSERT INTO mailinglist
		(lhs, descr, members_only, can_add_self, automatic, trustgroup,
		virtual)
	VALUES
		('admin', 'TG Administration', false, false, false, $tgname,
		true);
INSERT INTO mailinglist
		(lhs, descr, members_only, can_add_self, automatic, trustgroup)
	VALUES
		('general', 'General Discussion', true, true, true, $tgname);
INSERT INTO mailinglist
		(lhs, descr, members_only, can_add_self, automatic, trustgroup)
	VALUES
		('vetting', 'Vetting and Vouching', true, true, true, $tgname);
:EOF:

IFS=' '; set $initmemb
for v1; do
	cat <<:EOF:
INSERT INTO member_trustgroup
		(member, trustgroup, email, admin, state)
	SELECT '$v1' AS member,
		$tgname AS trustgroup,
		(SELECT email FROM member_email WHERE member = '$v1' LIMIT 1) AS email,
		TRUE AS admin,
		'active' AS state;
	INSERT INTO member_mailinglist
		(member, lhs, trustgroup)
	VALUES
		('$v1', 'general', $tgname);
INSERT INTO member_mailinglist
		(member, lhs, trustgroup)
	VALUES
		('$v1', 'vetting', $tgname);
:EOF:
done

IFS=' '; set $initmemb
for v1; do
	IFS=' '; set $initmemb
	for v2; do
		if [ $v1 != $v2 ]; then
			cat <<:EOF:
INSERT INTO member_vouch
		(vouchor, vouchee, comment, trustgroup, positive)
	VALUES
		('$v1', '$v2', '', $tgname, true);
:EOF:
		fi
	done
done

echo 'COMMIT;'

exit
