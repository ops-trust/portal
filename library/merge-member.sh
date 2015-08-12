#!/bin/sh

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

cd $(dirname $0) || exit 1

. ./funcs.sh

tg=$1
old=$2
new=$3

cat <<:EOF:
BEGIN;
UPDATE member_email SET member='$new'
	WHERE member = '$old';
UPDATE member_trustgroup SET member='$new'
	WHERE ROW(trustgroup, member) = ROW('$tg', '$old');
UPDATE member_vouch SET vouchor='$new'
	WHERE ROW(trustgroup, vouchor) = ROW('$tg', '$old');
UPDATE member_vouch SET vouchee='$new'
	WHERE ROW(trustgroup, vouchee) = ROW('$tg', '$old');
UPDATE member_mailinglist SET member='$new'
	WHERE ROW(trustgroup, member) = ROW('$tg', '$old');
UPDATE audit_history SET member='$new'
	WHERE member = '$old';
DELETE FROM member
	WHERE ident = '$old';
COMMIT;
:EOF:

exit
