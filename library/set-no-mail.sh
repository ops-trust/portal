#!/bin/bash

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

#
# Disable mail delivery for an email destination.
#
# Args:
#   email, an email that is in need of disabling.
DB=!pgname!
DBHOST=!pghost!
if [ "X$1" = "X" ] ; then
  echo "$0 <emailaddress>"
  exit 255
fi
/usr/bin/psql -h ${DBHOST} ${DB} << EOF
BEGIN;

UPDATE member m
  SET no_email = true
  FROM member_email me
  WHERE m.ident = me.member
  AND me.email = '$1';

COMMIT;
EOF
