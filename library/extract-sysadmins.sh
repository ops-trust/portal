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

#
# Get all sysadmins into a table, created on the fly.
# pgdump that into inserts for the destination/new database.
#

wt="extract_sysadmin_$$"
et="extract_member_email_$$"
connargs="-h !pghost! -p !pgport!"

# Create a working table for the members.
psql -q $connargs -d !pgname!<< EOF 
	SELECT *
	  INTO ${wt}
	  FROM member
	 WHERE sysadmin;
EOF

# Create a working table for the member_emails
psql -q $connargs -d !pgname! << EOF 
	SELECT me.member, me.email, me.verified
	  INTO ${et}
	  FROM member_email AS me, member AS m
	 WHERE m.sysadmin
	   AND me.member = m.ident;
EOF

# pg_dump the member working table into stdout
pg_dump -a --inserts --column-inserts $connargs -t ${wt} !pgname! | \
	sed "s/${wt}/member/"

# pg_dump the email working table into stdout
pg_dump -a --inserts --column-inserts $connargs -t ${et} !pgname! | \
	sed "s/${et}/member_email/"

# Remove the temporary table from the original location.
psql -q $connargs -d !pgname! << EOF
	DROP TABLE ${wt};
	DROP TABLE ${et};
EOF

exit
