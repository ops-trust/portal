# Helpful Shell Functions
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

# Force our path to contain /usr/local/bin, just in case
PATH=/usr/local/bin:$PATH
export PATH

# Always include our Portal configuration
. ./portal.conf

# Stores details in LOCKFILE + LOCKTOUCHPID
cron_lock()
{
	LOCKNAME=$1
	LOCKFILE=/tmp/portal-${LOCKNAME}.lock

	# Avoid running more than one at a time
	if [ -x /usr/bin/lockfile-create ] ; then
		lockfile-create $LOCKFILE
		if [ $? -ne 0 ];
		then
			DATE=$(date)
			cat <<EOF
Dear Admin,

At $(DATE) I was unable to run ${LOCKNAME} because lockfile
 ${LOCKFILE}
acquisition failed.

This probably means that the previous cron entry is still
running. Please check and correct if necessary.

EOF
			exit 1
		fi

		# Keep lockfile fresh
		lockfile-touch $LOCKFILE &
		LOCKTOUCHPID="$!"
	fi
}

# Uses LOCKFILE and LOCKTOUCHPID
cron_unlock()
{
	# Clean up lockfile
	#
	if [ -x /usr/bin/lockfile-create ];
	then
		kill $LOCKTOUCHPID
		lockfile-remove $LOCKFILE
	fi
}

export portal_query='psql -h ${PORTAL_DB_HOST} -p ${PORTAL_DB_PORT} -d ${PORTAL_DB_NAME}'

portal_dump()
{
	pg_dump -a --inserts --column-inserts -h ${PORTAL_DB_HOST} -p ${PORTAL_DB_PORT} -d ${PORTAL_DB_NAME} "$@"
}

