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

# Lock this crontab
cron_lock $(basename $0)

# Clean up pgp data files (for keys of users, etc).
./fsck-pgpkeys

# Run notification bits for each trustgroup.
for trustgroup in $(portal_query -A -t -c 'SELECT ident FROM trustgroup ORDER BY ident')
do
	./notify-unvetted $trustgroup
	./report-unvetted $trustgroup
done

# Unlock this crontab
cron_unlock

exit
