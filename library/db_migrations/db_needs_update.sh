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


# This script checks the current DB rev and reports if updates are ready
# to be applied. 

# exit value will be:
# - 0 if we can find no updates ready for automatic application.
# - 1 if we have run an update that we could run. 

if [ ! -d "./db_migrations" ]; then
        echo " - db_migrations directory not found in local dir."
        echo " This script must be run from the source pool library/ dir."
        echo " Not !library! "
        exit 1
fi

export CURRENT_VERSION=`psql -h !pghost! -d !pgname! -U !pguser! \
	-t --no-align \
	-c "SELECT value FROM schema_metadata WHERE key = 'portal_schema_version';"`
echo "Current DB Version: ${CURRENT_VERSION}, looking for updates."

export FILENAME="db_migrations/DB_${CURRENT_VERSION}.psql"
if [ -f $FILENAME ]; then
	echo "Updates ready to apply"
	exit 1
	
else
  echo "No Update to apply"
  exit 0
fi

