#!/bin/sh -x

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

# $0 email tgname

cd $(dirname $0) || exit 1

. ./funcs.sh

if [ $# -lt 2 ]; then
	echo "Usage: $0 <email> <trustgroup>"
	exit 1
fi

echo "DELETE FROM member_trustgroup WHERE trustgroup='$2' AND email='$1';" | portal_query

exit
