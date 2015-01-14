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

# $0 old new

cd !library! || exit 1

. ./funcs.sh

if [ "z$1" = "z" -o "z$2" = "z" ]; then
	echo "Usage: $0 <old email> <new email>"
	exit 1
fi

echo "UPDATE member_email SET email='$2' WHERE email='$1';" | portal_query

exit
