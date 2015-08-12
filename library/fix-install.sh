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

#
# Rsync'ing over a git clone is bobo... fix the permissions and add missing
# directories/links.

sudo mkdir -p !portal!/webvar
sudo chown !wwwuid!:!wwwgid! !portal!/webvar
for sub in badpgp ml_keys pgpkeys tmp; do
  sudo mkdir -p !portal!/webvar/${sub}
  sudo chown -R !wwwuid!:!wwwgid! !portal!/webvar/${sub}
  sudo chmod 755 !portal!/webvar/${sub}
done

sudo chmod -R 770 !portal!/webvar/ml_keys
sudo chmod -R 770 !portal!/webvar/pgpkeys
sudo chmod -R 775 !portal!/webvar
sudo chmod -R 775 !portal!/webroot

for dir in logs webroot; do
  sudo chown -R root:sudo !portal!/${dir}
done

for masondir in \
	/var/local/mason/ops-trust/cache \
	/var/local/mason/ops-trust/obj;
do
	mkdir -p $masondir
	chmod -R 770 $masondir
	chown -R !wwwuid!:!wwwgid! $masondir
done

exit
