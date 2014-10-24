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
SUBDIRS= library webroot 
OBJDIRS= logs webvar archival

all clean: siteconfig
	@set -e; for subdir in ${SUBDIRS}; do \
		( set -x && cd $$subdir && ${MAKE} ${MARGS} $@ ); \
	done

makedb: siteconfig
	@echo createdb -h !pghost! -p !pgport! !pgname! | \
		perl mycat.pl siteconfig | \
		sh -x
		
	@echo psql -h !pghost! -p !pgport! -d !pgname! \
			\< library/schema.psql |\
		perl mycat.pl siteconfig | \
		sh -x

install: all
	@set -e; for subdir in ${SUBDIRS}; do \
		echo mkdir -p !portal!/$$subdir | \
			perl mycat.pl siteconfig | \
			sh -x; \
		set -x && ( cd $$subdir && ${MAKE} ${MARGS} install ); \
	done
	@set -e; for objdir in ${OBJDIRS}; do \
		echo mkdir -p !portal!/$$objdir | \
			perl mycat.pl siteconfig  | \
			sh -x; \
	done
	@echo !library!/fix-install | \
		perl mycat.pl siteconfig | \
			sh -x

siteconfig:
	@echo copy siteconfig from siteconfig.template and localize it
	@exit 1
