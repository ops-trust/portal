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

SHELL_SCRIPTS= update_db db_needs_update

MADE=${SHELL_SCRIPTS}

all: ${SHELL_SCRIPTS}

clean:; rm -f ${MADE} 
.SUFFIXES: .sh

.sh:
	@echo $< =\> $@; \
		rm -f $@ && \
		perl ../../mycat.pl ../../siteconfig < $< > $@ && \
		chmod +x,-w $@

${SHELL_SCRIPTS}: ../../siteconfig Makefile
