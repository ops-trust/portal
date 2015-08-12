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


PERL_SCRIPTS= approve chpw dbck-password findmember \
	fsck-mlkeys fsck-pgpkeys gpgtest mail-handler \
	new-member notify-idle notify-stuck notify-unvetted \
	report-unvetted state-mon

SHELL_SCRIPTS= cronrun-day cronrun-minute cronrun-week \
	extract-sysadmins fix-install merge-member remove-from-tg \
	rename-email set-no-mail tg-maker

SCRIPTS= ${PERL_SCRIPTS} ${SHELL_SCRIPTS}

MADE= portal.conf common.pm http-real.inc signature ${SCRIPTS}

MADE_SGID= mh-wrapper

OTHER= schema.psql funcs.sh

SUBDIRS= db_migrations

all: ${MADE} ${MADE_SGID}
	@set -e; for subdir in ${SUBDIRS}; do \
		( set -x && cd $$subdir && ${MAKE} ${MARGS} $@ ); \
	done

clean:; rm -f ${MADE} ${MADE_SGID}
	@set -e; for subdir in ${SUBDIRS}; do \
		( set -x && cd $$subdir && ${MAKE} ${MARGS} $@ ); \
	done

CFLAGS= -O -Wall

portal.conf: portal.conf.template ../siteconfig
	perl ../mycat.pl ../siteconfig < $@.template > $@

common.pm: common.pm.template ../siteconfig
	perl ../mycat.pl ../siteconfig < $@.template > $@

http-real.inc: http-real.inc.template ../siteconfig
	perl ../mycat.pl ../siteconfig < $@.template > $@

signature: signature.template ../siteconfig
	perl ../mycat.pl ../siteconfig < $@.template > $@

mh-wrapper: ../siteconfig mh-wrapper.c Makefile
	@echo ${CC} ${CFLAGS} -DWRAPPED=!library!/mail-handler \
			-o $@ mh-wrapper.c | \
		perl ../mycat.pl ../siteconfig | \
		sh -x

# XXX not installing db_migrations or schema.psql since vixie thinks
# those will always be used from this source directory, not in !library!
install: ${MADE} ${MADE_SGID} ${OTHER}
	@( echo mkdir -p !library!; \
	   echo install -m 6755 -o !wwwuid! -g !wwwgid! \
		mh-wrapper !library!/; \
	   echo install -m 755 -o !wwwuid! -g !wwwgid! \
		${MADE} !library!/; \
	   echo install -m 644 -o !wwwuid! -g !wwwgid! \
		${OTHER} !library!/; \
	) | \
		perl ../mycat.pl ../siteconfig | \
		sh -x -e; \
	done

.SUFFIXES: .pl .sh

.pl:
	@echo $< =\> $@; \
		rm -f $@ && \
		perl ../mycat.pl ../siteconfig < $< > $@ && \
		chmod +x,-w $@

.sh:
	@echo $< =\> $@; \
		rm -f $@ && \
		perl ../mycat.pl ../siteconfig < $< > $@ && \
		chmod +x,-w $@

${PERL_SCRIPTS} ${SHELL_SCRIPTS}: ../siteconfig Makefile
