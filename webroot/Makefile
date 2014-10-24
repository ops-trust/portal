SUBDIRS= mech site

FILES= favicon.ico index.html robots.txt style.css

MADE= autohandler

all: ${MADE}
	@set -e -x; for subdir in ${SUBDIRS}; do \
		(cd $$subdir; ${MAKE} ${MARGS} $@); \
	done

clean:
	rm -f ${MADE}
	@set -e -x; for subdir in ${SUBDIRS}; do \
		(cd $$subdir; ${MAKE} ${MARGS} $@); \
	done

install:
	@( echo mkdir -p !webroot!; \
	   echo install -m 644 -o !wwwuid! -g !wwwgid! \
			${MADE} ${FILES} !webroot!; \
	) | \
		perl ../mycat.pl ../siteconfig | \
		sh -x
	@set -e -x; for subdir in ${SUBDIRS}; do \
		(cd $$subdir; ${MAKE} ${MARGS} install); \
	done

autohandler: autohandler.template ../siteconfig
	perl ../mycat.pl ../siteconfig < autohandler.template > $@

