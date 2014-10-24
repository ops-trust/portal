FILES= expired.html header.mas logout.html footer.mas index.html
MADE= login.html leftside.mas

all: ${MADE}

clean:; rm -f ${MADE}

install: all
	@( echo mkdir -p !mechdir!; \
	   echo install -m 644 -o !wwwuid! -g !wwwgid! \
			${MADE} ${FILES} !mechdir!/; \
	) | \
		perl ../../mycat.pl ../../siteconfig | \
		sh -x

login.html: login.html.template ../../siteconfig
	perl ../../mycat.pl ../../siteconfig < login.html.template > $@

leftside.mas: leftside.mas.template ../../siteconfig
	perl ../../mycat.pl ../../siteconfig < leftside.mas.template > $@
