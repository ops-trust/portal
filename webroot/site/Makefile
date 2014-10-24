FILES= chpw.html favicon.ico mailinglist.html index.html default_face.png \
	index_private.mas nominate.html edit_contact.html robots.txt \
	edit_second_factor.html leftside_private.mas emit_emerg.html \
	edit_email.html leftside_public.mas show_member.html \
	list_airports.html sitehandler.mas emit_mlkey.html \
	list_languages.html style.css emit_pgp.html list_members.html \
	vouch_cp.html emit_vouch.html

MADE= decor.mas index_public.mas select_tg.html

all: ${MADE}

clean:; rm -f ${MADE}

install: all
	@( echo mkdir -p !sitedir!; \
	   echo install -m 644 -o !wwwuid! -g !wwwgid! \
			${MADE} ${FILES} !sitedir!/; \
	) | \
		perl ../../mycat.pl ../../siteconfig | \
		sh -x

decor.mas: decor.mas.template ../../siteconfig
	perl ../../mycat.pl ../../siteconfig < decor.mas.template > $@

index_public.mas: index_public.mas.template ../../siteconfig
	perl ../../mycat.pl ../../siteconfig < index_public.mas.template > $@

select_tg.html: select_tg.html.template ../../siteconfig
	perl ../../mycat.pl ../../siteconfig < select_tg.html.template > $@
