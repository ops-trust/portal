= Installation =

== Debian ==

On Debian (7.0+) these are the packages you have to have installed for Ops-T:

From Debian:
```
apt-get install perl perl-base libcgi-session-perl perl-modules \
	libdatetime-format-mail-perl libdatetime-format-pg-perl \
	libdbi-perl libgnupg-interface-perl libmail-sendeasy-perl \
	libmime-tools-perl libhtml-mason-perl libdbd-pg-perl
```

From CPAN you will additionally need:
```
cpan install HTML::Barcode::QRCode
```

For compilation of the mail handler one also requires installation of 'make' and 'gcc'.
Outside of compilation though these package are not needed on your production hosts.

=== Database ===
postgres can be installed on the same or another host.

=== Apache ===
For the portal webinterface, Apache2 is required to serve the website:
```
apt-get install apache2-mpm-prefork package libapache2-mod-perl2 libapache2-reload-perl
a2enmod perl
a2enmod ssl

a2ensite http-real
service apache2 reload
```

Copy the config file generated from /home/user/portal/library/http-real.inc to /etc/apache2/sites-available/http-real.conf

