On Debian 7, these are the packages you have to have installed for Ops-T:

From Debian:
```
apt-get install perl perl-base libcgi-session-perl perl-modules \
	libdatetime-format-mail-perl libdatetime-format-pg-perl \
	libdbi-perl libgnupg-interface-perl libmail-sendeasy-perl \
	libmime-tools-perl libhtml-mason-perl libdbd-pg-perl
```

For compilation of the mail handler one also requires installation of 'make' and 'gcc'.
Outside of compilation though these package are not needed on your production hosts.

From CPAN:
```
cpan install HTML::Barcode::QRCode
```
