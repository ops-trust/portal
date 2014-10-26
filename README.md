# Ops-Trust Platform - Portal

This is the code that runs [Ops-Trust](https://www.ops-trust.net).

It is placed under the [Apache Version 2.0 License](http://www.apache.org/licenses/).

## Installation Requirements
The Ops-T Database permission architecture has the following invariants:

* we use PostGreSQL 9.1 or later, which need not run on the same host w/ us
* our users and apps do not specify a username or password in PQconnect()
* www (freebsd) and www-data (linux) and all sysadmins need to be in the ACL
* the "sysadmin" group has to have all the sysadmins in it as group members
* your pg_hba.conf file should permit the portal and mail hosts to connect
* Software: Apache2, FastCGI, mod_perl

Dev cycle is:

* cd ~root/portal, edit, 'make'
* sudo make install; test
* consider restarting apache if you've changed a file it may have cached
* consider installing some database updates
* commit and push; consider going to other portals and doing 'git pull' etc

Install cycle is:

* cd ~root/portal, clone, cp siteconfig.template siteconfig, edit, 'make'
* sudo make install
* cd /proj/ops-trust/library, and:
  * 'psql -h ... ops-trust < sysadmins.psql'
  * 'psql -h ... ops-trust < main-tg.psql'
* do something about postfix
* do something about apache
* test

One then needs to add to /etc/aliases:
```
opstrust-mail-handler: "|/proj/ops-trust/library/mh-wrapper"
```

and to /etc/postfix/virtual something similar to:
```
mail-handler@ops-trust.net	opstrust-mail-handler
@ops-trust.net			opstrust-mail-handler
```

Of course configuring postfix properly and setting up Apache.

So, please note:

~root/portal is "the" checked out copy of the portal code right now. We are
not yet managing this with 'puppet' because of the 'siteconfig' file. Don't
freak out, just please don't make your own on-host clone and 'make install'
from it without also (a) warning the other sysadmins, (b) committing your
changes and pushing them, (c) pulling your changes into ~root/portal, making,
and 'sudo make install' from there, to ensure that it's really what's running.

