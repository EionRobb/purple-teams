MS Teams Plugin for Pidgin
==========================

Hey there, I'm building a new plugin for Teams, based on the old skype4pidgin plugin.  At the moment it's primarily focused at "Teams for Work/School", but let me know in [this issue](https://github.com/EionRobb/purple-teams/issues/16) if you're interested in "Teams for Personal"
Totally a work in progress, but it's sending and receiving messages, so good enough to ship!

Building
========
You'll need libjson-glib-dev, libpurple-dev and glib-2.0-dev packages from your distro, then simply
```
git clone https://github.com/EionRobb/purple-teams
cd purple-teams
make
sudo make install
```
to install.

[![Latest Linux build](https://github.com/EionRobb/purple-teams/actions/workflows/linux.yml/badge.svg)](https://github.com/EionRobb/purple-teams/actions/workflows/linux.yml)

Windows Users
=============
Download from [GitHub Actions](https://nightly.link/EionRobb/purple-teams/workflows/cross/master/plugin.zip) (or from [my server](https://eion.robbmob.com/libteams.dll)), copy to `C:\Program Files (x86)\Pidgin\plugins\`.  You may also need [libjson-glib](https://eion.robbmob.com/libjson-glib-1.0.dll) in your `C:\Program Files (x86)\Pidgin\` folder (not the plugins folder)

General Login
=============
Usernames in purple-teams don't mean too much, they just need to be unique if you plan on signing into multiple servers/tenants at the same time.  Leave the 'tenant' field on the Advanced tab blank, unless you're following the below

Logging in as a guest
=====================
If you're like me and need to connect to multiple servers/tenants, then you'll need to set the 'Tenant' on the Advanced tab of the connection.  These are generally in the form of 'fancynamegoeshere.onmicrosoft.com'  you can leave off the '.onmicrosoft.com' bit and the plugin should add that on automatically.   Hopefully in the future I come up with an easier way to work that out.

You can also use a GUID/ID, eg using https://www.whatismytenantid.com
