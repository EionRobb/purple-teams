MS Teams Plugin for Pidgin
==========================

A third-party alternative for the Microsoft Teams client - in development since April 2022, with no Electron/Webview!

Comparasion to regular Teams client:
====================================
Pros
----
:+1: Uses less than 1/4 the RAM (when including the webview2 processes commit size)

:+1: Allows being logged into multiple tenants and accounts at the same time, without any switching

:+1: Shows all contacts in the buddy list, not just the most recent

:+1: Won't send idle/auto-away status, unless you tell it to

:+1: Has a shorter cache-time for contact names and pictures

Cons
----
:-1: Doesn't support Teams For Personal/Free (see [this issue](https://github.com/EionRobb/purple-teams/issues/16), work in progress!)

:-1: Doesn't support calls, provides direct links to the Teams website

:-1: Threaded conversations are not Pidgin's strong point

:-1: Message reactions are not Pidgin's strong point either

Windows Users
=============
Download from [GitHub Actions](https://nightly.link/EionRobb/purple-teams/workflows/cross/master/plugin.zip) (or from [my server](https://eion.robbmob.com/libteams.dll)), copy to `C:\Program Files (x86)\Pidgin\plugins\`.  You may also need [libjson-glib](https://eion.robbmob.com/libjson-glib-1.0.dll) in your `C:\Program Files (x86)\Pidgin\` folder (not the `plugins` folder)

[![Latest Windows build](https://github.com/EionRobb/purple-teams/actions/workflows/cross.yml/badge.svg)](https://github.com/EionRobb/purple-teams/actions/workflows/cross.yml)

Compiling
=========
Using debian bookworm (xfce4)
```
sudo apt install pidgin
sudo apt install libjson-glib-dev libpurple-dev libglib2.0-dev
git clone https://github.com/EionRobb/purple-teams
cd purple-teams
make
sudo make install
cp libteams.so libteams-personal.so ~/.purple/plugins
```
Now you can launch pidgin and enable the plugin!

[![Latest Linux build](https://github.com/EionRobb/purple-teams/actions/workflows/linux.yml/badge.svg)](https://github.com/EionRobb/purple-teams/actions/workflows/linux.yml)

F<!--erociously -->A<!--udible -->Q<!--uacks -->
===

What should I use for the 'username' field?
-------------------------------------------
When creating a new account in Pidgin, the username field in purple-teams don't mean too much, they just need to be unique if you plan on signing into multiple servers/tenants at the same time (eg, eion.robb@tenant1 eion.robb@tenant2).  Authentication is done through the browser (including username) so this is just a placeholder that libpurple requires.  Leave the 'Tenant' field on the Advanced tab blank, unless you're following the instructions below for 'logging in as a guest'.

Logging in as a guest
---------------------
If you're like me and need to connect to multiple servers/tenants, then you'll need to set the 'Tenant' on the Advanced tab of the connection.  These are generally in the form of 'fancynamegoeshere.onmicrosoft.com'  you can leave off the '.onmicrosoft.com' bit and the plugin should add that on automatically.   Hopefully in the future I come up with an easier way to work that out.

You can also use a GUID/ID, eg using https://www.whatismytenantid.com

Leave the 'Tenant' field blank if you don't need it

Sometimes users show as `orgid:...`
-----------------------------------
If the plugin hasn't seen that person before, it might take a few seconds to grab their info, until then Pidgin will show the message with the Teams internal ID.  For deleted contacts, this is a bit trickier as there's not a good source of info for people that no longer exist.  Sometimes, right clicking on a contact and choosing "Get Info" will forcibly download new info.

Sometimes group chats show as `19:...` or `48:...`
--------------------------------------------------
If the plugin hasn't seen that chat before, it'll show the internal ID of the chat.  Pidgin (well, more libpurple) doesn't have a great way of dealing with group chats that aren't saved to the buddy list yet.  It might take a few seconds to download the name of the chat and save it to the buddy list.  Switching away from that tab/window and back again may cause Pidgin to redisplay it.

When I click on an image to "view full version" it has a 401 error
------------------------------------------------------------------
Unfortunately, the web browser needs to be recently logged in to Teams on the web to display these.  Open a new tab to teams.microsoft.com then reload the origional tab and it should show up.

I'm on Windows and can't see emoji
----------------------------------
The best workaround is to try one of the emoji smiley themes from [here](https://developer.pidgin.im/wiki/ThirdPartySmileyThemes).  Personally, I use [Emoji One](https://github.com/niclashoyer/pidgin-emojione/)

I can't paste images into chat
------------------------------
Try the [Pidgin Paste Images](https://github.com/EionRobb/pidgin-paste-image) plugin

Toast notifications
-------------------
Thats not really a question!  Maybe you want to try one of the notification plugins at https://pidgin.im/plugins/

Something else!
---------------
Feel free to [open an issue](https://github.com/EionRobb/purple-teams/issues) and hopefully find a reasonable outcome :)
