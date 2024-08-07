
PIDGIN_TREE_TOP ?= ../pidgin-2.10.11
PIDGIN3_TREE_TOP ?= ../pidgin-main
LIBPURPLE_DIR ?= $(PIDGIN_TREE_TOP)/libpurple
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev

WIN32_CC ?= $(WIN32_DEV_TOP)/mingw-4.7.2/bin/gcc

PKG_CONFIG ?= pkg-config
DIR_PERM = 0755
LIB_PERM = 0755
FILE_PERM = 0644
MAKENSIS ?= makensis
XGETTEXT ?= xgettext

CFLAGS	?= -O2 -g -pipe
LDFLAGS ?= 

# Do some nasty OS and purple version detection
ifeq ($(OS),Windows_NT)
  #only defined on 64-bit windows
  PROGFILES32 = ${ProgramFiles(x86)}
  ifndef PROGFILES32
    PROGFILES32 = $(PROGRAMFILES)
  endif
  TEAMS_TARGET = libteams.dll libteams-personal.dll
  TEAMS_DEST = "$(PROGFILES32)/Pidgin/plugins"
  TEAMS_ICONS_DEST = "$(PROGFILES32)/Pidgin/pixmaps/pidgin/protocols"
  MAKENSIS = "$(PROGFILES32)/NSIS/makensis.exe"
else

  UNAME_S := $(shell uname -s)

  #.. There are special flags we need for OSX
  ifeq ($(UNAME_S), Darwin)
    #
    #.. /opt/local/include and subdirs are included here to ensure this compiles
    #   for folks using Macports.  I believe Homebrew uses /usr/local/include
    #   so things should "just work".  You *must* make sure your packages are
    #   all up to date or you will most likely get compilation errors.
    #
    INCLUDES = -I/opt/local/include -lz $(OS)

    CC = gcc
  else
    INCLUDES = 
    CC ?= gcc
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
    ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
      TEAMS_TARGET = FAILNOPURPLE
      TEAMS_DEST =
	  TEAMS_ICONS_DEST =
    else
      TEAMS_TARGET = libteams.so libteams-personal.so
      TEAMS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
	  TEAMS_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
    endif
  else
    TEAMS_TARGET = libteams3.so
    TEAMS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
	TEAMS_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
  endif
endif

WIN32_CFLAGS = -I$(WIN32_DEV_TOP)/glib-2.28.8/include -I$(WIN32_DEV_TOP)/glib-2.28.8/include/glib-2.0 -I$(WIN32_DEV_TOP)/glib-2.28.8/lib/glib-2.0/include -I$(WIN32_DEV_TOP)/json-glib-0.14/include/json-glib-1.0 -DENABLE_NLS -DPACKAGE_VERSION='"$(PLUGIN_VERSION)"' -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-parameter -fno-strict-aliasing -Wformat -Wno-sign-compare
WIN32_LDFLAGS = -L$(WIN32_DEV_TOP)/glib-2.28.8/lib -L$(WIN32_DEV_TOP)/json-glib-0.14/lib -lpurple -lintl -lglib-2.0 -lgobject-2.0 -ljson-glib-1.0 -g -ggdb -static-libgcc -lz
WIN32_PIDGIN2_CFLAGS = -I$(PIDGIN_TREE_TOP)/libpurple -I$(PIDGIN_TREE_TOP) $(WIN32_CFLAGS)
WIN32_PIDGIN3_CFLAGS = -I$(PIDGIN3_TREE_TOP)/libpurple -I$(PIDGIN3_TREE_TOP) -I$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_CFLAGS)
WIN32_PIDGIN2_LDFLAGS = -L$(PIDGIN_TREE_TOP)/libpurple $(WIN32_LDFLAGS)
WIN32_PIDGIN3_LDFLAGS = -L$(PIDGIN3_TREE_TOP)/libpurple -L$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_LDFLAGS) -lgplugin

C_FILES = \
	teams_connection.c \
	teams_contacts.c \
	teams_login.c \
	teams_messages.c \
	teams_util.c \
	purple-websocket.c \
	teams_trouter.c \
	teams_cards.c \
	markdown.c \
	libteams.c 
PURPLE_COMPAT_FILES := purple2compat/http.c purple2compat/purple-socket.c
PURPLE_C_FILES := libteams.c $(C_FILES)



.PHONY:	all install FAILNOPURPLE clean translations

all: $(TEAMS_TARGET)

libteams.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple glib-2.0 json-glib-1.0 zlib --libs --cflags`  $(INCLUDES) -Ipurple2compat -g -ggdb
libteams-personal.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -DENABLE_TEAMS_PERSONAL -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple glib-2.0 json-glib-1.0 zlib --libs --cflags`  $(INCLUDES) -Ipurple2compat -g -ggdb

libteams3.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple-3 glib-2.0 json-glib-1.0 zlib --libs --cflags` $(INCLUDES)  -g -ggdb
libteams3-personal.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -DENABLE_TEAMS_PERSONAL -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple-3 glib-2.0 json-glib-1.0 zlib --libs --cflags` $(INCLUDES)  -g -ggdb

libteams.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat
libteams-personal.dll: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -DENABLE_TEAMS_PERSONAL -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

libteams3.dll: $(PURPLE_C_FILES)
	$(WIN32_CC) -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)
libteams3-personal.dll: $(PURPLE_C_FILES)
	$(WIN32_CC) -DENABLE_TEAMS_PERSONAL -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)

install: $(TEAMS_TARGET) install-icons
	mkdir -m $(DIR_PERM) -p $(TEAMS_DEST)
	install -m $(LIB_PERM) -p $(TEAMS_TARGET) $(TEAMS_DEST)

install-icons: icons/16/teams.png icons/22/teams.png icons/48/teams.png icons/16/teams_personal.png icons/22/teams_personal.png icons/48/teams_personal.png
	mkdir -m $(DIR_PERM) -p $(TEAMS_ICONS_DEST)/16
	mkdir -m $(DIR_PERM) -p $(TEAMS_ICONS_DEST)/22
	mkdir -m $(DIR_PERM) -p $(TEAMS_ICONS_DEST)/48
	install -m $(FILE_PERM) -p icons/16/teams.png $(TEAMS_ICONS_DEST)/16/teams.png
	install -m $(FILE_PERM) -p icons/22/teams.png $(TEAMS_ICONS_DEST)/22/teams.png
	install -m $(FILE_PERM) -p icons/48/teams.png $(TEAMS_ICONS_DEST)/48/teams.png
	install -m $(FILE_PERM) -p icons/16/teams_personal.png $(TEAMS_ICONS_DEST)/16/teams_personal.png
	install -m $(FILE_PERM) -p icons/22/teams_personal.png $(TEAMS_ICONS_DEST)/22/teams_personal.png
	install -m $(FILE_PERM) -p icons/48/teams_personal.png $(TEAMS_ICONS_DEST)/48/teams_personal.png

installer: pidgin-teams.nsi libteams.dll
	$(MAKENSIS) "/DPIDGIN_VARIANT"="Pidgin" "/DPRODUCT_NAME"="pidgin-teams" "/DINSTALLER_NAME"="pidgin-teams-installer" "/DJSON_GLIB_DLL"="libjson-glib-1.0.dll" pidgin-teams.nsi

translations: po/purple-teams.pot

po/purple-teams.pot: $(PURPLE_C_FILES)
	$(XGETTEXT) $^ -k_ --no-location -o $@

po/%.po: po/purple-teams.pot
	msgmerge $@ po/purple-teams.pot > tmp-$*
	mv -f tmp-$* $@

po/%.mo: po/%.po
	msgfmt -o $@ $^

%-locale-install: po/%.mo
	install -D -m $(FILE_PERM) -p po/$(*F).mo $(LOCALEDIR)/$(*F)/LC_MESSAGES/purple-teams.mo
	
FAILNOPURPLE:
	echo "You need libpurple development headers installed to be able to compile this plugin"

clean:
	rm -f $(TEAMS_TARGET)

