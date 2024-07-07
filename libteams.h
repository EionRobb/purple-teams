/*
 * Teams Plugin for libpurple/Pidgin
 * Copyright (c) 2014-2020 Eion Robb
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBTEAMS_H
#define LIBTEAMS_H

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

/* Maximum number of simultaneous connections to a server */
#define TEAMS_MAX_CONNECTIONS 16

#include <glib.h>

#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <glib/gi18n.h>
#include <sys/types.h>
#ifdef __GNUC__
	#include <sys/time.h>
	#include <unistd.h>
#endif

#ifndef G_GNUC_NULL_TERMINATED
#	if __GNUC__ >= 4
#		define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#	else
#		define G_GNUC_NULL_TERMINATED
#	endif /* __GNUC__ >= 4 */
#endif /* G_GNUC_NULL_TERMINATED */

// workaround for MinGW32 which doesn't support "%zu"; see also https://stackoverflow.com/a/44383330
#ifdef _WIN32
#  ifdef _WIN64
#    define PRI_SIZET PRIu64
#  else
#    define PRI_SIZET PRIu32
#  endif
#else
#  define PRI_SIZET "zu"
#endif

#include "purplecompat.h"
#include "glibcompat.h"

#ifdef _WIN32
#	include <windows.h>
#	define dlopen(a,b)  GetModuleHandleA(a)
#	define RTLD_LAZY    0x0001
#	define dlsym(a,b)   GetProcAddress(a,b)
#	define dlclose(a)   FreeLibrary(a)
#else
#	include <arpa/inet.h>
#	include <dlfcn.h>
#	include <netinet/in.h>
#	include <sys/socket.h>
#endif

#include <json-glib/json-glib.h>

#define json_object_get_int_member(JSON_OBJECT, MEMBER) \
	((JSON_OBJECT) && json_object_has_member((JSON_OBJECT), (MEMBER)) ? json_object_get_int_member((JSON_OBJECT), (MEMBER)) : 0)
#define json_object_get_string_member(JSON_OBJECT, MEMBER) \
	((JSON_OBJECT) && json_object_has_member((JSON_OBJECT), (MEMBER)) ? json_object_get_string_member((JSON_OBJECT), (MEMBER)) : NULL)
#define json_object_get_array_member(JSON_OBJECT, MEMBER) \
	((JSON_OBJECT) && json_object_has_member((JSON_OBJECT), (MEMBER)) ? json_object_get_array_member((JSON_OBJECT), (MEMBER)) : NULL)
#define json_object_get_object_member(JSON_OBJECT, MEMBER) \
	((JSON_OBJECT) && json_object_has_member((JSON_OBJECT), (MEMBER)) ? json_object_get_object_member((JSON_OBJECT), (MEMBER)) : NULL)
#define json_object_get_boolean_member(JSON_OBJECT, MEMBER) \
	((JSON_OBJECT) && json_object_has_member((JSON_OBJECT), (MEMBER)) ? json_object_get_boolean_member((JSON_OBJECT), (MEMBER)) : FALSE)
#define json_array_get_length(JSON_ARRAY) \
	((JSON_ARRAY) ? json_array_get_length(JSON_ARRAY) : 0)
#define json_node_get_array(JSON_NODE) \
	((JSON_NODE) && JSON_NODE_TYPE(JSON_NODE) == (JSON_NODE_ARRAY) ? json_node_get_array(JSON_NODE) : NULL)

#include "accountopt.h"
#include "core.h"
#include "cmds.h"
#include "connection.h"
#include "debug.h"
#include "http.h"
#include "image.h"
#include "image-store.h"
#include "plugins.h"
#include "proxy.h"
#include "request.h"
#include "roomlist.h"
#include "savedstatuses.h"
#include "sslconn.h"
#include "util.h"
#include "version.h"

	
#if GLIB_MAJOR_VERSION >= 2 && GLIB_MINOR_VERSION >= 12
#	define atoll(a) g_ascii_strtoll(a, NULL, 0)
#endif

#define TEAMS_CALENDAR_REFRESH_MINUTES 15
#define TEAMS_MAX_MSG_RETRY 2
#define TEAMS_MAX_PROCESSED_EVENT_BUFFER 10

#define TEAMS_PLUGIN_ID "prpl-eionrobb-msteams"
#define TEAMS_PLUGIN_VERSION "1.0"

#define TEAMS_PERSONAL_PLUGIN_ID "prpl-eionrobb-msteams-personal"

#define TEAMS_LOCKANDKEY_APPID "msmsgs@msnmsgr.com"
#define TEAMS_LOCKANDKEY_SECRET "Q1P7W2E4J9R8U3S5"

#ifdef ENABLE_TEAMS_PERSONAL
#	define TEAMS_BASE_ORIGIN_HOST "teams.live.com"
#	define TEAMS_CONTACTS_HOST "msgapi.teams.live.com"
#else
#	define TEAMS_BASE_ORIGIN_HOST "teams.microsoft.com"
#	define TEAMS_CONTACTS_HOST "apac.ng.msg.teams.microsoft.com"
#endif

#define TEAMS_DEFAULT_MESSAGES_HOST "apac.notifications.teams.microsoft.com"
#define TEAMS_PRESENCE_HOST "presence." TEAMS_BASE_ORIGIN_HOST

#define TEAMS_NEW_CONTACTS_HOST "contacts.skype.com"
#define TEAMS_LOGIN_HOST "login.skype.com"
#define TEAMS_VIDEOMAIL_HOST "vm.skype.com"
#define TEAMS_XFER_HOST "api.asm.skype.com"
#define TEAMS_GRAPH_HOST "skypegraph.skype.com"
#define TEAMS_STATIC_HOST "static.asm.skype.com"
#define TEAMS_STATIC_CDN_HOST "static-asm.secure.skypeassets.com"
#define TEAMS_DEFAULT_CONTACT_SUGGESTIONS_HOST "peoplerecommendations.skype.com"

#ifdef ENABLE_TEAMS_PERSONAL
#	define TEAMS_PROFILES_PREFIX "/api/mt/beta/"
#else
#	define TEAMS_PROFILES_PREFIX "/api/mt/apac/beta/"
#endif

#define TEAMS_VDMS_TTL 300

#define TEAMS_CLIENTINFO_NAME "skypeteams"
#define TEAMS_CLIENTINFO_VERSION "49/24062722442"
#define TEAMS_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0 Teams/24165.1410.2974.6689/49"



#define TEAMS_BUDDY_IS_MSN(a) G_UNLIKELY((a) != NULL && strchr((a), '@') != NULL)
#define TEAMS_BUDDY_IS_PHONE(a) G_UNLIKELY((a) != NULL && *(a) == '+')
#define TEAMS_BUDDY_IS_S4B(a) G_UNLIKELY((a) != NULL && g_str_has_prefix((a), "2:"))
#define TEAMS_BUDDY_IS_BOT(a) G_UNLIKELY((a) != NULL && g_str_has_prefix((a), "28:"))
#define TEAMS_BUDDY_IS_NOTIFICATIONS(a) G_UNLIKELY((a) != NULL && g_str_has_prefix((a), "48:"))
#define TEAMS_BUDDY_IS_SKYPE(a) G_UNLIKELY((a) != NULL && g_str_has_prefix((a), "8:") && !g_str_has_prefix((a), "8:orgid:"))
#define TEAMS_BUDDY_IS_TEAMS(a) G_LIKELY((a) != NULL && g_str_has_prefix((a), "8:orgid:"))

typedef struct _TeamsAccount TeamsAccount;
typedef struct _TeamsBuddy TeamsBuddy;

typedef void (*TeamsFunc)(TeamsAccount *swa);

struct _TeamsAccount {
	gchar *username;
	gchar *primary_member_name;
	gchar *self_display_name;
	
	PurpleAccount *account;
	PurpleConnection *pc;
	PurpleHttpKeepalivePool *keepalive_pool;
	PurpleHttpConnectionSet *conns;
	PurpleHttpCookieJar *cookie_jar;
	gchar *messages_host;
	
	GHashTable *sent_messages_hash;
	guint poll_timeout;
	guint watchdog_timeout;
	
	guint authcheck_timeout;
	time_t last_authrequest;
	guint idle_timeout;
	
	//old skypeweb
	gchar *skype_token;
	gchar *registration_token;
	gchar *vdms_token;
	gchar *endpoint;
	gint registration_expiry;
	gint vdms_expiry;
	gchar *region;
	
	//teams
	gchar *id_token;
	gchar *refresh_token;
	gchar *messages_cursor;
	gchar *tenant;
	GHashTable *buddy_to_chat_lookup;
	GHashTable *chat_to_buddy_lookup;
	gint refresh_token_timeout;
	gchar *substrate_access_token;
	gchar *csa_access_token;
	gchar *presence_access_token;
	struct _TeamsConnection *poll_conn;
	guint friend_list_poll_timeout;
	GHashTable *calendar_reminder_timeouts;
	guint calendar_poll_timeout;
	GQueue *processed_event_messages;
	
	struct _PurpleWebsocket *trouter_socket;
	gchar *trouter_surl;
	guint trouter_ping_timeout;
	guint trouter_command_count;
	guint trouter_registration_timeout;
	JsonObject *trouter_socket_obj;

	//devicecode login
	gchar *login_device_code;
	guint login_device_code_timeout;
	guint login_device_code_expires_timeout;
};

struct _TeamsBuddy {
	TeamsAccount *sa;
	PurpleBuddy *buddy;
	
	/** Contact info */
	gchar *skypename;
	gchar *fullname;
	gchar *display_name;
	gboolean authorized;
	gboolean blocked;
	
	/** Profile info */
	gchar *avatar_url;
	gchar *mood;
};

void teams_buddy_free(PurpleBuddy *buddy);

void teams_do_all_the_things(TeamsAccount *sa);

#endif /* LIBTEAMS_H */
