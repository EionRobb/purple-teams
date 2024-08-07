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

#include "libteams.h"
#include "teams_contacts.h"
#include "teams_login.h"
#include "teams_messages.h"
#include "teams_util.h"
#include "teams_trouter.h"

void
teams_do_all_the_things(TeamsAccount *sa)
{
	// teams_get_vdms_token(sa);

	if (!sa->username) {
		teams_get_self_details(sa);
	} else
	if (sa->endpoint) {
		teams_get_self_details(sa);
		
		if (sa->authcheck_timeout) 
			g_source_remove(sa->authcheck_timeout);
		teams_check_authrequests(sa);
		sa->authcheck_timeout = g_timeout_add_seconds(120, (GSourceFunc)teams_check_authrequests, sa);
		purple_connection_set_state(sa->pc, PURPLE_CONNECTION_CONNECTED);

		teams_get_friend_list(sa);
		if (!purple_account_get_bool(sa->account, "only_use_websocket", FALSE)) {
			//TODO remove me when switching to websocket
			if (sa->friend_list_poll_timeout) 
				g_source_remove(sa->friend_list_poll_timeout);
			sa->friend_list_poll_timeout = g_timeout_add_seconds(300, (GSourceFunc)teams_get_friend_list, sa);
			teams_poll(sa);
		}
		teams_trouter_begin(sa);
		
		teams_get_offline_history(sa);

		teams_set_status(sa->account, purple_account_get_active_status(sa->account));
		teams_idle_update(sa);
		if (sa->idle_timeout) 
			g_source_remove(sa->idle_timeout);
		sa->idle_timeout = g_timeout_add_seconds(120, (GSourceFunc)teams_idle_update, sa);

		teams_check_calendar(sa);
		if (sa->calendar_poll_timeout) 
			g_source_remove(sa->calendar_poll_timeout);
		sa->calendar_poll_timeout = g_timeout_add_seconds(TEAMS_CALENDAR_REFRESH_MINUTES * 60, (GSourceFunc)teams_check_calendar, sa);
	} else {
		//Too soon!
		teams_subscribe(sa);
	}


}


/******************************************************************************/
/* PRPL functions */
/******************************************************************************/

static const char *
teams_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	if (buddy != NULL) {
		const gchar *buddy_name = purple_buddy_get_name(buddy);
		if (buddy_name != NULL) {
			if (TEAMS_BUDDY_IS_MSN(buddy_name)) {
				return "msn";
			} else if (TEAMS_BUDDY_IS_SKYPE(buddy_name)) {
				return "skype";
			}
		}
	}

	return "teams";
}

#ifdef ENABLE_TEAMS_PERSONAL
static const char *
teams_personal_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "teams_personal";
}
#endif /* ENABLE_TEAMS_PERSONAL */

static gchar *
teams_status_text(PurpleBuddy *buddy)
{
	TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);

	if (sbuddy && sbuddy->mood && *(sbuddy->mood))
	{
		gchar *stripped = purple_markup_strip_html(sbuddy->mood);
		gchar *escaped = g_markup_printf_escaped("%s", stripped);
		
		g_free(stripped);
		
		return escaped;
	}

	return NULL;
}

void
teams_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
	TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
	
	if (sbuddy)
	{
		PurplePresence *presence;
		PurpleStatus *status;
		TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);

		presence = purple_buddy_get_presence(buddy);
		status = purple_presence_get_active_status(presence);
		purple_notify_user_info_add_pair_html(user_info, _("Status"), purple_status_get_name(status));
		if (sbuddy->mood && *sbuddy->mood) {
			gchar *stripped = purple_markup_strip_html(sbuddy->mood);
			gchar *escaped = g_markup_printf_escaped("%s", stripped);
			
			purple_notify_user_info_add_pair_html(user_info, _("Message"), escaped);
			
			g_free(stripped);
			g_free(escaped);
		}
			
		if (sbuddy->display_name && *sbuddy->display_name) {
			gchar *escaped = g_markup_printf_escaped("%s", sbuddy->display_name);
			purple_notify_user_info_add_pair_html(user_info, "Alias", escaped);
			g_free(escaped);
		}
		if (sbuddy->fullname && *sbuddy->fullname) {
			gchar *escaped = g_markup_printf_escaped("%s", sbuddy->fullname);
			purple_notify_user_info_add_pair_html(user_info, "Full Name", escaped);
			g_free(escaped);
		}
	}
}

const gchar *
teams_list_emblem(PurpleBuddy *buddy)
{
	if (buddy != NULL) {
		//TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
		const gchar *buddy_name = purple_buddy_get_name(buddy);
		
		if (buddy_name && TEAMS_BUDDY_IS_BOT(buddy_name)) {
			return "bot";
		}
	}
	return NULL;
}

GList *
teams_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, NULL, FALSE, FALSE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "Available", _("Available"), TRUE, TRUE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "Away", _("Away"), TRUE, TRUE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_EXTENDED_AWAY, "BeRightBack", _("Be Right Back"), TRUE, TRUE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "Busy", _("Busy"), TRUE, TRUE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "DoNotDisturb", _("Do Not Disturb"), TRUE, TRUE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	// status = purple_status_type_new_with_attrs(PURPLE_STATUS_INVISIBLE, "Offline", _("Appear offline"), TRUE, TRUE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	// types = g_list_append(types, status);
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE, "Offline", _("Offline"), TRUE, TRUE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "AvailableIdle", _("Available (Idle)"), FALSE, FALSE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "BusyIdle", _("Busy (Idle)"), FALSE, FALSE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE, "PresenceUnknown", _("Unknown"), FALSE, FALSE, FALSE, "message", "Mood", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	
	return types;
}


static GList *
teams_chat_info(PurpleConnection *gc)
{
	GList *m = NULL;
	PurpleProtocolChatEntry *pce;

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Teams Name");
	pce->identifier = "chatname";
	pce->required = TRUE;
	m = g_list_append(m, pce);
	
	/*pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Password");
	pce->identifier = "password";
	pce->required = FALSE;
	m = g_list_append(m, pce);*/
	
	return m;
}

static GHashTable *
teams_chat_info_defaults(PurpleConnection *gc, const char *chatname)
{
	GHashTable *defaults;
	defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	if (chatname != NULL)
	{
		g_hash_table_insert(defaults, "chatname", g_strdup(chatname));
	}
	return defaults;
}

static gchar *
teams_get_chat_name(GHashTable *data)
{
	gchar *temp;

	if (data == NULL)
		return NULL;
	
	temp = g_hash_table_lookup(data, "chatname");

	if (temp == NULL)
		return NULL;

	return g_strdup(temp);
}


static void
teams_join_chat(PurpleConnection *pc, GHashTable *data)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	gchar *chatname;
	gchar *post;
	GString *url;
	PurpleChatConversation *chatconv;
	
	chatname = (gchar *)g_hash_table_lookup(data, "chatname");
	if (chatname == NULL)
	{
		return;
	}
	
	chatconv = purple_conversations_find_chat_with_account(chatname, sa->account);
	if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
		purple_conversation_present(PURPLE_CONVERSATION(chatconv));
		return;
	}
	
	url = g_string_new("/v1/threads/");
	g_string_append_printf(url, "%s", purple_url_encode(chatname));
	g_string_append(url, "/members/");
	g_string_append_printf(url, "8:%s", purple_url_encode(sa->username));
	
	/* Specifying the role does not seem to be required and often result in a users role being
	 * downgraded from admin to user
	 * post = "{\"role\":\"User\"}"; */
	post = "{}";
	
	//TODO find new endpoint
	//teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, sa->messages_host, url->str, post, NULL, NULL, TRUE);
	(void) post;
	
	g_string_free(url, TRUE);
	
	teams_get_conversation_history(sa, chatname);
	teams_get_thread_users(sa, chatname);
	
	chatconv = purple_serv_got_joined_chat(pc, g_str_hash(chatname), chatname);
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "chatname", g_strdup(chatname));
	
	purple_conversation_present(PURPLE_CONVERSATION(chatconv));
}

void
teams_buddy_free(PurpleBuddy *buddy)
{
	TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
	if (sbuddy != NULL)
	{
		purple_buddy_set_protocol_data(buddy, NULL);

		g_free(sbuddy->skypename);
		g_free(sbuddy->fullname);
		g_free(sbuddy->display_name);
		g_free(sbuddy->avatar_url);
		g_free(sbuddy->mood);
		
		g_free(sbuddy);
	}
}

void
teams_fake_group_buddy(PurpleConnection *pc, const char *who, const char *old_group, const char *new_group)
{
	// Do nothing to stop the remove+add behaviour
}
void
teams_fake_group_rename(PurpleConnection *pc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
	// Do nothing to stop the remove+add behaviour
}

static GList *
teams_node_menu(PurpleBlistNode *node)
{
	GList *m = NULL;
	PurpleMenuAction *act;
	PurpleBuddy *buddy;
	TeamsAccount *sa = NULL;
	
	if(PURPLE_IS_BUDDY(node))
	{
		buddy = PURPLE_BUDDY(node);
		if (purple_buddy_get_protocol_data(buddy)) {
			TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
			sa = sbuddy->sa;
		}
		if (sa == NULL) {
			PurpleConnection *pc = purple_account_get_connection(purple_buddy_get_account(buddy));
			sa = purple_connection_get_protocol_data(pc);
		}
		
		if (sa != NULL) {
			act = purple_menu_action_new(_("Initiate _Chat"),
								PURPLE_CALLBACK(teams_initiate_chat_from_node),
								sa, NULL);
			m = g_list_append(m, act);
		}
	}
	
	return m;
}

static gulong conversation_updated_signal = 0;
static gulong chat_conversation_typing_signal = 0;

static void
teams_login(PurpleAccount *account)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	TeamsAccount *sa = g_new0(TeamsAccount, 1);
	PurpleConnectionFlags flags;
	const gchar *tenant;
	const gchar *password = purple_connection_get_password(pc);
	
	purple_connection_set_protocol_data(pc, sa);

	flags = purple_connection_get_flags(pc);
	flags |= PURPLE_CONNECTION_FLAG_HTML | PURPLE_CONNECTION_FLAG_NO_BGCOLOR | PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
	purple_connection_set_flags(pc, flags);
	
	if (!TEAMS_BUDDY_IS_MSN(purple_account_get_username(account))) {
		sa->username = g_ascii_strdown(purple_account_get_username(account), -1);
	}
	sa->account = account;
	sa->pc = pc;
	sa->cookie_jar = purple_http_cookie_jar_new();
	sa->sent_messages_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	sa->buddy_to_chat_lookup = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	sa->chat_to_buddy_lookup = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	sa->calendar_reminder_timeouts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	sa->messages_host = g_strdup(TEAMS_DEFAULT_MESSAGES_HOST);
	sa->keepalive_pool = purple_http_keepalive_pool_new();
	purple_http_keepalive_pool_set_limit_per_host(sa->keepalive_pool, TEAMS_MAX_CONNECTIONS);
	sa->conns = purple_http_connection_set_new();
	sa->processed_event_messages = g_queue_new();
	
#ifdef ENABLE_TEAMS_PERSONAL
	tenant = TEAMS_PERSONAL_TENANT_ID;
#else
	tenant = purple_account_get_string(account, "tenant", NULL);
#endif // ENABLE_TEAMS_PERSONAL
	if (tenant != NULL) {
		sa->tenant = g_strdup(tenant);
	}
	
	if (password && *password) {
		sa->refresh_token = g_strdup(password);
		purple_connection_update_progress(pc, _("Authenticating"), 1, 3);
		teams_oauth_refresh_token(sa);
	} else {
		teams_do_devicecode_login(sa);
	}
	
	if (!conversation_updated_signal) {
		conversation_updated_signal = purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", purple_connection_get_protocol(pc), PURPLE_CALLBACK(teams_mark_conv_seen), NULL);
	}
	if (!chat_conversation_typing_signal) {
		chat_conversation_typing_signal = purple_signal_connect(purple_conversations_get_handle(), "chat-conversation-typing", purple_connection_get_protocol(pc), PURPLE_CALLBACK(teams_conv_send_typing), NULL);
	}
}

static void
teams_close(PurpleConnection *pc)
{
	TeamsAccount *sa;
	GSList *buddies;
	GList *convs;
	
	g_return_if_fail(pc != NULL);
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	purple_connection_set_state(pc, PURPLE_CONNECTION_DISCONNECTING);
#endif
	
	sa = purple_connection_get_protocol_data(pc);
	g_return_if_fail(sa != NULL);
	
	g_source_remove(sa->calendar_poll_timeout);
	g_source_remove(sa->friend_list_poll_timeout);
	g_source_remove(sa->authcheck_timeout);
	g_source_remove(sa->poll_timeout);
	g_source_remove(sa->watchdog_timeout);
	g_source_remove(sa->refresh_token_timeout);
	g_source_remove(sa->idle_timeout);
	g_source_remove(sa->login_device_code_expires_timeout);
	g_source_remove(sa->login_device_code_timeout);
	// Trouter timeouts handled in teams_trouter_stop()

	teams_logout(sa);
	
	purple_debug_info("teams", "destroying incomplete connections\n");

	purple_http_connection_set_destroy(sa->conns);
	sa->conns = NULL;
	purple_http_conn_cancel_all(pc);
	purple_http_keepalive_pool_unref(sa->keepalive_pool);
	purple_http_cookie_jar_unref(sa->cookie_jar);

	teams_trouter_stop(sa);

	buddies = purple_blist_find_buddies(sa->account, NULL);
	while (buddies != NULL) {
		PurpleBuddy *buddy = buddies->data;
		teams_buddy_free(buddy);
		purple_buddy_set_protocol_data(buddy, NULL);
		buddies = g_slist_delete_link(buddies, buddies);
	}

	convs = purple_get_conversations();
	while (convs != NULL) {
		PurpleConversation *conv = convs->data;
		if(purple_conversation_get_account(conv) == sa->account) {
			g_free(purple_conversation_get_data(conv, "last_teams_id"));
			g_free(purple_conversation_get_data(conv, "last_teams_clientmessageid"));
			g_free(purple_conversation_get_data(conv, "chatname"));
		}
		convs = g_list_next(convs);
	}

	// Don't use g_queue_free_full() since that's too-new for Windows
	while (!g_queue_is_empty(sa->processed_event_messages)) {
		gpointer event_message = g_queue_pop_head(sa->processed_event_messages);
		g_free(event_message);
	}
	g_queue_free(sa->processed_event_messages);
	
	g_hash_table_destroy(sa->sent_messages_hash);
	g_hash_table_destroy(sa->buddy_to_chat_lookup);
	g_hash_table_destroy(sa->chat_to_buddy_lookup);
	g_hash_table_destroy(sa->calendar_reminder_timeouts);
	
	g_free(sa->login_device_code);
	g_free(sa->substrate_access_token);
	g_free(sa->csa_access_token);
	g_free(sa->presence_access_token);
	g_free(sa->id_token);
	g_free(sa->refresh_token);
	g_free(sa->region);
	g_free(sa->messages_cursor);
	g_free(sa->tenant);
	
	g_free(sa->vdms_token);
	g_free(sa->messages_host);
	g_free(sa->skype_token);
	g_free(sa->registration_token);
	g_free(sa->endpoint);
	g_free(sa->primary_member_name);
	g_free(sa->self_display_name);
	g_free(sa->username);
	g_free(sa);
}

gboolean
teams_offline_message(const PurpleBuddy *buddy)
{
	return TRUE;
}

static PurpleCmdRet
teams_cmd_list(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	purple_roomlist_show_with_account(purple_conversation_get_account(conv));
	
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
teams_cmd_leave(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	TeamsAccount *sa;
	
	pc = purple_conversation_get_connection(conv);
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;
	
	sa = purple_connection_get_protocol_data(pc);
	if (sa == NULL)
		return PURPLE_CMD_RET_FAILED;
	
	teams_chat_kick(pc, id, sa->username);
	
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
teams_cmd_kick(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	
	pc = purple_conversation_get_connection(conv);
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;
	
	teams_chat_kick(pc, id, args[0]);
	
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
teams_cmd_invite(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	
	pc = purple_conversation_get_connection(conv);	
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;
	
	teams_chat_invite(pc, id, NULL, args[0]);
	
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
teams_cmd_topic(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	PurpleChatConversation *chat;
	int id = -1;
	
	pc = purple_conversation_get_connection(conv);
	chat = PURPLE_CHAT_CONVERSATION(conv);
	id = purple_chat_conversation_get_id(chat);
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;

	if (!args || !args[0]) {
		gchar *buf;
		const gchar *topic = purple_chat_conversation_get_topic(chat);

		if (topic) {
			gchar *tmp, *tmp2;
			tmp = g_markup_escape_text(topic, -1);
			tmp2 = purple_markup_linkify(tmp);
			buf = g_strdup_printf(_("current topic is: %s"), tmp2);
			g_free(tmp);
			g_free(tmp2);
		} else {
			buf = g_strdup(_("No topic is set"));
		}
		
		purple_conversation_write_system_message(conv, buf, PURPLE_MESSAGE_NO_LOG);
		
		g_free(buf);
		return PURPLE_CMD_RET_OK;
	}
	
	teams_chat_set_topic(pc, id, args[0]);
	
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
teams_cmd_call(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	TeamsAccount *sa;
	const gchar *convname = NULL;
	
	pc = purple_conversation_get_connection(conv);
	if (pc == NULL)
		return PURPLE_CMD_RET_FAILED;
	sa = purple_connection_get_protocol_data(pc);
	
	convname = purple_conversation_get_data(conv, "chatname");
	if (!convname) {
		convname = purple_conversation_get_name(conv);
	
		if (PURPLE_IS_IM_CONVERSATION(conv)) {
			if (!TEAMS_BUDDY_IS_NOTIFICATIONS(convname)) {
				convname = g_hash_table_lookup(sa->buddy_to_chat_lookup, convname);
			}
		}
	}
	
	if (!convname)
		return PURPLE_CMD_RET_FAILED;
	
	gchar *message = g_strconcat("https://" TEAMS_BASE_ORIGIN_HOST "/l/meetup-join/", purple_url_encode(convname), "/0", NULL);
	
	PurpleMessage *msg = purple_message_new_system(message, 0);
	purple_conversation_write_message(conv, msg);
	purple_message_destroy(msg);
	
	g_free(message);
	
	return PURPLE_CMD_RET_OK;
}

/******************************************************************************/
/* Plugin functions */
/******************************************************************************/

static gboolean
teams_uri_handler(const char *proto, const char *cmd, GHashTable *params)
{
	//PurpleAccount *account;
	//PurpleConnection *pc;
	
	if (!g_str_equal(proto, "msteams"))
		return FALSE;
	
	// msteams:/1/channel/19%3a.....%40thread.skype/{nameofchannel}?groupId={groupId}&tenantId={tenantId}
	
	//we don't know how to handle this
	return FALSE;
}

#if PURPLE_VERSION_CHECK(3, 0, 0)
	typedef struct _TeamsProtocol
	{
		PurpleProtocol parent;
	} TeamsProtocol;

	typedef struct _TeamsProtocolClass
	{
		PurpleProtocolClass parent_class;
	} TeamsProtocolClass;

	G_MODULE_EXPORT GType teams_protocol_get_type(void);
	#define TEAMS_TYPE_PROTOCOL             (teams_protocol_get_type())
	#define TEAMS_PROTOCOL(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), TEAMS_TYPE_PROTOCOL, TeamsProtocol))
	#define TEAMS_PROTOCOL_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), TEAMS_TYPE_PROTOCOL, TeamsProtocolClass))
	#define TEAMS_IS_PROTOCOL(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), TEAMS_TYPE_PROTOCOL))
	#define TEAMS_IS_PROTOCOL_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), TEAMS_TYPE_PROTOCOL))
	#define TEAMS_PROTOCOL_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), TEAMS_TYPE_PROTOCOL, TeamsProtocolClass))

	static PurpleProtocol *teams_protocol;
#else
	
// Normally set in core.c in purple3
void _purple_socket_init(void);
void _purple_socket_uninit(void);

#endif


static gboolean
plugin_load(PurplePlugin *plugin
#if PURPLE_VERSION_CHECK(3, 0, 0)
, GError **error
#endif
)
{
	
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	_purple_socket_init();
	purple_http_init();
#endif
	
	
	//leave
	purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						TEAMS_PLUGIN_ID, teams_cmd_leave,
						_("leave:  Leave the group chat"), NULL);
	//kick
	purple_cmd_register("kick", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY,
						TEAMS_PLUGIN_ID, teams_cmd_kick,
						_("kick &lt;user&gt;:  Kick a user from the group chat."),
						NULL);
	//add
	purple_cmd_register("add", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY,
						TEAMS_PLUGIN_ID, teams_cmd_invite,
						_("add &lt;user&gt;:  Add a user to the group chat."),
						NULL);
	//topic
	purple_cmd_register("topic", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						TEAMS_PLUGIN_ID, teams_cmd_topic,
						_("topic [&lt;new topic&gt;]:  View or change the topic"),
						NULL);
	/*
	//call, as in call person
	//kickban
	purple_cmd_register("kickban", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY,
						TEAMS_PLUGIN_ID, teams_cmd_kickban,
						_("kickban &lt;user&gt; [room]:  Kick and ban a user from the room."),
						NULL);
	//setrole
	purple_cmd_register("setrole", "ss", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY,
						TEAMS_PLUGIN_ID, teams_cmd_setrole,
						_("setrole &lt;user&gt; &lt;MASTER | USER | ADMIN&gt;:  Change the role of a user."),
						NULL);
	*/
	
	purple_cmd_register("list", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_IM,
						TEAMS_PLUGIN_ID, teams_cmd_list,
						_("list: Display a list of multi-chat group chats you are in."),
						NULL);
	
	purple_cmd_register("call", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_IM,
						TEAMS_PLUGIN_ID, teams_cmd_call,
						_("call: Create a URL link to start a voice/video call in the browser."),
						NULL);
	
	purple_signal_connect(purple_get_core(), "uri-handler", plugin, PURPLE_CALLBACK(teams_uri_handler), NULL);
	
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin
#if PURPLE_VERSION_CHECK(3, 0, 0)
, GError **error
#endif
)
{
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	_purple_socket_uninit();
	purple_http_uninit();
#endif
	purple_signals_disconnect_by_handle(plugin);
	
	return TRUE;
}

static GList *
teams_actions(
#if !PURPLE_VERSION_CHECK(3, 0, 0)
PurplePlugin *plugin, gpointer context
#else
PurpleConnection *pc
#endif
)
{
	GList *m = NULL;
	PurpleProtocolAction *act;

	act = purple_protocol_action_new(_("Search for Teams Contacts"), teams_search_users);
	m = g_list_append(m, act);

	return m;
}

#if !PURPLE_VERSION_CHECK(2, 8, 0)
#	define OPT_PROTO_INVITE_MESSAGE 0x00000800
#endif

// Add forwards-compatibility for newer libpurple's when compiling on older ones
typedef struct 
{
	PurplePluginProtocolInfo parent;

	#if !PURPLE_VERSION_CHECK(2, 14, 0)
		char *(*get_cb_alias)(PurpleConnection *gc, int id, const char *who);
		gboolean (*chat_can_receive_file)(PurpleConnection *, int id);
		void (*chat_send_file)(PurpleConnection *, int id, const char *filename);
	#endif
} PurplePluginProtocolInfoExt;

#if !PURPLE_VERSION_CHECK(3, 0, 0)
static void
plugin_init(PurplePlugin *plugin)
{
	PurplePluginInfo *info = g_new0(PurplePluginInfo, 1);
	PurplePluginProtocolInfoExt *prpl_info_ext = g_new0(PurplePluginProtocolInfoExt, 1);
	PurplePluginProtocolInfo *prpl_info = (PurplePluginProtocolInfo *) prpl_info_ext;
#endif

#if PURPLE_VERSION_CHECK(3, 0, 0)
static void 
teams_protocol_init(PurpleProtocol *prpl_info) 
{
	PurpleProtocol *info = prpl_info;
#endif
	PurpleAccountOption *opt;
	PurpleBuddyIconSpec icon_spec = {"jpeg", 0, 0, 96, 96, 0, PURPLE_ICON_SCALE_DISPLAY};

	//PurpleProtocol
	info->id = TEAMS_PLUGIN_ID;
	info->name = "Teams (Work and School)";
	prpl_info->options = OPT_PROTO_NO_PASSWORD | OPT_PROTO_CHAT_TOPIC /*| OPT_PROTO_INVITE_MESSAGE*/ | OPT_PROTO_IM_IMAGE;

#if !PURPLE_VERSION_CHECK(3, 0, 0)
#	define TEAMS_PRPL_APPEND_ACCOUNT_OPTION(opt) prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, (opt));
	prpl_info->icon_spec = icon_spec;
#else
#	define TEAMS_PRPL_APPEND_ACCOUNT_OPTION(opt) prpl_info->account_options = g_list_append(prpl_info->account_options, (opt));
	prpl_info->icon_spec = &icon_spec;
#endif
	
#ifndef ENABLE_TEAMS_PERSONAL
	opt = purple_account_option_string_new(_("Tenant"), "tenant", "");
	TEAMS_PRPL_APPEND_ACCOUNT_OPTION(opt);
#endif
	
	opt = purple_account_option_bool_new(_("Set global status"), "set-global-status", TRUE);
	TEAMS_PRPL_APPEND_ACCOUNT_OPTION(opt);
	
	opt = purple_account_option_bool_new(_("Collapse Teams threads into a single chat window"), "should_collapse_threads", TRUE);
	TEAMS_PRPL_APPEND_ACCOUNT_OPTION(opt);
	
	opt = purple_account_option_int_new(_("Notify me before meeting begins (minutes)"), "calendar_notify_minutes", -1);
	TEAMS_PRPL_APPEND_ACCOUNT_OPTION(opt);

	opt = purple_account_option_bool_new(_("Only use Websocket for message events (Experimental)"), "only_use_websocket", FALSE);
	TEAMS_PRPL_APPEND_ACCOUNT_OPTION(opt);

#undef TEAMS_PRPL_APPEND_ACCOUNT_OPTION
	
#if PURPLE_VERSION_CHECK(3, 0, 0)
}

static void 
teams_protocol_class_init(PurpleProtocolClass *prpl_info) 
{
#endif
	//PurpleProtocolClass
	prpl_info->login = teams_login;
	prpl_info->close = teams_close;
	prpl_info->status_types = teams_status_types;
	prpl_info->list_icon = teams_list_icon;
#if PURPLE_VERSION_CHECK(3, 0, 0)
}

static void 
teams_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info) 
{
	PurpleProtocolClientIface *info = prpl_info;
#endif
	
	//PurpleProtocolClientIface
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	info->actions = teams_actions;
#else
	info->get_actions = teams_actions;
#endif
	prpl_info->list_emblem = teams_list_emblem;
	prpl_info->status_text = teams_status_text;
	prpl_info->tooltip_text = teams_tooltip_text;
	prpl_info->blist_node_menu = teams_node_menu;
	prpl_info->buddy_free = teams_buddy_free;
	prpl_info->normalize = purple_normalize_nocase;
	prpl_info->offline_message = teams_offline_message;
	prpl_info->get_account_text_table = NULL; // teams_get_account_text_table;
#if PURPLE_VERSION_CHECK(3, 0, 0)
}

static void 
teams_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info) 
{
#endif
	
	//PurpleProtocolServerIface
	prpl_info->get_info = teams_get_info;
	prpl_info->set_status = teams_set_status;
	prpl_info->set_idle = teams_set_idle;
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	prpl_info->add_buddy = teams_add_buddy;
#else
	prpl_info->add_buddy = teams_add_buddy_with_invite;
#endif
	prpl_info->remove_buddy = teams_buddy_remove;
	prpl_info->group_buddy = teams_fake_group_buddy;
	prpl_info->rename_group = teams_fake_group_rename;
#if PURPLE_VERSION_CHECK(3, 0, 0)
}

static void 
teams_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info) 
{
#endif
	
	//PurpleProtocolIMIface
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	prpl_info->send_im = teams_send_im;
#else
	prpl_info->send = teams_send_im;
#endif
	prpl_info->send_typing = teams_send_typing;
#if PURPLE_VERSION_CHECK(3, 0, 0)
}

static void 
teams_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info) 
{
#endif
	
	//PurpleProtocolChatIface
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	prpl_info->chat_info = teams_chat_info;
	prpl_info->chat_info_defaults = teams_chat_info_defaults;
	prpl_info->join_chat = teams_join_chat;
	prpl_info->get_chat_name = teams_get_chat_name;
	prpl_info->chat_invite = teams_chat_invite;
	prpl_info->chat_leave =	NULL; //teams_chat_fake_leave;
	prpl_info->chat_send = teams_chat_send;
	prpl_info->set_chat_topic = teams_chat_set_topic;
	#if PURPLE_VERSION_CHECK(2, 14, 0)
		//prpl_info->get_cb_alias = teams_chat_get_cb_alias;
	#else
		//prpl_info_ext->get_cb_alias = teams_chat_get_cb_alias;
	#endif
#else
	prpl_info->info = teams_chat_info;
	prpl_info->info_defaults = teams_chat_info_defaults;
	prpl_info->join = teams_join_chat;
	prpl_info->get_name = teams_get_chat_name;
	prpl_info->invite = teams_chat_invite;
	prpl_info->leave =	NULL; //teams_chat_fake_leave;
	prpl_info->send = teams_chat_send;
	prpl_info->set_topic = teams_chat_set_topic;
#endif
#if PURPLE_VERSION_CHECK(3, 0, 0)
}

static void 
teams_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *prpl_info) 
{
#endif

	//PurpleProtocolPrivacyIface
	prpl_info->add_deny = teams_buddy_block;
	prpl_info->rem_deny = teams_buddy_unblock;
#if PURPLE_VERSION_CHECK(3, 0, 0)
}

static void 
teams_protocol_xfer_iface_init(PurpleProtocolXferInterface *prpl_info) 
{
#endif
	
	//PurpleProtocolXferInterface
	prpl_info->new_xfer = teams_new_xfer;
	prpl_info->send_file = teams_send_file;
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	prpl_info->can_receive_file = teams_can_receive_file;
#else
	prpl_info->can_receive = teams_can_receive_file;
#endif
	#if PURPLE_VERSION_CHECK(2, 14, 0)
		// prpl_info->chat_send_file = teams_chat_send_file;
		prpl_info->chat_can_receive_file = teams_chat_can_receive_file;
	#else
		// prpl_info_ext->chat_send_file = teams_chat_send_file;
		prpl_info_ext->chat_can_receive_file = teams_chat_can_receive_file;
	#endif
	
#if PURPLE_VERSION_CHECK(3, 0, 0)
}

static void 
teams_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info) 
{
#endif
	
	//PurpleProtocolRoomlistIface
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	prpl_info->roomlist_get_list = teams_roomlist_get_list;
#else
	prpl_info->get_list = teams_roomlist_get_list;
#endif
	
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	// Plugin info
	info->magic = PURPLE_PLUGIN_MAGIC;
	info->major_version = 2;
	info->minor_version = MIN(PURPLE_MINOR_VERSION, 8);
	info->type = PURPLE_PLUGIN_PROTOCOL;
	info->priority = PURPLE_PRIORITY_DEFAULT;
	info->version = TEAMS_PLUGIN_VERSION;
	info->summary = N_("Teams Protocol Plugin");
	info->description = N_("Teams Protocol Plugin");
	info->author = "Eion Robb <eionrobb@gmail.com>";
	info->homepage = "http://github.com/EionRobb/purple-teams";
	info->load = plugin_load;
	info->unload = plugin_unload;
	info->extra_info = prpl_info;
	
	// Protocol info
	#if PURPLE_MINOR_VERSION >= 5
		prpl_info->struct_size = sizeof(PurplePluginProtocolInfoExt);
	#endif
	#if PURPLE_MINOR_VERSION >= 8
		prpl_info->add_buddy_with_invite = teams_add_buddy_with_invite;
	#endif
	
	plugin->info = info;

#ifdef ENABLE_TEAMS_PERSONAL
	plugin->info->id = TEAMS_PERSONAL_PLUGIN_ID;
	plugin->info->name = "Teams (Personal)";
	prpl_info->list_icon = teams_personal_list_icon;
#endif // ENABLE_TEAMS_PERSONAL

#endif
	
}

#if PURPLE_VERSION_CHECK(3, 0, 0)


PURPLE_DEFINE_TYPE_EXTENDED(
	TeamsProtocol, teams_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  teams_protocol_client_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  teams_protocol_server_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  teams_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  teams_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
	                                  teams_protocol_privacy_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
	                                  teams_protocol_roomlist_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_XFER,
	                                  teams_protocol_xfer_iface_init)
);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	teams_protocol_register_type(plugin);
	teams_protocol = purple_protocols_add(TEAMS_TYPE_PROTOCOL, error);
	if (!teams_protocol)
		return FALSE;
	
	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(teams_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",           TEAMS_PLUGIN_ID,
		"name",         "Teams Protocol",
		"version",      TEAMS_PLUGIN_VERSION,
		"category",     N_("Protocol"),
		"summary",      N_("Teams Protocol Plugin"),
		"description",  N_("Teams Protocol Plugin"),
		"website",      "http://github.com/EionRobb/purple-teams",
		"abi-version",  PURPLE_ABI_VERSION,
		"flags",        PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		                PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}


PURPLE_PLUGIN_INIT(teams, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);
#else
	
static PurplePluginInfo aLovelyBunchOfCoconuts;
PURPLE_INIT_PLUGIN(teams, plugin_init, aLovelyBunchOfCoconuts);
#endif

