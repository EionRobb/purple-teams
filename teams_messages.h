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
 
#ifndef TEAMS_MESSAGES_H
#define TEAMS_MESSAGES_H

#include "libteams.h"

gint teams_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
	PurpleMessage *msg
#else
	const gchar *who, const gchar *message, PurpleMessageFlags flags
#endif
);

gint teams_chat_send(PurpleConnection *pc, gint id, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg
#else
const gchar *message, PurpleMessageFlags flags
#endif
);

void teams_set_idle(PurpleConnection *pc, int time);
void teams_set_status(PurpleAccount *account, PurpleStatus *status);
guint teams_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state);
guint teams_send_typing(PurpleConnection *pc, const gchar *name, PurpleIMTypingState state);
void teams_poll(TeamsAccount *sa);
void teams_get_registration_token(TeamsAccount *sa);
void teams_subscribe(TeamsAccount *sa);
void teams_get_vdms_token(TeamsAccount *sa);
void teams_chat_kick(PurpleConnection *pc, int id, const char *who);
void teams_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who);
void teams_initiate_chat(TeamsAccount *sa, const gchar *who, gboolean one_to_one, const gchar *initial_message);
void teams_initiate_chat_from_node(PurpleBlistNode *node, gpointer userdata);
PurpleRoomlist *teams_roomlist_get_list(PurpleConnection *pc);
void teams_chat_set_topic(PurpleConnection *pc, int id, const char *topic);

void teams_subscribe_to_contact_status(TeamsAccount *sa, GSList *contacts);
void teams_unsubscribe_from_contact_status(TeamsAccount *sa, const gchar *who);
void teams_get_conversation_history_since(TeamsAccount *sa, const gchar *convname, gint since);
void teams_get_conversation_history(TeamsAccount *sa, const gchar *convname);
void teams_get_thread_users(TeamsAccount *sa, const gchar *convname);
void teams_get_all_conversations_since(TeamsAccount *sa, gint since);
void skype_web_get_offline_history(TeamsAccount *sa);
void teams_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type);

void teams_gather_self_properties(TeamsAccount *sa);

#endif /* TEAMS_MESSAGES_H */
