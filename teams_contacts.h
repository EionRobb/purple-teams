/*
 * Teams Plugin for libpurple/Pidgin
 * Copyright (c) 2014-2015 Eion Robb    
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
 
#ifndef TEAMS_CONTACTS_H
#define TEAMS_CONTACTS_H

#include "libteams.h"

void teams_get_icon(PurpleBuddy *buddy);
void teams_download_uri_to_conv(TeamsAccount *sa, const gchar *uri, PurpleConversation *conv, time_t ts, const gchar* from);
void teams_download_video_message(TeamsAccount *sa, const gchar *sid, PurpleConversation *conv);
void teams_download_moji_to_conv(TeamsAccount *sa, const gchar *text, const gchar *url_thumbnail, PurpleConversation *conv, time_t ts, const gchar* from);
void teams_present_uri_as_filetransfer(TeamsAccount *sa, const gchar *uri, const gchar *from);

PurpleXfer *teams_new_xfer(
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleProtocolXfer *prplxfer, 
#endif
PurpleConnection *pc, const char *who);

void teams_send_file(
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleProtocolXfer *prplxfer, 
#endif
PurpleConnection *pc, const gchar *who, const gchar *filename);
void teams_chat_send_file(PurpleConnection *pc, int id, const char *filename);

gboolean teams_can_receive_file(
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleProtocolXfer *prplxfer, 
#endif
PurpleConnection *pc, const gchar *who);
gboolean teams_chat_can_receive_file(PurpleConnection *pc, int id);

void teams_search_users(PurpleProtocolAction *action);
void teams_set_work_location_action(PurpleProtocolAction *action);

void teams_received_contacts(TeamsAccount *sa, PurpleXmlNode *contacts);

void teams_get_friend_profiles(TeamsAccount *sa, GSList *contacts);
void teams_get_friend_profile(TeamsAccount *sa, const gchar *who);

gboolean teams_get_friend_list(TeamsAccount *sa);
gboolean teams_check_calendar(TeamsAccount *sa);
void teams_get_info(PurpleConnection *pc, const gchar *username);
void teams_get_self_details(TeamsAccount *sa);

void teams_buddy_remove(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group);
void teams_add_buddy_with_invite(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char* message);
void teams_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group);
void teams_buddy_block(PurpleConnection *pc, const char *name);
void teams_buddy_unblock(PurpleConnection *pc, const char *name);

gboolean teams_check_authrequests(TeamsAccount *sa);

void teams_set_mood_message(TeamsAccount *sa, const gchar *mood);

#endif /* TEAMS_CONTACTS_H */
