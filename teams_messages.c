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
 
#include "teams_messages.h"
#include "purplecompat.h"
#include "teams_util.h"
#include "teams_connection.h"
#include "teams_contacts.h"
#include "teams_trouter.h"
#include "teams_cards.h"
#include "util.h"

static GString* make_last_timestamp_setting(const gchar *convname) {
	GString *rv = g_string_new(NULL);
	g_string_printf(rv, "%s_last_message_timestamp", convname);
	return rv;
}

static gchar *
teams_meify(const gchar *message, gint skypeemoteoffset)
{
	guint len;
	len = strlen(message);
	
	if (skypeemoteoffset <= 0 || skypeemoteoffset >= len)
		return g_strdup(message);
	
	return g_strconcat("/me ", message + skypeemoteoffset, NULL);
}

static void
process_userpresence_resource(TeamsAccount *sa, JsonObject *resource)
{
	const gchar *selfLink = json_object_get_string_member(resource, "selfLink");
	const gchar *status = json_object_get_string_member(resource, "status");
	// const gchar *capabilities = json_object_get_string_member(resource, "capabilities");
	// const gchar *lastSeenAt = json_object_get_string_member(resource, "lastSeenAt");
	const gchar *from;
	// gboolean is_idle;
	
	from = teams_contact_url_to_name(selfLink);
	g_return_if_fail(from);
	
	if (!purple_blist_find_buddy(sa->account, from))
	{
		PurpleGroup *group = teams_get_blist_group(sa);
		
		if (teams_is_user_self(sa, from)) {
			return;
		}
		
		purple_blist_add_buddy(purple_buddy_new(sa->account, from, NULL), NULL, group, NULL);
	}

	purple_protocol_got_user_status(sa->account, from, status, NULL);

	gboolean is_idle = strstr(status, "Idle") != NULL;
	purple_prpl_got_user_idle(sa->account, from, is_idle, 0);
}

// static gboolean
// teams_clear_typing_hack(PurpleChatUser *cb)
// {
	// PurpleChatUserFlags cbflags;
	
	// cbflags = purple_chat_user_get_flags(cb);
	// cbflags &= ~PURPLE_CHAT_USER_TYPING;
	// purple_chat_user_set_flags(cb, cbflags);
	
	// return FALSE;
// }

static void
teams_find_incoming_img(TeamsAccount *sa, PurpleConversation *conv, time_t msg_time, const gchar *msg_who, gchar **msg_content)
{
	const char *tmp;
	const char *start;
	const char *end;
	GData *attributes;
	GString *newmsg = NULL;

	tmp = *msg_content;
	
	while (purple_markup_find_tag("img", tmp, &start, &end, &attributes)) {
		const char *srcstr = NULL;
		const char *itemtype = NULL;

		if (newmsg == NULL)
			newmsg = g_string_new("");

		//copy any text before the img tag
		if (tmp < start)
			g_string_append_len(newmsg, tmp, start - tmp);
		
		itemtype = g_datalist_get_data(&attributes, "itemtype");
		if (purple_strequal(itemtype, "http://schema.skype.com/AMSImage")) {
			srcstr = g_datalist_get_data(&attributes, "src");
			if (srcstr != NULL) {
				teams_download_uri_to_conv(sa, srcstr, conv, msg_time, msg_who);
			}
			
		} else if (purple_strequal(itemtype, "http://schema.skype.com/Emoji")) {
			const gchar *alt = g_datalist_get_data(&attributes, "alt");
			g_string_append(newmsg, alt);
			
		} else {
			srcstr = g_datalist_get_data(&attributes, "src");
			if (srcstr != NULL) {
				teams_download_uri_to_conv(sa, srcstr, conv, msg_time, msg_who);
				g_string_append(newmsg, srcstr);
			}
		}
		
		g_datalist_clear(&attributes);
		// Continue from the end of the tag 
		tmp = end + 1;
	}

	if (newmsg != NULL)
	{
		// Append any remaining message data
		g_string_append(newmsg, tmp);
		
		g_free(*msg_content);
		*msg_content = g_string_free(newmsg, FALSE);
	}
}

static gchar *
teams_process_files_in_properties(JsonObject *properties, gchar **html)
{
	if (html == NULL) {
		return NULL;
	}

	if (json_object_has_member(properties, "files")) {
		const gchar *files_str = json_object_get_string_member(properties, "files");
		JsonArray *files = json_decode_array(files_str, -1);
		GString *files_string = g_string_new(NULL);
		guint i, len = json_array_get_length(files);

		if (len > 0) {
			g_string_append(files_string, "<br>");
			g_string_append(files_string, _("Files sent"));
			g_string_append(files_string, "</b>: <br>");
		}
		for(i = 0; i < len; i++) {
			JsonObject *file = json_array_get_object_element(files, i);
			g_string_append(files_string, "* <a href=\"");
			g_string_append(files_string, json_object_get_string_member(file, "objectUrl"));
			g_string_append(files_string, "\">");
			g_string_append(files_string, json_object_get_string_member(file, "fileName"));
			g_string_append(files_string, "</a><br>");
			
			//Potentially use the preview image in  file.filePreview.previewUrl
		}
		
		json_array_unref(files);
		
		gchar *temp = g_strconcat(*html ? *html : "", files_string->str, NULL);
		g_free(*html);
		*html = temp;
		
		g_string_free(files_string, TRUE);
	}
	
	return *html;
}

static gchar *
teams_process_cards_in_properties(JsonObject *properties, gchar **html)
{
	if (html == NULL) {
		return NULL;
	}

	if (json_object_has_member(properties, "cards")) {
		const gchar *cards_str = json_object_get_string_member(properties, "cards");
		JsonArray *cards = json_decode_array(cards_str, -1);
		GString *cards_string = g_string_new(NULL);
		guint i, len = json_array_get_length(cards);

		for(i = 0; i < len; i++) {
			JsonObject *card = json_array_get_object_element(cards, i);
			JsonObject *content = json_object_get_object_member(card, "content");
			const gchar *contentType = json_object_get_string_member(card, "contentType");

			gchar *card_html = teams_convert_card_to_html(content, contentType);
			if (card_html == NULL) {
				// Couldn't process or unknown content type, dump the raw data
				card_html = teams_jsonobj_to_string(card);
			}
			g_string_append(cards_string, card_html);
			g_string_append(cards_string, "<br>");
			g_free(card_html);
		}
		
		json_array_unref(cards);
		
		gchar *temp = g_strconcat(*html ? *html : "", cards_string->str, NULL);
		g_free(*html);
		*html = temp;
		
		g_string_free(cards_string, TRUE);
	}
	
	return *html;

}

static gchar *
teams_clean_chat_name(TeamsAccount *sa, gchar *chatname)
{
	PurpleAccount *account = sa->account;
	gboolean should_collapse_threads = TRUE;
	
	should_collapse_threads = purple_account_get_bool(account, "should_collapse_threads", should_collapse_threads);
	
	//TODO allow a per-chat setting to not collapse
	if (should_collapse_threads) {
		gchar *qmark = strchr(chatname, ';');
		if (qmark != NULL) {
			*qmark = '\0';
		}
	}
	
	return chatname;
}

static void
process_message_resource(TeamsAccount *sa, JsonObject *resource)
{
	const gchar *clientmessageid = NULL;
	const gchar *skypeeditedid = NULL;
	const gchar *messagetype = json_object_get_string_member(resource, "messagetype");
	const gchar *from = json_object_get_string_member(resource, "from");
	const gchar *content = NULL;
	const gchar *composetime = json_object_get_string_member(resource, "composetime");
	const gchar *conversationLink = json_object_get_string_member(resource, "conversationLink");
	time_t composetimestamp = purple_str_to_time(composetime, TRUE, NULL, NULL, NULL);
	gchar **messagetype_parts;
	PurpleConversation *conv = NULL;
	gchar *convname = NULL;
	const gchar *chatname = NULL;
	JsonObject *properties = NULL;
	
	g_return_if_fail(messagetype != NULL);
	
	messagetype_parts = g_strsplit(messagetype, "/", -1);
	
	if (json_object_has_member(resource, "clientmessageid"))
		clientmessageid = json_object_get_string_member(resource, "clientmessageid");
	
	if (clientmessageid && *clientmessageid && g_hash_table_remove(sa->sent_messages_hash, clientmessageid)) {
		// We sent this message from here already
		g_strfreev(messagetype_parts);
		return;
	}
	
	if (json_object_has_member(resource, "skypeeditedid")) {
		skypeeditedid = json_object_get_string_member(resource, "skypeeditedid");
	}
	if (json_object_has_member(resource, "properties")) {
		properties = json_object_get_object_member(resource, "properties");
		if (json_object_has_member(properties, "edittime")) {
			skypeeditedid = json_object_get_string_member(properties, "edittime");
		}
		
		//TODO use "importance" for nudges
		//purple_prpl_got_attention(pc, username, 0);
		//purple_prpl_got_attention_in_chat(pc, id, username, 0);
		
		if (json_object_has_member(properties, "deletetime")) {
			// Deleted a message
		}
		
		if (json_object_has_member(properties, "emotions")) {
			// "emotions": [{
					// "key": "heart",
					// "users": []
				// }, {
					// "key": "like",
					// "users": [{
						// "mri": "8:orgid:{...guid...}",
						// "time": 1668285027384,
						// "value": "1668285027230"
					// }]
				// }]
		}
	}
	
	if (json_object_has_member(resource, "content")) {
		content = json_object_get_string_member(resource, "content");
	}
	
	if (conversationLink) {
		chatname = teams_thread_url_to_name(conversationLink);
		convname = g_strdup(chatname);
	}
	
	if (chatname && !g_hash_table_lookup(sa->chat_to_buddy_lookup, chatname) && !strstr(chatname, "@unq.gbl.spaces")) {
		// This is a Thread/Group chat message
		const gchar *topic;
		PurpleChatConversation *chatconv;
		
		//Turn threaded group chats into unthreaded ones, as required
		chatname = teams_clean_chat_name(sa, convname);
		
		chatconv = purple_conversations_find_chat_with_account(chatname, sa->account);
		if (!chatconv) {
			chatconv = purple_serv_got_joined_chat(sa->pc, g_str_hash(chatname), chatname);
			purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "chatname", g_strdup(chatname));

			if (json_object_has_member(resource, "threadtopic")) {
				topic = json_object_get_string_member(resource, "threadtopic");
				purple_chat_conversation_set_topic(chatconv, NULL, topic);
			}
				
			teams_get_conversation_history(sa, chatname);
			teams_get_thread_users(sa, chatname);
		}
		GString *chat_last_timestamp = make_last_timestamp_setting(convname);
		purple_account_set_int(sa->account, chat_last_timestamp->str, composetimestamp);
		g_string_free(chat_last_timestamp, TRUE);
		
		conv = PURPLE_CONVERSATION(chatconv);
		
		if (g_str_equal(messagetype_parts[0], "Control") && (g_str_equal(messagetype_parts[1], "ClearTyping") || g_str_equal(messagetype_parts[1], "Typing"))) {
			PurpleChatUserFlags cbflags;
			PurpleChatUser *cb;

			from = teams_contact_url_to_name(from);
			if (from == NULL) {
				g_strfreev(messagetype_parts);
				g_return_if_reached();
				return;
			}
			
			cb = purple_chat_conversation_find_user(chatconv, from);
			if (cb != NULL) {
				cbflags = purple_chat_user_get_flags(cb);
				
				if (g_str_equal(messagetype_parts[1], "Typing")) {
					cbflags |= PURPLE_CHAT_USER_TYPING;
				} else {
					// ClearTyping
					cbflags &= ~PURPLE_CHAT_USER_TYPING;
				}
				
				purple_chat_user_set_flags(cb, cbflags);
				
				//TODO clear typing after 22 seconds
			}
			
		} else if (g_str_equal(messagetype_parts[0], "RichText") || g_str_equal(messagetype_parts[0], "Text")) {
			gchar *html = NULL;
			gint64 skypeemoteoffset = 0;
			PurpleChatUserFlags cbflags;
			PurpleChatUser *cb; 
			
			from = teams_contact_url_to_name(from);
			if (from == NULL) {
				g_free(messagetype_parts);
				g_return_if_reached();
				return;
			}

			// Hard reset cbflags even if user changed settings while someone typing message.
			cb = purple_chat_conversation_find_user(chatconv, from);
			if (cb != NULL) {
				cbflags = purple_chat_user_get_flags(cb);
				
				cbflags &= ~PURPLE_CHAT_USER_TYPING;
				
				purple_chat_user_set_flags(cb, cbflags);
			
			} else {
				purple_chat_conversation_add_user(chatconv, from, NULL, PURPLE_CHAT_USER_NONE, FALSE);
				cb = purple_chat_conversation_find_user(chatconv, from);
			}

			if (json_object_has_member(resource, "imdisplayname") || json_object_has_member(resource, "imDisplayName")) {
				const gchar *displayname = json_object_get_string_member(resource, "imdisplayname");
				if (displayname == NULL) {
					displayname = json_object_get_string_member(resource, "imDisplayName");
				}
				
				if (cb && displayname && *displayname && !g_str_has_prefix(displayname, "orgid:")) {
					purple_chat_user_set_alias(cb, displayname);
				}
			}
			
			if (g_str_equal(messagetype, "RichText/UriObject")) {
				PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
				const gchar *uri = purple_xmlnode_get_attrib(blob, "url_thumbnail");
				
				if (from && *from) {
					teams_download_uri_to_conv(sa, uri, conv, composetimestamp, from);
				}
				purple_xmlnode_free(blob);
				
				g_free(messagetype_parts);
				return;
				
			} else if (purple_strequal(messagetype, "RichText/Media_Card")) {
				gboolean message_processed = FALSE;
				PurpleXmlNode *uriobject = purple_xmlnode_from_str(content, -1);
				const gchar *uriobject_type = purple_xmlnode_get_attrib(uriobject, "type");
				
				if (purple_strequal(purple_xmlnode_get_name(uriobject), "URIObject") && purple_strequal(uriobject_type, "SWIFT.1")) {
					PurpleXmlNode *swift = purple_xmlnode_get_child(uriobject, "Swift");
					const gchar *swift_b64 = purple_xmlnode_get_attrib(swift, "b64");
					gsize swift_b64_len;
					guchar *swift_data = purple_base64_decode(swift_b64, &swift_b64_len);
					JsonObject *swift_json = json_decode_object((const gchar *)swift_data, swift_b64_len);
					JsonArray *swift_attachments = json_object_get_array_member(swift_json, "attachments");
					guint i, len = json_array_get_length(swift_attachments);

					//Process JSON blob of a Card into something vaguely HTML
					
					if (swift_json == NULL || swift_attachments == NULL) {
						// Couldn't process, dump the raw data
						html = purple_markup_escape_text((gchar *)swift_data, swift_b64_len);
						purple_serv_got_chat_in(sa->pc, g_str_hash(chatname), from, teams_is_user_self(sa, from) ? PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV, html, composetimestamp);
						g_free(html);
					} else {
						for(i = 0; i < len; i++) {
							JsonObject *attachment = json_array_get_object_element(swift_attachments, i);
							JsonObject *content = json_object_get_object_member(attachment, "content");
							const gchar *contentType = json_object_get_string_member(attachment, "contentType");

							html = teams_convert_card_to_html(content, contentType);
							if (html == NULL) {
								// Couldn't process or unknown content type, dump the raw data
								html = teams_jsonobj_to_string(content);
							}
					
							purple_serv_got_chat_in(sa->pc, g_str_hash(chatname), from, teams_is_user_self(sa, from) ? PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV, html, composetimestamp);
							
							g_free(html);
						}
					}
					
					html = NULL;
					g_free(swift_data);
					json_object_unref(swift_json);
					message_processed = TRUE;
				}
				
				purple_xmlnode_free(uriobject);
				if (message_processed) {
					g_free(messagetype_parts);
					return;
				}
			} else if (purple_strequal(messagetype, "RichText/Media_CallRecording") ||
						purple_strequal(messagetype, "RichText/Media_LocalRecording")) {
				PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
				PurpleXmlNode *recordingStatus = purple_xmlnode_get_child(blob, "RecordingStatus");

				if (recordingStatus) {
					const gchar *recordingStatusValue = purple_xmlnode_get_attrib(recordingStatus, "status");
					if (recordingStatusValue && *recordingStatusValue) {
						if (purple_strequal(recordingStatusValue, "Initial")) {
							html = g_strconcat("<b>", _("Call recording"), "</b>: ", _("Started"), NULL);

						} else if (purple_strequal(recordingStatusValue, "ChunkFinished")) {
							html = g_strconcat("<b>", _("Call recording"), "</b>: ", _("Processing"), NULL);

						} else if (purple_strequal(recordingStatusValue, "Success")) {
							PurpleXmlNode *title = purple_xmlnode_get_child(blob, "Title");
							PurpleXmlNode *link = purple_xmlnode_get_child(blob, "a");
							PurpleXmlNode *originalName = purple_xmlnode_get_child(blob, "OriginalName");
							const gchar *titleValue = purple_xmlnode_get_data(title);
							const gchar *linkHref = purple_xmlnode_get_attrib(link, "href");
							const gchar *originalNameValue = purple_xmlnode_get_attrib(originalName, "v");

							html = g_strconcat("<h2>", titleValue ? titleValue : "", "</h2><br/><b>", _("Call recording"), "</b>: ", _("Success"), " - <a href=\"", linkHref ? linkHref : "#", "\">", originalNameValue ? originalNameValue : "Recording.mp4", "</a>", NULL);

						} else {
							purple_debug_error("teams", "Unknown recording status: %s\n", recordingStatusValue);
							html = g_strconcat("<b>", _("Call recording"), "</b>: ", recordingStatusValue, NULL);
						}

						purple_serv_got_chat_in(sa->pc, g_str_hash(chatname), from, PURPLE_MESSAGE_RECV, html, composetimestamp);
						g_free(html);
						html = NULL;
					}
				}
				purple_xmlnode_free(blob);
				
				g_free(messagetype_parts);
				return;
			} else if (purple_strequal(messagetype, "RichText/Media_CallTranscript")) {
				html = g_strdup(_("Transcript is available"));
				purple_serv_got_chat_in(sa->pc, g_str_hash(chatname), from, PURPLE_MESSAGE_RECV, html, composetimestamp);
				g_free(html);
				html = NULL;
			}
			
			if (json_object_has_member(resource, "skypeemoteoffset")) {
				skypeemoteoffset = g_ascii_strtoll(json_object_get_string_member(resource, "skypeemoteoffset"), NULL, 10);
			}
			
			if (content && *content) {
				if (g_str_equal(messagetype, "Text")) {
					gchar *temp = teams_meify(content, skypeemoteoffset);
					html = purple_markup_escape_text(temp, -1);
					g_free(temp);
				} else {
					html = teams_meify(content, skypeemoteoffset);
				}

				if (skypeeditedid && *skypeeditedid) {
					gchar *temp = g_strconcat(_("Edited: "), html, NULL);
					g_free(html);
					html = temp;
				}
			}
				
			if (properties != NULL) {
				if (json_object_has_member(properties, "deletetime")) {
					g_free(html);
					html = g_strconcat("<b>", _("User deleted their message"), "</b>", NULL);
				}
				
				if (json_object_has_member(properties, "emotions")) {
					JsonArray *emotions = json_object_get_array_member(properties, "emotions");
					guint i, len = json_array_get_length(emotions);
					GString *emotion_text = g_string_new("");
					
					for(i = 0; i < len; i++) {
						JsonObject *emotion = json_array_get_object_element(emotions, i);
						const gchar *emotion_name = json_object_get_string_member(emotion, "key");
						JsonArray *emotion_users = json_object_get_array_member(emotion, "users");
						guint emotion_users_count = json_array_get_length(emotion_users);
						//TODO include a portion of the original string (in html)
						//TODO list names of users   "users":[{"mri":"8:orgid:..."},{"mri":"..."}]
						//for (j = 0; j < emotion_users_count; j++) {
						g_string_append_printf(emotion_text, _("%u users reacted with a :%s:\n"), emotion_users_count, emotion_name);
					}
					
					g_free(html);
					if (emotion_text->str && *emotion_text->str) {
						html = g_strconcat("<b>", emotion_text->str, "</b>", NULL);
					} else {
						html = NULL;
					}
					g_string_free(emotion_text, TRUE);
					
				} else {
					html = teams_process_files_in_properties(properties, &html);
					html = teams_process_cards_in_properties(properties, &html);

				}
			}
			
			if (html != NULL && *html) {
				teams_find_incoming_img(sa, conv, composetimestamp, from, &html);
				
				purple_serv_got_chat_in(sa->pc, g_str_hash(chatname), from, teams_is_user_self(sa, from) ? PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV, html, composetimestamp);
				
				g_free(html);
			}
			
		} else if (g_str_equal(messagetype, "ThreadActivity/AddMember")) {
			PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
			PurpleXmlNode *target;
			for(target = purple_xmlnode_get_child(blob, "target"); target;
				target = purple_xmlnode_get_next_twin(target))
			{
				gchar *user = purple_xmlnode_get_data(target);
				const gchar *username = user;
				username = teams_strip_user_prefix(username);
				
				if (!purple_chat_conversation_find_user(chatconv, username))
					purple_chat_conversation_add_user(chatconv, username, NULL, PURPLE_CHAT_USER_NONE, TRUE);
				g_free(user);
			}
			purple_xmlnode_free(blob);
		} else if (g_str_equal(messagetype, "ThreadActivity/MemberJoined")) {
			JsonObject *info = json_decode_object(content, -1);
			JsonArray *members = json_object_get_array_member(info, "members");
			guint i, len = json_array_get_length(members);
			PurpleGroup *group = teams_get_blist_group(sa);
			
			for(i = 0; i < len; i++)
			{
				JsonObject *member = json_array_get_object_element(members, i);
				const gchar *username = json_object_get_string_member(member, "id");
				username = teams_strip_user_prefix(username);
				
				if (!purple_chat_conversation_find_user(chatconv, username)) {
					const gchar *friendlyname = json_object_get_string_member(member, "friendlyname");
					const gchar *meetingMemberType = json_object_get_string_member(member, "meetingMemberType");

					if (friendlyname == NULL) {
						friendlyname = json_object_get_string_member(resource, "friendlyName");
					}
					
					if (friendlyname && *friendlyname && !g_str_has_prefix(friendlyname, "orgid:")) {
						PurpleBuddy *buddy = purple_blist_find_buddy(sa->account, username);
						const gchar *local_alias;
						
						if (buddy == NULL) {
							purple_buddy_new(sa->account, username, NULL);
							if (purple_strequal(meetingMemberType, "temp")) {
								purple_blist_node_set_transient(PURPLE_BLIST_NODE(buddy), TRUE);
							}
							purple_blist_add_buddy(buddy, NULL, group, NULL);
						}
						
						local_alias = purple_buddy_get_local_alias(buddy);
						if (!local_alias || !*local_alias) {
							purple_serv_got_alias(sa->pc, username, friendlyname);
						}
					}
					
					purple_chat_conversation_add_user(chatconv, username, NULL, PURPLE_CHAT_USER_NONE, TRUE);
				}
			}
			
			json_object_unref(info);
			
		} else if (g_str_equal(messagetype, "ThreadActivity/MemberLeft")) {
			JsonObject *info = json_decode_object(content, -1);
			JsonArray *members = json_object_get_array_member(info, "members");
			guint i, len = json_array_get_length(members);
			PurpleGroup *group = teams_get_blist_group(sa);
			
			for(i = 0; i < len; i++)
			{
				JsonObject *member = json_array_get_object_element(members, i);
				const gchar *username = json_object_get_string_member(member, "id");
				username = teams_strip_user_prefix(username);
				
				// Add them to the buddy list so they have a nice 'left the room' message
				const gchar *friendlyname = json_object_get_string_member(member, "friendlyname");
				const gchar *meetingMemberType = json_object_get_string_member(member, "meetingMemberType");
				
				if (friendlyname == NULL) {
					friendlyname = json_object_get_string_member(resource, "friendlyName");
				}
				
				if (friendlyname && *friendlyname && !g_str_has_prefix(friendlyname, "orgid:")) {
					PurpleBuddy *buddy = purple_blist_find_buddy(sa->account, username);
					const gchar *local_alias;
					
					if (buddy == NULL) {
						purple_buddy_new(sa->account, username, NULL);
						if (purple_strequal(meetingMemberType, "temp")) {
							purple_blist_node_set_transient(PURPLE_BLIST_NODE(buddy), TRUE);
						}
						purple_blist_add_buddy(buddy, NULL, group, NULL);
					}
					
					local_alias = purple_buddy_get_local_alias(buddy);
					if (!local_alias || !*local_alias) {
						purple_serv_got_alias(sa->pc, username, friendlyname);
					}
				}
				
				if (teams_is_user_self(sa, username))
					purple_chat_conversation_leave(chatconv);
				purple_chat_conversation_remove_user(chatconv, username, NULL);
			}
			
			json_object_unref(info);
			
		} else if (g_str_equal(messagetype, "ThreadActivity/DeleteMember")) {
			PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
			PurpleXmlNode *target;
			for(target = purple_xmlnode_get_child(blob, "target"); target;
				target = purple_xmlnode_get_next_twin(target))
			{
				gchar *user = purple_xmlnode_get_data(target);
				const gchar *username = user;
				username = teams_strip_user_prefix(username);
				
				if (teams_is_user_self(sa, username))
					purple_chat_conversation_leave(chatconv);
				purple_chat_conversation_remove_user(chatconv, username, NULL);
				g_free(user);
			}
			purple_xmlnode_free(blob);
		} else if (g_str_equal(messagetype, "ThreadActivity/TopicUpdate")) {
			PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
			gchar *initiator = purple_xmlnode_get_data(purple_xmlnode_get_child(blob, "initiator"));
			const gchar *username = initiator;
			gchar *value = purple_xmlnode_get_data(purple_xmlnode_get_child(blob, "value"));
			
			username = teams_strip_user_prefix(username);
			purple_chat_conversation_set_topic(chatconv, username, value);
			purple_conversation_update(conv, PURPLE_CONVERSATION_UPDATE_TOPIC);
				
			g_free(initiator);
			g_free(value);
			purple_xmlnode_free(blob);
		} else if (g_str_equal(messagetype, "ThreadActivity/RoleUpdate")) {
			PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
			PurpleXmlNode *target;
			PurpleChatUser *cb;
			
			for(target = purple_xmlnode_get_child(blob, "target"); target;
				target = purple_xmlnode_get_next_twin(target))
			{
				gchar *user = purple_xmlnode_get_data(purple_xmlnode_get_child(target, "id"));
				gchar *role = purple_xmlnode_get_data(purple_xmlnode_get_child(target, "role"));
				PurpleChatUserFlags cbflags = PURPLE_CHAT_USER_NONE;
				const gchar *username = user;
				username = teams_strip_user_prefix(username);
				
				if (role && *role) {
					if (g_str_equal(role, "Admin") || g_str_equal(role, "admin")) {
						cbflags = PURPLE_CHAT_USER_OP;
					} else if (g_str_equal(role, "User") || g_str_equal(role, "user")) {
						cbflags = PURPLE_CHAT_USER_VOICE;
					}
				}
				#if !PURPLE_VERSION_CHECK(3, 0, 0)
					purple_conv_chat_user_set_flags(chatconv, username, cbflags);
					(void) cb;
				#else
					cb = purple_chat_conversation_find_user(chatconv, username);
					purple_chat_user_set_flags(cb, cbflags);
				#endif
				g_free(user);
				g_free(role);
			} 
			
			purple_xmlnode_free(blob);
		} else if (g_str_equal(messagetype, "Event/Call")) {
			//"content": "<ended/><partlist
			//"content": "<partlist alt =\"\"></partlist>",
			PurpleXmlNode *partlist = purple_xmlnode_from_str(content, -1);
			gchar *message = NULL;
			
			from = teams_contact_url_to_name(from);
			
			if (content == NULL || strstr(content, "<ended/>")) {
				message = g_strdup(_("Call ended"));
			} else {
				const gchar *count = purple_xmlnode_get_attrib(partlist, "count");
				if (!count) {
					// Add join link:  https://teams.microsoft.com/l/meetup-join/{convID}/0
					message = g_strconcat(_("Call started"), " - <a href=\"https://", TEAMS_BASE_ORIGIN_HOST, "/l/meetup-join/", purple_url_encode(chatname), "/0\">", _("Join Teams Meeting"), "</a>", NULL);
				} else {
					// someone left
				}
			}
			
			purple_xmlnode_free(partlist);
			
			purple_serv_got_chat_in(sa->pc, g_str_hash(chatname), from, PURPLE_MESSAGE_SYSTEM, message, composetimestamp);
		
			g_free(message);
		} else {
			purple_debug_warning("teams", "Unhandled thread message resource messagetype '%s'\n", messagetype);
		}
		
	} else {
		gchar *convbuddyname;
		// This is a One-to-one/IM message
		
		from = teams_contact_url_to_name(from);
		if (from == NULL) {
			g_free(convname);
			g_strfreev(messagetype_parts);
			g_return_if_reached();
			return;
		}
		
		if (convname && *convname) {
			convbuddyname = g_strdup(g_hash_table_lookup(sa->chat_to_buddy_lookup, convname));
		} else {
			convname = g_strdup(teams_thread_url_to_name(conversationLink));
			convbuddyname = g_strdup(teams_contact_url_to_name(conversationLink));
			from = teams_contact_url_to_name(json_object_get_string_member(resource, "from"));
		}
		
		if (convbuddyname == NULL && strstr(convname, "@unq.gbl.spaces")) {
			if (teams_is_user_self(sa, from)) {
				// Try to guess the other person from the chat id
				gchar** split = g_strsplit_set(convname, ":_@", 4);
				convbuddyname = g_strconcat("orgid:", split[1], NULL);
				
				if (teams_is_user_self(sa, convbuddyname)) {
					g_free(convbuddyname);
					convbuddyname = g_strconcat("orgid:", split[2], NULL);
				}
				g_strfreev(split);
			
			} else {
				convbuddyname = g_strdup(from);
			}
			
			g_hash_table_insert(sa->buddy_to_chat_lookup, g_strdup(convbuddyname), g_strdup(convname));
			g_hash_table_insert(sa->chat_to_buddy_lookup, g_strdup(convname), g_strdup(convbuddyname));
		}
		
		if (g_str_equal(messagetype_parts[0], "Control")) {
			if (g_str_equal(messagetype_parts[1], "ClearTyping")) {
				purple_serv_got_typing(sa->pc, from, 22, PURPLE_IM_NOT_TYPING);
			} else if (g_str_equal(messagetype_parts[1], "Typing")) {
				purple_serv_got_typing(sa->pc, from, 22, PURPLE_IM_TYPING);
			}
		} else if ((g_str_equal(messagetype_parts[0], "RichText") || g_str_equal(messagetype, "Text"))) {
			gchar *html = NULL;
			gint64 skypeemoteoffset = 0;
			PurpleIMConversation *imconv;
			
			if (json_object_has_member(resource, "skypeemoteoffset")) {
				skypeemoteoffset = g_ascii_strtoll(json_object_get_string_member(resource, "skypeemoteoffset"), NULL, 10);
			}
			
			if (content && *content) {
				if (g_str_equal(messagetype, "Text")) {
					gchar *temp = teams_meify(content, skypeemoteoffset);
					html = purple_markup_escape_text(temp, -1);
					g_free(temp);
				} else {
					html = teams_meify(content, skypeemoteoffset);
				}

				if (skypeeditedid && *skypeeditedid) {
					gchar *temp = g_strconcat(_("Edited: "), html, NULL);
					g_free(html);
					html = temp;
				}
			}
			
			if (properties != NULL) {
				if (json_object_has_member(properties, "deletetime")) {
					g_free(html);
					html = g_strconcat("<b>", _("User deleted their message"), "</b>", NULL);
				}
				
				if (json_object_has_member(properties, "emotions")) {
					JsonArray *emotions = json_object_get_array_member(properties, "emotions");
					guint i, len = json_array_get_length(emotions);
					GString *emotion_text = g_string_new("");
					
					for(i = 0; i < len; i++) {
						JsonObject *emotion = json_array_get_object_element(emotions, i);
						const gchar *emotion_name = json_object_get_string_member(emotion, "key");
						JsonArray *emotion_users = json_object_get_array_member(emotion, "users");
						guint j, emotion_users_count = json_array_get_length(emotion_users);
						
						for (j = 0; j < emotion_users_count; j++) {
							JsonObject *emotion_user = json_array_get_object_element(emotion_users, j);
							const gchar *mri = json_object_get_string_member(emotion_user, "mri");
							const gchar *buddyid = teams_strip_user_prefix(mri);
							
							if (!teams_is_user_self(sa, buddyid)) {
								//TODO include a portion of the original string (in html)
								g_string_append_printf(emotion_text, _("Reacted with a :%s:\n"), emotion_name);
							}
						}
					}
					
					g_free(html);
					if (emotion_text->str && *emotion_text->str) {
						html = g_strconcat("<b>", emotion_text->str, "</b>", NULL);
					} else {
						html = NULL;
					}
					g_string_free(emotion_text, TRUE);
				
				} else {
					html = teams_process_files_in_properties(properties, &html);
					html = teams_process_cards_in_properties(properties, &html);
					
				}
			}
			
			if (json_object_has_member(resource, "imdisplayname") || json_object_has_member(resource, "imDisplayName")) {
				const gchar *displayname = json_object_get_string_member(resource, "imdisplayname");
				if (displayname == NULL) {
					displayname = json_object_get_string_member(resource, "imDisplayName");
				}
				
				if (displayname && *displayname && !g_str_has_prefix(displayname, "orgid:")) {
					//Hopefully not too expensive to do a lookup?
					PurpleBuddy *buddy = purple_blist_find_buddy(sa->account, from);
					//TODO add to buddy list if null?
					if (buddy == NULL || !purple_strequal(purple_buddy_get_local_alias(buddy), displayname)) {
						purple_serv_got_alias(sa->pc, from, displayname);
					}
				}
			}
			
			if (html != NULL && *html && !purple_strequal(convbuddyname, "48:calllogs") && !purple_strequal(convbuddyname, "48:annotations")) {
				const gchar *modified_convbuddyname = convbuddyname;
				//Handle self-send messages
				if (purple_strequal(convbuddyname, "48:notes")) {
					if (sa->primary_member_name) {
						modified_convbuddyname = sa->primary_member_name;
					} else if (sa->username) {
						modified_convbuddyname = sa->username;
					}
				}
				
				imconv = purple_conversations_find_im_with_account(modified_convbuddyname, sa->account);
				if (imconv == NULL)
				{
					imconv = purple_im_conversation_new(sa->account, modified_convbuddyname);
				}
				conv = PURPLE_CONVERSATION(imconv);
				
				teams_find_incoming_img(sa, conv, composetimestamp, from, &html);
				
				if (teams_is_user_self(sa, from)) {
					if (!g_str_has_prefix(html, "?OTR")) {
						PurpleMessage *msg;
						
						msg = purple_message_new_outgoing(modified_convbuddyname, html, PURPLE_MESSAGE_SEND);
						purple_message_set_time(msg, composetimestamp);
						purple_conversation_write_message(conv, msg);
						purple_message_destroy(msg);
					}
					
				} else {
					purple_serv_got_im(sa->pc, from, html, PURPLE_MESSAGE_RECV, composetimestamp);
				}
				g_free(html);
			}
		} else if (g_str_equal(messagetype, "RichText/UriObject")) {
			PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
			const gchar *uri = purple_xmlnode_get_attrib(blob, "url_thumbnail");
			PurpleIMConversation *imconv;
			
			if (teams_is_user_self(sa, from)) {
				from = convbuddyname;
			}
			if (from != NULL) {
				imconv = purple_conversations_find_im_with_account(from, sa->account);
				if (imconv == NULL)
				{
					imconv = purple_im_conversation_new(sa->account, from);
				}
				
				conv = PURPLE_CONVERSATION(imconv);
				teams_download_uri_to_conv(sa, uri, conv, composetimestamp, from);
			}
			purple_xmlnode_free(blob);
		} else if (g_str_equal(messagetype, "RichText/Media_GenericFile")) {
			PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
			const gchar *uri = purple_xmlnode_get_attrib(blob, "uri");
			
			if (!teams_is_user_self(sa, from)) {
				
				teams_present_uri_as_filetransfer(sa, uri, from);
			}
			purple_xmlnode_free(blob);
		} else if (g_str_equal(messagetype, "RichText/Media_CallRecording")) {
			//TODO
			//"content": "<URIObject format_version=\"1.1\" type=\"Video.2/CallRecording.1\" url_thumbnail=\"https://au-prod.asyncgw.teams.microsoft.com/v1/objects/.../views/thumbnail\" uri=\"\" version=\"1.0\"><RecordingStatus status=\"Success\" code=\"200\"><amsErrorResult /></RecordingStatus><SessionEndReason value=\"CallEnded\" /><ChunkEndReason value=\"SessionEnded\" /><Title>...</Title><a href=\"https://...-my.sharepoint.com/:v:/g/personal/..._com/...\">Play</a><OriginalName v=\"...-20240114_232119-Meeting Recording.mp4\" /><MeetingOrganizerId value=\"8:orgid:...\" /><MeetingOrganizerTenantId value=\"...\" /><RecordingInitiatorId value=\"8:orgid:...\" /><ICalUid value=\"...\" /><Identifiers><Id type=\"callId\" value=\"...\" /><Id type=\"callLegId\" value=\"...\" /><Id type=\"chunkIndex\" value=\"0\" /><Id type=\"AMSDocumentID\" value=\"...\" /><Id type=\"StreamVideoId\" value=\"\" /><Id type=\"OriginatorParticipantId\" value=\"...\" /></Identifiers><RecordingContent contentTypes=\"Recording\" timestamp=\"2024-01-14T22:59:54.6362911Z\" duration=\"0:20:21.16\" canVideoExpire=\"True\"><item type=\"video\" uri=\"\" /><item type=\"amsVideo\" uri=\"https://au-prod.asyncgw.teams.microsoft.com/v1/objects/.../views/video\" /><item type=\"amsTranscript\" uri=\"https://au-prod.asyncgw.teams.microsoft.com/v1/objects/.../views/transcript\" /><item type=\"rosterevents\" uri=\"https://au-prod.asyncgw.teams.microsoft.com/v1/objects/.../views/rosterevents\" /><item type=\"onedriveForBusinessVideo\" uri=\"https://...-my.sharepoint.com/:v:/g/personal/..._com/...\" driveId=\"b!...\" driveItemId=\"...\" /></RecordingContent><RequestedExports><ExportResult type=\"ExportToOnedriveForBusiness\" /></RequestedExports></URIObject>",

		} else if (g_str_equal(messagetype, "Event/SkypeVideoMessage")) {
			PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);
			const gchar *sid = purple_xmlnode_get_attrib(blob, "sid");
			PurpleIMConversation *imconv;
			
			if (teams_is_user_self(sa, from)) {
				from = convbuddyname;
			}
			if (from != NULL) {
				imconv = purple_conversations_find_im_with_account(from, sa->account);
				if (imconv == NULL)
				{
					imconv = purple_im_conversation_new(sa->account, from);
				}
				
				conv = PURPLE_CONVERSATION(imconv);
				//teams_download_video_message(sa, sid, conv); //TODO
				(void) sid;
				purple_serv_got_im(sa->pc, from, content, PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_SYSTEM, composetimestamp);
			}
			purple_xmlnode_free(blob);
		} else if (g_str_equal(messagetype, "Event/Call")) {
			PurpleXmlNode *partlist = purple_xmlnode_from_str(content, -1);
			const gchar *partlisttype = purple_xmlnode_get_attrib(partlist, "type");
			gchar *message = NULL;
			PurpleIMConversation *imconv;
			gboolean incoming = TRUE;
			
			if (teams_is_user_self(sa, from)) {
				incoming = FALSE;
				(void) incoming;
				from = convbuddyname;
			}

			if (from != NULL) {
				imconv = purple_conversations_find_im_with_account(from, sa->account);
				if (imconv == NULL)
				{
					imconv = purple_im_conversation_new(sa->account, from);
				}
				
				conv = PURPLE_CONVERSATION(imconv);
				if (content == NULL || strstr(content, "<ended/>")) {
					message = g_strdup(_("Call ended"));
				} else if (!partlisttype || g_str_equal(partlisttype, "started")) {
					message = g_strconcat(_("Call started"), " - <a href=\"https://", TEAMS_BASE_ORIGIN_HOST, "/l/meetup-join/", purple_url_encode(chatname), "/0\">", _("Join Teams Meeting"), "</a>", NULL);

				} else if (g_str_equal(partlisttype, "ended")) {
					PurpleXmlNode *part;
					gint duration_int = -1;
					
					for(part = purple_xmlnode_get_child(partlist, "part");
						part;
						part = purple_xmlnode_get_next_twin(part))
					{
						const gchar *identity = purple_xmlnode_get_attrib(part, "identity");
						if (identity && teams_is_user_self(sa, identity)) {
							PurpleXmlNode *duration = purple_xmlnode_get_child(part, "duration");
							if (duration != NULL) {
								gchar *duration_str;
								duration_str = purple_xmlnode_get_data(duration);
								duration_int = atoi(duration_str);
								break;
							}
						}
					}
					if (duration_int < 0) {
						message = g_strdup(_("Call missed"));
					} else {
						message = g_strdup_printf("%s %d:%d", _("Call ended"), duration_int / 60, duration_int % 60);
					}
				}

				purple_serv_got_im(sa->pc, from, message, PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_SYSTEM, composetimestamp);
				
				g_free(message);
			}

			purple_xmlnode_free(partlist);
		} else if (g_str_equal(messagetype, "Signal/Flamingo")) {
			const gchar *message = NULL;

			if (teams_is_user_self(sa, from)) {
				from = convbuddyname;
			}

			if (from != NULL) {
				message = _("Unsupported call received");

				purple_serv_got_im(sa->pc, from, message, PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_SYSTEM, composetimestamp);
			}
		} else if (g_str_equal(messagetype, "RichText/Contacts")) {
			PurpleXmlNode *contacts = purple_xmlnode_from_str(content, -1);
			PurpleXmlNode *contact;

			for(contact = purple_xmlnode_get_child(contacts, "c"); contact;
				contact = purple_xmlnode_get_next_twin(contact))
			{
				const gchar *contact_id = purple_xmlnode_get_attrib(contact, "s");
				const gchar *contact_name = purple_xmlnode_get_attrib(contact, "f");

				gchar *message = g_strdup_printf(_("The user sent a contact: %s (%s)"), contact_id, contact_name); 

				purple_serv_got_im(sa->pc, from, message, PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_SYSTEM, composetimestamp);

				g_free(message);
			}

			teams_received_contacts(sa, contacts);
			purple_xmlnode_free(contacts);
		} else if (g_str_equal(messagetype, "RichText/Media_FlikMsg")) {
			
			
			PurpleXmlNode *blob = purple_xmlnode_from_str(content, -1);

			const gchar *url_thumbnail = purple_xmlnode_get_attrib(blob, "url_thumbnail");
			gchar *text = purple_markup_strip_html(content); //purple_xmlnode_get_data_unescaped doesn't work properly in this situation
			
			PurpleIMConversation *imconv;
			
			if (teams_is_user_self(sa, from)) {
				from = convbuddyname;
			}
			if (from != NULL) {
				imconv = purple_conversations_find_im_with_account(from, sa->account);
				if (imconv == NULL) {
					imconv = purple_im_conversation_new(sa->account, from);
				}
				
				conv = PURPLE_CONVERSATION(imconv);

				teams_download_moji_to_conv(sa, text, url_thumbnail, conv, composetimestamp, from);

				const gchar *message = _("The user sent a Moji");

				purple_serv_got_im(sa->pc, from, message, PURPLE_MESSAGE_NO_LOG, composetimestamp);

				g_free(text);
			}

			purple_xmlnode_free(blob);
		} else if (g_str_equal(messagetype, "RichText/Files")) {
			purple_serv_got_im(sa->pc, convbuddyname, _("The user sent files in an unsupported way"), PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_ERROR, composetimestamp);
		} else {
			purple_debug_warning("teams", "Unhandled message resource messagetype '%s'\n", messagetype);
		}
		
		g_free(convbuddyname);
	}
	
	if (conv != NULL) {
		const gchar *id = json_object_get_string_member(resource, "id");
		
		g_free(purple_conversation_get_data(conv, "last_teams_id"));
		g_free(purple_conversation_get_data(conv, "last_teams_clientmessageid"));
		
		if (purple_conversation_has_focus(conv) && convname && *convname) {
			// Mark message as seen straight away
			gchar *post, *url;
			
			url = g_strdup_printf("/v1/users/ME/conversations/%s/properties?name=consumptionhorizon", purple_url_encode(convname));
			// Should be [messageId];[timestampInMillis];[clientMessageId]
			post = g_strdup_printf("{\"consumptionhorizon\":\"%s;%" G_GINT64_FORMAT ";%s\"}", id ? id : "", teams_get_js_time(), clientmessageid ? clientmessageid : "");
			
			teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, post, NULL, NULL, TRUE);
			
			g_free(post);
			g_free(url);
			
			purple_conversation_set_data(conv, "last_teams_id", NULL);
			purple_conversation_set_data(conv, "last_teams_clientmessageid", NULL);
		} else {
			purple_conversation_set_data(conv, "last_teams_id", g_strdup(id));
			purple_conversation_set_data(conv, "last_teams_clientmessageid", g_strdup(clientmessageid));
		}
	}
	
	g_free(convname);
	g_strfreev(messagetype_parts);
	
	if (composetimestamp > purple_account_get_int(sa->account, "last_message_timestamp", 0))
		purple_account_set_int(sa->account, "last_message_timestamp", composetimestamp);
}

static void
process_conversation_resource(TeamsAccount *sa, JsonObject *resource)
{
	const gchar *id = json_object_get_string_member(resource, "id");
	JsonObject *threadProperties = json_object_get_object_member(resource, "threadProperties");
	JsonObject *lastMessage = json_object_get_object_member(resource, "lastMessage");
	
	if (threadProperties != NULL) {
		const gchar *uniquerosterthread = json_object_get_string_member(threadProperties, "uniquerosterthread");
		const gchar *productThreadType = json_object_get_string_member(threadProperties, "productThreadType");
		if (purple_strequal(uniquerosterthread, "true") || purple_strequal(productThreadType, "OneToOneChat")) {
			// This is a one-to-one chat
			
			if (!g_hash_table_lookup(sa->chat_to_buddy_lookup, id)) {
				// ... and we dont know about it yet
				gchar *buddyid = NULL;
				if (lastMessage != NULL) {
					const gchar *from = json_object_get_string_member(lastMessage, "from");
					buddyid = g_strdup(teams_contact_url_to_name(from));
				}
				
				if (buddyid == NULL || teams_is_user_self(sa, buddyid)) {
					// Try to guess the other person from the chat id
					gchar** split = g_strsplit_set(id, ":_@", 4);
					g_free(buddyid);
					buddyid = g_strconcat("orgid:", split[1], NULL);
					if (teams_is_user_self(sa, buddyid)) {
						g_free(buddyid);
						buddyid = g_strconcat("orgid:", split[2], NULL);
					}
					g_strfreev(split);
				}
				
				g_hash_table_insert(sa->buddy_to_chat_lookup, g_strdup(buddyid), g_strdup(id));
				g_hash_table_insert(sa->chat_to_buddy_lookup, g_strdup(id), g_strdup(buddyid));
				
				g_free(buddyid);
			}
		}
	}
}

static void
process_thread_resource(TeamsAccount *sa, JsonObject *resource)
{
	const gchar *id = json_object_get_string_member(resource, "id");
	JsonObject *properties = json_object_get_object_member(resource, "properties");
	JsonArray *members = json_object_get_array_member(resource, "members");
	
	if (properties != NULL) {
		const gchar *uniquerosterthread = json_object_get_string_member(properties, "uniquerosterthread");
		if (purple_strequal(uniquerosterthread, "true")) {
			// This is a one-to-one chat
			
			if (!g_hash_table_lookup(sa->chat_to_buddy_lookup, id)) {
				// ... and we dont know about it yet
				
				JsonObject *member = json_array_get_object_element(members, 0);
				const gchar *mri = json_object_get_string_member(member, "id");
				const gchar *buddyid = teams_strip_user_prefix(mri);
				
				if (teams_is_user_self(sa, buddyid)) {
					// There were two in the bed and the little one said....
					member = json_array_get_object_element(members, 1);
					mri = json_object_get_string_member(member, "id");
					buddyid = teams_strip_user_prefix(mri);
				}
				
				//Fetch buddy presence
				GSList *users_to_fetch = g_slist_prepend(NULL, (gchar *) buddyid);
				teams_get_friend_profiles(sa, users_to_fetch);
				teams_subscribe_to_contact_status(sa, users_to_fetch);
				g_slist_free(users_to_fetch);
				
				//Create an array of one to one mappings for IMs
				g_hash_table_insert(sa->buddy_to_chat_lookup, g_strdup(buddyid), g_strdup(id));
				g_hash_table_insert(sa->chat_to_buddy_lookup, g_strdup(id), g_strdup(buddyid));
				
				PurpleChatConversation *conv = purple_conversations_find_chat_with_account(id, sa->account);
				if (conv != NULL) {
					purple_conversation_destroy(PURPLE_CONVERSATION(conv));
				}
			}
		}
	}
}

static void
process_endpointpresence_resource(TeamsAccount *sa, JsonObject *resource)
{
	JsonObject *publicInfo = json_object_get_object_member(resource, "publicInfo");
	if (publicInfo != NULL) {
		const gchar *typ_str = json_object_get_string_member(publicInfo, "typ");
		const gchar *skypeNameVersion = json_object_get_string_member(publicInfo, "skypeNameVersion");
		
		if (typ_str && *typ_str) {
			if (g_str_equal(typ_str, "website")) {
			
			} else {
				gint typ = atoi(typ_str);
				switch(typ) {
					case 17: //Android
						break;
					case 16: //iOS
						break;
					case 12: //WinRT/Metro
						break;
					case 15: //Winphone
						break;
					case 13: //OSX
						break;
					case 11: //Windows
						break;
					case 14: //Linux
						break;
					case 10: //XBox ? skypeNameVersion 11/1.8.0.1006
						break;
					case 1:  //Teams
						break;
					default:
						purple_debug_warning("teams", "Unknown typ %d: %s\n", typ, skypeNameVersion ? skypeNameVersion : "");
						break;
				}
			}
		}
	}
}

gboolean
teams_timeout(gpointer userdata)
{
	TeamsAccount *sa = userdata;
	if (!purple_account_get_bool(sa->account, "only_use_websocket", FALSE)) {
		teams_poll(sa);
	}

	// If no response within 1 minute, assume connection lost and try again
	g_source_remove(sa->watchdog_timeout);
	sa->watchdog_timeout = g_timeout_add_seconds(60, teams_timeout, sa);
	
	return FALSE;
}

void
teams_process_event_message(TeamsAccount *sa, JsonObject *message)
{
	const gchar *resourceType = json_object_get_string_member(message, "resourceType");
	const gchar *time = json_object_get_string_member(message, "time");
	JsonObject *resource = json_object_get_object_member(message, "resource");

	if (time != NULL) {
		if (g_queue_find_custom(sa->processed_event_messages, time, (GCompareFunc) g_strcmp0)) {
			// Already processed this message
			return;
		}
		g_queue_push_head(sa->processed_event_messages, g_strdup(time));
		if (g_queue_get_length(sa->processed_event_messages) > TEAMS_MAX_PROCESSED_EVENT_BUFFER) {
			// Remove oldest message
			g_queue_pop_tail(sa->processed_event_messages);
		}
	}
	
	if (purple_strequal(resourceType, "NewMessage"))
	{
		process_message_resource(sa, resource);
	} else if (purple_strequal(resourceType, "UserPresence"))
	{
		process_userpresence_resource(sa, resource);
	} else if (purple_strequal(resourceType, "EndpointPresence"))
	{
		process_endpointpresence_resource(sa, resource);
	} else if (purple_strequal(resourceType, "ConversationUpdate"))
	{
		process_conversation_resource(sa, resource);
	} else if (purple_strequal(resourceType, "ThreadUpdate"))
	{
		process_thread_resource(sa, resource);
	} else if (purple_strequal(resourceType, "MessageUpdate"))
	{
		//Message edited
		process_message_resource(sa, resource);
	} else {
		purple_debug_info("teams", "Unknown resourceType '%s'\n", resourceType);
	}
}

static void
teams_poll_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonArray *messages = NULL;
	gint index, length;
	JsonObject *obj = NULL;

	// if (((int)time(NULL)) > sa->vdms_expiry) {
		// teams_get_vdms_token(sa);
	// }

	// if (node == NULL && ((int)time(NULL)) > sa->registration_expiry) {
		// teams_get_registration_token(sa);
		// return;
	// } 

	
	if (node != NULL && json_node_get_node_type(node) == JSON_NODE_OBJECT)
		obj = json_node_get_object(node);
	
	if (obj != NULL) {
		if (json_object_has_member(obj, "next")) {
			const gchar *next = json_object_get_string_member(obj, "next");
			gchar *next_server = teams_string_get_chunk(next, -1, "https://", "/users");
			
			if (next_server != NULL) {
				g_free(sa->messages_host);
				sa->messages_host = next_server;
			}
			
			gchar *cursor = teams_string_get_chunk(next, -1, "?cursor=", NULL);
			if (cursor != NULL) {
				g_free(sa->messages_cursor);
				sa->messages_cursor = cursor;
			}
		}
		
		if (json_object_has_member(obj, "eventMessages"))
			messages = json_object_get_array_member(obj, "eventMessages");
		
		if (messages != NULL) {
			length = json_array_get_length(messages);
			for(index = 0; index < length; index++)
			{
				JsonObject *message = json_array_get_object_element(messages, index);
				teams_process_event_message(sa, message);
			}
		} else if (json_object_has_member(obj, "errorCode")) {
			gint64 errorCode = json_object_get_int_member(obj, "errorCode");
			
			if (errorCode == 729) {
				// "You must create an endpoint before performing this operation"
				// Dammit, Jim; I'm a programmer, not a surgeon!
				teams_subscribe(sa);
				return;
			} else if (errorCode == 450) {
				// "Subscription requested could not be found."
				// No more Womens Weekly? :O
			}
		} else if (purple_strequal(json_object_get_string_member(obj, "code"), "Forbidden")) {
			teams_subscribe(sa);
		}
		
		//TODO record id of highest recieved id to make sure we dont process the same id twice
		
	} else {
		// No data received, or timeout
	}
	
	if (!purple_connection_is_disconnecting(sa->pc)) {
		sa->poll_timeout = g_timeout_add_seconds(1, teams_timeout, sa);
	}

	// poll_conn is free'd by parent function
	sa->poll_conn = NULL;
}

void
teams_poll(TeamsAccount *sa)
{
	GString *url;
	
	if (sa->poll_conn) {
		PurpleHttpConnection *http_conn = sa->poll_conn->http_conn;
		if (purple_http_conn_is_running(http_conn)) {
			
			// This will trigger a reconnection
			purple_http_conn_cancel(http_conn);
			return;
		}
	}
	
	url = g_string_new("/users/");
	
	if (sa->username) {
		g_string_append_printf(url, "8:%s", purple_url_encode(sa->username));
	} else {
		g_string_append(url, "ME");
	}
	g_string_append(url, "/endpoints/");
	if (sa->endpoint) {
		g_string_append(url, purple_url_encode(sa->endpoint));
	} else {
		g_string_append(url, "SELF");
	}
	g_string_append(url, "/events/poll");
	
	if (sa->messages_cursor) {
		g_string_append_printf(url, "?cursor=%s", sa->messages_cursor);
	}
	
	sa->poll_conn = teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, sa->messages_host, url->str, NULL, teams_poll_cb, NULL, TRUE);
	
	g_string_free(url, TRUE);
}

void
teams_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	if (!PURPLE_CONNECTION_IS_CONNECTED(pc))
		return;
	
	if (!purple_strequal(purple_protocol_get_id(purple_connection_get_protocol(pc)), TEAMS_PLUGIN_ID))
		return;
	
	if (type == PURPLE_CONVERSATION_UPDATE_UNSEEN) {
		gchar *last_teams_id = purple_conversation_get_data(conv, "last_teams_id");
		gchar *last_teams_clientmessageid = purple_conversation_get_data(conv, "last_teams_clientmessageid");
		
		if (last_teams_id && *last_teams_id) {
			TeamsAccount *sa = purple_connection_get_protocol_data(pc);
			gchar *post, *url, *convname;
			
			if (PURPLE_IS_IM_CONVERSATION(conv)) {
				const gchar *buddyname = purple_conversation_get_name(conv);
				convname = g_strdup(g_hash_table_lookup(sa->buddy_to_chat_lookup, buddyname));
			} else {
				convname = g_strdup(purple_conversation_get_data(conv, "chatname"));
			}
			
			if (convname && *convname) {
				url = g_strdup_printf("/v1/users/ME/conversations/%s/properties?name=consumptionhorizon", purple_url_encode(convname));
				// Should be [messageId];[timestampInMillis];[clientMessageId]
				post = g_strdup_printf("{\"consumptionhorizon\":\"%s;%" G_GINT64_FORMAT ";%s\"}", last_teams_id, teams_get_js_time(), last_teams_clientmessageid);
				
				teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, post, NULL, NULL, TRUE);
				
				g_free(convname);
				g_free(post);
				g_free(url);
			}
		}

		g_free(last_teams_id);
		g_free(last_teams_clientmessageid);
		purple_conversation_set_data(conv, "last_teams_id", NULL);
		purple_conversation_set_data(conv, "last_teams_clientmessageid", NULL);
	}
}

static void
teams_got_thread_users(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	PurpleChatConversation *chatconv;
	gchar *chatname = user_data;
	JsonObject *response;
	JsonArray *members;
	gint length, index;
	PurpleGroup *group = teams_get_blist_group(sa);
	GSList *users_to_fetch = NULL;
	
	chatconv = purple_conversations_find_chat_with_account(chatname, sa->account);
	g_free(chatname);

	if (chatconv == NULL)
		return;
	purple_chat_conversation_clear_users(chatconv);
	
	if (node == NULL || json_node_get_node_type(node) != JSON_NODE_OBJECT)
		return;
	response = json_node_get_object(node);
	
	members = json_object_get_array_member(response, "members");
	length = json_array_get_length(members);
	for(index = length - 1; index >= 0; index--)
	{
		JsonObject *member = json_array_get_object_element(members, index);
		const gchar *userLink = json_object_get_string_member(member, "userLink");
		const gchar *role = json_object_get_string_member(member, "role");
		const gchar *username = teams_contact_url_to_name(userLink);
		PurpleChatUserFlags cbflags = PURPLE_CHAT_USER_NONE;
		
		if (purple_strequal(role, "Admin") || purple_strequal(role, "admin")) {
			cbflags = PURPLE_CHAT_USER_OP;
		} else if (purple_strequal(role, "User") || purple_strequal(role, "user")) {
			cbflags = PURPLE_CHAT_USER_VOICE;
		}

		if (username == NULL && json_object_has_member(member, "linkedMri")) {
			username = teams_contact_url_to_name(json_object_get_string_member(member, "linkedMri"));
		}
		if (username != NULL) {
			const gchar *friendlyName = json_object_get_string_member(member, "friendlyName");
			PurpleBuddy *buddy;
			const gchar *local_alias;

			if (friendlyName == NULL) {
				friendlyName = json_object_get_string_member(member, "friendlyname");
			}
			
			if (friendlyName && *friendlyName && !g_str_has_prefix(friendlyName, "orgid:")) {
				buddy = purple_blist_find_buddy(sa->account, username);
				if (buddy == NULL) {
					purple_buddy_new(sa->account, username, NULL);
					if (purple_strequal(role, "Anonymous") || purple_strequal(role, "anonymous")) {
						purple_blist_node_set_transient(PURPLE_BLIST_NODE(buddy), TRUE);
					}
					purple_blist_add_buddy(buddy, NULL, group, NULL);
					
				}
				
				local_alias = purple_buddy_get_local_alias(buddy);
				if (!local_alias || !*local_alias) {
					purple_serv_got_alias(sa->pc, username, friendlyName);
				}
			}
			
			purple_chat_conversation_add_user(chatconv, username, NULL, cbflags, FALSE);
			users_to_fetch = g_slist_prepend(users_to_fetch, g_strdup(username));
		}
	}
	
	teams_get_friend_profiles(sa, users_to_fetch);
	teams_subscribe_to_contact_status(sa, users_to_fetch);
	g_slist_free_full(users_to_fetch, g_free);
}

void
teams_get_thread_users(TeamsAccount *sa, const gchar *convname)
{
	gchar *url;
	url = g_strdup_printf("/v1/threads/%s?view=msnp24Equivalent", purple_url_encode(convname));
	
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, NULL, teams_got_thread_users, g_strdup(convname), TRUE);
	
	g_free(url);
}

static void
teams_got_conv_history(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	gint since = GPOINTER_TO_INT(user_data);
	JsonObject *obj;
	JsonArray *messages;
	gint index, length;
	
	if (node == NULL || json_node_get_node_type(node) != JSON_NODE_OBJECT)
		return;
	obj = json_node_get_object(node);
	
	messages = json_object_get_array_member(obj, "messages");
	length = json_array_get_length(messages);
	for(index = length - 1; index >= 0; index--)
	{
		JsonObject *message = json_array_get_object_element(messages, index);
		const gchar *composetime = json_object_get_string_member(message, "composetime");
		gint composetimestamp = (gint) purple_str_to_time(composetime, TRUE, NULL, NULL, NULL);
		
		if (composetimestamp > since) {
			process_message_resource(sa, message);
		}
	}
}

void
teams_get_conversation_history_since(TeamsAccount *sa, const gchar *convname, gint since)
{
	gchar *url;
	url = g_strdup_printf("/v1/users/ME/conversations/%s/messages?startTime=%d000&pageSize=30&view=msnp24Equivalent&targetType=Passport|Skype|Lync|Thread|PSTN|Agent", purple_url_encode(convname), since);
	
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, NULL, teams_got_conv_history, GINT_TO_POINTER(since), TRUE);
	
	g_free(url);
}

void
teams_get_conversation_history(TeamsAccount *sa, const gchar *convname)
{
	GString *timestamp_key = make_last_timestamp_setting(convname);
	teams_get_conversation_history_since(sa, convname, purple_account_get_int(sa->account, timestamp_key->str, 0));
	g_string_free(timestamp_key, TRUE);
}

static void
teams_got_all_convs(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	gint since = GPOINTER_TO_INT(user_data);
	JsonObject *obj;
	JsonArray *conversations;
	gint index, length;
	
	if (node == NULL || json_node_get_node_type(node) != JSON_NODE_OBJECT)
		return;
	obj = json_node_get_object(node);
	
	conversations = json_object_get_array_member(obj, "conversations");
	length = json_array_get_length(conversations);
	for(index = 0; index < length; index++) {
		JsonObject *conversation = json_array_get_object_element(conversations, index);
		const gchar *id = json_object_get_string_member(conversation, "id");
		JsonObject *lastMessage = json_object_get_object_member(conversation, "lastMessage");
		
		if (lastMessage != NULL && json_object_has_member(lastMessage, "composetime")) {
			const gchar *composetime = json_object_get_string_member(lastMessage, "composetime");
			gint composetimestamp = (gint) purple_str_to_time(composetime, TRUE, NULL, NULL, NULL);
			
			// Check if it's a one-to-one before we fetch history
			process_conversation_resource(sa, conversation);
			
			if (composetimestamp > since) {
				teams_get_conversation_history_since(sa, id, since);
			}
		}
	}
}

void
teams_get_all_conversations_since(TeamsAccount *sa, gint since)
{
	gchar *url;
	url = g_strdup_printf("/v1/users/ME/conversations?startTime=%d000&pageSize=100&view=msnp24Equivalent&targetType=Passport|Skype|Lync|Thread|PSTN|Agent", since);
	
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, NULL, teams_got_all_convs, GINT_TO_POINTER(since), TRUE);
	
	g_free(url);
}

void
teams_get_offline_history(TeamsAccount *sa)
{
	teams_get_all_conversations_since(sa, purple_account_get_int(sa->account, "last_message_timestamp", ((gint) time(NULL))));
}


static void
teams_got_roomlist_threads(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	PurpleRoomlist *roomlist = user_data;
	JsonObject *obj;
	JsonArray *conversations;
	gint index, length;
	
	if (node == NULL || json_node_get_node_type(node) != JSON_NODE_OBJECT)
		return;
	obj = json_node_get_object(node);
	
	conversations = json_object_get_array_member(obj, "conversations");
	length = json_array_get_length(conversations);
	for(index = 0; index < length; index++) {
		JsonObject *conversation = json_array_get_object_element(conversations, index);
		const gchar *id = json_object_get_string_member(conversation, "id");
		PurpleRoomlistRoom *room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, id, NULL);
		
		purple_roomlist_room_add_field(roomlist, room, id);
		if (json_object_has_member(conversation, "threadProperties")) {
			JsonObject *threadProperties = json_object_get_object_member(conversation, "threadProperties");
			if (threadProperties != NULL) {
				const gchar *num_members = json_object_get_string_member(threadProperties, "membercount");
				purple_roomlist_room_add_field(roomlist, room, num_members);
				const gchar *topic = json_object_get_string_member(threadProperties, "topic");
				purple_roomlist_room_add_field(roomlist, room, topic);
			}
		}
		purple_roomlist_room_add(roomlist, room);
	}
	
	purple_roomlist_set_in_progress(roomlist, FALSE);
}

PurpleRoomlist *
teams_roomlist_get_list(PurpleConnection *pc)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	const gchar *url = "/v1/users/ME/conversations?startTime=0&pageSize=100&view=msnp24Equivalent&targetType=Thread";
	PurpleRoomlist *roomlist;
	GList *fields = NULL;
	PurpleRoomlistField *f;
	
	roomlist = purple_roomlist_new(sa->account);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("ID"), "chatname", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Users"), "users", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Topic"), "topic", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);

	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, NULL, teams_got_roomlist_threads, roomlist, TRUE);
	
	return roomlist;
}

void
teams_unsubscribe_from_contact_status(TeamsAccount *sa, const gchar *who)
{
	const gchar *contacts_url = "/v1/users/ME/contacts";
	gchar *url;
	
	url = g_strconcat(contacts_url, "/", teams_user_url_prefix(who), purple_url_encode(who), NULL);
	
	teams_post_or_get(sa, TEAMS_METHOD_DELETE | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, NULL, NULL, NULL, TRUE);
	
	g_free(url);
}

void
teams_got_contact_statuses(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	PurpleGroup *group = teams_get_blist_group(sa);
	JsonArray *responses = json_node_get_array(node);
	
	if (responses != NULL) {
		const gchar *from;
		guint length = json_array_get_length(responses);
		gint index;
		
		for(index = length - 1; index >= 0; index--)
		{
			JsonObject *response = json_array_get_object_element(responses, index);
			JsonObject *presence = json_object_get_object_member(response, "presence");
			const gchar *mri = json_object_get_string_member(response, "mri");
			const gchar *availability = json_object_get_string_member(presence, "availability");
			
			from = teams_strip_user_prefix(mri);
			g_return_if_fail(from);
			
			if (!purple_blist_find_buddy(sa->account, from))
			{
				if (!teams_is_user_self(sa, from)) {
					purple_blist_add_buddy(purple_buddy_new(sa->account, from, NULL), NULL, group, NULL);
				}
			}
			
			//TODO note/OOOnote -> status message
			/* 
				"presence": {
					"sourceNetwork": "SameEnterprise",
					"note": {
						"message": "",
						"publishTime": "2021-06-01T00:48:30.6948824Z",
						"expiry": "9999-12-30T14:00:00Z"
					},
					"calendarData": {
						"outOfOfficeNote": {
							"message": "I am on leave - returning 19th April",
							"publishTime": "2022-04-14T08:02:23.5053937Z",
							"expiry": "2022-04-19T07:00:00Z"
						},
						"isOutOfOffice": true
					},
					"capabilities": [],
					"availability": "Away",
					"activity": "Away",
					"lastActiveTime": "2022-04-14T04:41:35.67Z",
					"deviceType": "Desktop"
				},
				"etagMatch": false,
				"etag": "A0072086544",
				"status": 20000
			*/
			
			purple_protocol_got_user_status(sa->account, from, availability, NULL);

			gboolean is_idle = strstr(availability, "Idle") != NULL;
			purple_prpl_got_user_idle(sa->account, from, is_idle, 0);
		}
	}
}

static void
teams_lookup_contact_statuses(TeamsAccount *sa, GSList *contacts)
{
	const gchar *presence_path =  "/v1/presence/getpresence/";
	gchar *post;
	GSList *cur;
	JsonArray *contacts_array;
	guint count = 0;
	
	if (contacts == NULL) {
		return;
	}
	
	cur = contacts;
	contacts_array = json_array_new();
	count = 0;
	
	do {
		JsonObject *contact;
		gchar *id;

		contact = json_object_new();
		
		id = g_strconcat(teams_user_url_prefix(cur->data), cur->data, NULL);
		json_object_set_string_member(contact, "mri", id);
		json_array_add_object_element(contacts_array, contact);
		g_free(id);
		
		if (++count >= 650) {
			// Send off the current batch and continue
			post = teams_jsonarr_to_string(contacts_array);

			teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_PRESENCE_HOST, presence_path, post, teams_got_contact_statuses, NULL, TRUE);
			
			g_free(post);
			
			json_array_unref(contacts_array);
			contacts_array = json_array_new();
			count = 0;
		}
	} while((cur = g_slist_next(cur)));
	
	if (json_array_get_length(contacts_array) > 0) {
		post = teams_jsonarr_to_string(contacts_array);

		teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_PRESENCE_HOST, presence_path, post, teams_got_contact_statuses, NULL, TRUE);
		
		g_free(post);
	}
	json_array_unref(contacts_array);
}

void
teams_subscribe_to_contact_status(TeamsAccount *sa, GSList *contacts)
{
	if (contacts == NULL) {
		return;
	}

	if (sa->trouter_surl == NULL) {
		purple_debug_info("teams", "No trouter surl yet\n");
		// Websocket not ready yet, try the old way
		teams_lookup_contact_statuses(sa, contacts);
		return;
	}
	
	//TODO - switch to websocket for contact status reverse-webhooks

	/* 
	{
		"trouterUri": "trouter.surl ... /TeamsUnifiedPresenceService",
		"subscriptionsToAdd": [{
			"mri": "8:orgid:abc1234a-5289-8372-8234-djfs8a78f987"
		}, ...],
		"subscriptionsToRemove": [],
		"shouldPurgePreviousSubscriptions": false
	}
	*/
	//POST to https://presence.teams.microsoft.com/v1/pubsub/subscriptions/{sa->endpoint}
	//TODO how many in a batch?

	JsonArray *subscriptionsToAdd = json_array_new();
	JsonArray *subscriptionsToRemove = json_array_new();
	gchar *trouterUri = g_strconcat(sa->trouter_surl, "/TeamsUnifiedPresenceService", NULL);
	gchar *url = g_strdup_printf("/v1/pubsub/subscriptions/%s", purple_url_encode(sa->endpoint));

	gchar *post;
	GSList *cur = contacts;
	guint count = 0;
	do {
		JsonObject *contact;
		gchar *id;

		contact = json_object_new();

		id = g_strconcat(teams_user_url_prefix(cur->data), cur->data, NULL);
		json_object_set_string_member(contact, "mri", id);
		json_array_add_object_element(subscriptionsToAdd, contact);
		g_free(id);

		if (++count >= 100) {
			JsonObject *obj = json_object_new();

			// Send off the current batch and continue
			json_object_set_string_member(obj, "trouterUri", trouterUri);
			json_object_set_array_member(obj, "subscriptionsToAdd", subscriptionsToAdd);
			json_object_set_array_member(obj, "subscriptionsToRemove", subscriptionsToRemove);
			json_object_set_boolean_member(obj, "shouldPurgePreviousSubscriptions", FALSE);
			post = teams_jsonobj_to_string(obj);

			teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_PRESENCE_HOST, url, post, NULL, NULL, TRUE);

			g_free(post);
			json_object_unref(obj);

			subscriptionsToAdd = json_array_new();
			subscriptionsToRemove = json_array_new();
			count = 0;
		}
	} while((cur = g_slist_next(cur)));

	if (json_array_get_length(subscriptionsToAdd)) {
		JsonObject *obj = json_object_new();

		// Send off the current batch and continue
		json_object_set_string_member(obj, "trouterUri", trouterUri);
		json_object_set_array_member(obj, "subscriptionsToAdd", subscriptionsToAdd);
		json_object_set_array_member(obj, "subscriptionsToRemove", subscriptionsToRemove);
		json_object_set_boolean_member(obj, "shouldPurgePreviousSubscriptions", FALSE);
		post = teams_jsonobj_to_string(obj);

		teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_PRESENCE_HOST, url, post, NULL, NULL, TRUE);

		g_free(post);
		json_object_unref(obj);

	} else {
		// Would normally be unref'd when obj is unref'd
		json_array_unref(subscriptionsToAdd);
		json_array_unref(subscriptionsToRemove);
	}

	g_free(url);
	g_free(trouterUri);
}


static void
teams_subscribe_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	JsonArray *subscriptions = json_object_get_array_member(obj, "subscriptions");
	guint i, len;
	
	if (subscriptions != NULL) {
		len = json_array_get_length(subscriptions);
		for(i = 0; i < len; i++) {
			JsonObject *sub = json_array_get_object_element(subscriptions, i);

			const gchar * channelType = json_object_get_string_member(sub, "channelType");
			if (purple_strequal(channelType, "HttpLongPoll")) {
				// We have a longpoll url
				const gchar *longpollurl = json_object_get_string_member(sub, "longPollUrl");
				gchar *next_server = teams_string_get_chunk(longpollurl, -1, "https://", "/users");
				
				if (next_server != NULL) {
					g_free(sa->messages_host);
					sa->messages_host = next_server;
				}
				
				gchar *cursor = teams_string_get_chunk(longpollurl, -1, "?cursor=", NULL);
				if (cursor != NULL) {
					g_free(sa->messages_cursor);
					sa->messages_cursor = cursor;
				}
			}
		}
	}
	
	teams_do_all_the_things(sa);
}

void
teams_subscribe_with_callback(TeamsAccount *sa, TeamsProxyCallbackFunc callback)
{
	JsonObject *obj, *sub;
	JsonArray *interested;
	JsonArray *subscriptions;
	gchar *post;

	interested = json_array_new();
	json_array_add_string_element(interested, "/v1/users/ME/conversations/ALL/properties");
	json_array_add_string_element(interested, "/v1/users/ME/conversations/ALL/messages");
	json_array_add_string_element(interested, "/v1/users/ME/contacts/ALL");
	json_array_add_string_element(interested, "/v1/threads/ALL");
	
	obj = json_object_new();
	json_object_set_int_member(obj, "startingTimeSpan", 0);
	json_object_set_string_member(obj, "endpointFeatures", "Agent,Presence2015,MessageProperties,CustomUserProperties,NotificationStream,SupportsSkipRosterFromThreads");
	
	sub = json_object_new();
	json_object_set_array_member(sub, "interestedResources", interested);
	json_object_set_string_member(sub, "channelType", "HttpLongPoll");
	
	subscriptions = json_array_new();
	json_array_add_object_element(subscriptions, sub);
	json_object_set_array_member(obj, "subscriptions", subscriptions);

	if (sa->trouter_surl != NULL) {
		JsonObject *trouter_sub = json_object_new();
		json_object_set_string_member(trouter_sub, "channelType", "TrouterPush");
		json_object_set_string_member(trouter_sub, "longPollUrl", sa->trouter_surl);
		json_object_set_array_member(trouter_sub, "interestedResources", json_array_ref(interested));
		json_array_add_object_element(subscriptions, trouter_sub);
	}
	
	post = teams_jsonobj_to_string(obj);

	if (!sa->endpoint) {
		// Prevent running out of endpoints aka "Endpoint limit exceeded"
		const gchar *endpoint = purple_account_get_string(sa->account, "endpoint", NULL);
		if (!endpoint || !*endpoint) {
			sa->endpoint = purple_uuid_random();
			purple_account_set_string(sa->account, "endpoint", sa->endpoint);
		} else {
			sa->endpoint = g_strdup(endpoint);
		}
	}

	gchar *url = g_strdup_printf("/v2/users/ME/endpoints/%s", purple_url_encode(sa->endpoint));
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, post, callback, NULL, TRUE); // Personal: msgapi.teams.live.com
	g_free(url);
	
	g_free(post);
	json_object_unref(obj);
}

void
teams_subscribe(TeamsAccount *sa)
{
	teams_subscribe_with_callback(sa, teams_subscribe_cb);
}


static void
teams_got_vdms_token(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	const gchar *token;
	TeamsAccount *sa = user_data;
	JsonParser *parser = json_parser_new();
	const gchar *data;
	gsize len;
	
	data = purple_http_response_get_data(response, &len);

	if (json_parser_load_from_data(parser, data, len, NULL)) {
		JsonNode *root = json_parser_get_root(parser);
		JsonObject *obj = json_node_get_object(root);

		token = json_object_get_string_member(obj, "token");
		g_free(sa->vdms_token);
		sa->vdms_token = g_strdup(token); 
		sa->vdms_expiry = (int)time(NULL) + TEAMS_VDMS_TTL;
	}

	g_object_unref(parser);
	
}


void
teams_get_vdms_token(TeamsAccount *sa)
{
	const gchar *messages_url = "https://" TEAMS_STATIC_HOST "/pes/v1/petoken";
	PurpleHttpRequest *request;
	
	request = purple_http_request_new(messages_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "Origin", "https://web.skype.com");
	purple_http_request_header_set_printf(request, "Authorization", "skype_token %s", sa->skype_token);
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
	purple_http_request_set_contents(request, "{}", -1);
	purple_http_request(sa->pc, request, teams_got_vdms_token, sa);
	purple_http_request_unref(request);
}


	
static guint
teams_conv_send_typing_to_channel(TeamsAccount *sa, const gchar *channel, PurpleIMTypingState state)
{
	gchar *post, *url;
	JsonObject *obj;
	
	url = g_strdup_printf("/v1/users/ME/conversations/%s/messages", purple_url_encode(channel));
	
	obj = json_object_new();
	json_object_set_string_member(obj, "messagetype", state == PURPLE_IM_TYPING ? "Control/Typing" : "Control/ClearTyping");
	json_object_set_string_member(obj, "contenttype", "Application/Message");
	json_object_set_string_member(obj, "content", "");
	
	post = teams_jsonobj_to_string(obj);
	
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, post, NULL, NULL, TRUE);
	
	g_free(post);
	json_object_unref(obj);
	g_free(url);
	
	return 20;
}

guint
teams_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state)
{
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	
	if (!PURPLE_CONNECTION_IS_CONNECTED(pc))
		return 0;
	
	if (!purple_strequal(purple_protocol_get_id(purple_connection_get_protocol(pc)), TEAMS_PLUGIN_ID))
		return 0;
	
	return teams_conv_send_typing_to_channel(sa, purple_conversation_get_name(conv), state);
}

guint
teams_send_typing(PurpleConnection *pc, const gchar *name, PurpleIMTypingState state)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	
	const gchar *channel = g_hash_table_lookup(sa->buddy_to_chat_lookup, name);
	
	if (channel) {
		return teams_conv_send_typing_to_channel(sa, channel, state);
	}
	
	return 0;
}


static void
teams_set_global_statusid(TeamsAccount *sa, const gchar *status)
{
	gchar *post;
	
	g_return_if_fail(status);
	
	// This sets our status everywhere, including on other clients

	post = g_strdup_printf("{\"availability\":\"%s\"}", status);
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_PRESENCE_HOST, "/v1/me/forceavailability/", post, NULL, NULL, TRUE);
	g_free(post);
	

}

static void
teams_set_endpoint_statusid(TeamsAccount *sa, const gchar *status)
{
	gchar *post;
	PurplePresence *presence;
	const gchar *activity;
	
	g_return_if_fail(status);

	presence = purple_account_get_presence(sa->account);
	activity = purple_presence_is_idle(presence) ? "Away" : "Available";

	// This lets the 'reportmyactivity' idle/active endpoint work
	// and sets our status only on this endpoint
	//https://presence.teams.microsoft.com/v1/me/endpoints/
	// {
	// 	"id": "... endpoint id ...",
	// 	"availability": "Available",
	// 	"activity": "Available",
	// 	"activityReporting": "Transport",
	//	"capabilities": ["Audio", "Video"],
	// 	"deviceType": "Desktop"
	// }
	post = g_strdup_printf("{\"id\":\"%s\",\"availability\":\"%s\",\"activity\":\"%s\",\"activityReporting\":\"Transport\",\"deviceType\":\"Desktop\"}", sa->endpoint, status, activity);
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_PRESENCE_HOST, "/v1/me/endpoints/", post, NULL, NULL, TRUE);
	g_free(post);
}

void
teams_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	const gchar *statusid = purple_status_get_id(status);

	teams_set_endpoint_statusid(sa, statusid);
	
	if (!purple_account_get_bool(account, "set-global-status", TRUE)) {
		return;
	}
	
	teams_set_global_statusid(sa, statusid);
	teams_set_mood_message(sa, purple_status_get_attr_string(status, "message"));
}

void
teams_set_idle(PurpleConnection *pc, int time)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	gboolean is_active = FALSE;
	gchar *post;
	
	if (time < 30) {
		is_active = TRUE;
	}
	
	post = g_strdup_printf("{\"endpointId\":\"%s\",\"isActive\":%s}", sa->endpoint, is_active ? "true" : "false");
	//TODO check if it's a 404 response and recreate the endpoint (by resetting the availability) if it's gone
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_PRESENCE_HOST, "/v1/me/reportmyactivity/", post, NULL, NULL, TRUE);
	g_free(post);

	// send isactive on trouter if it's connected
	teams_trouter_send_active(sa, is_active);
}

gboolean
teams_idle_update(TeamsAccount *sa)
{
	PurplePresence *presence;
	gboolean is_idle;

	if (sa == NULL) {
		return FALSE;
	}

	if (!PURPLE_IS_CONNECTION(sa->pc) || purple_connection_get_state(sa->pc) != PURPLE_CONNECTED) {
		return FALSE;
	}

	presence = purple_account_get_presence(sa->account);
	is_idle = purple_presence_is_idle(presence);
	teams_set_idle(sa->pc, is_idle ? 30 : 0);

	return TRUE;
}


static void
teams_sent_message_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	gchar *convname = user_data;
	JsonObject *obj = NULL;
	
	if (node != NULL && json_node_get_node_type(node) == JSON_NODE_OBJECT)
		obj = json_node_get_object(node);
	
	if (obj != NULL) {
		if (json_object_has_member(obj, "errorCode")) {
			PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(convname, sa->account);
			if (chatconv == NULL) {
				purple_conversation_present_error(teams_strip_user_prefix(convname), sa->account, json_object_get_string_member(obj, "message"));
			} else {
				PurpleMessage *msg = purple_message_new_system(json_object_get_string_member(obj, "message"), PURPLE_MESSAGE_ERROR);
				purple_conversation_write_message(PURPLE_CONVERSATION(chatconv), msg);
				purple_message_destroy(msg);
			}
		}
	}
	
	g_free(convname);
}

static void teams_conversation_check_message_for_images(TeamsAccount *sa, const gchar *convname, gchar *message);

static void
teams_send_message(TeamsAccount *sa, const gchar *convname, const gchar *message)
{
	gchar *post, *url;
	JsonObject *obj;
	gint64 clientmessageid;
	gchar *clientmessageid_str;
	gchar *stripped;
	static GRegex *font_strip_regex = NULL;
	gchar *font_stripped;
	
	
	url = g_strdup_printf("/v1/users/ME/conversations/%s/messages", purple_url_encode(convname));
	
	clientmessageid = teams_get_js_time();
	clientmessageid_str = g_strdup_printf("%" G_GINT64_FORMAT "", clientmessageid);
	
	// Some clients don't receive messages with <br>'s in them
	//stripped = purple_strreplace(message, "<br>", "\r\n");
	stripped = g_strdup(message);
	
	teams_conversation_check_message_for_images(sa, convname, stripped);
	if (!stripped || !*stripped) {
		// Nothing to send
		g_free(url);
		g_free(clientmessageid_str);
		return;
	}
	
	// Pidgin has a nasty habit of sending <font size="3"> when copy-pasting text
	if (font_strip_regex == NULL) {
		font_strip_regex = g_regex_new("(<font [^>]*)size=\"[0-9]+\"([^>]*>)", G_REGEX_CASELESS | G_REGEX_RAW | G_REGEX_OPTIMIZE, 0, NULL);
	}
	font_stripped = g_regex_replace(font_strip_regex, stripped, -1, 0, "\\1\\2", 0, NULL);
	if (font_stripped != NULL) {
		g_free(stripped);
		stripped = font_stripped;
	}
	
	obj = json_object_new();
	json_object_set_string_member(obj, "clientmessageid", clientmessageid_str);
	json_object_set_string_member(obj, "content", stripped);
	if (G_UNLIKELY(g_str_has_prefix(message, "<URIObject "))) {
		json_object_set_string_member(obj, "messagetype", "RichText/Media_GenericFile"); //hax!
	} else {
		json_object_set_string_member(obj, "messagetype", "RichText/Html");
	}
	json_object_set_string_member(obj, "contenttype", "text");
	json_object_set_string_member(obj, "imdisplayname", sa->self_display_name ? sa->self_display_name : sa->username);
	
	if (g_str_has_prefix(message, "/me ")) {
		json_object_set_string_member(obj, "skypeemoteoffset", "4"); //Why is this a string :(
	}
	
	post = teams_jsonobj_to_string(obj);
	
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url, post, teams_sent_message_cb, g_strdup(convname), TRUE);
	
	g_free(post);
	json_object_unref(obj);
	g_free(url);
	g_free(stripped);
	
	g_hash_table_insert(sa->sent_messages_hash, clientmessageid_str, clientmessageid_str);
}


gint
teams_chat_send(PurpleConnection *pc, gint id, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	
	PurpleChatConversation *chatconv;
	const gchar* chatname;
	
	chatconv = purple_conversations_find_chat(pc, id);
	chatname = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "chatname");
	if (!chatname) {
		// Fix for a condition around the chat data and serv_got_joined_chat()
		chatname = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		if (!chatname)
			return -1;
		}

	teams_send_message(sa, chatname, message);

	purple_serv_got_chat_in(pc, id, sa->username, PURPLE_MESSAGE_SEND, message, time(NULL));

	return 1;
}

gint
teams_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif

	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	const gchar *convname;

	if (teams_is_user_self(sa, who)) {
		// Fake internal app for self-messages
		who = "48:notes";
	}
	
	if (TEAMS_BUDDY_IS_NOTIFICATIONS(who)) {
		convname = who;
	} else {
		convname = g_hash_table_lookup(sa->buddy_to_chat_lookup, who);
	}
	
	//convname should be like
	//19:{guid of user1}_{guid of user2}@unq.gpl.spaces
	
	if (!convname) {
		teams_initiate_chat(sa, who, TRUE, message);
		return 0;
	}
	
	teams_send_message(sa, convname, message);
	
	return 1;
}


void
teams_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;
	gchar *chatname;
	gchar *post;
	GString *url;

	chatconv = purple_conversations_find_chat(pc, id);
	chatname = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "chatname");
	
	url = g_string_new("/v1/threads/");
	g_string_append_printf(url, "%s", purple_url_encode(chatname));
	g_string_append(url, "/members/");
	g_string_append_printf(url, "%s%s", teams_user_url_prefix(who), purple_url_encode(who));
	
	post = "{\"role\":\"User\"}";
	
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url->str, post, NULL, NULL, TRUE);
	
	g_string_free(url, TRUE);
}

void
teams_chat_kick(PurpleConnection *pc, int id, const char *who)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;
	gchar *chatname;
	gchar *post;
	GString *url;

	chatconv = purple_conversations_find_chat(pc, id);
	chatname = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "chatname");
	
	url = g_string_new("/v1/threads/");
	g_string_append_printf(url, "%s", purple_url_encode(chatname));
	g_string_append(url, "/members/");
	g_string_append_printf(url, "%s%s", teams_user_url_prefix(who), purple_url_encode(who));
	
	post = "";
	
	teams_post_or_get(sa, TEAMS_METHOD_DELETE | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url->str, post, NULL, NULL, TRUE);
	
	g_string_free(url, TRUE);
}

static void
teams_created_chat(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	gchar *initial_message_copy = user_data;
	const gchar *convname = json_object_get_string_member(obj, "id");
	gint64 errorCode = json_object_get_int_member(obj, "errorCode");
	
	if (!errorCode && convname != NULL && initial_message_copy && *initial_message_copy) {
		process_thread_resource(sa, obj);
		
		teams_send_message(sa, convname, initial_message_copy);
		
		const gchar *convbuddyname = g_hash_table_lookup(sa->chat_to_buddy_lookup, convname);
		if (convbuddyname != NULL) {
			PurpleMessage *msg;
			PurpleIMConversation *conv = purple_conversations_find_im_with_account(convbuddyname, sa->account);
			
			msg = purple_message_new_outgoing(convbuddyname, initial_message_copy, PURPLE_MESSAGE_SEND);
			purple_message_set_time(msg, time(NULL));
			purple_conversation_write_message(PURPLE_CONVERSATION(conv), msg);
			purple_message_destroy(msg);
		}
		
	} else if (errorCode) {
		const gchar *message = json_object_get_string_member(obj, "message");
		
		//TODO present the error somehow... popup?
		(void) message;
	}
	
	g_free(initial_message_copy);
}

void
teams_initiate_chat(TeamsAccount *sa, const gchar *who, gboolean one_to_one, const gchar *initial_message)
{
	JsonObject *obj, *contact, *properties;
	JsonArray *members;
	gchar *id, *post, *initial_message_copy;
	TeamsConnection *conn;
	
	obj = json_object_new();
	members = json_array_new();
	
	contact = json_object_new();
	id = g_strconcat(teams_user_url_prefix(who), who, NULL);
	json_object_set_string_member(contact, "id", id);
	json_object_set_string_member(contact, "role", "User");
	json_array_add_object_element(members, contact);
	g_free(id);
	
	contact = json_object_new();
	id = g_strconcat(teams_user_url_prefix(sa->username), sa->username, NULL);
	json_object_set_string_member(contact, "id", id);
	json_object_set_string_member(contact, "role", "Admin");
	json_array_add_object_element(members, contact);
	g_free(id);
	
	json_object_set_array_member(obj, "members", members);
	
	properties = json_object_new();
	json_object_set_string_member(properties, "threadType", "chat");
	json_object_set_string_member(properties, "chatFilesIndexId", "2");
	if (one_to_one) {
		json_object_set_string_member(properties, "fixedRoster", "true");
		json_object_set_string_member(properties, "uniquerosterthread", "true");
	}
	json_object_set_object_member(obj, "properties", properties);
	
	post = teams_jsonobj_to_string(obj);
	
	if (initial_message && *initial_message) {
		initial_message_copy = g_strdup(initial_message);
	} else {
		initial_message_copy = NULL;
	}
	
	conn = teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, "/v1/threads", post, teams_created_chat, initial_message_copy, TRUE);
	
	// Enable redirects
	if (conn != NULL) {
		PurpleHttpRequest *request = purple_http_conn_get_request(conn->http_conn);
		purple_http_request_set_max_redirects(request, 1);
	}

	g_free(post);
	json_object_unref(obj);
}

void
teams_initiate_chat_from_node(PurpleBlistNode *node, gpointer userdata)
{
	if(PURPLE_IS_BUDDY(node))
	{
		PurpleBuddy *buddy = (PurpleBuddy *) node;
		TeamsAccount *sa;
		
		if (userdata) {
			sa = userdata;
		} else {
			PurpleConnection *pc = purple_account_get_connection(purple_buddy_get_account(buddy));
			sa = purple_connection_get_protocol_data(pc);
		}
		
		teams_initiate_chat(sa, purple_buddy_get_name(buddy), FALSE, NULL);
	}
}

void
teams_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;
	JsonObject *obj;
	gchar *chatname;
	gchar *post;
	GString *url;

	chatconv = purple_conversations_find_chat(pc, id);
	chatname = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "chatname");
	
	url = g_string_new("/v1/threads/");
	g_string_append_printf(url, "%s", purple_url_encode(chatname));
	g_string_append(url, "/properties?name=topic");
	
	obj = json_object_new();
	json_object_set_string_member(obj, "topic", topic);
	post = teams_jsonobj_to_string(obj);
	
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, url->str, post, NULL, NULL, TRUE);
	
	g_string_free(url, TRUE);
	g_free(post);
	json_object_unref(obj);
}

// TODO
// char *
// teams_chat_get_cb_alias(PurpleConnection *gc, int id, const char *who)
// {
// 	// Find the friendlyname for the user
// 	TeamsAccount *sa = purple_connection_get_protocol_data(gc);
//	return g_strdup(friendlyname);
// }

void
teams_get_thread_url(TeamsAccount *sa, const gchar *thread)
{
	//POST https://api.scheduler.skype.com/threads
	//{"baseDomain":"https://join.skype.com/launch/","threadId":"%s"}
	
	// {"Id":"MeMxigEAAAAxOTo5NDZkMjExMGQ4YmU0ZjQzODc3NjMxNDQ3ZTgxYWNmNkB0aHJlYWQuc2t5cGU","Blob":null,"JoinUrl":"https://join.skype.com/ALXsHZ2RFQnk","ThreadId":"19:946d2110d8be4f43877631447e81acf6@thread.skype"}
}

static void
teams_conversation_send_image_part2_cb(PurpleHttpConnection *connection, PurpleHttpResponse *response, gpointer user_data)
{
	PurpleConnection *pc = purple_http_conn_get_purple_connection(connection);
	TeamsAccount *sa;
	gchar *convname;
	gchar *image_id;
	gchar *image_url;
	gchar *html;
	
	if (purple_http_response_get_error(response) != NULL) {
		purple_notify_error(pc, _("Image Send Error"), _("There was an error sending the image"), purple_http_response_get_error(response), purple_request_cpar_from_connection(pc));
		g_dataset_destroy(connection);
		return;
	}
	
	sa = user_data;
	convname = g_dataset_get_data(connection, "convname");
	image_id = g_dataset_get_data(connection, "image_id");
	
	image_url = g_strdup_printf("https://as-api.asm.skype.com/v1/objects/%s/views/imgo", purple_url_encode(image_id));
	html = g_strdup_printf("<p><img itemscope=\"image\" style=\"vertical-align:bottom\" src=\"%s\" alt=\"image\" itemtype=\"http://schema.skype.com/AMSImage\" height=\"250\" id=\"%s\" itemid=\"%s\" href=\"%s\" target-src=\"%s\"></p>", image_url, image_id, image_id, image_url, image_url);
	
	teams_send_message(sa, convname, html);
	
	g_free(html);
	g_free(image_url);
}

static void
teams_conversation_send_image_cb(PurpleHttpConnection *connection, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa;
	gchar *convname;
	PurpleImage *image;
	PurpleHttpRequest *request;
	PurpleHttpConnection *new_connection;
	PurpleConnection *pc = purple_http_conn_get_purple_connection(connection);
	JsonObject *obj;
	const gchar *data;
	gsize len;
	const gchar *id;
	gchar *upload_url;
	
	sa = user_data;
	convname = g_dataset_get_data(connection, "convname");
	image = g_dataset_get_data(connection, "image");
	
	if (purple_http_response_get_error(response) != NULL) {
		purple_notify_error(pc, _("Image Send Error"), _("There was an error sending the image"), purple_http_response_get_error(response), purple_request_cpar_from_connection(pc));
		purple_image_unref(image);
		g_dataset_destroy(connection);
		return;
	}
	
	data = purple_http_response_get_data(response, &len);
	obj = json_decode_object(data, len);
	if (obj == NULL || !json_object_has_member(obj, "id")) {
		purple_image_unref(image);
		g_dataset_destroy(connection);
		if (obj != NULL) {
			json_object_unref(obj);
		}
		return;
	}
	
	id = json_object_get_string_member(obj, "id");
	
	upload_url = g_strdup_printf("https://as-prod.asyncgw." TEAMS_BASE_ORIGIN_HOST "/v1/objects/%s/content/imgpsh", purple_url_encode(id));
	
	request = purple_http_request_new(upload_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set(request, "Content-Type", "application/octet-stream");
	purple_http_request_header_set_printf(request, "Authorization", "skype_token %s", sa->skype_token);
	purple_http_request_header_set(request, "Referer", "https://" TEAMS_BASE_ORIGIN_HOST "/");
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_set_method(request, "PUT");
	purple_http_request_set_contents(request, purple_image_get_data(image), purple_image_get_data_size(image));
	purple_http_request_set_max_redirects(request, 0);
	purple_http_request_set_timeout(request, 120);

	new_connection = purple_http_request(sa->pc, request, teams_conversation_send_image_part2_cb, sa);
	purple_http_request_unref(request);
	
	g_dataset_set_data_full(new_connection, "convname", g_strdup(convname), g_free);
	g_dataset_set_data_full(new_connection, "image_id", g_strdup(id), g_free);
	
	g_dataset_destroy(connection);
	g_free(upload_url);
	purple_image_unref(image);
	json_object_unref(obj);
}

static void
teams_conversation_send_image(TeamsAccount *sa, const gchar *convname, PurpleImage *image)
{
	PurpleHttpRequest *request;
	PurpleHttpConnection *connection;
	gchar *filename;
	gchar *postdata;
	JsonObject *obj, *permissions;
	JsonArray *permissions_array;
	
	filename = (gchar *)purple_image_get_path(image);
	if (filename != NULL) {
		filename = g_path_get_basename(filename);
	} else {
		filename = g_strdup_printf("MicrosoftTeams-image.%s", purple_image_get_extension(image));
	}
	
	permissions_array = json_array_new();
	json_array_add_string_element(permissions_array, "read");
	
	permissions = json_object_new();
	json_object_set_array_member(permissions, convname, permissions_array);
	
	obj = json_object_new();
	json_object_set_string_member(obj, "type", "pish/image");
	json_object_set_object_member(obj, "permissions", permissions);
	json_object_set_string_member(obj, "filename", filename);
	json_object_set_string_member(obj, "sharingMode", "Inline");
	postdata = teams_jsonobj_to_string(obj);
	
	request = purple_http_request_new("https://as-prod.asyncgw." TEAMS_BASE_ORIGIN_HOST "/v1/objects/");
	purple_http_request_set_method(request, "POST");
	purple_http_request_header_set(request, "content-type", "application/json");
	purple_http_request_header_set_printf(request, "Authorization", "skype_token %s", sa->skype_token);
	purple_http_request_header_set(request, "x-ms-client-version", TEAMS_CLIENTINFO_VERSION);
	purple_http_request_header_set(request, "Accept", "application/json");
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_contents(request, postdata, strlen(postdata));
	purple_http_request_set_max_redirects(request, 0);
	purple_http_request_set_timeout(request, 120);
	
	connection = purple_http_request(sa->pc, request, teams_conversation_send_image_cb, sa);
	purple_http_request_unref(request);
	
	g_dataset_set_data_full(connection, "convname", g_strdup(convname), g_free);
	purple_image_ref(image);
	g_dataset_set_data_full(connection, "image", image, NULL);
	
	g_free(filename);
}


static void
teams_conversation_check_message_for_images(TeamsAccount *sa, const gchar *convname, gchar *message)
{
	int imgid;
	gchar *img;
	PurpleImage *image;
	
	if ((img = strstr(message, "<img ")) || (img = strstr(message, "<IMG "))) {
		const gchar *id, *src;
		const gchar *close = strchr(img, '>');
		imgid = 0;

		if (close == NULL)
			return;
		
		if (((id = strstr(img, "ID=\"")) || (id = strstr(img, "id=\""))) &&
				id < close) {
			imgid = atoi(id + 4);
			image = purple_image_store_get(imgid);
			
			if (image != NULL) {
				teams_conversation_send_image(sa, convname, image);
			}
		} else if (((src = strstr(img, "SRC=\"")) || (src = strstr(img, "src=\""))) &&
				src < close) {
			// purple3 embeds images using src="purple-image:1"
			if (strncmp(src + 5, "purple-image:", 13) == 0) {
				imgid = atoi(src + 5 + 13);
				image = purple_image_store_get(imgid);
				
				if (image != NULL) {
					teams_conversation_send_image(sa, convname, image);
				}
			}
		}
		
		if (imgid && image != NULL && close != NULL) {
			memmove(img, close + 1, strlen(close) + 1);
		}
	}
}

