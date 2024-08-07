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
 

#include "teams_contacts.h"
#include "libteams.h"
#include "teams_connection.h"
#include "teams_messages.h"
#include "teams_util.h"

#include "http.h"
#include "xfer.h"
#include "image-store.h"

static void purple_conversation_write_system_message_ts(
		PurpleConversation *conv, const gchar *msg, PurpleMessageFlags flags,
		time_t ts) {
	PurpleMessage *pmsg = purple_message_new_system(msg, flags);
	purple_message_set_time(pmsg, ts);
	purple_conversation_write_message(conv, pmsg);
	purple_message_destroy(pmsg);
}
static void purple_conversation_write_img_message(
		PurpleConversation *conv, const char* who, const gchar *msg,
		PurpleMessageFlags flags, time_t ts) {
	PurpleMessage *pmsg;

	if (flags & PURPLE_MESSAGE_SEND) {
		pmsg = purple_message_new_outgoing(who, msg, flags);
		purple_message_set_time(pmsg, ts);
	} else {
		pmsg = purple_message_new_incoming(who, msg, flags, ts);
	}
		
	purple_conversation_write_message(conv, pmsg);
	purple_message_destroy(pmsg);
}

// Check that the conversation hasn't been closed
static gboolean
purple_conversation_is_valid(PurpleConversation *conv)
{
	GList *convs = purple_conversations_get_all();
	
	return (g_list_find(convs, conv) != NULL);
}


typedef struct {
	PurpleXfer *xfer;
	JsonObject *info;
	gchar *from;
	gchar *url;
	gchar *id;
	TeamsAccount *sa;
} TeamsFileTransfer;

static guint active_icon_downloads = 0;

static void
teams_get_icon_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	PurpleHttpRequest *request = purple_http_conn_get_request(http_conn);
	PurpleBuddy *buddy = user_data;
	const gchar *url = purple_http_request_get_url(request);
	const gchar *data;
	gsize len;
	
	active_icon_downloads--;
	
	if (!buddy || !purple_http_response_is_successful(response)) {
		return;
	}
	
	data = purple_http_response_get_data(response, &len);
	
	if (!len || !*data) {
		return;
	}
	
	purple_buddy_icons_set_for_user(purple_buddy_get_account(buddy), purple_buddy_get_name(buddy), g_memdup2(data, len), len, url);
	
}

static void
teams_get_icon_now(PurpleBuddy *buddy)
{
	TeamsBuddy *sbuddy;
	TeamsAccount *sa;
	gchar *url;
	PurpleHttpRequest *request;
	
	purple_debug_info("teams", "getting new buddy icon for %s\n", purple_buddy_get_name(buddy));
	
	sbuddy = purple_buddy_get_protocol_data(buddy);
	
	if (!sbuddy || !sbuddy->sa || !sbuddy->sa->pc)
		return;

	if (sbuddy->avatar_url && sbuddy->avatar_url[0]) {
		url = g_strdup(sbuddy->avatar_url);
	} else {
		const gchar *buddy_name = purple_buddy_get_name(buddy);
		//https://teams.microsoft.com/api/mt/apac/beta/users/.../profilepicturev2?displayname=Eion%20Robb&size=HR96x96
		//https://teams.microsoft.com/api/mt/part/au-01/beta/users/...myid.../profilepicturev2/8:orgid:userid?displayname=Eion%20Robb&size=HR196x196&ETag=1704940983743
		url = g_strdup_printf("https://" TEAMS_BASE_ORIGIN_HOST TEAMS_PROFILES_PREFIX "users/%s%s/profilepicturev2?size=HR128x128", teams_user_url_prefix(buddy_name), purple_url_encode(buddy_name));

		// alternative
		//https://aus.loki.delve.office.com/api/v2/personaphoto?AadObjectId=12345678-abcd-4321-1234-123456789abc&AuthToken=eyJ...&ClientType=MicrosoftStream
	}

	if (purple_strequal(url, purple_buddy_icons_get_checksum_for_user(buddy))) {
		g_free(url);
		return;
	}

	sa = sbuddy->sa;
	
	request = purple_http_request_new(url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_max_redirects(request, 0);
	purple_http_request_set_timeout(request, 120);
	
	// Weirdly uses a cookie instead of the Authorization header
	if (strstr(url, "https://" TEAMS_BASE_ORIGIN_HOST "/api/mt/") == url && strstr(url, "/profilepicturev2")) {
		purple_http_request_header_set(request, "Referer", "https://" TEAMS_BASE_ORIGIN_HOST "/");
		purple_http_request_header_set_printf(request, "Cookie", "authtoken=Bearer%%3D%s%%26Origin%%3Dhttps%%3A%%2F%%2F" TEAMS_BASE_ORIGIN_HOST, purple_url_encode(sa->id_token));
	}
	
	purple_http_request(sa->pc, request, teams_get_icon_cb, buddy);
	
	purple_http_request_unref(request);
	g_free(url);

	active_icon_downloads++;
}

static gboolean
teams_get_icon_queuepop(gpointer data)
{
	PurpleBuddy *buddy = data;
	
	// Only allow 4 simultaneous downloads
	if (active_icon_downloads > 4)
		return TRUE;
	
	teams_get_icon_now(buddy);
	return FALSE;
}

void
teams_get_icon(PurpleBuddy *buddy)
{
	if (!buddy) return;
	if (purple_strequal(purple_core_get_ui(), "BitlBee"))
		return;
	
	g_timeout_add(100, teams_get_icon_queuepop, (gpointer)buddy);
}

typedef struct SkypeImgMsgContext_ {
	PurpleConversation *conv;
	time_t composetimestamp;
	gchar* from;
} SkypeImgMsgContext;

static void
teams_got_imagemessage(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	gint icon_id;
	gchar *msg_tmp;
	const gchar *url_text;
	gsize len;
	PurpleImage *image;
	PurpleMessageFlags flags = PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_IMAGES;
	
	SkypeImgMsgContext *ctx = user_data;
	PurpleConversation *conv = ctx->conv;
	PurpleConnection *pc = purple_conversation_get_connection(conv);
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	
	time_t ts = ctx->composetimestamp;
	gchar* ctx_from = ctx->from;
	ctx->from = NULL;
	g_free(ctx);
	
	// Conversation could have been closed before we retrieved the image
	if (!purple_conversation_is_valid(conv)) {
		g_free(ctx_from);
		return;
	}
	
	url_text = purple_http_response_get_data(response, &len);
	
	if (!url_text || !len || url_text[0] == '{' || url_text[0] == '<') {
		g_free(ctx_from);
		return;
	}
	
	if (!purple_http_response_is_successful(response)) {
		g_free(ctx_from);
		return;
	}
	
	image = purple_image_new_from_data(g_memdup2(url_text, len), len);
	icon_id = purple_image_store_add(image);
	msg_tmp = g_strdup_printf("<img id='%d'>", icon_id);
	
	if (sa && teams_is_user_self(sa, ctx_from)) {
		flags |= PURPLE_MESSAGE_SEND;
	} else {
		flags |= PURPLE_MESSAGE_RECV;
	}
	
	purple_conversation_write_img_message(conv, ctx_from, msg_tmp, flags, ts);
	
	g_free(msg_tmp);
	g_free(ctx_from);
}

void
teams_download_uri_to_conv(TeamsAccount *sa, const gchar *uri, PurpleConversation *conv, time_t ts, const gchar* from)
{
	gchar *url, *text;
	PurpleHttpRequest *request;
	PurpleMessageFlags flags = 0;
	
	text = purple_strreplace(uri, "/imgt1", "/imgpsh_fullsize");
	url = purple_strreplace(text, "/imgo", "/imgpsh_fullsize");
	g_free(text);

	if (purple_strequal(purple_core_get_ui(), "BitlBee")) {
		// Bitlbee doesn't support images, so just plop a url to the image instead
		
		purple_conversation_write_system_message_ts(conv, url, PURPLE_MESSAGE_SYSTEM, ts);
		g_free(url);
		
		return;
	}
	
	request = purple_http_request_new(uri);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	
	static GRegex *skype_token_uri_regex = NULL;
	if (skype_token_uri_regex == NULL) {
		skype_token_uri_regex = g_regex_new("^https://api\\.asm\\.skype\\.com/|^https://[^\\.]*\\.asyncgw\\.teams\\.microsoft\\.com/", G_REGEX_OPTIMIZE, 0, NULL);
	}

	//Only for skype domains
	if (skype_token_uri_regex != NULL && g_regex_match(skype_token_uri_regex, uri, 0, NULL)) {
		purple_http_request_header_set_printf(request, "Cookie", "skypetoken_asm=%s", sa->skype_token);
	}
	
	purple_http_request_header_set(request, "Accept", "image/*");
	SkypeImgMsgContext *ctx = g_new(SkypeImgMsgContext, 1);
	ctx->composetimestamp = ts;
	ctx->conv = conv;
	ctx->from = g_strdup(from);
	purple_http_request(sa->pc, request, teams_got_imagemessage, ctx);
	purple_http_request_unref(request);
	
	if (teams_is_user_self(sa, from)) {
		flags |= PURPLE_MESSAGE_SEND;
	} else {
		flags |= PURPLE_MESSAGE_RECV;
	}

	text = g_strdup_printf("<a href=\"%s\">Click here to view full version</a>", url);
	purple_conversation_write_img_message(conv, from, text, flags, ts);
	
	g_free(url);
	g_free(text);
}

void
teams_download_moji_to_conv(TeamsAccount *sa, const gchar *text, const gchar *url_thumbnail, PurpleConversation *conv, time_t ts, const gchar* from)
{
	gchar *cdn_url_thumbnail;
	PurpleHttpURL *httpurl;
	PurpleHttpRequest *request;
	PurpleMessageFlags flags = 0;

	httpurl = purple_http_url_parse(url_thumbnail);

	cdn_url_thumbnail = g_strdup_printf("https://%s/%s", TEAMS_STATIC_CDN_HOST, purple_http_url_get_path(httpurl));
	
	request = purple_http_request_new(cdn_url_thumbnail);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set_printf(request, "Cookie", "vdms-skype-token=%s", sa->vdms_token);
	purple_http_request_header_set(request, "Accept", "image/*");
	SkypeImgMsgContext *ctx = g_new(SkypeImgMsgContext, 1);
	ctx->composetimestamp = ts;
	ctx->conv = conv;
	ctx->from = g_strdup(from);
	purple_http_request(sa->pc, request, teams_got_imagemessage, ctx);
	purple_http_request_unref(request);
	
	if (teams_is_user_self(sa, from)) {
		flags |= PURPLE_MESSAGE_SEND;
	} else {
		flags |= PURPLE_MESSAGE_RECV;
	}
	
	purple_conversation_write_img_message(conv, from, text, flags, ts);

	g_free(cdn_url_thumbnail);
	purple_http_url_free(httpurl);
}

static void
teams_got_vm_file(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	PurpleXfer *xfer = user_data;
	const gchar *data;
	gsize len;
	
	data = purple_http_response_get_data(response, &len);
	purple_xfer_write(xfer, (guchar *)data, len);
}

static void
teams_init_vm_download(PurpleXfer *xfer)
{
	TeamsAccount *sa;
	JsonObject *file = purple_xfer_get_protocol_data(xfer);
	gint64 fileSize;
	const gchar *url;
	PurpleHttpRequest *request;

	fileSize = json_object_get_int_member(file, "fileSize");
	url = json_object_get_string_member(file, "url");
	
	purple_xfer_set_completed(xfer, FALSE);
	sa = purple_connection_get_protocol_data(purple_account_get_connection(purple_xfer_get_account(xfer)));
	
	request = purple_http_request_new(url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_max_len(request, fileSize);
	purple_http_request(sa->pc, request, teams_got_vm_file, xfer);
	purple_http_request_unref(request);
	
	json_object_unref(file);
}

static void
teams_cancel_vm_download(PurpleXfer *xfer)
{
	JsonObject *file = purple_xfer_get_protocol_data(xfer);
	json_object_unref(file);
}

static void
teams_got_vm_download_info(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	PurpleConversation *conv = user_data;
	PurpleXfer *xfer;
	JsonObject *obj, *file;
	JsonArray *files;
	gint64 fileSize;
	const gchar *url, *assetId, *status;
	gchar *filename;
	
	if (node == NULL || json_node_get_node_type(node) != JSON_NODE_OBJECT)
		return;
	obj = json_node_get_object(node);
	
	files = json_object_get_array_member(obj, "files");
	file = json_array_get_object_element(files, 0);
	if (file != NULL) {
		status = json_object_get_string_member(file, "status");
		if (status && g_str_equal(status, "ok")) {
			assetId = json_object_get_string_member(obj, "assetId");
			fileSize = json_object_get_int_member(file, "fileSize");
			url = json_object_get_string_member(file, "url");
			(void) url;
			
			filename = g_strconcat(assetId, ".mp4", NULL);
			
			xfer = purple_xfer_new(sa->account, PURPLE_XFER_TYPE_RECEIVE, purple_conversation_get_name(conv));
			purple_xfer_set_size(xfer, fileSize);
			purple_xfer_set_filename(xfer, filename);
			json_object_ref(file);
			purple_xfer_set_protocol_data(xfer, file);
			purple_xfer_set_init_fnc(xfer, teams_init_vm_download);
			purple_xfer_set_cancel_recv_fnc(xfer, teams_cancel_vm_download);
			purple_xfer_add(xfer);
			
			g_free(filename);
		} else if (status && g_str_equal(status, "running")) {
			//teams_download_video_message(sa, sid??????, conv);
		}
	}
}

static void
teams_got_vm_info(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	PurpleConversation *conv = user_data;
	JsonObject *obj, *response, *media_stream;
	const gchar *filename;
	
	if (node == NULL || json_node_get_node_type(node) != JSON_NODE_OBJECT)
		return;
	obj = json_node_get_object(node);
	
	response = json_object_get_object_member(obj, "response");
	media_stream = json_object_get_object_member(response, "media_stream");
	filename = json_object_get_string_member(media_stream, "filename");
	
	if (filename != NULL) {
		// Need to keep retrying this url until it comes back with status:ok
		gchar *url = g_strdup_printf("/vod/api-create?assetId=%s&profile=mp4-vm", purple_url_encode(filename));
		teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, "media.vm.skype.com", url, NULL, teams_got_vm_download_info, conv, TRUE);
		g_free(url);
	}

}

void
teams_download_video_message(TeamsAccount *sa, const gchar *sid, PurpleConversation *conv)
{
	gchar *url, *username_encoded;
	
	username_encoded = g_strdup(purple_url_encode(sa->username));
	url = g_strdup_printf("/users/%s/video_mails/%s", username_encoded, purple_url_encode(sid));
	
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_VIDEOMAIL_HOST, url, NULL, teams_got_vm_info, conv, TRUE);
	
	g_free(url);
	g_free(username_encoded);
	
}


static void
teams_free_xfer(PurpleXfer *xfer)
{
	TeamsFileTransfer *swft;
	
	swft = purple_xfer_get_protocol_data(xfer);
	g_return_if_fail(swft != NULL);
	
	if (swft->info != NULL)
		json_object_unref(swft->info);
	g_free(swft->url);
	g_free(swft->id);
	g_free(swft->from);
	g_free(swft);
	
	purple_xfer_set_protocol_data(xfer, NULL);
}

static void
teams_got_file(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsFileTransfer *swft = user_data;
	PurpleXfer *xfer = swft->xfer;
	TeamsAccount *sa = swft->sa;
	const gchar *data;
	gsize len;
	
	
	if (!purple_http_response_is_successful(response)) {
		purple_xfer_error(purple_xfer_get_xfer_type(xfer), sa->account, swft->from, purple_http_response_get_error(response));
		purple_xfer_cancel_local(xfer);
	} else {
		data = purple_http_response_get_data(response, &len);
		purple_xfer_write_file(xfer, (guchar *)data, len);
		purple_xfer_set_completed(xfer, TRUE);
	}
	
	//cleanup
	teams_free_xfer(xfer);
	purple_xfer_end(xfer);
}

static void
teams_init_file_download(PurpleXfer *xfer)
{
	TeamsAccount *sa;
	TeamsFileTransfer *swft;
	const gchar *view_location;
	gint64 content_full_length;
	PurpleHttpRequest *request;
	
	swft = purple_xfer_get_protocol_data(xfer);
	sa = swft->sa;
	
	view_location = json_object_get_string_member(swft->info, "view_location");
	content_full_length = json_object_get_int_member(swft->info, "content_full_length");
	
	purple_xfer_start(xfer, -1, NULL, 0);
	
	request = purple_http_request_new(view_location);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set_printf(request, "Cookie", "skypetoken_asm=%s", sa->skype_token);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_set_max_len(request, content_full_length);
	purple_http_request(sa->pc, request, teams_got_file, swft);
	purple_http_request_unref(request);
}

static void
teams_got_file_info(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	JsonObject *obj;
	PurpleXfer *xfer;
	TeamsFileTransfer *swft = user_data;
	TeamsAccount *sa = swft->sa;
	const gchar *data;
	gsize len;
	
	data = purple_http_response_get_data(response, &len);
	obj = json_decode_object(data, len);

	if (obj == NULL) {
		g_free(swft->url);
		g_free(swft->from);
		g_free(swft);
		return;
	}
	
	/* 
	{
		"content_length": 40708,
		"content_full_length": 40708,
		"view_length": 40708,
		"content_state": "ready",
		"view_state": "ready",
		"view_location": "uri/views/original",
		"status_location": "uri/views/original/status",
		"scan": {
			"status": "passed"
		},
		"original_filename": "filename"
	} */
	purple_debug_info("teams", "File info: %s\n", data);
	
	if (!json_object_has_member(obj, "content_state") || !purple_strequal(json_object_get_string_member(obj, "content_state"), "ready")) {
		teams_present_uri_as_filetransfer(sa, json_object_get_string_member(obj, "status_location"), swft->from);
		g_free(swft->url);
		g_free(swft->from);
		g_free(swft);
		json_object_unref(obj);
		return;
	}
	
	swft->info = obj;
	
	xfer = purple_xfer_new(sa->account, PURPLE_XFER_TYPE_RECEIVE, swft->from);
	purple_xfer_set_size(xfer, json_object_get_int_member(obj, "content_full_length"));
	purple_xfer_set_filename(xfer, json_object_get_string_member(obj, "original_filename"));
	purple_xfer_set_init_fnc(xfer, teams_init_file_download);
	purple_xfer_set_cancel_recv_fnc(xfer, teams_free_xfer);
	
	swft->xfer = xfer;
	purple_xfer_set_protocol_data(xfer, swft);
	
	purple_xfer_request(xfer);
}

void
teams_present_uri_as_filetransfer(TeamsAccount *sa, const gchar *uri, const gchar *from)
{
	TeamsFileTransfer *swft;
	PurpleHttpRequest *request;
	
	swft = g_new0(TeamsFileTransfer, 1);
	swft->sa = sa;
	swft->url = g_strdup(uri);
	swft->from = g_strdup(from);
	
	request = purple_http_request_new(uri);
	if (!g_str_has_suffix(uri, "/views/original/status")) {
		purple_http_request_set_url_printf(request, "%s%s", uri, "/views/original/status");
	}
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set_printf(request, "Cookie", "skypetoken_asm=%s", sa->skype_token);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request(sa->pc, request, teams_got_file_info, swft);
	purple_http_request_unref(request);
}

static void
got_file_send_progress(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsFileTransfer *swft = user_data;
	PurpleXfer *xfer = swft->xfer;
	TeamsAccount *sa = swft->sa;
	JsonObject *obj;
	const gchar *data;
	gsize len;
	
	data = purple_http_response_get_data(response, &len);
	obj = json_decode_object(data, len);
	if (obj == NULL) {
		return;
	}
	
	//{"content_length":0,"content_full_length":0,"view_length":0,"content_state":"no content","view_state":"none","view_location":"https://nus1-api.asm.skype.com/v1/objects/0-cus-d1-61121cfae8cf601944627a66afdb77ad/views/original","status_location":"https://nus1-api.asm.skype.com/v1/objects/0-cus-d1-61121cfae8cf601944627a66afdb77ad/views/original/status"}
	
	if (json_object_has_member(obj, "status_location")) {
		g_free(swft->url);
		swft->url = g_strdup(json_object_get_string_member(obj, "status_location"));
	}
	
	if (json_object_has_member(obj, "content_state") && purple_strequal(json_object_get_string_member(obj, "content_state"), "ready")) {
		PurpleXmlNode *uriobject = purple_xmlnode_new("URIObject");
		PurpleXmlNode *title = purple_xmlnode_new_child(uriobject, "Title");
		PurpleXmlNode *description = purple_xmlnode_new_child(uriobject, "Description");
		PurpleXmlNode *anchor = purple_xmlnode_new_child(uriobject, "a");
		PurpleXmlNode *originalname = purple_xmlnode_new_child(uriobject, "OriginalName");
		PurpleXmlNode *filesize = purple_xmlnode_new_child(uriobject, "FileSize");
		gchar *message, *temp;
		//We finally did it!
		// May the pesants rejoyce
		purple_xfer_set_completed(xfer, TRUE);
		
		// Don't forget to let the other end know about it
		
		purple_xmlnode_set_attrib(uriobject, "type", "File.1");
		temp = g_strconcat("https://" TEAMS_XFER_HOST "/v1/objects/", purple_url_encode(swft->id), NULL);
		purple_xmlnode_set_attrib(uriobject, "uri", temp);
		g_free(temp);
		temp = g_strconcat("https://" TEAMS_XFER_HOST "/v1/objects/", purple_url_encode(swft->id), "/views/thumbnail", NULL);
		purple_xmlnode_set_attrib(uriobject, "url_thumbnail", temp);
		g_free(temp);
		purple_xmlnode_insert_data(title, purple_xfer_get_filename(xfer), -1);
		purple_xmlnode_insert_data(description, "Description: ", -1);
		temp = g_strconcat("https://login.skype.com/login/sso?go=webclient.xmm&docid=", purple_url_encode(swft->id), NULL);
		purple_xmlnode_set_attrib(anchor, "href", temp);
		purple_xmlnode_insert_data(anchor, temp, -1);
		g_free(temp);
		purple_xmlnode_set_attrib(originalname, "v", purple_xfer_get_filename(xfer));
		temp = g_strdup_printf("%" G_GSIZE_FORMAT, (gsize) purple_xfer_get_size(xfer));
		purple_xmlnode_set_attrib(filesize, "v", temp);
		g_free(temp);
		
		temp = purple_xmlnode_to_str(uriobject, NULL);
		message = purple_strreplace(temp, "'", "\"");
		g_free(temp);
#if PURPLE_VERSION_CHECK(3, 0, 0)
		PurpleMessage *msg = purple_message_new_outgoing(swft->from, message, PURPLE_MESSAGE_SEND);
		teams_send_im(sa->pc, msg);
		purple_message_destroy(msg);
#else
		teams_send_im(sa->pc, swft->from, message, PURPLE_MESSAGE_SEND);
#endif
		g_free(message);
		
		teams_free_xfer(xfer);
		purple_xfer_unref(xfer);
		
		purple_xmlnode_free(uriobject);
	}
	
	json_object_unref(obj);
	
	// probably good
}

static gboolean
poll_file_send_progress(gpointer user_data)
{
	TeamsFileTransfer *swft = user_data;
	TeamsAccount *sa = swft->sa;
	PurpleHttpRequest *request;
	
	request = purple_http_request_new(swft->url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set_printf(request, "Cookie", "skypetoken_asm=%s", sa->skype_token);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request(sa->pc, request, got_file_send_progress, swft);
	purple_http_request_unref(request);
	
	return FALSE;
}

static void
teams_xfer_send_contents_reader(PurpleHttpConnection *con, gchar *buf, size_t offset, size_t len, gpointer user_data, PurpleHttpContentReaderCb cb)
{
	TeamsFileTransfer *swft = user_data;
	PurpleXfer *xfer = swft->xfer;
	gsize read;
	
	purple_debug_info("teams", "Asked %" G_GSIZE_FORMAT " bytes from offset %" G_GSIZE_FORMAT "\n", len, offset);
	purple_xfer_set_bytes_sent(xfer, offset);
	read = purple_xfer_read_file(xfer, (guchar *)buf, len);
	purple_debug_info("teams", "Read %" G_GSIZE_FORMAT " bytes\n", read);
	
	cb(con, TRUE, read != len, read);
}

static void
teams_xfer_send_done(PurpleHttpConnection *conn, PurpleHttpResponse *resp, gpointer user_data)
{
	gsize len;
	const gchar *data = purple_http_response_get_data(resp, &len);
	const gchar *error = purple_http_response_get_error(resp);
	int code = purple_http_response_get_code(resp);
	purple_debug_info("teams", "Finished [%d]: %s\n", code, error);
	purple_debug_info("teams", "Server message: %s\n", data);
	g_timeout_add_seconds(1, poll_file_send_progress, user_data);
}

static void
teams_xfer_send_watcher(PurpleHttpConnection *http_conn, gboolean state, int processed, int total, gpointer user_data)
{
	TeamsFileTransfer *swft = user_data;
	PurpleXfer *xfer = swft->xfer;
	if (!state) purple_xfer_update_progress(xfer);
}

static void
teams_xfer_send_begin(gpointer user_data)
{
	TeamsFileTransfer *swft = user_data;
	PurpleXfer *xfer = swft->xfer;
	TeamsAccount *sa = swft->sa;
	PurpleHttpConnection *http_conn;

	PurpleHttpRequest *request = purple_http_request_new("");
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_url_printf(request, "https://%s/v1/objects/%s/content/original", TEAMS_XFER_HOST, purple_url_encode(swft->id));
	purple_http_request_set_method(request, "PUT");
	purple_http_request_header_set(request, "Host", TEAMS_XFER_HOST);
	purple_http_request_header_set(request, "Content-Type", "multipart/form-data");
	purple_http_request_header_set_printf(request, "Content-Length", "%" G_GSIZE_FORMAT, (gsize) purple_xfer_get_size(xfer));
	purple_http_request_header_set_printf(request, "Authorization", "skype_token %s", sa->skype_token);
	purple_http_request_set_contents_reader(request, teams_xfer_send_contents_reader, purple_xfer_get_size(xfer), user_data);
	purple_http_request_set_http11(request, TRUE);
	purple_xfer_start(xfer, -1, NULL, 0);
	http_conn = purple_http_request(sa->pc, request, teams_xfer_send_done, user_data);
	purple_http_conn_set_progress_watcher(http_conn, teams_xfer_send_watcher, user_data, 1);

	purple_http_request_unref(request);
}

static void
teams_got_object_for_file(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsFileTransfer *swft = user_data;
	PurpleXfer *xfer = swft->xfer;
	JsonObject *obj;
	const gchar *data;
	gsize len;
	
	data = purple_http_response_get_data(response, &len);
	obj = json_decode_object(data, len);
	
	//Get back {"id": "0-cus-d3-deadbeefdeadbeef012345678"}
	if (obj == NULL || !json_object_has_member(obj, "id")) {
		g_free(swft->from);
		g_free(swft);
		purple_xfer_cancel_local(xfer);
		if (obj != NULL) {
			json_object_unref(obj);
		}
		return;
	}
	
	swft->id = g_strdup(json_object_get_string_member(obj, "id"));
	swft->url = g_strconcat("https://" TEAMS_XFER_HOST "/v1/objects/", purple_url_encode(swft->id), "/views/original/status", NULL);
	
	json_object_unref(obj);
	
	//Send the data
	
	//can't use fetch_url_request because it doesn't handle binary data
	teams_xfer_send_begin(user_data);
	
}

static void
teams_xfer_send_init(PurpleXfer *xfer)
{
	PurpleConnection *pc = purple_account_get_connection(purple_xfer_get_account(xfer));
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	gchar *basename = g_path_get_basename(purple_xfer_get_local_filename(xfer));
	gchar *id, *post;
	TeamsFileTransfer *swft = purple_xfer_get_protocol_data(xfer);
	JsonObject *obj = json_object_new();
	JsonObject *permissions = json_object_new();
	JsonArray *userpermissions = json_array_new();
	PurpleHttpRequest *request;
	
	purple_xfer_set_filename(xfer, basename);
	purple_xfer_ref(xfer);
	
	json_object_set_string_member(obj, "type", "sharing/file");
	json_object_set_string_member(obj, "filename", basename);
	
	id = g_strconcat(teams_user_url_prefix(swft->from), swft->from, NULL);
	json_array_add_string_element(userpermissions, "read");
	json_object_set_array_member(permissions, id, userpermissions);
	json_object_set_object_member(obj, "permissions", permissions);
	
	post = teams_jsonobj_to_string(obj);
	//POST to api.asm.skype.com  /v1/objects
	//{"type":"sharing/file","permissions":{"8:eionrobb":["read"]},"filename":"GiantLobsterMoose.txt"}
	
	request = purple_http_request_new("https://" TEAMS_XFER_HOST "/v1/objects");
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set_printf(request, "Authorization", "skype_token %s", sa->skype_token); //slightly different to normal!
	purple_http_request_header_set(request, "Content-Type", "application/json");
	purple_http_request_header_set(request, "X-Client-Version", TEAMS_CLIENTINFO_VERSION);
	purple_http_request_set_contents(request, post, -1);
	purple_http_request(sa->pc, request, teams_got_object_for_file, swft);
	purple_http_request_unref(request);
	
	g_free(post);
	json_object_unref(obj);
	g_free(id);
	g_free(basename);
}

PurpleXfer *
teams_new_xfer(
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleProtocolXfer *prplxfer, 
#endif
PurpleConnection *pc, const char *who)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	PurpleXfer *xfer;
	TeamsFileTransfer *swft;
	
	xfer = purple_xfer_new(sa->account, PURPLE_XFER_TYPE_SEND, who);
	
	swft = g_new0(TeamsFileTransfer, 1);
	swft->sa = sa;
	swft->from = g_strdup(who);
	swft->xfer = xfer;
	purple_xfer_set_protocol_data(xfer, swft);
	
	purple_xfer_set_init_fnc(xfer, teams_xfer_send_init);
	//purple_xfer_set_write_fnc(xfer, teams_xfer_send_write);
	//purple_xfer_set_end_fnc(xfer, teams_xfer_send_end);
	purple_xfer_set_request_denied_fnc(xfer, teams_free_xfer);
	purple_xfer_set_cancel_send_fnc(xfer, teams_free_xfer);
	
	return xfer;
}

void
teams_send_file(
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleProtocolXfer *prplxfer, 
#endif
PurpleConnection *pc, const gchar *who, const gchar *filename)
{
	PurpleXfer *xfer = teams_new_xfer(
#if PURPLE_VERSION_CHECK(3, 0, 0)
		prplxfer, 
#endif
		pc, who);
	
	if (filename && *filename)
		purple_xfer_request_accepted(xfer, filename);
	else
		purple_xfer_request(xfer);
}


void
teams_chat_send_file(PurpleConnection *pc, int id, const char *filename)
{
	//TODO
// 	PurpleConversation *conv = purple_find_chat(pc, id);
// 	PurpleXfer *xfer = teams_new_xfer(
// #if PURPLE_VERSION_CHECK(3, 0, 0)
// 		prplxfer, 
// #endif
// 		pc, who);
	
// 	if (filename && *filename)
// 		purple_xfer_request_accepted(xfer, filename);
// 	else
// 		purple_xfer_request(xfer);
}

gboolean
teams_can_receive_file(
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleProtocolXfer *prplxfer, 
#endif
PurpleConnection *pc, const gchar *who)
{
	if (!who || g_str_equal(who, purple_account_get_username(purple_connection_get_account(pc))))
		return FALSE;
	
	return TRUE;
}

gboolean
teams_chat_can_receive_file(PurpleConnection *pc, int id)
{
	// Probably?
	//return TRUE;
	// But not until we implement it!
	return FALSE;
}


static void
teams_got_self_details(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *userobj;
	const gchar *old_alias;
	const gchar *displayname = NULL;
	const gchar *username;
	
	if (node == NULL || json_node_get_node_type(node) != JSON_NODE_OBJECT)
		return;
	userobj = json_node_get_object(node);
	
	username = json_object_get_string_member(userobj, "skypeName");
	g_free(sa->username); sa->username = g_strdup(username);
	purple_connection_set_display_name(sa->pc, sa->username);
	
	old_alias = purple_account_get_private_alias(sa->account);
	if (!old_alias || !*old_alias) {
		JsonObject *userDetails = json_decode_object(json_object_get_string_member(userobj, "userDetails"), -1);
		
		if (json_object_has_member(userDetails, "name"))
			displayname = json_object_get_string_member(userDetails, "name");
		if (!displayname || purple_strequal(displayname, username))
			displayname = json_object_get_string_member(userDetails, "upn");
	
		if (displayname)
			purple_account_set_private_alias(sa->account, displayname);
		
		json_object_unref(userDetails);
	}
	
	if (json_object_has_member(userobj, "primaryMemberName")) {
		g_free(sa->primary_member_name);
		sa->primary_member_name = g_strdup(json_object_get_string_member(userobj, "primaryMemberName"));
	}
	
	if (!PURPLE_CONNECTION_IS_CONNECTED(sa->pc)) {
		teams_do_all_the_things(sa);
	}
}


void
teams_get_self_details(TeamsAccount *sa)
{
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_CONTACTS_HOST, "/v1/users/ME/properties", NULL, teams_got_self_details, NULL, TRUE);
}









void
teams_search_results_add_buddy(PurpleConnection *pc, GList *row, void *user_data)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	PurpleAccount *account = purple_connection_get_account(pc);
	PurpleGroup *group = teams_get_blist_group(sa);
	const gchar *mri = g_list_nth_data(row, 0);
	const gchar *displayName = g_list_nth_data(row, 1);
	
	mri = teams_strip_user_prefix(mri);

	if (!purple_blist_find_buddy(account, mri)) {
		purple_blist_request_add_buddy(account, mri, purple_group_get_name(group), displayName);
	}
}

void
teams_received_contacts(TeamsAccount *sa, PurpleXmlNode *contacts)
{
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;

	PurpleXmlNode *contact;
	
	results = purple_notify_searchresults_new();
	if (results == NULL) {
		return;
	}
		
	/* columns: Friend ID, Name */
	column = purple_notify_searchresults_column_new(_("Skype Name"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Display Name"));
	purple_notify_searchresults_column_add(results, column);

	
	purple_notify_searchresults_button_add(results,
			PURPLE_NOTIFY_BUTTON_ADD,
			teams_search_results_add_buddy);
	
	for(contact = purple_xmlnode_get_child(contacts, "c"); contact;
		contact = purple_xmlnode_get_next_twin(contact))
	{
		GList *row = NULL;

		gchar *contact_id = g_strdup(purple_xmlnode_get_attrib(contact, "s"));
		gchar *contact_name = g_strdup(purple_xmlnode_get_attrib(contact, "f"));

		row = g_list_append(row, contact_id);
		row = g_list_append(row, contact_name);

		purple_notify_searchresults_row_add(results, row);
	}
	
	purple_notify_searchresults(sa->pc, _("Received contacts"), NULL, NULL, results, NULL, NULL);
}

static PurpleNotifySearchResults*
create_search_results(JsonNode *node, gint *olength)
{
	PurpleNotifySearchColumn *column;
	gint index, length;
	JsonObject *response = NULL;
	JsonArray *resultsarray = NULL;
	
	response = json_node_get_object(node);
	resultsarray = json_object_get_array_member(response, "results");
	if (resultsarray == NULL) {
		resultsarray = json_object_get_array_member(response, "value");
	}
	if (resultsarray == NULL) {
		resultsarray = json_object_get_array_member(response, "values");
	}
	length = json_array_get_length(resultsarray);
	
	PurpleNotifySearchResults *results = purple_notify_searchresults_new();
	if (results == NULL || length == 0)
	{
		if (olength)
		{
			*olength = 0;
		}
		return NULL;
	}
	
	column = purple_notify_searchresults_column_new(_("ID"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Display Name"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Email"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Given Name"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Surname"));
	purple_notify_searchresults_column_add(results, column);
	
	purple_notify_searchresults_button_add(results,
			PURPLE_NOTIFY_BUTTON_ADD,
			teams_search_results_add_buddy);
	
	for(index = 0; index < length; index++)
	{
		JsonObject *result = json_array_get_object_element(resultsarray, index);
		JsonObject *contact = json_object_get_object_member(result, "nodeProfileData");
		if (contact == NULL) {
			contact = result;
		}
		
		/* the row in the search results table */
		/* prepend to it backwards then reverse to speed up adds */
		GList *row = NULL;

#define add_skypecontact_row(value) (\
		row = g_list_prepend(row, \
			!json_object_has_member(contact, (value)) ? NULL : \
			g_strdup(json_object_get_string_member(contact, (value)))\
		) \
)		
		add_skypecontact_row("mri");
		add_skypecontact_row("email");
		add_skypecontact_row("displayName");
		add_skypecontact_row("givenName");
		add_skypecontact_row("surname");
		
		row = g_list_reverse(row);
		
		purple_notify_searchresults_row_add(results, row);
	}
	
	if (olength)
	{
		*olength = length;
	}
	return results;
}

static void
teams_search_users_text_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	gint length;
	gchar *search_term = user_data;
	PurpleNotifySearchResults *results = create_search_results(node, &length);
	
	if (results == NULL || length == 0)
	{
		gchar *primary_text = g_strdup_printf(_("Your search for the user \"%s\" returned no results"), search_term);
		purple_notify_warning(sa->pc, _("No users found"), primary_text, "", purple_request_cpar_from_connection(sa->pc));
		g_free(primary_text);
		g_free(search_term);
		return;
	}
	
	purple_notify_searchresults(sa->pc, NULL, search_term, NULL, results, NULL, NULL);
}

void
teams_search_users_text(gpointer user_data, const gchar *text)
{
	TeamsAccount *sa = user_data;
	const gchar *url = TEAMS_PROFILES_PREFIX "users/searchV2?includeDLs=true&includeBots=true&enableGuest=true&source=newChat&skypeTeamsInfo=true";
	//https://teams.microsoft.com/api/mt/part/au-01/beta/users/emailaddressgoeshere@example.com/externalsearchv3?includeTFLUsers=true
	//https://substrate.office.com/search/api/v1/suggestions?scenario=peoplepicker.addToChat&setflight=ServeEdContactsFromEdShards

	//https://teams.live.com/api/mt/beta/users/searchUsers
	// {"emails":["emailaddressgoeshere@example.com"],"phones":[]}
	
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, text, teams_search_users_text_cb, g_strdup(text), TRUE);
	
}

void
teams_search_users(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	
	purple_request_input(pc, _("Search for Teams Contacts"),
					   _("Search for Teams Contacts"),
					   NULL,
					   NULL, FALSE, FALSE, NULL,
					   _("_Search"), G_CALLBACK(teams_search_users_text),
					   _("_Cancel"), NULL,
					   purple_request_cpar_from_connection(pc),
					   sa);

}

static void
teams_got_friend_profiles(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj;
	JsonArray *contacts;
	PurpleBuddy *buddy;
	TeamsBuddy *sbuddy;
	gint index, length;
	PurpleGroup *group = teams_get_blist_group(sa);
	
	if (node == NULL)
		return;
	obj = json_node_get_object(node);
	contacts = json_object_get_array_member(obj, "value");
	length = json_array_get_length(contacts);
	
	for(index = 0; index < length; index++)
	{
		JsonObject *contact = json_array_get_object_element(contacts, index);
		
		const gchar *mri = json_object_get_string_member(contact, "mri");
		const gchar *username = teams_strip_user_prefix(mri);
		const gchar *new_avatar;
		const gchar *displayName = json_object_get_string_member(contact, "displayName");
		const gchar *givenName = json_object_get_string_member(contact, "givenName");
		
		buddy = purple_blist_find_buddy(sa->account, username);
		if (!buddy)
		{
			buddy = purple_buddy_new(sa->account, username, NULL);
			purple_blist_add_buddy(buddy, NULL, group, NULL);
		}
		
		sbuddy = purple_buddy_get_protocol_data(buddy);
		if (sbuddy == NULL) {
			sbuddy = g_new0(TeamsBuddy, 1);
			purple_buddy_set_protocol_data(buddy, sbuddy);
			sbuddy->skypename = g_strdup(username);
			sbuddy->sa = sa;
		}
		
		g_free(sbuddy->display_name); 
		sbuddy->display_name = g_strdup(displayName);
		if (sbuddy->display_name && *sbuddy->display_name && !purple_strequal(purple_buddy_get_local_alias(buddy), sbuddy->display_name)) {
			purple_serv_got_alias(sa->pc, username, sbuddy->display_name);
		}
		
		if (!purple_strequal(json_object_get_string_member(contact, "email"), givenName)) {
			if (json_object_has_member(contact, "surname")) {
				gchar *fullname = g_strconcat(givenName, " ", json_object_get_string_member(contact, "surname"), NULL);
				
				if (fullname && *fullname) {
					purple_buddy_set_server_alias(buddy, fullname);
				}
				
				g_free(fullname);
			} else {
				if (givenName && *givenName) {
					purple_buddy_set_server_alias(buddy, givenName);
				}
			}
		}
		
		// Only bots have images
		new_avatar = json_object_get_string_member(contact, "imageUri");
		if (new_avatar && *new_avatar && (!sbuddy->avatar_url || !g_str_equal(sbuddy->avatar_url, new_avatar))) {
			g_free(sbuddy->avatar_url);
			sbuddy->avatar_url = g_strdup(new_avatar);
		}
		teams_get_icon(buddy);
	}
}

void
teams_get_friend_profiles(TeamsAccount *sa, GSList *contacts)
{
	//TODO users/fetch?isMailAddress=false&skypeTeamsInfo=true&includeIBBarredUsers=true
	const gchar *profiles_url = TEAMS_PROFILES_PREFIX "users/fetchShortProfile?isMailAddress=false&canBeSmtpAddress=false&enableGuest=true&includeIBBarredUsers=true&skypeTeamsInfo=true&includeBots=true";
	const gchar *federated_profiles_url = TEAMS_PROFILES_PREFIX "users/fetchFederated";
	GString *postdata;
	GSList *cur = contacts;
	const gchar *user_prefix;
	
	if (contacts == NULL)
		return;
	
	postdata = g_string_new("[\"\"");
	
	do {
		user_prefix = teams_user_url_prefix(cur->data);
		if (g_str_equal(user_prefix, "8:") && strncmp(cur->data, "orgid:", 6) != 0) continue;
		g_string_append_printf(postdata, ",\"%s%s\"", user_prefix, (gchar *) cur->data);
	} while((cur = g_slist_next(cur)));
	
	g_string_append(postdata, "]");
	
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, profiles_url, postdata->str, teams_got_friend_profiles, NULL, TRUE);
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, federated_profiles_url, postdata->str, teams_got_friend_profiles, NULL, TRUE);
	
	g_string_free(postdata, TRUE);
}


static void
teams_got_info(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	gchar *username = user_data;
	PurpleNotifyUserInfo *user_info;
	JsonObject *userobj;
	PurpleBuddy *buddy;
	
	if (node == NULL)
		return;
	if (json_node_get_node_type(node) == JSON_NODE_ARRAY)
		node = json_array_get_element(json_node_get_array(node), 0);
	if (json_node_get_node_type(node) != JSON_NODE_OBJECT)
		return;
	userobj = json_node_get_object(node);
	if (json_object_has_member(userobj, "value")) {
		node = json_object_get_member(userobj, "value");
		
		if (json_node_get_node_type(node) == JSON_NODE_ARRAY)
			node = json_array_get_element(json_node_get_array(node), 0);
		userobj = json_node_get_object(node);
	}
	
	if (!json_object_has_member(userobj, "mri")) {
		return;
	}
	
	if (!username || !*username) {
		const gchar *mri = json_object_get_string_member(userobj, "mri");
		g_free(username);
		username = g_strdup(teams_strip_user_prefix(mri));
	}
	if (!username || !*username) {
		g_free(username);
		return;
	}
	
	user_info = purple_notify_user_info_new();
	
#define _SKYPE_USER_INFO(prop, key) if (prop && json_object_has_member(userobj, (prop)) && !json_object_get_null_member(userobj, (prop))) \
	purple_notify_user_info_add_pair_html(user_info, _(key), json_object_get_string_member(userobj, (prop)));
	
	_SKYPE_USER_INFO("givenName", "First Name");
	_SKYPE_USER_INFO("surname", "Last Name");
	_SKYPE_USER_INFO("email", "Email");
	_SKYPE_USER_INFO("tenantName", "Tenant");
	_SKYPE_USER_INFO("displayName", "Display Name");
	_SKYPE_USER_INFO("type", "User Type");
	
	buddy = purple_blist_find_buddy(sa->account, username);
	if (buddy) {
		const gchar *firstname = json_object_get_string_member(userobj, "givenName");
		const gchar *surname = json_object_get_string_member(userobj, "surname");
		const gchar *display_name = json_object_get_string_member(userobj, "displayName");
		TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
		
		if (sbuddy == NULL) {
			
			sbuddy = g_new0(TeamsBuddy, 1);
			sbuddy->skypename = g_strdup(username);
			sbuddy->sa = sa;
			sbuddy->fullname = g_strconcat(firstname, (surname ? " " : NULL), surname, NULL);
			sbuddy->display_name = g_strdup(display_name);
			
			sbuddy->buddy = buddy;
			purple_buddy_set_protocol_data(buddy, sbuddy);
			
		} else {
			sbuddy->fullname = g_strconcat(firstname, (surname ? " " : NULL), surname, NULL);
			sbuddy->display_name = g_strdup(display_name);
		}
		
		if (sbuddy->display_name && *sbuddy->display_name && !purple_strequal(purple_buddy_get_local_alias(buddy), sbuddy->display_name)) {
			purple_serv_got_alias(sa->pc, username, sbuddy->display_name);
		}
		if (sbuddy->fullname && *sbuddy->fullname && !purple_strequal(purple_buddy_get_server_alias(buddy), sbuddy->fullname)) {
			purple_buddy_set_server_alias(buddy, sbuddy->fullname);
		}
	}
	
	purple_notify_userinfo(sa->pc, username, user_info, NULL, NULL);
	
	g_free(username);
}

void
teams_get_info(PurpleConnection *pc, const gchar *username)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	gchar *url = NULL;
	gchar *postdata;
	
	url = g_strconcat(TEAMS_PROFILES_PREFIX, "users/", teams_user_url_prefix(username), purple_url_encode(username), "/?throwIfNotFound=false&isMailAddress=false&enableGuest=true&includeIBBarredUsers=true&skypeTeamsInfo=true&includeBots=true", NULL);
	
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, NULL, teams_got_info, g_strdup(username), TRUE);
	
	g_free(url);
	
	// just in case they're a user on a different tenant:
	
	if (strncmp(username, "orgid:", 6) != 0) {
		return;
	}
	
	url = TEAMS_PROFILES_PREFIX "users/fetchFederated";
	
	postdata = g_strconcat("[\"", teams_user_url_prefix(username), username, "\"]", NULL);
	
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, postdata, teams_got_info, g_strdup(username), TRUE);
	
	//TODO users/fetch?isMailAddress=false&skypeTeamsInfo=true&includeIBBarredUsers=true

	g_free(postdata);

	//TODO deleted users
	//https://aus.loki.delve.office.com/api/v3/personacards?viewType=Card&personaType=User&ConvertGetPost=true&teamsMri=8%3Aorgid%3A...
	// {
	// 	"Card": {
	// 		"headerInfo": {
	// 		"attributedUserHeaderInfo": {
	// 			"displayName": {
	// 				"value": "... Deleted User Name ...",
	// 				"source": "Directory"
	// 			},
	// 		}
	// 	}
	// }
}

void
teams_get_friend_profile(TeamsAccount *sa, const gchar *who)
{
	GSList *contacts = NULL;
	gchar *whodup;
	
	g_return_if_fail(sa && who && *who);
	
	whodup = g_strdup(who);
	contacts = g_slist_prepend(contacts, whodup);
	
	teams_get_friend_profiles(sa, contacts);
	
	g_free(contacts);
	g_free(whodup);
}

PurpleChat *
teams_find_chat_from_node(const PurpleAccount *account, const char *id, PurpleBlistNode *root)
{
	PurpleBlistNode *node;

	for (
		node = root;
		node != NULL;
		node = purple_blist_node_next(node, TRUE)
	) {
		if (PURPLE_IS_CHAT(node)) {
			PurpleChat *chat = PURPLE_CHAT(node);

			if (purple_chat_get_account(chat) != account) {
				continue;
			}

			GHashTable *components = purple_chat_get_components(chat);
			const gchar *chat_id = g_hash_table_lookup(components, "chatname");

			if (purple_strequal(chat_id, id)) {
				return chat;
			}
		}
	}

	return NULL;
}

PurpleChat *
teams_find_chat(PurpleAccount *account, const char *id)
{
	return teams_find_chat_from_node(account, id, purple_blist_get_root());
}


PurpleChat *
teams_find_chat_in_group(PurpleAccount *account, const char *id, PurpleGroup *group)
{
	g_return_val_if_fail(group != NULL, NULL);

	return teams_find_chat_from_node(account, id, PURPLE_BLIST_NODE(group));
}

static void
teams_get_friend_list_teams_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj;
	JsonArray *teams, *chats, *users;
	guint index, length;
	PurpleGroup *group = teams_get_blist_group(sa);
	GSList *users_to_fetch = NULL;
	PurpleBuddy *buddy;
	
	obj = json_node_get_object(node);
	
	// Group chats
	chats = json_object_get_array_member(obj, "chats");
	length = json_array_get_length(chats);
	for(index = 0; index < length; index++)
	{
		JsonObject *chat = json_array_get_object_element(chats, index);
		const gchar *id = json_object_get_string_member(chat, "id");
		gboolean is_one_on_one = json_object_get_boolean_member(chat, "isOneOnOne");
		
		if (is_one_on_one) {
			JsonArray *members = json_object_get_array_member(chat, "members");
			JsonObject *member = json_array_get_object_element(members, 0);
			const gchar *mri = json_object_get_string_member(member, "mri");
			const gchar *buddyid = teams_strip_user_prefix(mri);
			
			if (teams_is_user_self(sa, buddyid)) {
				// There were two in the bed and the little one said....
				member = json_array_get_object_element(members, 1);
				if (member == NULL) {
					// ... goodnight!
					continue;
				}
				mri = json_object_get_string_member(member, "mri");
				buddyid = teams_strip_user_prefix(mri);
			}
			
			users_to_fetch = g_slist_prepend(users_to_fetch, g_strdup(buddyid));
			
			//Create an array of one to one mappings for IMs
			g_hash_table_insert(sa->buddy_to_chat_lookup, g_strdup(buddyid), g_strdup(id));
			g_hash_table_insert(sa->chat_to_buddy_lookup, g_strdup(id), g_strdup(buddyid));
			
			buddy = purple_blist_find_buddy(sa->account, buddyid);
			if (!buddy)
			{
				buddy = purple_buddy_new(sa->account, buddyid, NULL);
				purple_blist_add_buddy(buddy, NULL, group, NULL);
			}
			
		} else {
			const gchar *title = json_object_get_string_member(chat, "title");
			PurpleChat *purple_chat = teams_find_chat(sa->account, id);
			
			if (purple_chat == NULL) {
				GHashTable *components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
				g_hash_table_replace(components, g_strdup("chatname"), g_strdup(id));
				
				purple_chat = purple_chat_new(sa->account, title, components);
				purple_blist_add_chat(purple_chat, group, NULL);
				
			} else {
				purple_chat_set_alias(purple_chat, title);
				
			}
			
			JsonArray *members = json_object_get_array_member(chat, "members");
			guint members_index, members_length = json_array_get_length(members);
			
			for(members_index = 0; members_index < members_length; members_index++)
			{
				JsonObject *member = json_array_get_object_element(members, members_index);
				const gchar *mri = json_object_get_string_member(member, "mri");
				const gchar *buddyid = teams_strip_user_prefix(mri);
				
				users_to_fetch = g_slist_prepend(users_to_fetch, g_strdup(buddyid));
			}
		}
	}
	
	// Teams
	teams = json_object_get_array_member(obj, "teams");
	// TODO treat as a group with channels within?
	(void) teams;
	
	// Users
	users = json_object_get_array_member(obj, "users");
	(void) users;
	
	if (users_to_fetch)
	{
		teams_get_friend_profiles(sa, users_to_fetch);
		teams_subscribe_to_contact_status(sa, users_to_fetch);
		g_slist_free_full(users_to_fetch, g_free);
	}
}

static void
teams_get_friend_suggestions_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj, *firstgroup;
	JsonArray *groups, *suggestions;
	PurpleGroup *group = teams_get_blist_group(sa);
	GSList *users_to_fetch = NULL;
	guint index, length;
	
	obj = json_node_get_object(node);
	groups = json_object_get_array_member(obj, "Groups");
	firstgroup = json_array_get_object_element(groups, 0);
	suggestions = json_object_get_array_member(firstgroup, "Suggestions");
	length = json_array_get_length(suggestions);
	
	for(index = 0; index < length; index++)
	{
		JsonObject *contact = json_array_get_object_element(suggestions, index);
		const gchar *mri = json_object_get_string_member(contact, "MRI");
		const gchar *display_name = json_object_get_string_member(contact, "DisplayName");
		const gchar *firstname = json_object_get_string_member(contact, "GivenName");
		const gchar *surname = json_object_get_string_member(contact, "Surname");
		
		PurpleBuddy *buddy;
		const gchar *id;
		
		id = teams_strip_user_prefix(mri);
		
		buddy = purple_blist_find_buddy(sa->account, id);
		if (!buddy)
		{
			buddy = purple_buddy_new(sa->account, id, display_name);
			purple_blist_add_buddy(buddy, NULL, group, NULL);
		}

		TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
		if (sbuddy == NULL) {
			sbuddy = g_new0(TeamsBuddy, 1);
			sbuddy->skypename = g_strdup(id);
			sbuddy->sa = sa;
			
			sbuddy->buddy = buddy;
			purple_buddy_set_protocol_data(buddy, sbuddy);
		}

		g_free(sbuddy->fullname);
		sbuddy->fullname = g_strconcat(firstname, (surname ? " " : NULL), surname, NULL);
		g_free(sbuddy->display_name);
		sbuddy->display_name = g_strdup(display_name);
		
		if (sbuddy->display_name && *sbuddy->display_name && !purple_strequal(purple_buddy_get_local_alias(buddy), sbuddy->display_name)) {
			purple_serv_got_alias(sa->pc, id, sbuddy->display_name);
		}
		if (sbuddy->fullname && *sbuddy->fullname && !purple_strequal(purple_buddy_get_server_alias(buddy), sbuddy->fullname)) {
			purple_buddy_set_server_alias(buddy, sbuddy->fullname);
		}
		
		teams_get_icon(buddy);
		users_to_fetch = g_slist_prepend(users_to_fetch, sbuddy->skypename);
		
		if (purple_strequal(id, sa->primary_member_name)) {
			g_free(sa->self_display_name);
			sa->self_display_name = g_strdup(display_name);
		}
	}
	
	if (users_to_fetch)
	{
		teams_get_friend_profiles(sa, users_to_fetch);
		teams_subscribe_to_contact_status(sa, users_to_fetch);
		g_slist_free(users_to_fetch);
	}
}

static void
teams_get_workingwith_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj;
	JsonArray *contacts;
	PurpleGroup *group = teams_get_blist_group(sa);
	GSList *users_to_fetch = NULL;
	guint index, length;
	
	obj = json_node_get_object(node);
	contacts = json_object_get_array_member(obj, "value");
	length = json_array_get_length(contacts);
	
	for(index = 0; index < length; index++)
	{
		JsonObject *contact = json_array_get_object_element(contacts, index);
		const gchar *aadObjectId = json_object_get_string_member(contact, "aadObjectId");
		const gchar *full_name = json_object_get_string_member(contact, "fullName");
		
		PurpleBuddy *buddy;
		gchar *id;
		
		id = g_strconcat("orgid:", aadObjectId, NULL);
		
		buddy = purple_blist_find_buddy(sa->account, id);
		if (!buddy)
		{
			buddy = purple_buddy_new(sa->account, id, full_name);
			purple_blist_add_buddy(buddy, NULL, group, NULL);
		}
		
		TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
		if (sbuddy == NULL) {
			sbuddy = g_new0(TeamsBuddy, 1);
			sbuddy->skypename = g_strdup(id);
			sbuddy->sa = sa;
			
			sbuddy->buddy = buddy;
			purple_buddy_set_protocol_data(buddy, sbuddy);
		}
		
		if(full_name && *full_name && !purple_strequal(sbuddy->fullname, full_name)) {
			sbuddy->fullname = g_strdup(full_name);
			if (!purple_strequal(purple_buddy_get_server_alias(buddy), sbuddy->fullname)) {
				purple_buddy_set_server_alias(buddy, sbuddy->fullname);
			}
		}

		g_free(id);
		
		teams_get_icon(buddy);
		users_to_fetch = g_slist_prepend(users_to_fetch, sbuddy->skypename);
	}
	
	if (users_to_fetch)
	{
		teams_get_friend_profiles(sa, users_to_fetch);
		teams_subscribe_to_contact_status(sa, users_to_fetch);
		g_slist_free(users_to_fetch);
	}

}

static void
teams_get_friend_list_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj;
	JsonArray *contacts;
	PurpleGroup *group = teams_get_blist_group(sa);
	GSList *users_to_fetch = NULL;
	guint index, length;
	
	obj = json_node_get_object(node);
	contacts = json_object_get_array_member(obj, "value");
	length = json_array_get_length(contacts);
	
	for(index = 0; index < length; index++)
	{
		JsonObject *contact = json_array_get_object_element(contacts, index);
		const gchar *type = json_object_get_string_member(contact, "type");
		
		if (purple_strequal(type, "Group")) {
			continue;
		}
		
		const gchar *mri = json_object_get_string_member(contact, "mri");
		const gchar *display_name = json_object_get_string_member(contact, "displayName");
		// const gchar *avatar_url = NULL;
		// gboolean authorized = json_object_get_boolean_member(contact, "authorized");
		// gboolean blocked = json_object_get_boolean_member(contact, "blocked");
		
		// const gchar *mood = json_object_get_string_member(profile, "mood");
		// JsonObject *name = json_object_get_object_member(profile, "name");
		const gchar *firstname = json_object_get_string_member(contact, "givenName");
		const gchar *surname = json_object_get_string_member(contact, "surname");
		
		PurpleBuddy *buddy;
		const gchar *id;
		
		id = teams_strip_user_prefix(mri);
		
		buddy = purple_blist_find_buddy(sa->account, id);
		if (!buddy)
		{
			buddy = purple_buddy_new(sa->account, id, display_name);
			purple_blist_add_buddy(buddy, NULL, group, NULL);
		}

		TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
		if (sbuddy == NULL) {
			sbuddy = g_new0(TeamsBuddy, 1);
			sbuddy->skypename = g_strdup(id);
			sbuddy->sa = sa;
			
			sbuddy->buddy = buddy;
			purple_buddy_set_protocol_data(buddy, sbuddy);
		}
		
		g_free(sbuddy->fullname);
		sbuddy->fullname = g_strconcat(firstname, (surname ? " " : NULL), surname, NULL);
		g_free(sbuddy->display_name);
		sbuddy->display_name = g_strdup(display_name);
		
		if (sbuddy->display_name && *sbuddy->display_name && !purple_strequal(purple_buddy_get_local_alias(buddy), sbuddy->display_name)) {
			purple_serv_got_alias(sa->pc, id, sbuddy->display_name);
		}
		if (sbuddy->fullname && *sbuddy->fullname && !purple_strequal(purple_buddy_get_server_alias(buddy), sbuddy->fullname)) {
			purple_buddy_set_server_alias(buddy, sbuddy->fullname);
		}
		
		// if (json_object_has_member(profile, "avatar_url")) {
			// avatar_url = json_object_get_string_member(profile, "avatar_url");
			// if (avatar_url && *avatar_url && (!sbuddy->avatar_url || !g_str_equal(sbuddy->avatar_url, avatar_url))) {
				// g_free(sbuddy->avatar_url);
				// sbuddy->avatar_url = g_strdup(avatar_url);			
				// teams_get_icon(buddy);
			// }
		// }
		teams_get_icon(buddy);
		
		// if (blocked == TRUE) {
			// purple_account_privacy_deny_add(sa->account, id, TRUE);
		// } else {
			users_to_fetch = g_slist_prepend(users_to_fetch, sbuddy->skypename);
		// }
		
		if (purple_strequal(id, sa->primary_member_name)) {
			g_free(sa->self_display_name);
			sa->self_display_name = g_strdup(display_name);
		}
	}
	
	if (users_to_fetch)
	{
		teams_get_friend_profiles(sa, users_to_fetch);
		teams_subscribe_to_contact_status(sa, users_to_fetch);
		g_slist_free(users_to_fetch);
	}
}

static void
teams_get_buddylist_cb(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj;
	JsonArray *values;
	PurpleGroup *group = teams_get_blist_group(sa);
	GSList *users_to_fetch = NULL;
	guint index, length;
	
	obj = json_node_get_object(node);
	values = json_object_get_array_member(obj, "value");
	length = json_array_get_length(values);
	
	for(index = 0; index < length; index++)
	{
		JsonObject *buddygroup = json_array_get_object_element(values, index);
		//TODO  groupType, displayName
		JsonArray *buddies = json_object_get_array_member(buddygroup, "buddies");
		guint buddy_index, buddy_length = json_array_get_length(buddies);

		for(buddy_index = 0; buddy_index < buddy_length; buddy_index++)
		{
			JsonObject *contact = json_array_get_object_element(buddies, buddy_index);
			const gchar *mri = json_object_get_string_member(contact, "mri");
			const gchar *display_name = json_object_get_string_member(contact, "displayName");
		
			PurpleBuddy *buddy;
			const gchar *id;
		
			id = teams_strip_user_prefix(mri);
			
			buddy = purple_blist_find_buddy(sa->account, id);
			if (!buddy)
			{
				buddy = purple_buddy_new(sa->account, id, display_name);
				purple_blist_add_buddy(buddy, NULL, group, NULL);
			}

			TeamsBuddy *sbuddy = purple_buddy_get_protocol_data(buddy);
			if (sbuddy == NULL) {
				sbuddy = g_new0(TeamsBuddy, 1);
				sbuddy->skypename = g_strdup(id);
				sbuddy->sa = sa;
				
				sbuddy->buddy = buddy;
				purple_buddy_set_protocol_data(buddy, sbuddy);
			}
		
			if (display_name && *display_name) {
				g_free(sbuddy->display_name);
				sbuddy->display_name = g_strdup(display_name);
				
				if (!purple_strequal(purple_buddy_get_local_alias(buddy), sbuddy->display_name)) {
					purple_serv_got_alias(sa->pc, id, sbuddy->display_name);
				}
			}

			teams_get_icon(buddy);
			
			// if (blocked == TRUE) {
				// purple_account_privacy_deny_add(sa->account, id, TRUE);
			// } else {
				users_to_fetch = g_slist_prepend(users_to_fetch, sbuddy->skypename);
			// }
			
			if (purple_strequal(id, sa->primary_member_name)) {
				g_free(sa->self_display_name);
				sa->self_display_name = g_strdup(display_name);
			}
		}
	}
		
	if (users_to_fetch)
	{
		teams_get_friend_profiles(sa, users_to_fetch);
		teams_subscribe_to_contact_status(sa, users_to_fetch);
		g_slist_free(users_to_fetch);
	}
}



gboolean
teams_get_friend_list(TeamsAccount *sa)
{
	PurpleConnection *pc = sa->pc;
	if (!PURPLE_IS_CONNECTION(pc)) {
		return FALSE;
	}

	const gchar *url = TEAMS_PROFILES_PREFIX "users/searchV2?includeDLs=true&includeBots=true&enableGuest=true&source=newChat&skypeTeamsInfo=true";
	
	//TODO
	// get tenants: https://teams.microsoft.com/api/mt/apac/beta/users/tenants or https://teams.microsoft.com/api/mt/part/au-01/beta/users/tenantsv2
	// https://teams.microsoft.com/api/mt/part/au-01/beta/contactsv3/?pageSize=500
	
	// Do a search for all users with . in their email addresses - doesn't work for Guests
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, ".", teams_get_friend_list_cb, NULL, TRUE);
	
	// Fetch a list of teams and chats we're part of - doesn't include users for Guests
	url = "/api/csa/api/v1/teams/users/me?isPrefetch=false&enableMembershipSummary=true";
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, NULL, teams_get_friend_list_teams_cb, NULL, TRUE);
	
	// Search all of office for suggestions
	// needs auth with scope of https://substrate.office.com
	url = "/search/api/v1/suggestions?scenario=";
	const gchar *postdata = "{\"EntityRequests\":[{\"EntityType\":\"People\",\"Fields\":[\"DisplayName\",\"MRI\",\"GivenName\",\"Surname\"],\"Query\":{\"QueryString\":\"\",\"DisplayQueryString\":\"\"},\"Provenances\":[\"Mailbox\",\"Directory\"],\"Filter\":{\"And\":[{\"Or\":[{\"Term\":{\"PeopleType\":\"Person\"}},{\"Term\":{\"PeopleType\":\"Other\"}}]},{\"Or\":[{\"Term\":{\"PeopleSubtype\":\"OrganizationUser\"}},{\"Term\":{\"PeopleSubtype\":\"Guest\"}}]}]},\"Size\":500,\"From\":0}],\"Cvid\":\"12345678-1234-4321-1234-123412341234\",\"AppName\":\"Microsoft Teams\",\"Scenario\":{\"Name\":\"peoplecache\"}}";
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, "substrate.office.com", url, postdata, teams_get_friend_suggestions_cb, NULL, TRUE);

	// Search org chart for people you work with
	gchar *search_url = g_strconcat("/api/v1/workingwith?teamsMri=", purple_url_encode(sa->primary_member_name), "&personaType=User&limit=50", NULL);
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, "aus.loki.delve.office.com", search_url, NULL, teams_get_workingwith_cb, NULL, TRUE);
	g_free(search_url);

	// Teams personal has a buddy list?!@
	url = "/api/mt/beta/contacts/buddylist?migrationRequested=true&federatedContactsSupported=true";
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, NULL, teams_get_buddylist_cb, NULL, TRUE);

	if (purple_account_get_bool(sa->account, "only_use_websocket", FALSE)) {
		return FALSE;
	}
	return TRUE;
}

typedef struct {
	TeamsAccount *sa;
	gchar *chatname;
	gchar *teams_join_link;
	gchar *subject;
} TeamsCalendarNotificationData;

gboolean
teams_calendar_timer_cb(gpointer user_data)
{
	TeamsCalendarNotificationData *data = user_data;
	TeamsAccount *sa = data->sa;
	PurpleConnection *pc = sa->pc;

	if (PURPLE_IS_CONNECTION(pc)) {
		gchar *chatname = data->chatname;
		PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(chatname, sa->account);
		if (!chatconv) {
			chatconv = purple_serv_got_joined_chat(pc, g_str_hash(chatname), chatname);
			purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "chatname", g_strdup(chatname));

			if (data->subject && *data->subject) {
				purple_chat_conversation_set_topic(chatconv, NULL, data->subject);
			}
			
			teams_get_conversation_history(sa, chatname);
			teams_get_thread_users(sa, chatname);
		}

		gchar *html = g_strdup_printf("%s <a href=\"%s\">%s</a>", _("Reminder: You have a Teams meeting starting soon"), data->teams_join_link, _("Join Teams Meeting"));
		purple_conversation_write_system_message(PURPLE_CONVERSATION(chatconv), html, PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_NOTIFY | PURPLE_MESSAGE_RECV);
		g_free(html);
	}
	
	g_free(data->subject);
	g_free(data->chatname);
	g_free(data->teams_join_link);
	g_free(data);
	return FALSE;
}

static void
teams_got_calendar(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *obj;
	JsonArray *events;
	guint index, length;
	
	if (node == NULL)
		return;
	obj = json_node_get_object(node);
	events = json_object_get_array_member(obj, "value");
	length = json_array_get_length(events);
	
	gint calendar_notify_minutes = purple_account_get_int(sa->account, "calendar_notify_minutes", 0);
	gint calendar_notify_seconds = calendar_notify_minutes * 60;
	
	for(index = 0; index < length; index++)
	{
		JsonObject *event = json_array_get_object_element(events, index);
		gboolean isOnlineMeeting = json_object_get_boolean_member(event, "isOnlineMeeting");

		if (!isOnlineMeeting) {
			continue;
		}

		const gchar *iCalUID = json_object_get_string_member(event, "iCalUID");
		if (g_hash_table_contains(sa->calendar_reminder_timeouts, iCalUID)) {
			continue;
		}
		
		const gchar *skypeTeamsMeetingUrl = json_object_get_string_member(event, "skypeTeamsMeetingUrl");
		JsonObject *skypeTeamsDataObject = json_object_get_object_member(event, "skypeTeamsDataObject");
		const gchar *chatname = json_object_get_string_member(skypeTeamsDataObject, "cid");
		const gchar *subject = json_object_get_string_member(event, "subject");
		const gchar *startTime = json_object_get_string_member(event, "startTime");
		time_t event_timestamp = purple_str_to_time(startTime, TRUE, NULL, NULL, NULL);
		gint seconds_until_event = event_timestamp - time(NULL);

		purple_debug_info("teams", "Teams meeting %s for chat %s starting at %s\n", subject && *subject ? subject : "", chatname, startTime);

		if (seconds_until_event <= calendar_notify_seconds) {
			continue;
		}

		TeamsCalendarNotificationData *data = g_new0(TeamsCalendarNotificationData, 1);
		data->sa = sa;
		data->chatname = g_strdup(chatname);
		data->subject = g_strdup(subject);
		data->teams_join_link = g_strdup(skypeTeamsMeetingUrl);
		
		// Set a timer to go off at X minutes before the start time to write a message to the conversation
		guint timer = purple_timeout_add_seconds(seconds_until_event - calendar_notify_seconds, teams_calendar_timer_cb, data);
		g_hash_table_insert(sa->calendar_reminder_timeouts, g_strdup(iCalUID), GUINT_TO_POINTER(timer));
	}
}


gboolean
teams_check_calendar(TeamsAccount *sa)
{
	PurpleConnection *pc = sa->pc;
	if (!PURPLE_IS_CONNECTION(pc)) {
		return FALSE;
	}

	gint calendar_notify_minutes = purple_account_get_int(sa->account, "calendar_notify_minutes", 0);
	if (calendar_notify_minutes > 0) {
		struct tm *tm;
		time_t start_time = time(NULL);
		tm = localtime(&start_time);
		gchar *start_date = g_strdup(purple_url_encode(purple_utf8_strftime("%Y-%m-%dT%H:%M:%S%z", tm)));

		time_t end_time = time(NULL) + TEAMS_CALENDAR_REFRESH_MINUTES * 60;
		tm = localtime(&end_time);
		gchar *end_date = g_strdup(purple_url_encode(purple_utf8_strftime("%Y-%m-%dT%H:%M:%S%z", tm)));
		
		gchar *url = g_strconcat("/api/mt/part/au-01/v2.0/me/calendars/default/calendarView?StartDate=", start_date, "&EndDate=", end_date, "&shouldDecryptData=true", NULL);

		teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, NULL, teams_got_calendar, NULL, TRUE);

		g_free(start_date);
		g_free(end_date);
		g_free(url);
	}
	return TRUE;
}



void
teams_auth_accept_cb(
#if PURPLE_VERSION_CHECK(3, 0, 0)
	const gchar *who,
#endif
	gpointer sender)
{
	PurpleBuddy *buddy = sender;
	TeamsAccount *sa;
	gchar *url = NULL;
	GSList *users_to_fetch;
	gchar *buddy_name;
	
	sa = purple_connection_get_protocol_data(purple_account_get_connection(purple_buddy_get_account(buddy)));
	buddy_name = g_strdup(purple_buddy_get_name(buddy));
	
	url = g_strdup_printf("/contacts/v2/users/SELF/invites/%s%s/accept", teams_user_url_prefix(buddy_name), purple_url_encode(buddy_name));
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_NEW_CONTACTS_HOST, url, NULL, NULL, NULL, TRUE);
	g_free(url);
	
	// Subscribe to status/message updates
	users_to_fetch = g_slist_prepend(NULL, buddy_name);
	teams_subscribe_to_contact_status(sa, users_to_fetch);
	g_slist_free(users_to_fetch);
	g_free(buddy_name);
}

void
teams_auth_reject_cb(
#if PURPLE_VERSION_CHECK(3, 0, 0)
	const gchar *who,
#endif
	gpointer sender)
{
	PurpleBuddy *buddy = sender;
	TeamsAccount *sa;
	gchar *url = NULL;
	gchar *buddy_name;
	
	sa = purple_connection_get_protocol_data(purple_account_get_connection(purple_buddy_get_account(buddy)));
	buddy_name = g_strdup(purple_buddy_get_name(buddy));
	
	url = g_strdup_printf("/contacts/v2/users/SELF/invites/%s%s/decline", teams_user_url_prefix(buddy_name), purple_url_encode(buddy_name));
	
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_NEW_CONTACTS_HOST, url, NULL, NULL, NULL, TRUE);
	
	g_free(url);
	g_free(buddy_name);
}

static void
teams_got_authrequests(TeamsAccount *sa, JsonNode *node, gpointer user_data)
{
	JsonObject *requests;
	JsonArray *invite_list;
	guint index, length;
	time_t latest_timestamp = 0;
	
	requests = json_node_get_object(node);
	invite_list = json_object_get_array_member(requests, "invite_list");
	length = json_array_get_length(invite_list);
	for(index = 0; index < length; index++)
	{
		JsonObject *invite = json_array_get_object_element(invite_list, index);
		JsonArray *invites = json_object_get_array_member(invite, "invites");
		const gchar *event_time_iso = json_object_get_string_member(json_array_get_object_element(invites, 0), "time");
		time_t event_timestamp = purple_str_to_time(event_time_iso, TRUE, NULL, NULL, NULL);
		const gchar *sender = json_object_get_string_member(invite, "mri");
		const gchar *greeting = json_object_get_string_member(invite, "greeting");
		if (!greeting)
			greeting = json_object_get_string_member(json_array_get_object_element(invites, 0), "message");
		const gchar *displayname = json_object_get_string_member(invite, "displayname");
		
		latest_timestamp = MAX(latest_timestamp, event_timestamp);
		if (sa->last_authrequest && latest_timestamp <= sa->last_authrequest)
			continue;
		
		if (sender == NULL)
			continue;
		sender = teams_strip_user_prefix(sender);
		
		purple_account_request_authorization(
				sa->account, sender, NULL,
				displayname, greeting, FALSE,
				teams_auth_accept_cb, teams_auth_reject_cb, purple_buddy_new(sa->account, sender, displayname));
		
	}
	
	sa->last_authrequest = latest_timestamp;
}

gboolean
teams_check_authrequests(TeamsAccount *sa)
{
	//TODO
	return FALSE;
	
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_NEW_CONTACTS_HOST, "/contacts/v2/users/SELF/invites", NULL, teams_got_authrequests, NULL, TRUE);
	return TRUE;
}


void
teams_add_buddy_with_invite(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char *message)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	gchar *postdata;
	const gchar *url = "/contacts/v2/users/SELF/contacts";
	GSList *users_to_fetch;
	JsonObject *obj;
	gchar *buddy_name, *mri;
	
	//https://contacts.skype.com/contacts/v2/users/SELF/contacts
	// POST {"mri":"2:eionrobb@dequis.onmicrosoft.com","greeting":"Hi, eionrobb@dequis.onmicrosoft.com, I'd like to add you as a contact."}
	
	buddy_name = g_strdup(purple_buddy_get_name(buddy));
	mri = g_strconcat(teams_user_url_prefix(buddy_name), buddy_name, NULL);
	
	obj = json_object_new();
	
	json_object_set_string_member(obj, "mri", mri);
	json_object_set_string_member(obj, "greeting", message ? message : _("Please authorize me so I can add you to my buddy list."));
	postdata = teams_jsonobj_to_string(obj);
	
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_NEW_CONTACTS_HOST, url, postdata, NULL, NULL, TRUE);
	
	g_free(mri);
	g_free(postdata);
	json_object_unref(obj);
	
	// Subscribe to status/message updates
	users_to_fetch = g_slist_prepend(NULL, buddy_name);
	teams_subscribe_to_contact_status(sa, users_to_fetch);
	g_slist_free(users_to_fetch);
	
	g_free(buddy_name);
}

void 
teams_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	teams_add_buddy_with_invite(pc, buddy, group, NULL);
}

void
teams_buddy_remove(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	gchar *url;
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	
	url = g_strdup_printf("/contacts/v2/users/SELF/contacts/%s%s", teams_user_url_prefix(buddy_name), purple_url_encode(buddy_name));
	
	teams_post_or_get(sa, TEAMS_METHOD_DELETE | TEAMS_METHOD_SSL, TEAMS_NEW_CONTACTS_HOST, url, NULL, NULL, NULL, TRUE);
	
	g_free(url);
	
	teams_unsubscribe_from_contact_status(sa, buddy_name);
}

void
teams_buddy_block(PurpleConnection *pc, const char *name)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	gchar *url;
	gchar *postdata;
	
	// Old skype (teams personal?)
	url = g_strdup_printf("/contacts/v2/users/SELF/contacts/blocklist/%s%s", teams_user_url_prefix(name), purple_url_encode(name));
	postdata = g_strdup("{\"report_abuse\":\"false\",\"ui_version\":\"skype.com\"}");
	
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_NEW_CONTACTS_HOST, url, postdata, NULL, NULL, TRUE);

	g_free(url);
	g_free(postdata);
	
	// New teams
	url = g_strdup(TEAMS_PROFILES_PREFIX "userSettings/blocklist/manage");
	postdata = g_strdup_printf("{\"add\":[\"%s%s\"]}", teams_user_url_prefix(name), name);
	
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, postdata, NULL, NULL, TRUE);

	g_free(url);
	g_free(postdata);
}

void
teams_buddy_unblock(PurpleConnection *pc, const char *name)
{
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	gchar *url;
	gchar *postdata;
	
	// Old skype (teams personal?)
	url = g_strdup_printf("/contacts/v2/users/SELF/contacts/blocklist/%s%s", teams_user_url_prefix(name), purple_url_encode(name));
	
	teams_post_or_get(sa, TEAMS_METHOD_DELETE | TEAMS_METHOD_SSL, TEAMS_NEW_CONTACTS_HOST, url, NULL, NULL, NULL, TRUE);

	g_free(url);
	
	// New teams
	url = g_strdup(TEAMS_PROFILES_PREFIX "userSettings/blocklist/manage");
	postdata = g_strdup_printf("{\"remove\":[\"%s%s\"]}", teams_user_url_prefix(name), name);
	
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, TEAMS_BASE_ORIGIN_HOST, url, postdata, NULL, NULL, TRUE);

	g_free(url);
	g_free(postdata);
}

// TODO
// add_allow
// POST https://teams.microsoft.com/api/mt/beta/userSettings/acceptlist/manage
// {
//	"add": ["8:orgid:...."]
//}


void
teams_set_mood_message(TeamsAccount *sa, const gchar *mood)
{
	JsonObject *obj;
	gchar *post;
	
	obj = json_object_new();
	
	json_object_set_string_member(obj, "message", mood ? mood : "");
	json_object_set_string_member(obj, "expiry", "9999-12-31T00:00:00.000Z");
	
	post = teams_jsonobj_to_string(obj);
	
	teams_post_or_get(sa, TEAMS_METHOD_PUT | TEAMS_METHOD_SSL, TEAMS_PRESENCE_HOST, "/v1/me/publishnote", post, NULL, NULL, TRUE);
	
	g_free(post);
	json_object_unref(obj);
}
