/*
 * Teams Plugin for libpurple/Pidgin
 * Copyright (c) 2014-2022 Eion Robb
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

#include "teams_trouter.h"

#include "teams_contacts.h"
#include "teams_messages.h"
#include "teams_util.h"

void
teams_trouter_stop(TeamsAccount *sa)
{
	if (sa->trouter_socket) {
		purple_websocket_abort(sa->trouter_socket);
		sa->trouter_socket = NULL;
	}
	if (sa->trouter_ping_timeout) {
		purple_timeout_remove(sa->trouter_ping_timeout);
		sa->trouter_ping_timeout = 0;
	}
	if (sa->trouter_surl) {
		g_free(sa->trouter_surl);
		sa->trouter_surl = NULL;
	}

}

static void
teams_trouter_websocket_cb(PurpleWebsocket *ws, gpointer user_data, PurpleWebsocketOp op, const guchar *msg, size_t len)
{
	TeamsAccount *sa = user_data;

	purple_debug_info("teams", "Trouter WS: %d %.*s\n", op, len, msg);
	if (op == PURPLE_WEBSOCKET_OPEN) {
		purple_debug_info("teams", "Trouter WS: Opened\n");

		teams_trouter_send_message(sa, "{\"name\":\"user.activity\",\"args\":[{\"state\":\"active\"}]}");

		return;
	} else if (op == PURPLE_WEBSOCKET_CLOSE) {
		purple_debug_info("teams", "Trouter WS: Closed\n");
		teams_trouter_stop(sa);
		return;
	} else if (op == PURPLE_WEBSOCKET_ERROR) {
		purple_debug_info("teams", "Trouter WS: Error\n");
		teams_trouter_stop(sa);
		return;
	} else if (op == PURPLE_WEBSOCKET_PING) {
		purple_debug_info("teams", "Trouter WS: Ping\n");
		return;
	} else if (op == PURPLE_WEBSOCKET_PONG) {
		purple_debug_info("teams", "Trouter WS: Pong\n");
		return;
	} else if (op == PURPLE_WEBSOCKET_TEXT) {
		//purple_debug_info("teams", "Trouter WS: Text\n");
	} else if (op == PURPLE_WEBSOCKET_BINARY) {
		purple_debug_info("teams", "Trouter WS: Binary\n");
		return; // unexpected
	}

	// Guesses at what each number means
	// 1:: - connected
	// 5:X:: - sequential message from server
	// 5:X+:: - sequential message requiring a response
	// 3::: ephephmeral message from server
	// 6:X+:: - sequential response to message X

	//3:::{"id":123456789,"method":"POST","url":"/v4/f/V_Qsweryuiopqyerwquioerutp/TeamsUnifiedPresenceService","headers":{"X-Microsoft-Skype-Chain-ID":"asdfasdf-asdf-asdf-asdf-asdfasdfasdf","X-Microsoft-Skype-Message-ID":"0","X-Trouter-Delivery-Control":"async; ttl=600","x-ms-client-user-agent":"Microsoft.Skype.Presence.App/1.0","Content-Length":"458","Content-Type":"application/json; charset=utf-8","Accept":"application/json","Host":"trouter2-azsc-ince-1-a.trouter.teams.microsoft.com:20000","User-Agent":"Microsoft.Skype.Presence.App/1.0","MS-CV":"asdf+asdfsadf.1","trouter-request":"{\"id\":\"asdfasdf-asdf-asdf-asdf-asdfasdfasdf\",\"src\":\"trouter2-azsc-ince-1-a\",\"port\":31037}","Trouter-Timeout":"117298"},"body":"{\"presence\":[{\"mri\":\"8:orgid:asdfasdf-asdf-asdf-asdf-asdfasdfasdf\",\"etag\":\"A1234567890\",\"presence\":{\"sourceNetwork\":\"Self\",\"forcedAvailability\":{\"expiry\":\"2020-01-01T01:01:01.0101010Z\",\"availability\":\"Available\",\"activity\":\"Available\",\"publishTime\":\"2020-01-01T01:01:01.0101010Z\"},\"calendarData\":{\"isOutOfOffice\":false},\"capabilities\":[],\"availability\":\"Available\",\"activity\":\"Available\",\"lastActiveTime\":\"2020-01-01T01:01:01.0101010Z\",\"deviceType\":\"Web\"}}]}"}
	//3:::{"id":123456789,"status":200,"headers":{"MS-CV":"asdf+asdfsadf.1.0","trouter-request":"{\"id\":\"asdfasdf-asdf-asdf-asdf-asdfasdfasdf\",\"src\":\"trouter2-azsc-ince-1-a\",\"port\":31037}","trouter-client":"{\"cd\":1}"},"body":""}
	
	if (msg[0] == '3') {
		// Find 3rd ':'
		int colon_to_go = 3, i = 1;
		while (colon_to_go && i < len) {
			if (msg[i++] == ':') {
				colon_to_go--;
			}
		}
		if (!colon_to_go) {
			JsonObject *request = json_decode_object((const gchar *) &msg[i], len - i);
			JsonObject *response = json_object_new();
			gchar *response_str;
			
			json_object_set_int_member(response, "id", json_object_get_int_member(request, "id"));
			json_object_set_int_member(response, "status", 200);
			json_object_set_string_member(response, "body", "");
			
			response_str = teams_jsonobj_to_string(response);
			purple_websocket_send(ws, PURPLE_WEBSOCKET_TEXT, (guchar *) response_str, strlen(response_str));
			json_object_unref(response);
			g_free(response_str);

			const gchar *request_url = json_object_get_string_member(request, "url");
			// if request_url ends with /TeamsUnifiedPresenceService
			if (g_str_has_suffix(request_url, "/TeamsUnifiedPresenceService")) {
				const gchar *body = json_object_get_string_member(request, "body");
				JsonObject *body_obj = json_decode_object(body, strlen(body));
				JsonArray *presences = json_object_get_array_member(body_obj, "presence");

				if (presences != NULL) {
					JsonNode *presences_node = json_node_new(JSON_NODE_ARRAY);
					
					json_node_set_array(presences_node, presences);
					teams_got_contact_statuses(sa, presences_node, NULL);
				}

				json_object_unref(body_obj);
			} else if (g_str_has_suffix(request_url, "/messaging")) {
				const gchar *body = json_object_get_string_member(request, "body");
				JsonObject *body_obj = json_decode_object(body, strlen(body));
				const gchar *type = json_object_get_string_member(body_obj, "type");

				if (purple_strequal(type, "EventMessage")) {
					teams_process_event_message(sa, body_obj);
				}

				json_object_unref(body_obj);
			}

			json_object_unref(request);
		}
	}
}

gboolean
teams_trouter_send_message(TeamsAccount *sa, const gchar *message)
{
	if (sa == NULL || sa->trouter_socket == NULL) {
		return FALSE;
	}

	if (!PURPLE_IS_CONNECTION(sa->pc) || purple_connection_get_state(sa->pc) != PURPLE_CONNECTED) {
		return FALSE;
	}

	gchar *msg_str = g_strdup_printf("5:%d+::%s", sa->trouter_command_count++, message);
	purple_websocket_send(sa->trouter_socket, PURPLE_WEBSOCKET_TEXT, (guchar *) msg_str, strlen(msg_str));

	return TRUE;
}


static gboolean
teams_trouter_send_ping(gpointer user_data)
{
	TeamsAccount *sa = user_data;

	return teams_trouter_send_message(sa, "{\"name\":\"ping\"}");
}

static void
teams_trouter_sessionid_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	// node is plaintext
	// abcdef123487698-abcdef123487698:180:180:websocket,xhr-polling
	// grab bit before first colon and use as trouter websocket session

	PurpleConnection *pc = purple_http_conn_get_purple_connection(http_conn);
	TeamsAccount *sa = purple_connection_get_protocol_data(pc);
	JsonObject *obj = user_data;
	JsonObject *connectparams;
	const gchar *data;
	gsize len;
	GList *iter;
	
	data = purple_http_response_get_data(response, &len);

	gchar *session_id = g_strndup(data, strchr(data, ':') - data);

	if (sa->trouter_socket) {
		purple_websocket_abort(sa->trouter_socket);
	}

	GString *url = g_string_new("");

	const gchar *socketio = json_object_get_string_member(obj, "socketio");
	if (socketio == NULL) {
		socketio = "https://go.trouter.teams.microsoft.com/";
	}
	g_string_append_printf(url, "%ssocket.io/1/websocket/%s?v=v4&", socketio, session_id);

	connectparams = json_object_get_object_member(obj, "connectparams");
	for (iter = json_object_get_members(connectparams); iter; iter = iter->next) {
		const gchar *key = iter->data;
		const gchar *value = json_object_get_string_member(connectparams, key);
		g_string_append_printf(url, "%s=%s&", key, purple_url_encode(value));
	}
	g_string_append_printf(url, "tc=%s&", purple_url_encode("{\"cv\":\"2023.45.01.11\",\"ua\":\"TeamsCDL\",\"hr\":\"\",\"v\":\"49/23111630013\"}"));
	g_string_append_printf(url, "con_num=%" G_GINT64_FORMAT "_%d&", 1234567890123, 1); //TODO sa->trouter_count++
	const gchar *ccid = json_object_get_string_member(obj, "ccid");
	if (ccid != NULL) {
		g_string_append_printf(url, "ccid=%s&", purple_url_encode(ccid));
	}
	g_string_append(url, "auth=true&timeout=40&");

	sa->trouter_ping_timeout = purple_timeout_add_seconds(30, teams_trouter_send_ping, sa);
	sa->trouter_command_count = 1;

	purple_debug_info("teams", "Trouter WS URL: %s\n", url->str);
	
	// Inject the extra header (hack!)
	gchar *skypetoken_header = g_strdup_printf("\r\nX-Skypetoken: %s", sa->skype_token);
	sa->trouter_socket = purple_websocket_connect(sa->account, url->str, skypetoken_header, teams_trouter_websocket_cb, sa);
	g_free(skypetoken_header);

	// Register the trouter path at 
	// https://teams.microsoft.com/registrar/prod/V2/registrations
	// with postbody
	// {
	// 	"clientDescription": {
	// 		"appId": "TeamsCDLWebWorker",
	// 		"aesKey": "",
	// 		"languageId": "en-US",
	// 		"platform": "electron",
	// 		"templateKey": "TeamsCDLWebWorker_1.6",
	// 		"platformUIVersion": "27/1.0.0.2023052414"
	// 	},
	// 	"registrationId": "... obj.epid ...",
	// 	"nodeId": "",
	// 	"transports": {
	// 		"TROUTER": [{
	// 			"context": "",
	// 			"path": "... obj.surl ...",
	// 			"ttl": 86400
	// 		}]
	// 	}
	// }

	if (sa->trouter_surl) {
		g_free(sa->trouter_surl);
	}
	sa->trouter_surl = g_strdup(json_object_get_string_member(obj, "surl"));
	
	teams_get_friend_list(sa);

	JsonObject *reg_obj = json_object_new();
	JsonObject *clientDescription = json_object_new();
	JsonObject *transports = json_object_new();
	JsonArray *trouter = json_array_new();
	JsonObject *trouter_obj = json_object_new();

	json_object_set_string_member(clientDescription, "appId", "TeamsCDLWebWorker");
	json_object_set_string_member(clientDescription, "aesKey", "");
	json_object_set_string_member(clientDescription, "languageId", "en-US");
	json_object_set_string_member(clientDescription, "platform", "electron");
	json_object_set_string_member(clientDescription, "templateKey", "TeamsCDLWebWorker_1.6");
	json_object_set_string_member(clientDescription, "platformUIVersion", "27/1.0.0.2023052414");

	json_object_set_string_member(trouter_obj, "context", "");
	json_object_set_string_member(trouter_obj, "path", sa->trouter_surl);
	json_object_set_int_member(trouter_obj, "ttl", 86400);

	json_array_add_object_element(trouter, trouter_obj);
	json_object_set_array_member(transports, "TROUTER", trouter);

	json_object_set_string_member(reg_obj, "registrationId", sa->endpoint);
	json_object_set_object_member(reg_obj, "clientDescription", clientDescription);
	json_object_set_string_member(reg_obj, "nodeId", "");
	json_object_set_object_member(reg_obj, "transports", transports);

	gchar *reg_str = teams_jsonobj_to_string(reg_obj);
	purple_debug_info("teams", "Trouter registration: %s\n", reg_str);

	PurpleHttpRequest *request = purple_http_request_new("https://teams.microsoft.com/registrar/prod/V2/registrations");
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set(request, "Content-Type", "application/json");
	purple_http_request_header_set(request, "Content-Length", g_strdup_printf("%d", strlen(reg_str)));
	purple_http_request_header_set(request, "X-Skypetoken", sa->skype_token);
	purple_http_request_set_contents(request, reg_str, strlen(reg_str));
	purple_http_request(sa->pc, request, NULL, NULL);
	purple_http_request_unref(request);

	json_object_unref(reg_obj);
	g_free(reg_str);
	json_object_unref(obj);
	g_free(session_id);
	g_string_free(url, TRUE);
}

static void
teams_trouter_info_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj = NULL;
	GString *url = g_string_new("");
	const gchar *data;
	gsize len;
	PurpleHttpRequest *request;
	JsonObject *connectparams;
	GList *iter;
	
	data = purple_http_response_get_data(response, &len);
	obj = json_decode_object(data, len);
	
	// node is {
	// 	"socketio": "https://trouter2-abcd-abcd-1-a.trouter.teams.microsoft.com:443/",
	//  "surl": "https://trouter2-abcd-abcd-1-a.trouter.teams.microsoft.com:3443/v4/f/blahblahblah/",
	// 	"connectparams": {
	// 		"sr": "...-...-...",
	// 		"issuer": "prod-2",
	// 		"sp": "connect",
	// 		"se": "...",
	// 		"st": "...",
	// 		"sig": "...-...-..."
	// 	}
	// }

	connectparams = json_object_get_object_member(obj, "connectparams");
	
	const gchar *socketio = json_object_get_string_member(obj, "socketio");
	if (socketio == NULL) {
		socketio = "https://go.trouter.teams.microsoft.com/";
	}
	g_string_append_printf(url, "%ssocket.io/1/?v=v4&", socketio);
	// Loop over each of the connect params to add to the url
	for (iter = json_object_get_members(connectparams); iter; iter = iter->next) {
		const gchar *key = iter->data;
		const gchar *value = json_object_get_string_member(connectparams, key);
		g_string_append_printf(url, "%s=%s&", key, purple_url_encode(value));
	}
	g_string_append_printf(url, "tc=%s&", purple_url_encode("{\"cv\":\"2023.45.01.11\",\"ua\":\"TeamsCDL\",\"hr\":\"\",\"v\":\"49/23111630013\"}"));
	g_string_append_printf(url, "con_num=%" G_GINT64_FORMAT "_%d&", 1234567890123, 1);
	const gchar *ccid = json_object_get_string_member(obj, "ccid");
	if (ccid != NULL) {
		g_string_append_printf(url, "ccid=%s&", purple_url_encode(ccid));
	}

	purple_debug_info("teams", "Trouter URL: %s\n", url->str);
	request = purple_http_request_new(url->str);
	purple_http_request_set_method(request, "GET");
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set(request, "X-Skypetoken", sa->skype_token);
	purple_http_request(sa->pc, request, teams_trouter_sessionid_cb, obj);
	purple_http_request_unref(request);
	
	g_string_free(url, TRUE);
	// Do not unref obj, passed to callback
}

void
teams_trouter_begin(TeamsAccount *sa) 
{
	// https://go.trouter.teams.microsoft.com/v4/a?cor_id={sessionId}&con_num={clientId}_{incrementingCount}&epid={endpointId} 
	GString *url = g_string_new("https://go.trouter.teams.microsoft.com/v4/a?");
	PurpleHttpRequest *request;

	// Doesn't seem to be needed
	// g_string_append_printf(url, "cor_id=%s&", purple_url_encode(sa->session_id));
	// g_string_append_printf(url, "con_num=%s_%d&", purple_url_encode(sa->client_id), sa->trouter_count++);
	g_string_append_printf(url, "epid=%s", purple_url_encode(sa->endpoint));

	request = purple_http_request_new(url->str);
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set(request, "x-skypetoken", sa->skype_token);
	purple_http_request_header_set(request, "Content-Length", "0");
	purple_http_request(sa->pc, request, teams_trouter_info_cb, sa);
	purple_http_request_unref(request);
	
	g_string_free(url, TRUE);
}