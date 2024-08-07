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

#define TEAMS_TROUTER_TTL 86400
#define TEAMS_TROUTER_TCCV "2024.23.01.2"

static gboolean teams_trouter_register(gpointer user_data);
static void teams_trouter_register_one(TeamsAccount *sa, const gchar *appId, const gchar *templateKey, const gchar *path);

void
teams_trouter_stop(TeamsAccount *sa)
{
	if (sa->trouter_socket) {
		purple_websocket_send(sa->trouter_socket, PURPLE_WEBSOCKET_CLOSE, NULL, 0);
		purple_websocket_abort(sa->trouter_socket);
		sa->trouter_socket = NULL;
	}
	if (sa->trouter_ping_timeout) {
		purple_timeout_remove(sa->trouter_ping_timeout);
		sa->trouter_ping_timeout = 0;
	}
	if (sa->trouter_registration_timeout) {
		purple_timeout_remove(sa->trouter_registration_timeout);
		sa->trouter_registration_timeout = 0;
	}
	if (sa->trouter_surl) {
		g_free(sa->trouter_surl);
		sa->trouter_surl = NULL;
	}

	if (sa->trouter_socket_obj) {
		json_object_unref(sa->trouter_socket_obj);
		sa->trouter_socket_obj = NULL;
	}
}

static const gchar *
teams_generate_correlation_vector()
{
	static const gchar *valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+";
	static const gchar *valid_suffix = "AgQw";
	static const int valid_chars_len = 64;
	static gchar *cv = NULL;
	gint i;
	
	if (cv == NULL) {
		cv = g_new(gchar, 23);
	}

	for (i = 0; i < 21; i++) {
		cv[i] = valid_chars[g_random_int_range(0, valid_chars_len)];
	}
	cv[21] = valid_suffix[g_random_int_range(0, 4)];
	cv[22] = '\0';

	return cv;
}

void
teams_trouter_send_active(TeamsAccount *sa, gboolean active)
{
	gchar *message;
	const gchar *cv;

	cv = teams_generate_correlation_vector();
	message = g_strdup_printf("{\"name\":\"user.activity\",\"args\":[{\"state\":\"%s\",\"cv\":\"%s.0.1\"}]}", active ? "active" : "inactive", cv);
	
	teams_trouter_send_message(sa, message);
	
	g_free(message);
}

static void
teams_trouter_send_authentication(TeamsAccount *sa)
{
	JsonObject *obj = json_object_new();
	JsonArray *args = json_array_new();
	JsonObject *arg0 = json_object_new();
	JsonObject *headers = json_object_new();
	JsonObject *connectparams = json_object_get_object_member(sa->trouter_socket_obj, "connectparams");

	json_object_set_string_member(headers, "X-Ms-Test-User", "False");
	gchar *auth_header = g_strdup_printf("Bearer %s", sa->id_token);
	json_object_set_string_member(headers, "Authorization", auth_header);
	g_free(auth_header);
	json_object_set_string_member(headers, "X-MS-Migration", "True");

	json_object_set_object_member(arg0, "headers", headers);
	json_object_set_object_member(arg0, "connectparams", json_object_ref(connectparams));
	json_array_add_object_element(args, arg0);

	json_object_set_string_member(obj, "name", "user.authenticate");
	json_object_set_array_member(obj, "args", args);

	gchar *message = teams_jsonobj_to_string(obj);
	teams_trouter_send_ephemeral_message(sa, message);
	g_free(message);
	json_object_unref(obj);
}

static void
teams_trouter_websocket_cb(PurpleWebsocket *ws, gpointer user_data, PurpleWebsocketOp op, const guchar *msg, size_t len)
{
	TeamsAccount *sa = user_data;

	purple_debug_info("teams", "Trouter WS: %d %.*s\n", op, (int) len, msg);
	if (op == PURPLE_WEBSOCKET_OPEN) {
		purple_debug_info("teams", "Trouter WS: Opened\n");
		return;
	} else if (op == PURPLE_WEBSOCKET_CLOSE) {
		purple_debug_info("teams", "Trouter WS: Closed\n");
		// _CLOSE calls abort internally, bypass to prevent double-free
		sa->trouter_socket = NULL;
		// Reopen the connection
		teams_trouter_begin(sa);
		return;
	} else if (op == PURPLE_WEBSOCKET_ERROR) {
		purple_debug_info("teams", "Trouter WS: Error\n");
		// _ERROR calls abort internally, bypass to prevent double-free
		sa->trouter_socket = NULL;
		// Reopen the connection
		teams_trouter_begin(sa);
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
	// 3::: ephemeral message from server
	// 6:X+:: - sequential response to message X

	//3:::{"id":123456789,"method":"POST","url":"/v4/f/V_Qsweryuiopqyerwquioerutp/TeamsUnifiedPresenceService","headers":{"X-Microsoft-Skype-Chain-ID":"asdfasdf-asdf-asdf-asdf-asdfasdfasdf","X-Microsoft-Skype-Message-ID":"0","X-Trouter-Delivery-Control":"async; ttl=600","x-ms-client-user-agent":"Microsoft.Skype.Presence.App/1.0","Content-Length":"458","Content-Type":"application/json; charset=utf-8","Accept":"application/json","Host":"trouter2-azsc-ince-1-a.trouter.teams.microsoft.com:20000","User-Agent":"Microsoft.Skype.Presence.App/1.0","MS-CV":"asdf+asdfsadf.1","trouter-request":"{\"id\":\"asdfasdf-asdf-asdf-asdf-asdfasdfasdf\",\"src\":\"trouter2-azsc-ince-1-a\",\"port\":31037}","Trouter-Timeout":"117298"},"body":"{\"presence\":[{\"mri\":\"8:orgid:asdfasdf-asdf-asdf-asdf-asdfasdfasdf\",\"etag\":\"A1234567890\",\"presence\":{\"sourceNetwork\":\"Self\",\"forcedAvailability\":{\"expiry\":\"2020-01-01T01:01:01.0101010Z\",\"availability\":\"Available\",\"activity\":\"Available\",\"publishTime\":\"2020-01-01T01:01:01.0101010Z\"},\"calendarData\":{\"isOutOfOffice\":false},\"capabilities\":[],\"availability\":\"Available\",\"activity\":\"Available\",\"lastActiveTime\":\"2020-01-01T01:01:01.0101010Z\",\"deviceType\":\"Web\"}}]}"}
	//3:::{"id":123456789,"status":200,"headers":{"MS-CV":"asdf+asdfsadf.1.0","trouter-request":"{\"id\":\"asdfasdf-asdf-asdf-asdf-asdfasdfasdf\",\"src\":\"trouter2-azsc-ince-1-a\",\"port\":31037}","trouter-client":"{\"cd\":1}"},"body":""}
	
	if (G_UNLIKELY(msg[0] == '1')) {
		teams_trouter_send_authentication(sa);
		teams_trouter_send_active(sa, TRUE);
		teams_trouter_register(sa);

	} else if (msg[0] == '3') {
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
			gchar *response_str, *response_msg;
			
			json_object_set_int_member(response, "id", json_object_get_int_member(request, "id"));
			json_object_set_int_member(response, "status", 200);
			json_object_set_string_member(response, "body", "");
			
			response_str = teams_jsonobj_to_string(response);
			response_msg = g_strconcat("3:::", response_str, NULL);
			purple_websocket_send(ws, PURPLE_WEBSOCKET_TEXT, (guchar *) response_msg, strlen(response_msg));
			json_object_unref(response);
			g_free(response_str);
			g_free(response_msg);

			JsonObject *headers = json_object_get_object_member(request, "headers");
			gchar *body = g_strdup(json_object_get_string_member(request, "body"));
			if (purple_strequal(json_object_get_string_member(headers, "X-Microsoft-Skype-Content-Encoding"), "gzip")) {
				gsize body_len;
				guchar *body_base64_decoded = g_base64_decode(body, &body_len);
				gchar *body_unzipped = teams_gunzip(body_base64_decoded, &body_len);
				g_free(body_base64_decoded);
				g_free(body);
				body = body_unzipped;
			}

			JsonObject *body_obj = json_decode_object(body, strlen(body));
			JsonObject *orig_body = json_object_ref(body_obj);
			
			if (json_object_has_member(body_obj, "cp")) {
				const gchar *cp = json_object_get_string_member(body_obj, "cp");
				gsize cp_len;
				guchar *cp_base64_decoded = g_base64_decode(cp, &cp_len);
				gchar *cp_unzipped = teams_gunzip(cp_base64_decoded, &cp_len);
				json_object_unref(body_obj);
				body_obj = json_decode_object(cp_unzipped, cp_len);
				g_free(cp_unzipped);
				g_free(cp_base64_decoded);
			} else if (json_object_has_member(body_obj, "gp")) {
				const gchar *gp = json_object_get_string_member(body_obj, "gp");
				gsize gp_len;
				guchar *gp_base64_decoded = g_base64_decode(gp, &gp_len);
				json_object_unref(body_obj);
				body_obj = json_decode_object((gchar *) gp_base64_decoded, gp_len);
				g_free(gp_base64_decoded);
			}

			const gchar *request_url = json_object_get_string_member(request, "url");
			// if request_url ends with /TeamsUnifiedPresenceService
			if (g_str_has_suffix(request_url, "/TeamsUnifiedPresenceService") ||
					g_str_has_suffix(request_url, "/unifiedPresenceService")) {
				JsonArray *presences = json_object_get_array_member(body_obj, "presence");

				if (presences != NULL) {
					JsonNode *presences_node = json_node_new(JSON_NODE_ARRAY);
					
					json_node_set_array(presences_node, presences);
					teams_got_contact_statuses(sa, presences_node, NULL);
					json_node_free(presences_node);
				}

			} else if (g_str_has_suffix(request_url, "/messaging")) {
				const gchar *type = json_object_get_string_member(body_obj, "type");

				if (purple_strequal(type, "EventMessage")) {
					teams_process_event_message(sa, body_obj);
				}

			} else if (g_str_has_suffix(request_url, "/NGCallManagerWin") || strstr(request_url, "/SkypeSpacesWeb")) {

				// Incoming call:
				/// body: "{\"evt\":107,\"cp\":\"...\",\"callId\":\"... callid guid ...\",\"callerId\":\"orgid:...\"}"
				// cp:
				// {
				// 	"callNotification":{
				// 		"from":{
				// 			"id":"8:orgid:...",
				// 			"displayName":"Person Calling",
				// 			"endpointId":"abcd1234-ffff-ffff-abcd-123456781234",
				// 			"languageId":"en-us",
				// 			"participantId":"... participant1 guid ...",
				// 			"hidden":false,
				// 			"tenantId":"... tenant1 guid ...",
				// 			"region":"au",
				// 			"propertyBag":null
				// 		},
				// 		"to":{
				// 			"id":"8:orgid:...",
				// 			"displayName":null,
				// 			"endpointId":"00000000-0000-0000-0000-000000000000",
				// 			"languageId":null,
				// 			"participantId":"... participant2 guid ...",
				// 			"hidden":false,
				// 			"tenantId":"... tenant2 guid ...",
				// 			"propertyBag":null
				// 		},
				// 		"links":{
				// 			"attach":"https://api.flightproxy.teams.microsoft.com/api/v2/ep/cc-auea-05-prod-aks.cc.skype.com/cc/v1/forked/...forkedid.../27/i1/1006/attach?i=10-60-10-157",
				// 			"mediaAnswer":"cc://ma",
				// 			"progress":"https://api.flightproxy.teams.microsoft.com/api/v2/ep/cc-auea-05-prod-aks.cc.skype.com/cc/v1/forked/...forkedid.../27/i1/1006/progress?i=10-60-10-157",
				// 			"reject":"https://api.flightproxy.teams.microsoft.com/api/v2/ep/cc-auea-05-prod-aks.cc.skype.com/cc/v1/forked/...forkedid.../27/i1/1006/reject?i=10-60-10-157",
				// 			"udpTransport":"udp://52.123.160.45:3478/"
				// 		},
				// 		"mediaContent":null, //or
				//		"mediaContent": {
				//   		"contentType": "application/sdp-ngc-0.5",
				//   		"blob": "v=0\r\no=- 0 0 IN IP4 52.115.99.55\r\ns=session\r\nc=IN IP4 52.115.99.55\r\nb=CT:4000\r\nt=0 0\r\n...",,
				//   		"mediaLegId": "C88DBF5EExxxAFCA5",
				//   		"escalationOccurring": false,
				//   		"newOffer": false,
				//   		"clientLocation": "NZ"
				// 		},
				// 		"udpKey":{
				// 			"sessionKey":"7Ia+pXXXXjUjjRf2cQ==",
				// 			"ticket":"RHQN4nbXXXXXKWnd1g1JA=="
				// 		}
				// 	},
				// 	"conversationInvitation":{
				// 		"conversationController":"https://api.flightproxy.teams.microsoft.com/api/v2/ep/conv-auea-05-prod-aks.conv.skype.com/conv/xyzabcDeyuiof?i=10-60-11-74&e=638407063083483437",
				// 		"isMultiParty":false,
				// 		"isBroadcast":false
				// 	},
				// 	"debugContent":{
				// 		"causeId":"",
				// 		"clientDebugContent":{
							
				// 		},
				// 		"ecsEtag":"\"X1xx7IIMeKXXXanrv3I=\"",
				// 		"callId":"... callid guid ...",
				// 		"ProcessingCallControllerInstance":"https://cc-auea-05-prod-aks.cc.skype.com/",
				// 		"potentialCallNotificationSent":false,
				// 		"participantId":"... participant1 guid ..."
				// 	},
				// 	"groupContext":null
				// }


				// Call started?
				// {
				//     "correlationId": "... callid guid ...",
				//     "conversationController": "https://api.flightproxy.teams.microsoft.com/api/v2/ep/conv-auea-05-prod-aks.conv.skype.com/conv/xyzabcDeyuiof?i=10-60-11-74&e=638407063083483437",
				//     "userJoinTime": "2024-01-16T20:22:03.6438865Z",
				//     "participants": [
				//         "8:orgid:...",
				//         "8:orgid:..."
				//     ]
				// }

				// Call ended
				// {
				//   "callEnd": {
				//     "reason": "clientError",
				//     "sender": {
				//       "id": "8:orgid:...",
				//       "displayName": "Eion Robb",
				//       "endpointId": "... endpoint id ...",
				//       "languageId": "en-NZ",
				//       "participantId": "... participant2 guid ...",
				//       "hidden": false,
				//       "tenantId": "... tenant2 guid ...",
				//       "region": "au"
				//     },
				//     "code": 487,
				//     "subCode": 10003,
				//     "phrase": "Call cancelled as it was accepted by another fork.",
				//     "resultCategories": [
				//       "ExpectedError"
				//     ],
				//     "acceptedElsewhereBy": {
				//       "id": "8:orgid:...",
				//       "displayName": "Eion Robb",
				//       "endpointId": "... endpoint id ...",
				//       "languageId": "en-NZ",
				//       "participantId": "... participant2 guid ...",
				//       "hidden": false,
				//       "tenantId": "... tenant2 guid ...",
				//       "region": "au"
				//     }
				//   },
				//   "debugContent": null
				// }

			} else {
				purple_debug_info("teams", "Trouter WS: Unknown request: %s\n", request_url);
			}

			json_object_unref(orig_body);
			json_object_unref(body_obj);
			json_object_unref(request);
			g_free(body);
		}

	} else if (msg[0] == '5') {
		// Find 3rd ':'
		int colon_to_go = 3, i = 1;
		while (colon_to_go && i < len) {
			if (msg[i++] == ':') {
				colon_to_go--;
			}
		}
		if (!colon_to_go) {
			JsonObject *obj = json_decode_object((const gchar *) &msg[i], len - i);
			const gchar *name = json_object_get_string_member(obj, "name");
			if (purple_strequal(name, "trouter.message_loss")) {
				teams_trouter_register_one(sa, "TeamsCDLWebWorker", "TeamsCDLWebWorker_1.9", sa->trouter_surl);
			}
			json_object_unref(obj);
		}

	} else if (msg[0] == '6') {
		// noop (for now)
	} else {
		purple_debug_info("teams", "Trouter WS: Unknown message\n");
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
	g_free(msg_str);

	return TRUE;
}

gboolean
teams_trouter_send_ephemeral_message(TeamsAccount *sa, const gchar *message)
{
	if (sa == NULL || sa->trouter_socket == NULL) {
		return FALSE;
	}

	if (!PURPLE_IS_CONNECTION(sa->pc) || purple_connection_get_state(sa->pc) != PURPLE_CONNECTED) {
		return FALSE;
	}

	gchar *msg_str = g_strdup_printf("5:::%s", message);
	purple_websocket_send(sa->trouter_socket, PURPLE_WEBSOCKET_TEXT, (guchar *) msg_str, strlen(msg_str));
	g_free(msg_str);

	return TRUE;
}


static gboolean
teams_trouter_send_ping(gpointer user_data)
{
	TeamsAccount *sa = user_data;

	return teams_trouter_send_message(sa, "{\"name\":\"ping\"}");
}

static void
teams_trouter_register_one(TeamsAccount *sa, const gchar *appId, const gchar *templateKey, const gchar *path)
{
	JsonObject *reg_obj = json_object_new();
	JsonObject *clientDescription = json_object_new();
	JsonObject *transports = json_object_new();
	JsonArray *trouter = json_array_new();
	JsonObject *trouter_obj = json_object_new();

	json_object_set_string_member(clientDescription, "appId", appId);
	json_object_set_string_member(clientDescription, "aesKey", "");
	json_object_set_string_member(clientDescription, "languageId", "en-US");
	json_object_set_string_member(clientDescription, "platform", "edge");
	json_object_set_string_member(clientDescription, "templateKey", templateKey);
	json_object_set_string_member(clientDescription, "platformUIVersion", TEAMS_CLIENTINFO_VERSION);
#ifdef ENABLE_TEAMS_PERSONAL
	json_object_set_string_member(clientDescription, "productContext", "TFL");
#endif

	json_object_set_string_member(trouter_obj, "context", "");
	json_object_set_string_member(trouter_obj, "path", path);
	json_object_set_int_member(trouter_obj, "ttl", TEAMS_TROUTER_TTL);

	json_array_add_object_element(trouter, trouter_obj);
	json_object_set_array_member(transports, "TROUTER", trouter);

	json_object_set_object_member(reg_obj, "clientDescription", clientDescription);
	json_object_set_string_member(reg_obj, "registrationId", sa->endpoint);
	json_object_set_string_member(reg_obj, "nodeId", "");
	json_object_set_object_member(reg_obj, "transports", transports);

	gchar *reg_str = teams_jsonobj_to_string(reg_obj);
	purple_debug_info("teams", "Trouter registration: %s\n", reg_str);

#ifdef ENABLE_TEAMS_PERSONAL
#	define TEAMS_REGISTRAR_URL "https://edge.skype.com/registrar/prod/v2/registrations"
#else
#	define TEAMS_REGISTRAR_URL "https://teams.microsoft.com/registrar/prod/V2/registrations"
#endif

	PurpleHttpRequest *request = purple_http_request_new(TEAMS_REGISTRAR_URL);
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set(request, "Content-Type", "application/json");
	purple_http_request_header_set(request, "X-Skypetoken", sa->skype_token);
	purple_http_request_header_set_printf(request, "Authorization", "Bearer %s", sa->id_token); // Only for chat?
	purple_http_request_set_contents(request, reg_str, strlen(reg_str));
	purple_http_request(sa->pc, request, NULL, NULL);
	purple_http_request_unref(request);

	g_free(reg_str);
	json_object_unref(reg_obj);
}

static gboolean
teams_trouter_register(gpointer user_data)
{
	TeamsAccount *sa = user_data;

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

	// NextGenCalling for call messages
	// SkypeSpacesWeb has additional call info
	// TeamsCDLWebWorker for events and messaging (must be last!)
	
	//TODO scan through buddy list and call teams_subscribe_to_contact_status instead
	teams_get_friend_list(sa);
	teams_subscribe_with_callback(sa, NULL);

	gchar *ngc_path = g_strconcat(sa->trouter_surl, "NGCallManagerWin", NULL);
	teams_trouter_register_one(sa, "NextGenCalling", "DesktopNgc_2.3:SkypeNgc", ngc_path);
	g_free(ngc_path);

	gchar *ssw_path = g_strconcat(sa->trouter_surl, "SkypeSpacesWeb", NULL);
	teams_trouter_register_one(sa, "SkypeSpacesWeb", "SkypeSpacesWeb_2.3", ssw_path);
	g_free(ssw_path);

	teams_trouter_register_one(sa, "TeamsCDLWebWorker", "TeamsCDLWebWorker_1.9", sa->trouter_surl);

	return TRUE;
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
	GList *iter, *list;
	
	data = purple_http_response_get_data(response, &len);

	gchar **node_parts = g_strsplit(data, ":", 2);
	const gchar *session_id = node_parts[0];

	if (sa->trouter_socket) {
		purple_websocket_abort(sa->trouter_socket);
	}

	GString *url = g_string_new("");

	const gchar *socketio = json_object_get_string_member(obj, "socketio");
	if (socketio == NULL) {
#ifdef ENABLE_TEAMS_PERSONAL
		socketio = "https://go.trouter.skype.com/";
#else
		socketio = "https://go.trouter.teams.microsoft.com/";
#endif
	}
	g_string_append_printf(url, "%ssocket.io/1/websocket/%s?v=v4&", socketio, session_id);

	connectparams = json_object_get_object_member(obj, "connectparams");
	list = json_object_get_members(connectparams);
	for (iter = list; iter; iter = iter->next) {
		const gchar *key = iter->data;
		const gchar *value = json_object_get_string_member(connectparams, key);
		g_string_append_printf(url, "%s=%s&", key, purple_url_encode(value));
	}
	g_list_free(list);
	g_string_append_printf(url, "tc=%s&", purple_url_encode("{\"cv\":\"" TEAMS_TROUTER_TCCV "\",\"ua\":\"TeamsCDL\",\"hr\":\"\",\"v\":\"" TEAMS_CLIENTINFO_VERSION "\"}"));
	g_string_append_printf(url, "con_num=%" G_GINT64_FORMAT "_%d&", 1234567890123, 1); //TODO sa->trouter_count++
	g_string_append_printf(url, "epid=%s&", purple_url_encode(sa->endpoint));
	const gchar *ccid = json_object_get_string_member(obj, "ccid");
	if (ccid != NULL) {
		g_string_append_printf(url, "ccid=%s&", purple_url_encode(ccid));
	}
	g_string_append(url, "auth=true&timeout=40&");

	sa->trouter_ping_timeout = purple_timeout_add_seconds(30, teams_trouter_send_ping, sa);
	sa->trouter_command_count = 1;

	purple_debug_info("teams", "Trouter WS URL: %s\n", url->str);
	
	// Inject the extra header (hack!)
	gchar *skypetoken_header = g_strdup_printf("\r\nX-Skypetoken: %s\r\nUser-Agent: " TEAMS_USER_AGENT, sa->skype_token);
	sa->trouter_socket = purple_websocket_connect(sa->account, url->str, skypetoken_header, teams_trouter_websocket_cb, sa);
	g_free(skypetoken_header);

	if (sa->trouter_surl) {
		g_free(sa->trouter_surl);
	}
	sa->trouter_surl = g_strdup(json_object_get_string_member(obj, "surl"));

	sa->trouter_registration_timeout = purple_timeout_add_seconds(TEAMS_TROUTER_TTL - 10, teams_trouter_register, sa);

	json_object_unref(obj);
	g_strfreev(node_parts);
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
	GList *iter, *list;
	
	data = purple_http_response_get_data(response, &len);
	obj = json_decode_object(data, len);

	if (sa->trouter_socket_obj) {
		json_object_unref(sa->trouter_socket_obj);
	}
	sa->trouter_socket_obj = json_object_ref(obj);
	
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
	list = json_object_get_members(connectparams);
	for (iter = list; iter; iter = iter->next) {
		const gchar *key = iter->data;
		const gchar *value = json_object_get_string_member(connectparams, key);
		g_string_append_printf(url, "%s=%s&", key, purple_url_encode(value));
	}
	g_list_free(list);
	g_string_append_printf(url, "tc=%s&", purple_url_encode("{\"cv\":\"" TEAMS_TROUTER_TCCV "\",\"ua\":\"TeamsCDL\",\"hr\":\"\",\"v\":\"" TEAMS_CLIENTINFO_VERSION "\"}"));
	g_string_append_printf(url, "con_num=%" G_GINT64_FORMAT "_%d&", 1234567890123, 1);
	g_string_append_printf(url, "epid=%s&", purple_url_encode(sa->endpoint));
	const gchar *ccid = json_object_get_string_member(obj, "ccid");
	if (ccid != NULL) {
		g_string_append_printf(url, "ccid=%s&", purple_url_encode(ccid));
	}
	g_string_append(url, "auth=true&timeout=40&");

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

	//TODO we can bypass this if we already have the obj response from the previous connectparams

	teams_trouter_stop(sa);

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
