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
 
#include "teams_connection.h"

#include "http.h"

static void
teams_destroy_connection(TeamsConnection *conn)
{
	g_free(conn->url);
	g_free(conn);
}

static void
teams_post_or_get_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsConnection *conn = user_data;
	const gchar *data;
	gsize len;
	
	data = purple_http_response_get_data(response, &len);
	
	if (conn->callback != NULL) {
		if (!len)
		{
			purple_debug_info("teams", "No data in response\n");
			conn->callback(conn->sa, NULL, conn->user_data);
		} else {
			JsonParser *parser = json_parser_new();
			if (!json_parser_load_from_data(parser, data, len, NULL))
			{
				if (conn->error_callback != NULL) {
					conn->error_callback(conn->sa, data, len, conn->user_data);
				} else {
					purple_debug_error("teams", "Error parsing response: %s\n", data);
				}
			} else {
				JsonNode *root = json_parser_get_root(parser);
				
				purple_debug_info("teams", "executing callback for %s\n", conn->url);
				conn->callback(conn->sa, root, conn->user_data);
			}
			g_object_unref(parser);
		}
	}
	
	teams_destroy_connection(conn);
}

TeamsConnection *teams_post_or_get(TeamsAccount *sa, TeamsMethod method,
		const gchar *host, const gchar *url, const gchar *postdata,
		TeamsProxyCallbackFunc callback_func, gpointer user_data,
		gboolean keepalive)
{
	TeamsConnection *conn;
	PurpleHttpRequest *request;
	const gchar* const *languages;
	gchar *language_names;
	gchar *real_url;
	
	g_return_val_if_fail(host != NULL, NULL);
	g_return_val_if_fail(url != NULL, NULL);
	g_return_val_if_fail(sa && sa->conns != NULL, NULL);
	
	real_url = g_strdup_printf("%s://%s%s", method & TEAMS_METHOD_SSL ? "https" : "http", host, url);
	
	purple_debug_info("teams", "Fetching url %s\n", real_url);
	
	request = purple_http_request_new(real_url);
	if (method & TEAMS_METHOD_POST) {
		purple_http_request_set_method(request, "POST");
	} else if (method & TEAMS_METHOD_PUT) {
		purple_http_request_set_method(request, "PUT");
	} else if (method & TEAMS_METHOD_DELETE) {
		purple_http_request_set_method(request, "DELETE");
	}
	if (keepalive) {
		purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	}
	
	purple_http_request_set_max_redirects(request, 0);
	purple_http_request_set_timeout(request, 120);
	
	if (method & (TEAMS_METHOD_POST | TEAMS_METHOD_PUT)) {
		if (postdata && (postdata[0] == '[' || postdata[0] == '{')) {
			purple_http_request_header_set(request, "Content-Type", "application/json"); // hax
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}
		if (postdata && *postdata) {
			purple_http_request_set_contents(request, postdata, strlen(postdata));
		}
		
		//Zero-length PUT's dont get the content-length header set
		if ((method & TEAMS_METHOD_PUT) && (!postdata || !*postdata)) {
			purple_http_request_header_set(request, "Content-Length", "0");
		}
	}
	
	purple_http_request_header_set(request, "BehaviorOverride", "redirectAs404");
#ifdef ENABLE_TEAMS_PERSONAL
	purple_http_request_header_set(request, "X-MS-Client-Consumer-Type", "teams4life");
#endif
	purple_http_request_header_set(request, "User-Agent", TEAMS_USER_AGENT);
	
	if (g_str_equal(host, TEAMS_CONTACTS_HOST) || g_str_equal(host, TEAMS_VIDEOMAIL_HOST) || g_str_equal(host, TEAMS_NEW_CONTACTS_HOST)) {
		purple_http_request_header_set(request, "X-Skypetoken", sa->skype_token);
		purple_http_request_header_set(request, "X-Stratus-Caller", TEAMS_CLIENTINFO_NAME);
		purple_http_request_header_set(request, "X-Stratus-Request", "abcd1234");
		purple_http_request_header_set(request, "Origin", "https://" TEAMS_BASE_ORIGIN_HOST);
		purple_http_request_header_set(request, "Referer", "https://" TEAMS_BASE_ORIGIN_HOST "/");
		purple_http_request_header_set(request, "Accept", "application/json; ver=1.0;");
		
	} else if (g_str_equal(host, TEAMS_GRAPH_HOST)) {
		purple_http_request_header_set(request, "X-Skypetoken", sa->skype_token);
		purple_http_request_header_set(request, "Accept", "application/json");
		
	} else if (g_str_equal(host, sa->messages_host)) {
		purple_http_request_header_set_printf(request, "Authentication", "skypetoken=%s", sa->skype_token);
		purple_http_request_header_set(request, "Referer", "https://" TEAMS_BASE_ORIGIN_HOST "/");
		purple_http_request_header_set(request, "Accept", "application/json; ver=1.0");
		purple_http_request_header_set(request, "ClientInfo", "os=windows; osVer=10; proc=x86; lcid=en-us; deviceType=1; country=n/a; clientName=" TEAMS_CLIENTINFO_NAME "; clientVer=" TEAMS_CLIENTINFO_VERSION);
		
	} else if (g_str_equal(host, TEAMS_DEFAULT_CONTACT_SUGGESTIONS_HOST)) {
		purple_http_request_header_set(request, "X-RecommenderServiceSettings", "{\"experiment\":\"default\",\"recommend\":\"true\"}");
		purple_http_request_header_set(request, "X-ECS-ETag", TEAMS_CLIENTINFO_NAME);
		purple_http_request_header_set(request, "X-Skypetoken", sa->skype_token);
		purple_http_request_header_set(request, "Accept", "application/json");
		purple_http_request_header_set(request, "X-Skype-Client", TEAMS_CLIENTINFO_VERSION);
		
	} else if (g_str_equal(host, TEAMS_PRESENCE_HOST)) {
		if (sa->presence_access_token != NULL) {
			purple_http_request_header_set_printf(request, "Authorization", "Bearer %s", sa->presence_access_token);
		} else {
			purple_http_request_header_set(request, "X-Skypetoken", sa->skype_token);
		}
		purple_http_request_header_set(request, "Accept", "application/json");
		purple_http_request_header_set(request, "x-ms-client-user-agent", "Teams-V2-Desktop");
		purple_http_request_header_set(request, "x-ms-correlation-id", "1");
		purple_http_request_header_set(request, "x-ms-client-version", TEAMS_CLIENTINFO_VERSION); 
		purple_http_request_header_set(request, "x-ms-endpoint-id", sa->endpoint);
		
	} else if (g_str_equal(host, "substrate.office.com")) {
		purple_http_request_header_set_printf(request, "Authorization", "Bearer %s", sa->substrate_access_token);
		purple_http_request_header_set(request, "Accept", "application/json");
#ifdef ENABLE_TEAMS_PERSONAL
		purple_http_request_header_set(request, "X-AnchorMailbox", sa->username);
#endif
		
	} else if (g_str_equal(host, TEAMS_BASE_ORIGIN_HOST)) { // maybe chatsvcagg.teams.microsoft.com too?
#ifdef ENABLE_TEAMS_PERSONAL
		if (strstr(url, "/api/csa/") == url) {
#else
		if (strstr(url, "/api/csa/") == url && sa->csa_access_token != NULL) {
			purple_http_request_header_set_printf(request, "Authorization", "Bearer %s", sa->csa_access_token);
#endif
		} else {
			purple_http_request_header_set_printf(request, "Authorization", "Bearer %s", sa->id_token);
		}
		purple_http_request_header_set(request, "X-Skypetoken", sa->skype_token);
		purple_http_request_header_set(request, "Accept", "application/json");
		
	} else {
		purple_http_request_header_set(request, "Accept", "*/*");
		purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	}
	
	/* Tell the server what language we accept, so that we get error messages in our language (rather than our IP's) */
	languages = g_get_language_names();
	language_names = g_strjoinv(", ", (gchar **)languages);
	purple_util_chrreplace(language_names, '_', '-');
	purple_http_request_header_set(request, "Accept-Language", language_names);
	g_free(language_names);
	
	conn = g_new0(TeamsConnection, 1);
	conn->sa = sa;
	conn->user_data = user_data;
	conn->url = real_url;
	conn->callback = callback_func;
	
	conn->http_conn = purple_http_request(sa->pc, request, teams_post_or_get_cb, conn);
	if (conn->http_conn != NULL) {
		purple_http_connection_set_add(sa->conns, conn->http_conn);
	}
	
	purple_http_request_unref(request);
	
	return conn;
}
