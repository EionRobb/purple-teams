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

#include "teams_login.h"
#include "teams_util.h"
#include "http.h"


#define TEAMS_GUID_REGEX_PATTERN "^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$"

void
teams_logout(TeamsAccount *sa)
{
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_LOGIN_HOST, "/logout", NULL, NULL, NULL, TRUE);
}

static const gchar *
teams_get_tenant_host(const gchar *tenant)
{
	static gchar *tenant_host = NULL;
	
	if (tenant_host) {
		g_free(tenant_host);
	}

	if (tenant && *tenant) {
		if (strchr(tenant, '.')) {
			// Likely a FQDN
			tenant_host = g_strdup(tenant);
		} else if (g_regex_match_simple(TEAMS_GUID_REGEX_PATTERN, tenant, 0, 0)) {
			tenant_host = g_strdup(tenant);
		} else {
			tenant_host = g_strconcat(tenant, ".onmicrosoft.com", NULL);
		}
		
	} else {
#ifdef ENABLE_TEAMS_PERSONAL
		tenant_host = g_strdup("consumers");
#else
		tenant_host = g_strdup("organizations");
#endif
	}

	return tenant_host;
}


typedef struct {
	gpointer unused1;
	gpointer unused2;
	gpointer unused3;
	gpointer unused4;
	gpointer unused5;
	int unused6;
	int unused7;
	int unused8;
	int unused9;
	
	gpointer set;
} bitlbee_account_t;

typedef struct {
	bitlbee_account_t *acc;
} bitlbee_im_connection;

static gpointer bitlbee_module;
static bitlbee_im_connection *(*bitlbee_purple_ic_by_pa)(PurpleAccount *);
static int (*bitlbee_set_setstr)(gpointer *, const char *, const char *);
static gboolean bitlbee_password_funcs_loaded = FALSE;

#ifdef _WIN32
#ifndef dlerror
static gchar *last_dlopen_error = NULL;
#	define dlerror()               (g_free(last_dlopen_error),last_dlopen_error=g_win32_error_message(GetLastError()))
#endif
#endif

static void
save_bitlbee_password(PurpleAccount *account, const gchar *password)
{
	bitlbee_account_t *acc;
	bitlbee_im_connection *imconn;

	gboolean result = GPOINTER_TO_INT(purple_signal_emit_return_1(purple_accounts_get_handle(), "bitlbee-set-account-password", account, password));

	if (result) {
		return;
	}
	
	if (bitlbee_password_funcs_loaded == FALSE) {
		bitlbee_module = dlopen(NULL, RTLD_LAZY);
		if (bitlbee_module == NULL) {
			purple_debug_error("teams", "Couldn't acquire address of bitlbee handle: %s\n", dlerror());
			g_return_if_fail(bitlbee_module);
		}
		
		bitlbee_purple_ic_by_pa = (gpointer) dlsym(bitlbee_module, "purple_ic_by_pa");
		bitlbee_set_setstr = (gpointer) dlsym(bitlbee_module, "set_setstr");
		
		bitlbee_password_funcs_loaded = TRUE;
	}
	
	imconn = bitlbee_purple_ic_by_pa(account);
	acc = imconn->acc;
	bitlbee_set_setstr(&acc->set, "password", password ? password : "");
}



static void
teams_save_refresh_token_password(PurpleAccount *account, const gchar *password)
{
	purple_account_set_password(account, password, NULL, NULL);
	
	if (g_strcmp0(purple_core_get_ui(), "BitlBee") == 0) {
		save_bitlbee_password(account, password);
	}
}


static void
teams_login_did_got_api_skypetoken(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	const gchar *data;
	gsize len;
	JsonObject *obj, *tokens;
	gchar *error = NULL;
	PurpleConnectionError error_type = PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
	const gchar *skypeToken;

	data = purple_http_response_get_data(response, &len);
	
	//purple_debug_misc("teams", "Full skypetoken response: %s\n", data);
	
	obj = json_decode_object(data, len);

	if (!json_object_has_member(obj, "tokens") && !json_object_has_member(obj, "skypeToken")) {
		JsonObject *status = json_object_get_object_member(obj, "status");
		
		if (status) {
			//{"status":{"code":40120,"text":"Authentication failed. Bad username or password."}}
			error = g_strdup_printf(_("Login error: %s (code %" G_GINT64_FORMAT ")"),
				json_object_get_string_member(status, "text"),
				json_object_get_int_member(status, "code")
			);
			error_type = PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;
		
		} else {
			//{"errorCode":"UserLicenseNotPresentForbidden","message":"User Login. Teams is disabled in user licenses"}
			error = g_strdup_printf(_("Login error: %s (code %" G_GINT64_FORMAT ")"),
				json_object_get_string_member(obj, "message"),
				json_object_get_int_member(obj, "errorCode")
			);
			error_type = PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;
			
		}
		goto fail;
	}

	if (json_object_has_member(obj, "tokens")) {
		tokens = json_object_get_object_member(obj, "tokens");
		skypeToken = json_object_get_string_member(tokens, "skypeToken");
	} else {
		tokens = json_object_get_object_member(obj, "skypeToken");
		skypeToken = json_object_get_string_member(tokens, "skypetoken");
	}

	if (sa->skype_token) g_free(sa->skype_token);
	sa->skype_token = g_strdup(skypeToken);
	
	gint64 expiresIn = json_object_get_int_member(tokens, "expiresIn");
	if (sa->refresh_token_timeout) 
		g_source_remove(sa->refresh_token_timeout);
	sa->refresh_token_timeout = g_timeout_add_seconds(expiresIn - 5, (GSourceFunc)teams_oauth_refresh_token, sa);
	//set_timeout
	
	if (sa->region) g_free(sa->region);
	if (json_object_has_member(obj, "region")) {
		sa->region = g_strdup(json_object_get_string_member(obj, "region"));
	} else {
		sa->region = NULL;
	}

	teams_do_all_the_things(sa);

	json_object_unref(obj);
	return;
fail:
	purple_connection_error(sa->pc, error_type,
		error ? error : _("Failed getting Skype Token (alt)"));

	g_free(error);
	json_object_unref(obj);
}

static void
teams_login_get_api_skypetoken(TeamsAccount *sa, const gchar *url, const gchar *username, const gchar *password)
{
	PurpleHttpRequest *request;
	JsonObject *obj = NULL;
	gchar *postdata = NULL;
	
	if (url == NULL) {
#ifdef ENABLE_TEAMS_PERSONAL
		url = "https://teams.live.com/api/auth/v1.0/authz/consumer";
#else
		url = "https://teams.microsoft.com/api/authsvc/v1.0/authz";
#endif // ENABLE_TEAMS_PERSONAL
	}
	
	request = purple_http_request_new(url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_method(request, "POST");

	obj = json_object_new();

	if (username) {
		json_object_set_string_member(obj, "username", username);
		json_object_set_string_member(obj, "passwordHash", password);
		json_object_set_string_member(obj, "scopes", "client");
		postdata = teams_jsonobj_to_string(obj);
		purple_http_request_set_contents(request, postdata ? postdata : "", -1);
		purple_http_request_header_set(request, "Content-Type", "application/json");
	} else {
		purple_http_request_header_set_printf(request, "Authorization", "Bearer %s", password);
	}

	purple_http_request_header_set(request, "Accept", "application/json; ver=1.0");
	purple_http_request(sa->pc, request, teams_login_did_got_api_skypetoken, sa);
	purple_http_request_unref(request);

	g_free(postdata);
	json_object_unref(obj);
}

#define TEAMS_WORK_OAUTH_CLIENT_ID "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
#define TEAMS_PERSONAL_OAUTH_CLIENT_ID "8ec6bc83-69c8-4392-8f08-b3c986009232"
#define TEAMS_OAUTH_RESOURCE "https://api.spaces.skype.com"
#ifdef ENABLE_TEAMS_PERSONAL
#	define TEAMS_OAUTH_CLIENT_ID TEAMS_PERSONAL_OAUTH_CLIENT_ID
#	define TEAMS_OAUTH_SERVICE "service::api.fl.teams.microsoft.com::MBI_SSL"
#	define TEAMS_SKYPETOKEN_SERVICE "service::api.fl.spaces.skype.com::MBI_SSL"
#else
#	define TEAMS_OAUTH_CLIENT_ID TEAMS_WORK_OAUTH_CLIENT_ID
#	define TEAMS_OAUTH_SERVICE TEAMS_OAUTH_RESOURCE "/.default"
#	define TEAMS_SKYPETOKEN_SERVICE TEAMS_OAUTH_SERVICE
#endif // ENABLE_TEAMS_PERSONAL
#	define TEAMS_OAUTH_SCOPE TEAMS_OAUTH_SERVICE " openid profile offline_access"
#define TEAMS_OAUTH_REDIRECT_URI "https://login.microsoftonline.com/common/oauth2/nativeclient"

// Personal client id maybe: 4b3e8f46-56d3-427f-b1e2-d239b2ea6bca
// Personal tenant id: 9188040d-6c67-4c5b-b112-36a304b66dad
// Old personal client id: 8ec6bc83-69c8-4392-8f08-b3c986009232
// redirect_uri  msauth.com.microsoft.teams://auth (mac)  x-msauth-ms-st://com.microsoft.skype.teams (iphone)
// scope=service%3a%3aapi.fl.teams.microsoft.com%3a%3aMBI_SSL+openid+profile+offline_access    service::api.fl.teams.microsoft.com::MBI_SSL
// scope = service::api.fl.spaces.skype.com::MBI_SSL
// scope	https://converged.signin.teams.microsoft.com/User.Read openid profile offline_access

static void
teams_oauth_refreshed_skypetoken_access(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj;
	const gchar *raw_response;
	gsize response_len;

	raw_response = purple_http_response_get_data(response, &response_len);
	obj = json_decode_object(raw_response, response_len);

	if (obj)
	{
		if (purple_http_response_is_successful(response))
		{
			const gchar *id_token = json_object_get_string_member(obj, "access_token");
			
			teams_login_get_api_skypetoken(sa, NULL, NULL, id_token);
		}
		json_object_unref(obj);
	}
}

static void
teams_oauth_with_code_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj;
	const gchar *raw_response;
	gsize response_len;
	PurpleAccount *account = sa->account;

	raw_response = purple_http_response_get_data(response, &response_len);
	obj = json_decode_object(raw_response, response_len);

	if (purple_http_response_is_successful(response) && obj)
	{
		const gchar *id_token = json_object_get_string_member(obj, "access_token");

		if (sa->id_token) {
			g_free(sa->id_token);
		}
		sa->id_token = g_strdup(id_token);
		if (json_object_has_member(obj, "refresh_token")) {
			if (sa->refresh_token != NULL) {
				g_free(sa->refresh_token);
			}
			sa->refresh_token = g_strdup(json_object_get_string_member(obj, "refresh_token"));
		
			purple_account_set_remember_password(account, TRUE);
			teams_save_refresh_token_password(account, sa->refresh_token);
		}
	} else {
		if (obj != NULL) {
			if (json_object_has_member(obj, "error")) {
				const gchar *error = json_object_get_string_member(obj, "error");
				if (g_strcmp0(error, "invalid_grant") == 0 || g_strcmp0(error, "interaction_required") == 0) {
					teams_save_refresh_token_password(sa->account, NULL);
					purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
						json_object_get_string_member(obj, "error_description"));
				} else {
					purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
						json_object_get_string_member(obj, "error_description"));
				}
			} else {
				purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, 
					_("Invalid response"));
			}
		}
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Invalid response"));
	}

	json_object_unref(obj);
}

static void
teams_presence_oauth_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj;
	const gchar *raw_response;
	gsize response_len;

	raw_response = purple_http_response_get_data(response, &response_len);
	obj = json_decode_object(raw_response, response_len);

	if (purple_http_response_is_successful(response) && obj)
	{
		gchar *presence_access_token = g_strdup(json_object_get_string_member(obj, "access_token"));
		if (sa->presence_access_token) {
			g_free(sa->presence_access_token);
		}
		sa->presence_access_token = presence_access_token;
	}

	json_object_unref(obj);
}

static void
teams_csa_oauth_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj;
	const gchar *raw_response;
	gsize response_len;

	raw_response = purple_http_response_get_data(response, &response_len);
	obj = json_decode_object(raw_response, response_len);

	if (purple_http_response_is_successful(response) && obj)
	{
		gchar *csa_access_token = g_strdup(json_object_get_string_member(obj, "access_token"));
		if (sa->csa_access_token) {
			g_free(sa->csa_access_token);
		}
		sa->csa_access_token = csa_access_token;
	}

	json_object_unref(obj);
}

static void
teams_substrate_oauth_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj;
	const gchar *raw_response;
	gsize response_len;

	raw_response = purple_http_response_get_data(response, &response_len);
	obj = json_decode_object(raw_response, response_len);

	if (purple_http_response_is_successful(response) && obj)
	{
		gchar *substrate_access_token = g_strdup(json_object_get_string_member(obj, "access_token"));
		if (sa->substrate_access_token) {
			g_free(sa->substrate_access_token);
		}
		sa->substrate_access_token = substrate_access_token;
	}

	json_object_unref(obj);
}

static void
teams_oauth_refresh_token_for_scope(TeamsAccount *sa, const gchar *scope, PurpleHttpCallback callback) 
{
	PurpleHttpRequest *request;
	PurpleConnection *pc;
	GString *postdata;
	const gchar *tenant_host;
	gchar *auth_url;

	pc = sa->pc;
	if (!PURPLE_IS_CONNECTION(pc)) {
		return;
	}

	postdata = g_string_new(NULL);
	g_string_append_printf(postdata, "scope=%s&", purple_url_encode(scope));
	g_string_append_printf(postdata, "client_id=%s&", purple_url_encode(TEAMS_OAUTH_CLIENT_ID));
	g_string_append(postdata, "grant_type=refresh_token&");
	g_string_append_printf(postdata, "refresh_token=%s&", purple_url_encode(sa->refresh_token));
	
	tenant_host = teams_get_tenant_host(sa->tenant);
	auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/v2.0/token", NULL);
	
	request = purple_http_request_new(auth_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request_set_method(request, "POST");
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
	purple_http_request_set_contents(request, postdata->str, postdata->len);

	purple_http_request(pc, request, callback, sa);
	purple_http_request_unref(request);
	
	g_string_free(postdata, TRUE);
	
	g_free(auth_url);
	return;
}

void
teams_oauth_refresh_token_for_resource(TeamsAccount *sa, const gchar *resource, PurpleHttpCallback callback)
{
	gchar *scope = g_strdup_printf("%s/.default openid profile offline_access", resource);
	teams_oauth_refresh_token_for_scope(sa, scope, callback);
	g_free(scope);
}

static void
teams_oauth_refresh_services(TeamsAccount *sa)
{

#ifdef ENABLE_TEAMS_PERSONAL
	teams_oauth_refresh_token_for_scope(sa, "service::api.fl.spaces.skype.com::MBI_SSL openid profile offline_access", teams_oauth_refreshed_skypetoken_access);
	teams_oauth_refresh_token_for_scope(sa, "https://substrate.office.com/M365.Access openid profile offline_access", teams_substrate_oauth_cb);

	// TODO do we need to register these?
	(void) teams_presence_oauth_cb;
	(void) teams_csa_oauth_cb;
#else
	teams_oauth_refresh_token_for_resource(sa, TEAMS_OAUTH_RESOURCE, teams_oauth_refreshed_skypetoken_access);
	teams_oauth_refresh_token_for_resource(sa, "https://substrate.office.com", teams_substrate_oauth_cb);
	teams_oauth_refresh_token_for_resource(sa, "https://" TEAMS_PRESENCE_HOST, teams_presence_oauth_cb);
	teams_oauth_refresh_token_for_resource(sa, "https://chatsvcagg.teams.microsoft.com", teams_csa_oauth_cb);
#endif // ENABLE_TEAMS_PERSONAL
	
}

gboolean
teams_oauth_refresh_token(TeamsAccount *sa)
{
	teams_oauth_refresh_token_for_scope(sa, TEAMS_OAUTH_SCOPE, teams_oauth_with_code_cb);
	teams_oauth_refresh_services(sa);

	// For working with purple_timeout_add()
	return FALSE;
}

void
teams_oauth_with_code(TeamsAccount *sa, const gchar *auth_code)
{
	PurpleHttpRequest *request;
	PurpleConnection *pc = sa->pc;
	GString *postdata;
	const gchar *tenant_host;
	gchar *auth_url;
	
	if (strstr(auth_code, "nativeclient")) {
		gchar *tmp = strchr(auth_code, '?');
		if (tmp == NULL) {
			//todo error
			return;
		}
		auth_code = tmp + 1;
		
		tmp = strstr(auth_code, "code=");
		if (tmp == NULL) {
			//todo error
			return;
		}
		auth_code = tmp + 5;
		
		tmp = strchr(auth_code, '&');
		if (tmp != NULL) {
			*tmp = '\0';
		}
		
		auth_code = purple_url_decode(auth_code);
	}

	postdata = g_string_new(NULL);
	//g_string_append(postdata, "resource=" TEAMS_OAUTH_RESOURCE "&");
	g_string_append_printf(postdata, "scope=%s&", purple_url_encode(TEAMS_OAUTH_SCOPE));
	g_string_append_printf(postdata, "client_id=%s&", purple_url_encode(TEAMS_OAUTH_CLIENT_ID));
	g_string_append(postdata, "grant_type=authorization_code&");
	g_string_append_printf(postdata, "code=%s&", purple_url_encode(auth_code));
	g_string_append_printf(postdata, "redirect_uri=%s&", purple_url_encode(TEAMS_OAUTH_REDIRECT_URI));

	tenant_host = teams_get_tenant_host(sa->tenant);
	auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/v2.0/token", NULL);

	request = purple_http_request_new(auth_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request_set_method(request, "POST");
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
	purple_http_request_set_contents(request, postdata->str, postdata->len);

	purple_http_request(pc, request, teams_oauth_with_code_cb, sa);
	purple_http_request_unref(request);
	
	g_string_free(postdata, TRUE);
	g_free(auth_url);
}

static void
teams_authcode_input_cb(gpointer user_data, const gchar *auth_code)
{
	TeamsAccount *sa = user_data;
	PurpleConnection *pc = sa->pc;

	purple_connection_update_progress(pc, _("Authenticating"), 1, 3);
	teams_oauth_with_code(sa, auth_code);
}

static void
teams_authcode_input_cancel_cb(gpointer user_data)
{
	TeamsAccount *sa = user_data;
	purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE, _("User cancelled authorization"));
}

void
teams_do_web_auth(TeamsAccount *sa)
{
	PurpleConnection *pc = sa->pc;
	const gchar *tenant_host;
	gchar *auth_url;
	
	//https://login.microsoftonline.com/organizations/oauth2/authorize?resource=https%3A%2F%2Fapi.spaces.skype.com&client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&response_type=code&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&prompt=select_account&display=popup&amr_values=mfa
	
	tenant_host = teams_get_tenant_host(sa->tenant);

	auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/authorize?client_id=", TEAMS_OAUTH_CLIENT_ID, "&response_type=code&display=popup&prompt=select_account&amr_values=mfa&redirect_uri=", purple_url_encode(TEAMS_OAUTH_REDIRECT_URI), NULL);
	
	purple_notify_uri(pc, auth_url);
	purple_request_input(pc, _("Authorization Code"), auth_url,
		_("Please login in your browser"),
		_("and then paste the URL of the blank page here (should contain 'nativeclient')"), FALSE, FALSE, NULL, 
		_("OK"), G_CALLBACK(teams_authcode_input_cb), 
		_("Cancel"), G_CALLBACK(teams_authcode_input_cancel_cb), 
		purple_request_cpar_from_connection(pc), sa);
	
	g_free(auth_url);
}

static gboolean
teams_devicecode_login_expires_cb(gpointer user_data)
{
	TeamsAccount *sa = user_data;
	purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Device code expired"));
	return FALSE;
}

static void
teams_devicecode_login_poll_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj;
	const gchar *raw_response;
	gsize response_len;

	raw_response = purple_http_response_get_data(response, &response_len);
	obj = json_decode_object(raw_response, response_len);

	if (purple_http_response_is_successful(response) && obj)
	{
		const gchar *access_token = json_object_get_string_member(obj, "access_token");
		if (sa->id_token) g_free(sa->id_token);
		sa->id_token = g_strdup(access_token);

		purple_notify_close_with_handle(sa->pc);
		if (json_object_has_member(obj, "refresh_token")) {
			if (sa->refresh_token != NULL) {
				g_free(sa->refresh_token);
			}
			sa->refresh_token = g_strdup(json_object_get_string_member(obj, "refresh_token"));
		
			purple_account_set_remember_password(sa->account, TRUE);
			teams_save_refresh_token_password(sa->account, sa->refresh_token);
		}
		
		teams_oauth_refresh_services(sa);

		g_free(sa->login_device_code);
		sa->login_device_code = NULL;
		g_source_remove(sa->login_device_code_expires_timeout);
		sa->login_device_code_expires_timeout = 0;
		g_source_remove(sa->login_device_code_timeout);
		sa->login_device_code_timeout = 0;
	} else {
		if (obj != NULL) {
			if (json_object_has_member(obj, "error")) {
				const gchar *error = json_object_get_string_member(obj, "error");
				if (purple_strequal(error, "invalid_grant") || purple_strequal(error, "interaction_required")) {
					teams_save_refresh_token_password(sa->account, NULL);
					purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
						json_object_get_string_member(obj, "error_description"));
				} else if (purple_strequal(error, "authorization_pending")) {
					// Do nothing, just wait for the next poll
				} else {
					purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
						json_object_get_string_member(obj, "error_description"));
				}
			} else {
				purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, 
					_("Invalid response"));
			}
		}
	}

	json_object_unref(obj);

}

static gboolean
teams_devicecode_login_poll(gpointer user_data)
{
	TeamsAccount *sa = user_data;
	PurpleConnection *pc = sa->pc;
	const gchar *tenant_host;
	gchar *auth_url;
	GString *postdata;
	PurpleHttpRequest *request;

#ifdef ENABLE_TEAMS_PERSONAL
	tenant_host = "common";
#else
	tenant_host = teams_get_tenant_host(sa->tenant);
#endif // ENABLE_TEAMS_PERSONAL
	auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/token", NULL);

	postdata = g_string_new(NULL);
	g_string_append_printf(postdata, "client_id=%s&", TEAMS_OAUTH_CLIENT_ID);
	g_string_append(postdata, "grant_type=urn:ietf:params:oauth:grant-type:device_code&");
	g_string_append_printf(postdata, "code=%s", purple_url_encode(sa->login_device_code));
	
	request = purple_http_request_new(auth_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request_set_method(request, "POST");
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
	purple_http_request_set_contents(request, postdata->str, postdata->len);

	purple_http_request(pc, request, teams_devicecode_login_poll_cb, sa);
	purple_http_request_unref(request);
	
	g_string_free(postdata, TRUE);
	g_free(auth_url);
	
	return TRUE;
}

static void
teams_devicecode_login_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj;
	const gchar *raw_response;
	gsize response_len;

	raw_response = purple_http_response_get_data(response, &response_len);
	obj = json_decode_object(raw_response, response_len);

	if (purple_http_response_is_successful(response) && obj)
	{
		const gchar *device_code = json_object_get_string_member(obj, "device_code");
		const gchar *user_code = json_object_get_string_member(obj, "user_code");
		const gchar *verification_url = json_object_get_string_member(obj, "verification_url");
		gint interval = (int) json_object_get_int_member(obj, "interval");
		gint expires_in = (int) json_object_get_int_member(obj, "expires_in");
		gchar *message;

		if (interval == 0) {
			const gchar *interval_str = json_object_get_string_member(obj, "interval");
			if (interval_str != NULL) {
				interval = atoi(interval_str);
			}
		}
		if (expires_in == 0) {
			const gchar *expires_in_str = json_object_get_string_member(obj, "expires_in");
			if (expires_in_str != NULL) {
				expires_in = atoi(expires_in_str);
			}
		}
		if (verification_url == NULL) {
			verification_url = json_object_get_string_member(obj, "verification_uri");
		}
		
		if (json_object_has_member(obj, "message")) {
			message = g_strdup(json_object_get_string_member(obj, "message"));
		} else {
			message = g_strdup_printf(_("To sign in, use a web browser to open the page %s and enter the code %s to authenticate."), verification_url, user_code);
		}

		purple_notify_uri(sa->pc, verification_url);
		purple_notify_message(sa->pc, PURPLE_NOTIFY_MSG_INFO, _("Authorization Code"),
			message, NULL, NULL, NULL);

		if (g_strcmp0(purple_core_get_ui(), "spectrum") == 0) {
			purple_serv_got_im(sa->pc, "TeamsLogin", message, PURPLE_MESSAGE_RECV, time(NULL));
		}
		
		g_free(message);
		
		if (sa->login_device_code) g_free(sa->login_device_code);
		sa->login_device_code = g_strdup(device_code);

		if (sa->login_device_code_timeout) 
			g_source_remove(sa->login_device_code_timeout);
		sa->login_device_code_timeout = g_timeout_add_seconds(interval, (GSourceFunc)teams_devicecode_login_poll, sa);
		
		if (sa->login_device_code_expires_timeout) 
			g_source_remove(sa->login_device_code_expires_timeout);
		sa->login_device_code_expires_timeout = g_timeout_add_seconds(expires_in, (GSourceFunc)teams_devicecode_login_expires_cb, sa);
		
	} else {
		if (obj != NULL) {
			if (json_object_has_member(obj, "error")) {
				const gchar *error = json_object_get_string_member(obj, "error");
				if (g_strcmp0(error, "invalid_grant") == 0 || g_strcmp0(error, "interaction_required") == 0) {
					teams_save_refresh_token_password(sa->account, NULL);
					purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
						json_object_get_string_member(obj, "error_description"));
				} else {
					purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
						json_object_get_string_member(obj, "error_description"));
				}
			} else {
				purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, 
					_("Invalid response"));
			}
		}
	}

	json_object_unref(obj);
}

void
teams_do_devicecode_login(TeamsAccount *sa) 
{
	PurpleConnection *pc = sa->pc;
	const gchar *tenant_host;
	gchar *auth_url;
	GString *postdata;
	PurpleHttpRequest *request;

#ifdef ENABLE_TEAMS_PERSONAL
	tenant_host = "common";
#else	
	tenant_host = teams_get_tenant_host(sa->tenant);
#endif // ENABLE_TEAMS_PERSONAL

	auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/devicecode", NULL);
	//auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/v2.0/devicecode", NULL);

	postdata = g_string_new(NULL);
	g_string_append_printf(postdata, "client_id=%s&", TEAMS_OAUTH_CLIENT_ID);
	g_string_append(postdata, "resource=" TEAMS_OAUTH_RESOURCE "&");
	//g_string_append_printf(postdata, "scope=%s&", purple_url_encode(TEAMS_OAUTH_SCOPE));

	request = purple_http_request_new(auth_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request_set_method(request, "POST");
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
	purple_http_request_set_contents(request, postdata->str, postdata->len);

	purple_http_request(pc, request, teams_devicecode_login_cb, sa);
	purple_http_request_unref(request);
	
	g_string_free(postdata, TRUE);
	g_free(auth_url);
}


// Places to find tenant id's you can use:
// https://portal.azure.com/#settings/directory
// https://api.myaccount.microsoft.com/api/organizations triggered by https://myaccount.microsoft.com/organizations
// https://graph.microsoft.com/beta/tenantRelationships/getResourceTenants?$select=tenantId,displayName
// https://teams.microsoft.com/api/mt/apac/beta/users/tenants
// https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties
