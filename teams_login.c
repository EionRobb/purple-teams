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
#include "teams_contacts.h"	/* Personal/TFL: teams_get_friend_list (mt-token re-fetch) */
#include "http.h"


#define TEAMS_GUID_REGEX_PATTERN "^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$"

void
teams_logout(TeamsAccount *sa)
{
	//teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_LOGIN_HOST, "/logout", NULL, NULL, NULL, TRUE);
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



/* Personal/TFL: the OAuth refresh_token is persisted as the account password so
 * steady-state logins take the silent refresh path (teams_oauth_refresh_token)
 * with no device code. teams_load_refresh_token_password() reads it back at login. */
gchar *
teams_load_refresh_token_password(PurpleAccount *account)
{
	const gchar *password = purple_account_get_password(account);
	if (password == NULL || *password == '\0')
		return NULL;
	/* The "devicecode" and "webauth:<url>" sentinels are login-flow selectors, not
	 * refresh tokens. Return NULL for them so the caller falls through to the
	 * device-code / auth-code paths instead of POSTing the sentinel to the token
	 * endpoint. */
	if (purple_strequal(password, "devicecode") || g_str_has_prefix(password, "webauth:"))
		return NULL;
	return g_strdup(password); /* caller frees */
}

static void
teams_save_refresh_token_password(PurpleAccount *account, const gchar *password)
{
	/* NULL/empty clears it, e.g. on invalid_grant so the next login cleanly
	 * falls back to the device-code flow. */
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
#	define TEAMS_OAUTH_SERVICE "https://mtsvc.fl.teams.microsoft.com/teams.mt.readwrite"
#	define TEAMS_SKYPETOKEN_SERVICE "service::api.fl.spaces.skype.com::MBI_SSL"
#else
#	define TEAMS_OAUTH_CLIENT_ID TEAMS_WORK_OAUTH_CLIENT_ID
#	define TEAMS_OAUTH_SERVICE TEAMS_OAUTH_RESOURCE "/.default"
#	define TEAMS_SKYPETOKEN_SERVICE TEAMS_OAUTH_SERVICE
#endif // ENABLE_TEAMS_PERSONAL
#	define TEAMS_OAUTH_SCOPE TEAMS_OAUTH_SERVICE " openid profile offline_access"
#ifdef ENABLE_TEAMS_PERSONAL
/* Personal/MSA: v2.0 for this Teams client only accepts the NATIVE app redirect (web redirects get
 * invalid_request). The embedding browser intercepts the msauth...://auth?code= navigation and returns the
 * code; this MUST match the redirect_uri the app put in the authorize request, and is sent again here
 * at the /oauth2/v2.0/token exchange (AAD requires authorize/redeem redirect_uri to match). */
#define TEAMS_OAUTH_REDIRECT_URI "msauth.com.microsoft.teams://auth"
#else
#define TEAMS_OAUTH_REDIRECT_URI "https://login.microsoftonline.com/common/oauth2/nativeclient"
#endif

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

/* Personal/TFL: fetch a token for the personal mt/beta endpoints (which reject
 * the mtsvc-audience id_token with 401). Store it and re-run the friend-list fetch
 * now that the correct token is available (the first fetch, kicked off by
 * teams_do_all_the_things, likely raced ahead of this token and 401'd). */
static void
teams_mt_oauth_cb(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	JsonObject *obj;
	const gchar *raw_response;
	gsize response_len;

	raw_response = purple_http_response_get_data(response, &response_len);
	obj = json_decode_object(raw_response, response_len);

	if (purple_http_response_is_successful(response) && obj)
	{
		const gchar *tok = json_object_get_string_member(obj, "access_token");
		g_free(sa->mt_access_token);
		sa->mt_access_token = g_strdup(tok);
		purple_debug_info("teams", "MT-TOKEN acquired for mt/beta; re-fetching mt/beta contacts\n");
		/* Only the mt/beta endpoints depend on this token — retry just those, not the
		 * whole friend-list pipeline (which already ran from teams_do_all_the_things). */
		teams_get_mt_beta_contacts(sa);
	} else {
		purple_debug_info("teams", "MT-TOKEN fetch failed (code %d)\n",
			purple_http_response_get_code(response));
	}

	if (obj) json_object_unref(obj);
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

	/* Personal/TFL: dedicated Bearer for the consumer mt/beta endpoints
	 * (teams.live.com/api/mt/beta/…). VERIFIED live against MS: mt/beta needs
	 * Bearer<mtsvc> + X-Skypetoken together (see teams_connection.c). The correct
	 * audience is the MT read/write service — the SAME scope the browser login used
	 * (https://mtsvc.fl.teams.microsoft.com/teams.mt.readwrite). teams_mt_oauth_cb
	 * stores it as sa->mt_access_token and re-fetches the friend list.
	 * (The earlier api.spaces.skype.com audience was wrong and always 401'd.) */
	teams_oauth_refresh_token_for_scope(sa, "https://mtsvc.fl.teams.microsoft.com/teams.mt.readwrite openid profile offline_access", teams_mt_oauth_cb);

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
	
	/* If handed a full redirect URL rather than a bare code, extract the code. Covers BOTH the work
	 * "...nativeclient?code=<code>&..." web redirect AND the personal/MSA native scheme
	 * "msauth.com.microsoft.teams://auth?code=<code>&..." (captured by the embedding browser's navigation hook).
	 * A bare code has no "code=" substring, so it passes through untouched. Work on a private copy so
	 * we never mutate the caller's credential string. */
	gchar *code_copy = NULL;
	{
		const gchar *cp = strstr(auth_code, "code=");
		if (cp != NULL) {
			code_copy = g_strdup(cp + 5);
			gchar *amp = strchr(code_copy, '&');
			if (amp != NULL) {
				*amp = '\0';
			}
			/* purple_url_decode returns a static-buffer pointer valid until the next call */
			auth_code = purple_url_decode(code_copy);
		}
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
	g_free(code_copy);
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
		_("and then paste the URL of the blank page here (it will contain '" TEAMS_OAUTH_REDIRECT_URI "')"), FALSE, FALSE, NULL,
		_("OK"), G_CALLBACK(teams_authcode_input_cb), 
		_("Cancel"), G_CALLBACK(teams_authcode_input_cancel_cb), 
		purple_request_cpar_from_connection(pc), sa);
	
	g_free(auth_url);
}

/* Personal/TFL: headless auth-code login. An embedding browser
 * signs the user in and captures the redirect to
 * .../oauth2/nativeclient?code=<code>; the Teams app stores that redirect URL as
 * the account credential ("webauth:<url>"). Here we hand it straight to
 * teams_oauth_with_code (which strips everything up to "code=") — no interactive
 * purple_request_input (which the headless transport can't service, unlike
 * teams_do_web_auth). On success teams_oauth_with_code_cb persists the
 * refresh_token, so the next login takes the silent refresh path. */
void
teams_do_authcode_login(TeamsAccount *sa, const gchar *code_or_url)
{
	purple_connection_update_progress(sa->pc, _("Authenticating"), 1, 3);
	teams_oauth_with_code(sa, code_or_url);
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
	purple_http_request_header_set(request, "User-Agent", TEAMS_USER_AGENT);
	purple_http_request_header_set(request, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8");
	purple_http_request_header_set(request, "Accept-Language", "en-US,en;q=0.5");
	purple_http_request_header_set(request, "Connection", "keep-alive");
	purple_http_request_header_set(request, "Upgrade-Insecure-Requests", "1");
	purple_http_request_header_set(request, "Sec-Fetch-Dest", "document");
	purple_http_request_header_set(request, "Sec-Fetch-Mode", "navigate");
	purple_http_request_header_set(request, "Sec-Fetch-Site", "none");
	purple_http_request_header_set(request, "Sec-Fetch-User", "?1");
	purple_http_request_header_set(request, "Priority", "u=0, i");
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

		/* Personal/TFL: headless UIs (transports such as spectrum and the webOS
		 * "adapter") implement no interactive purple_notify UI, so the notify_message/
		 * notify_uri above are invisible to the user. Only for those UIs, also deliver
		 * the sign-in instructions (verification URL + user code) as an incoming IM from
		 * a synthetic "TeamsLogin" buddy so they surface through the conversation uiops.
		 * Interactive UIs (Pidgin, bitlbee) already showed the notify and must not get a
		 * duplicate. Detect headless by the absence of a notify_message uiop (with a
		 * known-headless UI-id fallback). Always log it for retrieval from the debug log. */
		PurpleNotifyUiOps *notify_ops = purple_notify_get_ui_ops();
		const gchar *core_ui = purple_core_get_ui();
		gboolean headless_ui = (notify_ops == NULL || notify_ops->notify_message == NULL)
			|| purple_strequal(core_ui, "spectrum") || purple_strequal(core_ui, "adapter");

		purple_debug_info("teams", "DEVICE-CODE-LOGIN: %s\n", message);
		if (headless_ui)
			purple_serv_got_im(sa->pc, "TeamsLogin", message, PURPLE_MESSAGE_RECV, time(NULL));

		g_free(message);
		
		if (sa->login_device_code) g_free(sa->login_device_code);
		sa->login_device_code = g_strdup(device_code);

		if (sa->login_device_code_timeout) 
			g_source_remove(sa->login_device_code_timeout);
		sa->login_device_code_timeout = g_timeout_add_seconds(interval, (GSourceFunc)teams_devicecode_login_poll, sa);
		
		if (sa->login_device_code_expires_timeout)
			g_source_remove(sa->login_device_code_expires_timeout);
		sa->login_device_code_expires_timeout = g_timeout_add_seconds(expires_in, (GSourceFunc)teams_devicecode_login_expires_cb, sa);

		/* Personal/TFL: some UIs/transports run a login watchdog that calls
		 * purple_account_disconnect if the account has not signed on within a short
		 * window. The device-code flow needs the user to authorise in a browser,
		 * which takes minutes -> the watchdog could kill the connection (and the
		 * in-memory device_code) before it completes. Mark the connection CONNECTED
		 * now so such a watchdog stands down and the poll loop can run the full
		 * expires_in window. The real login (token success -> libteams.c set_state
		 * CONNECTED) still runs and re-asserts CONNECTED, so this only pre-empts the
		 * watchdog; it does not skip any setup. First-time bootstrap only: once the
		 * refresh_token is saved as the password, subsequent logins take the fast
		 * refresh path with no device code. Headless UIs only: an interactive UI has
		 * no such watchdog and marking it CONNECTED early would let it flush buffered
		 * messages before login truly completes. */
		if (headless_ui)
			purple_connection_set_state(sa->pc, PURPLE_CONNECTION_CONNECTED);

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
	purple_http_request_header_set(request, "User-Agent", TEAMS_USER_AGENT);
	purple_http_request_header_set(request, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8");
	purple_http_request_header_set(request, "Accept-Language", "en-US,en;q=0.5");
	purple_http_request_header_set(request, "Connection", "keep-alive");
	purple_http_request_header_set(request, "Upgrade-Insecure-Requests", "1");
	purple_http_request_header_set(request, "Sec-Fetch-Dest", "document");
	purple_http_request_header_set(request, "Sec-Fetch-Mode", "navigate");
	purple_http_request_header_set(request, "Sec-Fetch-Site", "none");
	purple_http_request_header_set(request, "Sec-Fetch-User", "?1");
	purple_http_request_header_set(request, "Priority", "u=0, i");
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
