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

static void
teams_login_did_auth(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	gchar *refresh_token = NULL;
	TeamsAccount *sa = user_data;
	const gchar *data;
	gsize len;
	
	data = purple_http_response_get_data(response, &len);
	
	if (data != NULL) {
		refresh_token = teams_string_get_chunk(data, len, "=\"skypetoken\" value=\"", "\"");
	} else {
		purple_connection_error(sa->pc,
								PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
								_("Failed getting Skype Token, please try logging in via browser first"));
		return;
	}
	
	if (refresh_token == NULL) {
		purple_account_set_string(sa->account, "refresh-token", NULL);
		if (g_strstr_len(data, len, "recaptcha_response_field")) {
			purple_connection_error(sa->pc,
									PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
									_("Captcha required.\nTry logging into web.skype.com and try again."));
			return;
		} else {
			purple_debug_info("teams", "login response was %s\r\n", data);
			purple_connection_error(sa->pc,
									PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
									_("Failed getting Skype Token, please try logging in via browser first"));
			return;
		}
	}
	
	sa->skype_token = refresh_token;
	
	if (purple_account_get_remember_password(sa->account)) {
		purple_account_set_string(sa->account, "refresh-token", purple_http_cookie_jar_get(sa->cookie_jar, "refresh-token"));
	}
	
	teams_do_all_the_things(sa);
}

static void
teams_login_got_pie(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	PurpleAccount *account = sa->account;
	gchar *pie;
	gchar *etm;
	const gchar *login_url = "https://" TEAMS_LOGIN_HOST "/login?client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com";
	GString *postdata;
	struct timeval tv;
	struct timezone tz;
	gint tzhours, tzminutes;
	int tmplen;
	PurpleHttpRequest *request;
	const gchar *data;
	gsize len;
	
	if (!purple_http_response_is_successful(response)) {
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, purple_http_response_get_error(response));
		return;
	}
	
	data = purple_http_response_get_data(response, &len);
	
	gettimeofday(&tv, &tz);
	(void) tv;
	tzminutes = tz.tz_minuteswest;
	if (tzminutes < 0) tzminutes = -tzminutes;
	tzhours = tzminutes / 60;
	tzminutes -= tzhours * 60;
	
	pie = teams_string_get_chunk(data, len, "=\"pie\" value=\"", "\"");
	if (!pie) {
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Failed getting PIE value, please try logging in via browser first"));
		return;
	}
	
	etm = teams_string_get_chunk(data, len, "=\"etm\" value=\"", "\"");
	if (!etm) {
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Failed getting ETM value, please try logging in via browser first"));
		return;
	}
	
	
	postdata = g_string_new("");
	g_string_append_printf(postdata, "username=%s&", purple_url_encode(purple_account_get_username(account)));
	g_string_append_printf(postdata, "password=%s&", purple_url_encode(purple_connection_get_password(sa->pc)));
	g_string_append_printf(postdata, "timezone_field=%c|%d|%d&", (tz.tz_minuteswest < 0 ? '+' : '-'), tzhours, tzminutes);
	g_string_append_printf(postdata, "pie=%s&", purple_url_encode(pie));
	g_string_append_printf(postdata, "etm=%s&", purple_url_encode(etm));
	g_string_append_printf(postdata, "js_time=%" G_GINT64_FORMAT "&", teams_get_js_time());
	g_string_append(postdata, "client_id=578134&");
	g_string_append(postdata, "redirect_uri=https://web.skype.com/");

	tmplen = postdata->len;
	if (postdata->len > INT_MAX) tmplen = INT_MAX;
	
	request = purple_http_request_new(login_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "BehaviorOverride", "redirectAs404");
	purple_http_request_set_contents(request, postdata->str, tmplen);
	purple_http_request(sa->pc, request, teams_login_did_auth, sa);
	purple_http_request_unref(request);
	
	g_string_free(postdata, TRUE);
	g_free(pie);
	g_free(etm);
	
	purple_connection_update_progress(sa->pc, _("Authenticating"), 2, 4);
}

void
teams_begin_web_login(TeamsAccount *sa)
{
	const gchar *login_url = "https://" TEAMS_LOGIN_HOST "/login?method=skype&client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com";
	
	purple_http_get(sa->pc, teams_login_got_pie, sa, login_url);
	
	purple_connection_set_state(sa->pc, PURPLE_CONNECTION_CONNECTING);
	purple_connection_update_progress(sa->pc, _("Connecting"), 1, 4);
}

static void
teams_login_got_t(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	const gchar *login_url = "https://" TEAMS_LOGIN_HOST "/login/microsoft";
	PurpleHttpRequest *request;
	GString *postdata;
	gchar *magic_t_value; // T is for tasty
	gchar *error_code;
	gchar *error_text;
	int tmplen;
	const gchar *data;
	gsize len;
	
	data = purple_http_response_get_data(response, &len);
	
	// <input type="hidden" name="t" id="t" value="...">
	error_text = teams_string_get_chunk(data, len, ",sErrTxt:'", "',Am:'");
	error_code = teams_string_get_chunk(data, len, ",sErrorCode:'", "',Ag:");
	magic_t_value = teams_string_get_chunk(data, len, "=\"t\" value=\"", "\"");

	if (!magic_t_value) {
		//No Magic T????  Maybe it be the mighty 2fa-beast
		
		if (FALSE)
		/*if (g_strnstr(data, len, "Set-Cookie: LOpt=0;"))*/ {
			//XX - Would this be better retrieved with JSON decoding the "var ServerData = {...}" code?
			//     <script type="text/javascript">var ServerData = {...};</script>
			gchar *session_state = teams_string_get_chunk(data, len, ":'https://login.live.com/GetSessionState.srf?", "',");
			if (session_state) {
				//These two appear to have different object keys each request :(
				/*
				gchar *PPFT = teams_string_get_chunk(data, len, ",sFT:'", "',");
				gchar *SLK = teams_string_get_chunk(data, len, ",aB:'", "',");
				gchar *ppauth_cookie = teams_string_get_chunk(data, len, "Set-Cookie: PPAuth=", ";");
				gchar *mspok_cookie = teams_string_get_chunk(data, len, "Set-Cookie: MSPOK=", "; domain=");
				*/
				
				//Poll https://login.live.com/GetSessionState.srv?{session_state} to retrieve GIF(!!) of 2fa status
				//1x1 size GIF means pending, 2x2 rejected, 1x2 approved
				//Then re-request the MagicT, if approved with a slightly different GET parameters
				//purpose=eOTT_OneTimePassword&PPFT={ppft}&login={email}&SLK={slk}
				return;
			}
		}

		if (error_text) {
			GString *new_error;
			new_error = g_string_new("");
			g_string_append_printf(new_error, "%s: ", error_code);
			g_string_append_printf(new_error, "%s", error_text);

			gchar *error_msg = g_string_free(new_error, FALSE);

			purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, error_msg);
			g_free (error_msg);
			return;
		}

		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Failed getting Magic T value, please try logging in via browser first"));

		return;
	}
	
	// postdata: t=...&oauthPartner=999&client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com
	postdata = g_string_new("");
	g_string_append_printf(postdata, "t=%s&", purple_url_encode(magic_t_value));
	g_string_append(postdata, "site_name=lw.skype.com&");
	g_string_append(postdata, "oauthPartner=999&");
	g_string_append(postdata, "client_id=578134&");
	g_string_append(postdata, "redirect_uri=https%3A%2F%2Fweb.skype.com");

	tmplen = postdata->len;
	if (postdata->len > INT_MAX) tmplen = INT_MAX;

	// post the t to https://login.skype.com/login/oauth?client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com
	
	request = purple_http_request_new(login_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "BehaviorOverride", "redirectAs404");
	purple_http_request_set_contents(request, postdata->str, tmplen);
	purple_http_request_set_max_redirects(request, 0);
	purple_http_request(sa->pc, request, teams_login_did_auth, sa);
	purple_http_request_unref(request);
	
	g_string_free(postdata, TRUE);
	g_free(magic_t_value);
	
	purple_connection_update_progress(sa->pc, _("Verifying"), 3, 4);
}

static void
teams_login_got_opid(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	const gchar *live_login_url = "https://login.live.com" "/ppsecure/post.srf?wa=wsignin1.0&wp=MBI_SSL&wreply=https%3A%2F%2Flw.skype.com%2Flogin%2Foauth%2Fproxy%3Fsite_name%3Dlw.skype.com";
	gchar *ppft;
	gchar *opid;
	GString *postdata;
	PurpleHttpRequest *request;
	int tmplen;
	const gchar *data;
	gsize len;

	data = purple_http_response_get_data(response, &len);
	
	ppft = teams_string_get_chunk(data, len, ",sFT:'", "',");
	if (!ppft) {
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Failed getting PPFT value, please try logging in via browser first"));
		return;
	}
	opid = teams_string_get_chunk(data, len, "&opid=", "'");
	if (!opid) {
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Failed getting opid value, try using 'Alternate Auth Method' settings"));
		return;
	}
	postdata = g_string_new("");
	g_string_append_printf(postdata, "opid=%s&", purple_url_encode(opid));
	g_string_append(postdata, "site_name=lw.skype.com&");
	g_string_append(postdata, "oauthPartner=999&");
	g_string_append(postdata, "client_id=578134&");
	g_string_append(postdata, "redirect_uri=https%3A%2F%2Fweb.skype.com&");
	g_string_append_printf(postdata, "PPFT=%s&", purple_url_encode(ppft));
	g_string_append(postdata, "type=28&");

	tmplen = postdata->len;
	if (postdata->len > INT_MAX) tmplen = INT_MAX;
	
	request = purple_http_request_new(live_login_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_set_contents(request, postdata->str, tmplen);
	purple_http_request(sa->pc, request, teams_login_got_t, sa);
	purple_http_request_unref(request);
	
	g_string_free(postdata, TRUE);
	
	g_free(ppft);
	g_free(opid);
	
	purple_connection_update_progress(sa->pc, _("Authenticating"), 2, 4);
}

static void
teams_login_got_ppft(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	const gchar *live_login_url = "https://login.live.com" "/ppsecure/post.srf?wa=wsignin1.0&wp=MBI_SSL&wreply=https%3A%2F%2Flw.skype.com%2Flogin%2Foauth%2Fproxy%3Fsite_name%3Dlw.skype.com";
	gchar *cktst_cookie;
	gchar *ppft;
	GString *postdata;
	PurpleHttpRequest *request;
	int tmplen;
	const gchar *data;
	gsize len;

	data = purple_http_response_get_data(response, &len);
	
	// <input type="hidden" name="PPFT" id="i0327" value="..."/>
	ppft = teams_string_get_chunk(data, len, "name=\"PPFT\" id=\"i0327\" value=\"", "\"");
	if (!ppft) {
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Failed getting PPFT value, please try logging in via browser first"));
		return;
	}
	// CkTst=G + timestamp   e.g. G1422309314913
	cktst_cookie = g_strdup_printf("G%" G_GINT64_FORMAT, teams_get_js_time());
	purple_http_cookie_jar_set(sa->cookie_jar, "CkTst", cktst_cookie);
	
	// postdata: login={username}&passwd={password}&PPFT={ppft value}
	postdata = g_string_new("");
	g_string_append_printf(postdata, "login=%s&", purple_url_encode(purple_account_get_username(sa->account)));
	g_string_append_printf(postdata, "passwd=%s&", purple_url_encode(purple_connection_get_password(sa->pc)));
	g_string_append_printf(postdata, "PPFT=%s&", purple_url_encode(ppft));
	g_string_append(postdata, "loginoptions=3&");

	tmplen = postdata->len;
	if (postdata->len > INT_MAX) tmplen = INT_MAX;

	// POST to https://login.live.com/ppsecure/post.srf?wa=wsignin1.0&wreply=https%3A%2F%2Fsecure.skype.com%2Flogin%2Foauth%2Fproxy%3Fclient_id%3D578134%26redirect_uri%3Dhttps%253A%252F%252Fweb.skype.com
	
	request = purple_http_request_new(live_login_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_set_contents(request, postdata->str, tmplen);
	purple_http_request(sa->pc, request, teams_login_got_opid, sa);
	purple_http_request_unref(request);
	
	g_string_free(postdata, TRUE);
	
	g_free(cktst_cookie);
	g_free(ppft);
	
	purple_connection_update_progress(sa->pc, _("Authenticating"), 2, 4);
}

void
teams_begin_oauth_login(TeamsAccount *sa)
{
	const gchar *login_url = "https://" TEAMS_LOGIN_HOST "/login/oauth/microsoft?client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com";
	PurpleHttpRequest *request;
	
	request = purple_http_request_new(login_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_cookie_jar(request, sa->cookie_jar);
	purple_http_request(sa->pc, request, teams_login_got_ppft, sa);
	purple_http_request_unref(request);
	
	purple_connection_set_state(sa->pc, PURPLE_CONNECTION_CONNECTING);
	purple_connection_update_progress(sa->pc, _("Connecting"), 1, 4);
}

void
teams_logout(TeamsAccount *sa)
{
	teams_post_or_get(sa, TEAMS_METHOD_GET | TEAMS_METHOD_SSL, TEAMS_LOGIN_HOST, "/logout", NULL, NULL, NULL, TRUE);
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
			purple_debug_error("googlechat", "Couldn't acquire address of bitlbee handle: %s\n", dlerror());
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

void
teams_refresh_token_login(TeamsAccount *sa)
{
	PurpleAccount *account = sa->account;
	const gchar *login_url = "https://" TEAMS_LOGIN_HOST "/login?client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com";
	PurpleHttpRequest *request;
	
	request = purple_http_request_new(login_url);
	purple_http_request_set_method(request, "GET");
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "BehaviorOverride", "redirectAs404");
	purple_http_request_header_set_printf(request, "Cookie", "refresh-token=%s", purple_account_get_string(account, "refresh-token", ""));
	purple_http_request(sa->pc, request, teams_login_did_auth, sa);
	purple_http_request_unref(request);
	
	purple_connection_update_progress(sa->pc, _("Authenticating"), 2, 4);
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

	data = purple_http_response_get_data(response, &len);
	
	//purple_debug_misc("teams", "Full skypetoken response: %s\n", data);
	
	obj = json_decode_object(data, len);

	if (!json_object_has_member(obj, "tokens")) {
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

	tokens = json_object_get_object_member(obj, "tokens");

	if (sa->skype_token) g_free(sa->skype_token);
	sa->skype_token = g_strdup(json_object_get_string_member(tokens, "skypeToken"));
	
	gint64 expiresIn = json_object_get_int_member(tokens, "expiresIn");
	if (sa->refresh_token_timeout) 
		g_source_remove(sa->refresh_token_timeout);
	sa->refresh_token_timeout = g_timeout_add_seconds(expiresIn - 5, (GSourceFunc)teams_oauth_refresh_token, sa);
	//set_timeout
	
	if (sa->region) g_free(sa->region);
	sa->region = g_strdup(json_object_get_string_member(obj, "region"));

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
		url = "https://teams.microsoft.com/api/authsvc/v1.0/authz";
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

static void
teams_login_soap_got_token(TeamsAccount *sa, gchar *token)
{
	const gchar *login_url = NULL;//"https://edge.skype.com/rps/v1/rps/skypetoken"; //TODO equiv?

	teams_login_get_api_skypetoken(sa, login_url, NULL, token);
}

static void
teams_login_did_soap(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	TeamsAccount *sa = user_data;
	const gchar *data;
	gsize len;
	PurpleXmlNode *envelope, *main_node, *node, *fault;
	gchar *token;
	const char *error = NULL;

	data = purple_http_response_get_data(response, &len);
	envelope = purple_xmlnode_from_str(data, len);

	if (!data) {
		error = _("Error parsing SOAP response");
		goto fail;
	}

	main_node = purple_xmlnode_get_child(envelope, "Body/RequestSecurityTokenResponseCollection/RequestSecurityTokenResponse");

	if ((fault = purple_xmlnode_get_child(envelope, "Fault")) ||
	    (main_node && (fault = purple_xmlnode_get_child(main_node, "Fault")))) {
		gchar *code, *string, *error_;

		code = purple_xmlnode_get_data(purple_xmlnode_get_child(fault, "faultcode"));
		string = purple_xmlnode_get_data(purple_xmlnode_get_child(fault, "faultstring"));

		if (purple_strequal(code, "wsse:FailedAuthentication")) {
			error_ = g_strdup_printf(_("Login error: Bad username or password (%s)"), string);
		} else {
			error_ = g_strdup_printf(_("Login error: %s - %s"), code, string);
		}

		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, error_);

		g_free(code);
		g_free(string);
		g_free(error_);
		goto fail;
	}

	node = purple_xmlnode_get_child(main_node, "RequestedSecurityToken/BinarySecurityToken");

	if (!node) {
		error = _("Error getting BinarySecurityToken");
		goto fail;
	}

	token = purple_xmlnode_get_data(node);
	teams_login_soap_got_token(sa, token);
	g_free(token);

fail:
	if (error) {
		purple_connection_error(sa->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error);
	}
	purple_xmlnode_free(envelope);
	return;
}

#define SIMPLE_OBJECT_ACCESS_PROTOCOL \
"<Envelope xmlns='http://schemas.xmlsoap.org/soap/envelope/'\n" \
"   xmlns:wsse='http://schemas.xmlsoap.org/ws/2003/06/secext'\n" \
"   xmlns:wsp='http://schemas.xmlsoap.org/ws/2002/12/policy'\n" \
"   xmlns:wsa='http://schemas.xmlsoap.org/ws/2004/03/addressing'\n" \
"   xmlns:wst='http://schemas.xmlsoap.org/ws/2004/04/trust'\n" \
"   xmlns:ps='http://schemas.microsoft.com/Passport/SoapServices/PPCRL'>\n" \
"   <Header>\n" \
"       <wsse:Security>\n" \
"           <wsse:UsernameToken Id='user'>\n" \
"               <wsse:Username>%s</wsse:Username>\n" \
"               <wsse:Password>%s</wsse:Password>\n" \
"           </wsse:UsernameToken>\n" \
"       </wsse:Security>\n" \
"   </Header>\n" \
"   <Body>\n" \
"       <ps:RequestMultipleSecurityTokens Id='RSTS'>\n" \
"           <wst:RequestSecurityToken Id='RST0'>\n" \
"               <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>\n" \
"               <wsp:AppliesTo>\n" \
"                   <wsa:EndpointReference>\n" \
"                       <wsa:Address>https://teams.events.data.microsoft.com/OneCollector/1.0/</wsa:Address>\n" \
"                   </wsa:EndpointReference>\n" \
"               </wsp:AppliesTo>\n" \
"               <wsse:PolicyReference URI='MBI_SSL'></wsse:PolicyReference>\n" \
"           </wst:RequestSecurityToken>\n" \
"       </ps:RequestMultipleSecurityTokens>\n" \
"   </Body>\n" \
"</Envelope>" \

void
teams_begin_soapy_login(TeamsAccount *sa)
{
	PurpleAccount *account = sa->account;
	const gchar *login_url = "https://login.live.com/RST.srf";
	const gchar *template = SIMPLE_OBJECT_ACCESS_PROTOCOL;
	gchar *postdata;
	PurpleHttpRequest *request;

	postdata = g_markup_printf_escaped(template,
		purple_account_get_username(account),
		purple_connection_get_password(sa->pc)
	);

	request = purple_http_request_new(login_url);
	purple_http_request_set_keepalive_pool(request, sa->keepalive_pool);
	purple_http_request_set_method(request, "POST");
	purple_http_request_set_contents(request, postdata, -1);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "Content-Type", "text/xml; charset=UTF-8");
	purple_http_request(sa->pc, request, teams_login_did_soap, sa);
	purple_http_request_unref(request);

	purple_connection_update_progress(sa->pc, _("Authenticating"), 2, 4);

	g_free(postdata);
}

#define TEAMS_OAUTH_CLIENT_ID "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
#define TEAMS_OAUTH_RESOURCE "https://api.spaces.skype.com"
#define TEAMS_OAUTH_REDIRECT_URI "https://login.microsoftonline.com/common/oauth2/nativeclient"


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
		gchar *id_token = g_strdup(json_object_get_string_member(obj, "access_token"));
		if (sa->id_token) {
			g_free(sa->id_token);
		}
		sa->id_token = id_token;
		if (json_object_has_member(obj, "refresh_token")) {
			if (sa->refresh_token != NULL) {
				g_free(sa->refresh_token);
			}
			sa->refresh_token = g_strdup(json_object_get_string_member(obj, "refresh_token"));
		
			purple_account_set_remember_password(account, TRUE);
			teams_save_refresh_token_password(account, sa->refresh_token);
		}
		
		teams_login_get_api_skypetoken(sa, NULL, NULL, sa->id_token);
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

void
teams_oauth_refresh_token_for_resource(TeamsAccount *sa, const gchar *resource, PurpleHttpCallback callback) {

	PurpleHttpRequest *request;
	PurpleConnection *pc;
	GString *postdata;
	gchar *tenant_host;
	gchar *auth_url;

	pc = sa->pc;
	if (!PURPLE_IS_CONNECTION(pc)) {
		return;
	}

	postdata = g_string_new(NULL);
	g_string_append_printf(postdata, "resource=%s&", purple_url_encode(resource));
	g_string_append_printf(postdata, "client_id=%s&", purple_url_encode(TEAMS_OAUTH_CLIENT_ID));
	g_string_append(postdata, "grant_type=refresh_token&");
	g_string_append_printf(postdata, "refresh_token=%s&", purple_url_encode(sa->refresh_token));
	
	if (sa->tenant && *sa->tenant) {
		if (strchr(sa->tenant, '.')) {
			// Likely a FQDN
			tenant_host = g_strdup(sa->tenant);
		} else if (g_regex_match_simple(TEAMS_GUID_REGEX_PATTERN, sa->tenant, 0, 0)) {
			tenant_host = g_strdup(sa->tenant);
		} else {
			tenant_host = g_strconcat(sa->tenant, ".onmicrosoft.com", NULL);
		}
		
	} else {
		tenant_host = g_strdup("Common");
	}
	
	auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/token", NULL);
	
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
	g_free(tenant_host);
	return;
}

gboolean
teams_oauth_refresh_token(TeamsAccount *sa)
{
	teams_oauth_refresh_token_for_resource(sa, "https://api.spaces.skype.com", teams_oauth_with_code_cb);
	teams_oauth_refresh_token_for_resource(sa, "https://presence.teams.microsoft.com", teams_presence_oauth_cb);
	teams_oauth_refresh_token_for_resource(sa, "https://chatsvcagg.teams.microsoft.com", teams_csa_oauth_cb);
	teams_oauth_refresh_token_for_resource(sa, "https://substrate.office.com", teams_substrate_oauth_cb);
	
	// For working with purple_timeout_add()
	return FALSE;
}

void
teams_oauth_with_code(TeamsAccount *sa, const gchar *auth_code)
{
	PurpleHttpRequest *request;
	PurpleConnection *pc = sa->pc;
	GString *postdata;
	gchar *tenant_host;
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
	g_string_append(postdata, "resource=https%3A%2F%2Fapi.spaces.skype.com&");
	g_string_append_printf(postdata, "client_id=%s&", purple_url_encode(TEAMS_OAUTH_CLIENT_ID));
	g_string_append(postdata, "grant_type=authorization_code&");
	g_string_append_printf(postdata, "code=%s&", purple_url_encode(auth_code));
	g_string_append_printf(postdata, "redirect_uri=%s&", purple_url_encode(TEAMS_OAUTH_REDIRECT_URI));

	if (sa->tenant && *sa->tenant) {
		if (strchr(sa->tenant, '.')) {
			// Likely a FQDN
			tenant_host = g_strdup(sa->tenant);
		} else if (g_regex_match_simple(TEAMS_GUID_REGEX_PATTERN, sa->tenant, 0, 0)) {
			tenant_host = g_strdup(sa->tenant);
		} else {
			tenant_host = g_strconcat(sa->tenant, ".onmicrosoft.com", NULL);
		}
		
	} else {
		tenant_host = g_strdup("Common");
	}
	
	auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/token", NULL);

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
	gchar *tenant_host;
	gchar *auth_url;
	
	//https://login.microsoftonline.com/Common/oauth2/authorize?resource=https%3A%2F%2Fapi.spaces.skype.com&client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&response_type=code&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&prompt=login&display=popup
	
	if (sa->tenant && *sa->tenant) {
		if (strchr(sa->tenant, '.')) {
			// Likely a FQDN
			tenant_host = g_strdup(sa->tenant);
		} else if (g_regex_match_simple(TEAMS_GUID_REGEX_PATTERN, sa->tenant, 0, 0)) {
			tenant_host = g_strdup(sa->tenant);
		} else {
			tenant_host = g_strconcat(sa->tenant, ".onmicrosoft.com", NULL);
		}
		
	} else {
		tenant_host = g_strdup("Common");
	}
	
	auth_url = g_strconcat("https://login.microsoftonline.com/", purple_url_encode(tenant_host), "/oauth2/authorize?client_id=" TEAMS_OAUTH_CLIENT_ID "&response_type=code&display=popup&prompt=select_account&amr_values=mfa&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient", NULL);
	
	purple_notify_uri(pc, auth_url);
	purple_request_input(pc, _("Authorization Code"), auth_url,
		_("Please login in your browser"),
		_("and then paste the URL of the blank page here (should contain 'nativeclient')"), FALSE, FALSE, NULL, 
		_("OK"), G_CALLBACK(teams_authcode_input_cb), 
		_("Cancel"), G_CALLBACK(teams_authcode_input_cancel_cb), 
		purple_request_cpar_from_connection(pc), sa);
	
	g_free(tenant_host);
	g_free(auth_url);
}

//alternate flow:
//  POST to https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode
//		with    client_id= TEAMS_OAUTH_CLIENT_ID  &scope= {https://api.spaces.skype.com/.default offline_access profile openid}
//  comes back with device_code  and tells user to go to https://microsoft.com/devicelogin  with user_code ABCDEFGHI
// {
// 	"user_code": "ABCDEFGHI",
// 	"device_code": "ABCDEFGHI--ABCDEFGHI-ABCDEFGHI",
// 	"verification_uri": "https://microsoft.com/devicelogin",
// 	"expires_in": 900,
// 	"interval": 5,
// 	"message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ABCDEFGHI to authenticate."
// }
//  periodically (every interval seconds) poll with POST to https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
// with
//    client_id= TEAMS_OAUTH_CLIENT_ID &client_info=1&scope={scope}&grant_type=device_code&device_code={device_code}
//  and eventually it'll come back with client id's etc


// Places to find tenant id's you can use:
// https://portal.azure.com/#settings/directory
// https://api.myaccount.microsoft.com/api/organizations triggered by https://myaccount.microsoft.com/organizations
// https://graph.microsoft.com/beta/tenantRelationships/getResourceTenants?$select=tenantId,displayName
// https://teams.microsoft.com/api/mt/apac/beta/users/tenants