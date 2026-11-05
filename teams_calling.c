/*
 * Teams Plugin for libpurple/Pidgin - NGC (NextGenCalling) 1:1 calls.
 * See teams_calling.h and docs/CALLING.md for the protocol overview.
 *
 *   - PARSE:   turn the callNotification into a TeamsCall (peer, offer SDP, relay, links).
 *   - STATE:   drive incoming/dialing/active/disconnected and notify the front end.
 *   - CONTROL: answer (attach -> accept with our SDP answer), reject, hang up and dial (cpconv)
 *     over the call control plane.
 *   - MEDIA:   the out-of-process teams_media engine (TEAMS_MEDIA_BIN), one per call, driven over
 *     its stdin/stdout line protocol (docs/CALLING.md).
 *
 * Message shapes marked CAPTURED were read from the teams.live.com web client's traffic.
 */

#include "teams_calling.h"
#include "teams_call_sdp.h"
#include "teams_connection.h"
#include "teams_util.h"

#include <glib-unix.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef TEAMS_MEDIA_BIN
#error "TEAMS_MEDIA_BIN (the path of the teams_media engine) must be defined"
#endif

/* ------------------------------------------------------------------ logging */

void
teams_call_log(const char *fmt, ...)
{
	va_list ap;
	gchar *s;

	va_start(ap, fmt);
	s = g_strdup_vprintf(fmt, ap);
	va_end(ap);
	purple_debug_info("teams", "call: %s\n", s);
	/* The purple debug log is all protocols or none, and with every account signed in it
	 * outruns journald's rate limit, so call lines get dropped. TEAMS_CALL_DEBUG sends just
	 * these to stderr. */
	if (g_getenv("TEAMS_CALL_DEBUG"))
		g_printerr("teams call: %s\n", s);
	g_free(s);
}

/* s as a JSON string literal, quotes included. */
gchar *
teams_call_json_quote(const char *s)
{
	JsonNode *n = json_node_new(JSON_NODE_VALUE);
	gchar *ret;

	json_node_set_string(n, s ? s : "");
	ret = json_to_string(n, FALSE);
	json_node_unref(n);
	return ret;
}

/* ------------------------------------------------------- NULL-safe JSON getters
 * NGC notifications are reverse-engineered and fields drop in/out between tenants;
 * json-glib's own getters assert on a missing/typed-wrong member, so guard everything. */

static const gchar *
sget(JsonObject *o, const gchar *k)
{
	JsonNode *n;
	if (!o || !json_object_has_member(o, k)) return NULL;
	n = json_object_get_member(o, k);
	if (n && JSON_NODE_HOLDS_VALUE(n)) return json_node_get_string(n);
	return NULL;
}

static JsonObject *
oget(JsonObject *o, const gchar *k)
{
	JsonNode *n;
	if (!o || !json_object_has_member(o, k)) return NULL;
	n = json_object_get_member(o, k);
	if (n && JSON_NODE_HOLDS_OBJECT(n)) return json_node_get_object(n);
	return NULL;
}

/* --------------------------------------------------------- state / media hooks */

static TeamsCallStateCb g_state_cb = NULL;
static TeamsCallVideoCb g_video_cb = NULL;

void
teams_calling_set_state_cb(TeamsCallStateCb cb)
{
	g_state_cb = cb;
}

void
teams_calling_set_video_cb(TeamsCallVideoCb cb)
{
	g_video_cb = cb;
}

static TeamsCallAccountCb g_connected_cb = NULL;
static TeamsCallAccountCb g_closing_cb = NULL;

void
teams_calling_set_account_cbs(TeamsCallAccountCb connected, TeamsCallAccountCb closing)
{
	g_connected_cb = connected;
	g_closing_cb = closing;
}

void
teams_calling_account_connected(TeamsAccount *sa)
{
	if (g_connected_cb) g_connected_cb(sa);
}

gboolean
teams_calling_has_frontend(void)
{
	return g_state_cb != NULL;
}

/* ---- media engine integration (teams_media, out-of-process) -----------------------------
 * On answer we: parse the offer SDP (peer ice-ufrag/pwd, a=crypto GCM key, opus PT, candidates),
 * spawn `teams_media --answer`, feed it START + the peer candidates, read back OUR ice creds +
 * TX SRTP key + local candidates, build an SDP answer and POST it to links.attach. teams_media
 * does the ICE + SRTP + Opus to and from the audio devices.
 *
 * One engine runs at a time (g_mproc) and it always belongs to an account's current call: freeing
 * a TeamsCall stops its engine, so g_mproc->call is never left dangling. */

/* Reaps one engine process. Outlives the TeamsMediaProc when the engine is told to stop: if it has
 * not exited a few seconds after STOP, it is sent SIGTERM. */
typedef struct {
	GPid  pid;
	guint kill_timer;
} MediaReaper;

typedef struct {
	TeamsCall   *call;
	MediaReaper *reaper;       /* NULL once the engine has exited */
	int          in_fd;        /* -> child stdin (our end of a socketpair; written with MSG_NOSIGNAL) */
	GIOChannel  *out_ch;       /* <- child stdout */
	guint        out_watch;
	gchar       *our_ufrag, *our_pwd, *our_txkey;
	gchar       *answer_ufrag; /* outgoing: the ICE ufrag of the answer we applied */
	guint32      our_ssrc;     /* the engine's audio RTP SSRC (its SSRC line); 0 = not known */
	guint32      our_vssrc;    /* its video SSRC (VSSRC line); 0 = the engine has no video */
	const char  *video_offer;  /* the last offer's m=video direction (teams_sdp_video_direction) */
	const char  *video_answer; /* our last answer's m=video direction */
	gboolean     camera_wanted;  /* the user has our camera on (teams_calling_set_camera) */
	gboolean     camera_sent;    /* the engine has been told VIDEO 1 */
	int          vsend_w, vsend_h, vsend_kbps;  /* what the last offer lets us send */
	GString     *our_cands;    /* accumulated "candidate:..." lines, one per line */
	gboolean     answered;
	guint        answer_timer;
	gboolean     gathered;
	gboolean     sent_sdp;     /* our offer or answer has gone out */     /* the engine reported GATHERED: our candidates are complete */
	gboolean     is_caller;    /* TRUE = outgoing (we build+POST the offer via cpconv) */

	/* Set by teams_calling_handle_renegotiation() right after it sends a RESTART to the engine;
	 * consumed by media_on_output() when the engine's matching RESTARTED line arrives. We can't
	 * build+POST the renegotiation answer synchronously in the same call as the RESTART write -
	 * nice_agent_restart_stream() regenerates OUR OWN local ice-ufrag/pwd (see teams_media.c's
	 * RESTART handler), and build_answer_sdp() needs those NEW values, which only reach us
	 * asynchronously over the pipe (the same UFRAG/PWD lines media_on_output already parses for
	 * the initial START). Answering immediately would race and very likely still send the STALE
	 * pre-restart local creds. */
	gchar       *pending_reneg_answer_link;

	/* Last remote ice-ufrag we actually applied via RESTART. Teams' trouter redelivers the same
	 * renegotiation push (observed live: 3 identical-ufrag frames within ~2s of each other) - see
	 * teams_calling_handle_renegotiation()'s dedup check. Without this, every redelivery tears
	 * down and rebuilds the ICE agent, so no single ICE session ever gets enough uninterrupted
	 * time to finish connectivity checks before being restarted again. */
	gchar       *last_restarted_ufrag;
	/* The offer's m-lines we decline (sdp_declined_mlines), to end our answer with; NULL: none. */
	gchar       *declined_mlines;
	/* The last renegotiation offer's mediaContent.mediaLegId, which our answer names; NULL: none. */
	gchar       *reneg_leg_id;
	/* An offer of ours (send_reneg_offer) is waiting for its answer, which comes as a mediaAnswer
	 * frame; the timer gives up on it so that the camera button can try again. */
	gboolean     reneg_offer_pending;
	guint        reneg_offer_timer;
} TeamsMediaProc;

static TeamsMediaProc *g_mproc;

/* An async HTTP callback's handle on a call: the call itself may be gone by the time the
 * response arrives (hung up, replaced, account closed). */
typedef struct {
	TeamsAccount *sa;
	guint         serial;
} CallRef;

static guint g_call_serial;

static void end_call(TeamsAccount *sa, const char *cause, gboolean notify_remote);
static void accept_resp_cb(PurpleHttpConnection *hc, PurpleHttpResponse *resp, gpointer u);

static CallRef *
call_ref_new(TeamsCall *call)
{
	CallRef *ref = g_new0(CallRef, 1);
	ref->sa = call->sa;
	ref->serial = call->serial;
	return ref;
}

/* The call ref names, if it is still its account's current call. */
static TeamsCall *
call_ref_resolve(const CallRef *ref)
{
	TeamsCall *call;
	if (!teams_account_is_live(ref->sa)) return NULL;
	call = teams_calling_current(ref->sa);
	return (call && call->serial == ref->serial) ? call : NULL;
}

/* Log the outcome of a calling-backend request. Bodies are only logged for failures; a 2xx body
 * is not needed and the requests themselves carry our SRTP key. */
static void
flightproxy_resp_cb(PurpleHttpConnection *hc, PurpleHttpResponse *resp, gpointer u)
{
	int code; size_t len = 0; const gchar *data;
	(void) hc; (void) u;
	code = purple_http_response_get_code(resp);
	if (code <= 0) {
		teams_call_log("FLIGHTPROXY resp code=%d err=%s", code,
		               purple_http_response_get_error(resp) ? purple_http_response_get_error(resp) : "(none)");
	} else if (code < 200 || code >= 300) {
		data = purple_http_response_get_data(resp, &len);
		teams_call_log("FLIGHTPROXY resp code=%d body=%.300s", code, data ? data : "(none)");
	} else {
		teams_call_log("FLIGHTPROXY resp code=%d", code);
	}
}

/* Teams calling client identity (matches teams.live.com's SkypeSpacesWeb TFL client string). */
#define TEAMS_SKYPE_CLIENT "SkypeSpaces/1415/26070217343/os=linux; osVer=undefined; " \
	"deviceType=computer; browser=chrome; browserVer=150.0.0.0/TsCallingVersion=2026.24.01.6/Ovb=0"

/* POST JSON to a flightproxy/calling URL WITH the x-skypetoken auth header (teams_post_or_get does
 * not add it for api.flightproxy.skype.com -> "Anonymous access is not allowed" 403), the calling
 * headers and a caller-supplied response callback (NULL: flightproxy_resp_cb, which just logs). */
/* How long a leave may take. It is answered 204 without a body; the bound is generous. */
#define TEAMS_LEAVE_TIMEOUT_S 120

static void
flightproxy_send(TeamsAccount *sa, const gchar *method, const gchar *url, const gchar *body,
                 PurpleHttpCallback cb, gpointer user, gboolean fresh_connection)
{
	gchar *chain = purple_uuid_random(), *msgid = purple_uuid_random();
	PurpleHttpRequest *req = purple_http_request_new(url);
	purple_http_request_set_method(req, method);
	/* fresh_connection: not on a kept-alive connection, which may have been dropped by the network
	 * without either end noticing during a call's quiet minutes; a request sent on one is never
	 * answered and fails only at the 30 s request timeout. */
	if (!fresh_connection)
		purple_http_request_set_keepalive_pool(req, sa->keepalive_pool);
	else
		purple_http_request_set_timeout(req, TEAMS_LEAVE_TIMEOUT_S);
	purple_http_request_header_set(req, "Content-Type", "application/json");
	purple_http_request_header_set(req, "X-Skypetoken", sa->skype_token);
	/* calling backend rejects requests without a client identity as 400 Bad Request */
	purple_http_request_header_set(req, "X-Microsoft-Skype-Client", TEAMS_SKYPE_CLIENT);
	purple_http_request_header_set(req, "X-Microsoft-Skype-Chain-Id", chain);
	purple_http_request_header_set(req, "X-Microsoft-Skype-Message-Id", msgid);
	purple_http_request_header_set(req, "ms-teams-ring", "general");
	purple_http_request_set_contents(req, body, strlen(body));
	purple_http_request(sa->pc, req, cb ? cb : flightproxy_resp_cb, user);
	purple_http_request_unref(req);
	g_free(chain); g_free(msgid);
}

static void
flightproxy_post_full(TeamsAccount *sa, const gchar *url, const gchar *body,
                      PurpleHttpCallback cb, gpointer user, gboolean fresh_connection)
{
	flightproxy_send(sa, "POST", url, body, cb, user, fresh_connection);
}

static void
flightproxy_post_cb(TeamsAccount *sa, const gchar *url, const gchar *body,
                    PurpleHttpCallback cb, gpointer user)
{
	flightproxy_post_full(sa, url, body, cb, user, FALSE);
}

#define TEAMS_FLIGHTPROXY_CP "https://api.flightproxy.skype.com/api/v2/cp/"

/* A calling-backend URL as the web client sends it: through flightproxy's cp/<host>/<path> when it
 * names a backend host directly ("https://conv-x.conv.skype.com/conv/C?q" ->
 * "https://api.flightproxy.skype.com/api/v2/cp/conv-x.conv.skype.com/conv/C?q"), as is when it
 * already goes through flightproxy or is not https. NULL for NULL. g_free() it. */
static gchar *
teams_calling_via_flightproxy(const gchar *url)
{
	if (!url) return NULL;
	if (!g_str_has_prefix(url, "https://") || g_str_has_prefix(url, "https://api.flightproxy.skype.com/"))
		return g_strdup(url);
	return g_strconcat(TEAMS_FLIGHTPROXY_CP, url + strlen("https://"), NULL);
}

/* A URL's host, for the log (paths and queries carry call ids). g_free() it. */
static gchar *
url_host_for_log(const gchar *url)
{
	const gchar *h = url ? strstr(url, "://") : NULL, *e;
	if (!h) return g_strdup("?");
	h += 3;
	if (g_str_has_prefix(h, "api.flightproxy.skype.com/api/v2/cp/")) {
		const gchar *in = h + strlen("api.flightproxy.skype.com/api/v2/cp/");
		e = strchr(in, '/');
		return g_strdup_printf("flightproxy cp/%.*s", (int) (e ? e - in : (gssize) strlen(in)), in);
	}
	e = strpbrk(h, "/?");
	return g_strndup(h, e ? (gsize) (e - h) : strlen(h));
}

/* A leave in flight: sent once more, on a new connection, if it got no HTTP answer at all. */
typedef struct {
	TeamsAccount *sa;
	gchar *url, *body;
	gint64 sent_us;
	gboolean retried;
} LeaveReq;

static void
leave_req_free(LeaveReq *lr)
{
	g_free(lr->url);
	g_free(lr->body);
	g_free(lr);
}

static void
leave_resp_cb(PurpleHttpConnection *hc, PurpleHttpResponse *resp, gpointer u)
{
	LeaveReq *lr = u;
	int code = purple_http_response_get_code(resp);
	teams_call_log("hangup: leave answered after %d ms%s", (int) ((g_get_monotonic_time() - lr->sent_us) / 1000),
	               lr->retried ? " (retry)" : "");
	flightproxy_resp_cb(hc, resp, NULL);
	if (code <= 0 && !lr->retried && teams_account_is_live(lr->sa)) {
		lr->retried = TRUE;
		lr->sent_us = g_get_monotonic_time();
		teams_call_log("hangup: no answer to the leave, sending it again");
		flightproxy_post_full(lr->sa, lr->url, lr->body, leave_resp_cb, lr, TRUE);
		return;
	}
	leave_req_free(lr);
}

/* The conversation's leave link when only its controller is known: CAPTURED (teams.live.com)
 * the join response's links.leave is the controller URL with "/leave" before its query
 * ("…/conv/<id>?i=..&e=.." -> "…/conv/<id>/leave?i=..&e=.."). */
gchar *
teams_calling_leave_link(const gchar *controller)
{
	return teams_calling_conv_link(controller, "leave");
}

/* The same for another conversation action. CAPTURED (teams.live.com): the web
 * client's updateEndpointState and updateEndpointMetadata URLs have the leave's shape. */
gchar *
teams_calling_conv_link(const gchar *controller, const gchar *action)
{
	const gchar *q;
	if (!controller || !*controller || !action || !*action) return NULL;
	q = strchr(controller, '?');
	if (!q) return g_strconcat(controller, "/", action, NULL);
	return g_strdup_printf("%.*s/%s%s", (int) (q - controller), controller, action, q);
}

static gchar *language_id(void);
static const gchar *self_display_name(TeamsAccount *sa);

/* {"id":"8:<user>","displayName":..,"endpointId":..,"participantId":..,"languageId":..}: us, as
 * the conversation requests name us. g_free() it. */
static gchar *
participant_from_json(TeamsAccount *sa, const gchar *endpoint_id, const gchar *participant_id)
{
	gchar *from_id = g_strconcat("8:", sa->username ? sa->username : "", NULL);
	gchar *from_q = teams_call_json_quote(from_id);
	gchar *name_q = teams_call_json_quote(self_display_name(sa));
	gchar *epid_q = teams_call_json_quote(endpoint_id ? endpoint_id : (sa->endpoint ? sa->endpoint : ""));
	gchar *pid_q = teams_call_json_quote(participant_id ? participant_id : "");
	gchar *lang = language_id(), *lang_q = teams_call_json_quote(lang);
	gchar *ret = g_strdup_printf("{\"id\":%s,\"displayName\":%s,\"endpointId\":%s,"
	                             "\"participantId\":%s,\"languageId\":%s}",
	                             from_q, name_q, epid_q, pid_q, lang_q);
	g_free(from_id); g_free(from_q); g_free(name_q); g_free(epid_q); g_free(pid_q);
	g_free(lang); g_free(lang_q);
	return ret;
}

/* Tell the conversation our endpoint's state, as the web client does once its attach (with the
 * join) is answered. CAPTURED (teams.live.com answering an incoming call): two POSTs
 * to <conversation>/updateEndpointState, both answered 200 -
 *   {from, endpointState{state{isMuted:true}, endpointStateSequenceNumber:1}}
 *   {from, endpointState{state{isMuted:false}, endpointStateSequenceNumber:2,
 *          endpointProperties{additionalEndpointProperties{infoShownInReportMode:"FullInformation"}}}}
 * Without them (live, the same day) the conversation sent no roster updates and never
 * answered the leave. */
static void
post_endpoint_state(TeamsCall *call)
{
	gchar *url, *from, *b1, *b2;
	if (!call->link_endpoint_state) return;
	url = teams_calling_via_flightproxy(call->link_endpoint_state);
	from = participant_from_json(call->sa, call->our_endpoint_id, call->our_participant_id);
	b1 = g_strdup_printf("{\"from\":%s,\"endpointState\":{\"state\":{\"isMuted\":true},"
	                     "\"endpointStateSequenceNumber\":1}}", from);
	b2 = g_strdup_printf("{\"from\":%s,\"endpointState\":{\"state\":{\"isMuted\":false},"
	                     "\"endpointStateSequenceNumber\":2,\"endpointProperties\":"
	                     "{\"additionalEndpointProperties\":{\"infoShownInReportMode\":\"FullInformation\"}}}}",
	                     from);
	teams_call_log("endpoint state: posting muted (1) and unmuted (2)");
	flightproxy_post_cb(call->sa, url, b1, NULL, NULL);
	flightproxy_post_cb(call->sa, url, b2, NULL, NULL);
	g_free(url); g_free(from); g_free(b1); g_free(b2);
}

/* And its metadata, once the accept is answered. CAPTURED (the same call): PUT
 * <conversation>/updateEndpointMetadata {participants{from}, endpointMetadata{holographicCapabilities:3}}
 * -> 200. */
static void
put_endpoint_metadata(TeamsCall *call)
{
	gchar *url, *from, *body;
	if (!call->link_endpoint_metadata) return;
	url = teams_calling_via_flightproxy(call->link_endpoint_metadata);
	from = participant_from_json(call->sa, call->our_endpoint_id, call->our_participant_id);
	body = g_strdup_printf("{\"participants\":{\"from\":%s},"
	                       "\"endpointMetadata\":{\"holographicCapabilities\":3}}", from);
	teams_call_log("endpoint metadata: putting holographicCapabilities");
	flightproxy_send(call->sa, "PUT", url, body, NULL, NULL, FALSE);
	g_free(url); g_free(from); g_free(body);
}

/* Leave the conversation (hang up). CAPTURED (teams.live.com hanging up an answered call):
 * POST to the conversation's links.leave, answered 204, with who is leaving and why.
 * A DELETE on the controller (what this did before) is refused: 400 "Delete conversation not
 * supported with empty request or without participantInfo". */
static void
post_leave(TeamsAccount *sa, const gchar *url, const gchar *endpoint_id, const gchar *participant_id)
{
	gchar *from_id, *from_q, *name_q, *epid_q, *pid_q, *lang, *lang_q, *body;
	if (!url) return;
	from_id = g_strconcat("8:", sa->username ? sa->username : "", NULL);
	from_q = teams_call_json_quote(from_id);
	name_q = teams_call_json_quote(self_display_name(sa));
	epid_q = teams_call_json_quote(endpoint_id ? endpoint_id : (sa->endpoint ? sa->endpoint : ""));
	pid_q = teams_call_json_quote(participant_id ? participant_id : "");
	lang = language_id();
	lang_q = teams_call_json_quote(lang);
	body = g_strdup_printf(
		"{\"participants\":{\"from\":{\"id\":%s,\"displayName\":%s,\"endpointId\":%s,"
		  "\"participantId\":%s,\"languageId\":%s}},"
		"\"conversationTransactionEnd\":{\"reason\":\"noError\",\"code\":0,"
		  "\"phrase\":\"ConversationEndNoModalityConnected\"},"
		"\"callTransactionEnd\":{\"code\":0,\"subCode\":0,"
		  "\"phrase\":\"CallEndReasonLocalUserInitiated\",\"resultCategories\":[\"Success\"]}}",
		from_q, name_q, epid_q, pid_q, lang_q);
	{
		LeaveReq *lr = g_new0(LeaveReq, 1);
		gchar *host;
		lr->sa = sa;
		lr->url = teams_calling_via_flightproxy(url);
		lr->body = body;
		lr->sent_us = g_get_monotonic_time();
		host = url_host_for_log(lr->url);
		teams_call_log("hangup: leaving the conversation via %s (%d-byte body)", host, (int) strlen(body));
		g_free(host);
		/* On a new connection: see flightproxy_post_full. The call's last request may be minutes old. */
		flightproxy_post_full(sa, lr->url, lr->body, leave_resp_cb, lr, TRUE);
	}
	g_free(from_id); g_free(from_q); g_free(name_q); g_free(epid_q); g_free(pid_q);
	g_free(lang); g_free(lang_q);
}

/* build a callAgent trouter control path: <surl>callAgent/<agent>/<hash8>/<kind>/<name>/ */
static gchar *
callagent_path(TeamsCall *call, const char *agent, const char *kind, const char *name)
{
	gchar *hash = g_strdup_printf("%08x", g_random_int());
	gchar *surl = call->sa->trouter_surl ? call->sa->trouter_surl : "";
	gchar *p = g_strdup_printf("%scallAgent/%s/%s/%s/%s/", surl, agent, hash, kind, name);
	g_free(hash);
	return p;
}

/* Our name and location as the calling backend sees them. */
static const gchar *
self_display_name(TeamsAccount *sa)
{
	if (sa->self_display_name && *sa->self_display_name) return sa->self_display_name;
	return sa->username ? sa->username : "";
}

/* The first of the user's locales with a language and a country ("nl_NL.UTF-8"): the language
 * ("nl") and country ("NL") are copied into lang and country. FALSE if there is none, e.g. "C". */
static gboolean
user_locale(gchar lang[3], gchar country[3])
{
	const gchar * const *langs = g_get_language_names();
	int i;
	for (i = 0; langs && langs[i]; i++) {
		const gchar *l = langs[i];
		if (g_ascii_isalpha(l[0]) && g_ascii_isalpha(l[1]) && l[2] == '_' &&
		    g_ascii_isalpha(l[3]) && g_ascii_isalpha(l[4]) &&
		    (l[5] == '\0' || l[5] == '.' || l[5] == '@')) {
			lang[0] = g_ascii_tolower(l[0]); lang[1] = g_ascii_tolower(l[1]); lang[2] = '\0';
			country[0] = g_ascii_toupper(l[3]); country[1] = g_ascii_toupper(l[4]); country[2] = '\0';
			return TRUE;
		}
	}
	return FALSE;
}

/* mediaContent.clientLocation, the locale's country: "NL" (what every call so far has sent) when
 * the locale has none. */
static gchar *
client_location(void)
{
	gchar lang[3], country[3];
	return g_strdup(user_locale(lang, country) ? country : "NL");
}

/* languageId, as the web client sends it ("en-us"): from the locale, "en-us" when it has none. */
static gchar *
language_id(void)
{
	gchar lang[3], country[3];
	if (!user_locale(lang, country)) return g_strdup("en-us");
	return g_strdup_printf("%s-%c%c", lang, g_ascii_tolower(country[0]), g_ascii_tolower(country[1]));
}

/* return the value after "a=<prefix>:" on the first matching line (newly-allocated), or NULL */
static gchar *
sdp_line_val(const char *sdp, const char *prefix)
{
	gchar **lines, *ret = NULL;
	int i;
	if (!sdp) return NULL;
	lines = g_strsplit(sdp, "\n", -1);
	for (i = 0; lines[i]; i++) {
		gchar *l = g_strstrip(lines[i]);
		if (g_str_has_prefix(l, prefix)) { ret = g_strdup(l + strlen(prefix)); break; }
	}
	g_strfreev(lines);
	return ret;
}

/* Log the lines that say how media is set up (m=, codecs, crypto suite and tag, direction, mid,
 * Teams' x- attributes) and nothing that is a secret: a=crypto stops before its key, ICE
 * passwords and candidates are left out. For working out why one direction carries no audio. */
static void
sdp_log_shape(const char *what, const char *sdp)
{
	gchar **lines;
	int i;
	if (!sdp) return;
	lines = g_strsplit(sdp, "\n", -1);
	for (i = 0; lines[i]; i++) {
		gchar *l = g_strstrip(lines[i]);
		if (g_str_has_prefix(l, "a=crypto:")) {
			const char *in = strstr(l, " inline:");
			teams_call_log("%s sdp: %.*s", what, in ? (int) (in - l) : (int) strlen(l), l);
		} else if (g_str_has_prefix(l, "m=") || g_str_has_prefix(l, "a=rtpmap:") ||
		           g_str_has_prefix(l, "a=mid:") || g_str_has_prefix(l, "a=group:") ||
		           g_str_has_prefix(l, "a=x-") || g_str_has_prefix(l, "a=label:") ||
		           g_str_has_prefix(l, "a=ssrc") || g_str_has_prefix(l, "a=rtcp") ||
		           !strcmp(l, "a=sendrecv") || !strcmp(l, "a=sendonly") ||
		           !strcmp(l, "a=recvonly") || !strcmp(l, "a=inactive")) {
			teams_call_log("%s sdp: %s", what, l);
		}
	}
	g_strfreev(lines);
}

/* the AEAD_AES_256_GCM inline key (base64, up to the '|') from the offer's a=crypto lines */
static gchar *
sdp_gcm_key(const char *sdp)
{
	gchar **lines; int i; gchar *ret = NULL;
	if (!sdp) return NULL;
	lines = g_strsplit(sdp, "\n", -1);
	for (i = 0; lines[i]; i++) {
		gchar *l = g_strstrip(lines[i]);
		if (strstr(l, "AEAD_AES_256_GCM") && strstr(l, "inline:")) {
			gchar *k = strstr(l, "inline:") + 7;
			gchar *bar = strchr(k, '|');
			ret = bar ? g_strndup(k, bar - k) : g_strdup(k);
			break;
		}
	}
	g_strfreev(lines);
	return ret;
}

/* The offer's Opus payload type (a=rtpmap:<pt> opus/48000...), 102 if it names none. */
static int
sdp_opus_pt(const char *sdp)
{
	gchar **lines; int i, pt = 102;
	if (!sdp) return pt;
	lines = g_strsplit(sdp, "\n", -1);
	for (i = 0; lines[i]; i++) {
		gchar *l = g_strstrip(lines[i]);
		if (g_str_has_prefix(l, "a=rtpmap:") && strstr(l, " opus/48000")) {
			gint64 v = g_ascii_strtoll(l + 9, NULL, 10);
			if (v >= 96 && v <= 127) pt = (int) v;
			break;
		}
	}
	g_strfreev(lines);
	return pt;
}

/* Write one command line to the engine. A socket written with MSG_NOSIGNAL, so an engine that has
 * died gives EPIPE here instead of a SIGPIPE that would kill the whole messaging service. The
 * formatted line may hold a key, so it is wiped. */
static gboolean media_send(TeamsMediaProc *mp, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
static gboolean
media_send(TeamsMediaProc *mp, const char *fmt, ...)
{
	va_list ap;
	gchar *s;
	size_t len, off = 0;
	int saved = 0;

	if (!mp || mp->in_fd < 0) return FALSE;
	va_start(ap, fmt);
	s = g_strdup_vprintf(fmt, ap);
	va_end(ap);
	len = strlen(s);
	while (off < len) {
		ssize_t n = send(mp->in_fd, s + off, len - off, MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) { saved = n < 0 ? errno : EPIPE; break; }
		off += (size_t) n;
	}
	explicit_bzero(s, len);
	g_free(s);
	if (off < len) {
		teams_call_log("media engine: write failed: %s", g_strerror(saved));
		return FALSE;
	}
	return TRUE;
}

/* Feed every a=candidate line of an SDP to the engine as RCAND. */
static void
media_send_candidates(TeamsMediaProc *mp, const char *sdp)
{
	gchar **lines = g_strsplit(sdp, "\n", -1);
	int i;
	for (i = 0; lines[i]; i++) {
		gchar *l = g_strstrip(lines[i]);
		if (g_str_has_prefix(l, "a=candidate:"))
			media_send(mp, "RCAND %s\n", l + 2); /* strip "a=" -> "candidate:..." */
	}
	g_strfreev(lines);
}

static void teams_calling_post_answer(TeamsCall *call);
static gboolean send_reneg_offer(TeamsMediaProc *mp);
static void call_http_post(TeamsAccount *sa, const gchar *full_url, const gchar *body);

/* Our own connection address for c=/m=, from the first UDP host candidate (NOT the offerer's relay
 * IP - advertising the peer's address as ours confuses the NGC validator). */
static gchar *
our_host_address(TeamsMediaProc *mp, int *port)
{
	gchar *ip = NULL;
	*port = 3480;
	if (mp->our_cands) {
		gchar **cl = g_strsplit(mp->our_cands->str, "\n", -1); int i;
		for (i = 0; cl[i]; i++) {
			/* "candidate:<f> <comp> UDP <pri> <ip> <port> typ host ..." */
			if (strstr(cl[i], " UDP ") && strstr(cl[i], "typ host")) {
				gchar **t = g_strsplit(g_strstrip(cl[i]), " ", -1);
				if (t[0] && t[1] && t[2] && t[3] && t[4] && t[5]) {
					ip = g_strdup(t[4]); *port = atoi(t[5]);
				}
				g_strfreev(t);
				break;
			}
		}
		g_strfreev(cl);
	}
	return ip;
}

/* The m-lines of offer other than audio and video, each declined as RFC 3264 has it (port 0, the
 * first format) with its mid. CAPTURED LIVE (a call from the Teams Android app): its
 * renegotiation offers add "m=x-data ... a=mid:data_2" (SCTP data), and an answer has to carry as
 * many m-lines as the offer, in its order; ours had only audio and video. The web client accepts
 * that stream with SCTP, which this engine does not have. NULL when there are none. g_free() it. */
static gchar *
sdp_declined_mlines(const gchar *offer)
{
	gchar **lines;
	GString *out;
	gboolean in_declined = FALSE;
	int i;
	if (!offer) return NULL;
	lines = g_strsplit(offer, "\n", -1);
	out = g_string_new(NULL);
	for (i = 0; lines[i]; i++) {
		gchar *l = g_strchomp(lines[i]);   /* drops the \r */
		if (g_str_has_prefix(l, "m=")) {
			gchar **f = g_strsplit(l + 2, " ", -1);
			in_declined = g_strv_length(f) >= 4 && strcmp(f[0], "audio") && strcmp(f[0], "video");
			if (in_declined)
				g_string_append_printf(out, "m=%s 0 %s %s\r\n", f[0], f[2], f[3]);
			g_strfreev(f);
		} else if (in_declined && g_str_has_prefix(l, "a=mid:")) {
			g_string_append_printf(out, "%s\r\n", l);
		}
	}
	g_strfreev(lines);
	if (!out->len) { g_string_free(out, TRUE); return NULL; }
	return g_string_free(out, FALSE);
}

/* ---- video ------------------------------------------------------------------------------
 * The engine always receives video when it has the elements for it (it says so with VSSRC), and
 * sends our camera after VIDEO 1. The m=video answer follows the offer (RFC 3264): we receive
 * when the far side sends, and send when our camera is on and the far side receives. A voice-only
 * offer - the Android app's first offer has video a=recvonly, its renegotiations a=inactive - is
 * answered a=inactive as before (see build_answer_sdp). Turning our camera on mid-call when our
 * answer so far does not let us send makes an offer of our own (send_reneg_offer). */

static void
video_event(TeamsMediaProc *mp, const char *line)
{
	if (g_video_cb && mp->call) g_video_cb(mp->call->sa, line);
}

/* An offer (initial or renegotiation) arrived: remember its video direction for the answer. */
static void
media_video_offer(TeamsMediaProc *mp, const char *sdp)
{
	mp->video_offer = teams_sdp_video_direction(sdp);
	teams_video_send_params(sdp, &mp->vsend_w, &mp->vsend_h, &mp->vsend_kbps);
	teams_call_log("video: offer %s, engine %s, camera %s", mp->video_offer ? mp->video_offer : "none",
	               mp->our_vssrc ? "has video" : "voice only", mp->camera_wanted ? "on" : "off");
	video_event(mp, teams_video_dir_peer_sends(mp->video_offer) ? "OFFERED 1" : "OFFERED 0");
}

/* Our m=video direction for the answer being built. */
static const char *
media_video_answer(TeamsMediaProc *mp)
{
	mp->video_answer = teams_video_answer_direction(mp->video_offer, mp->our_vssrc != 0, mp->camera_wanted);
	return mp->video_answer;
}

/* After an answer went out: the engine's camera follows what it lets us do. */
static void
media_video_apply(TeamsMediaProc *mp)
{
	gboolean send = mp->camera_wanted && teams_video_dir_we_send(mp->video_answer);
	if (send == mp->camera_sent) return;
	if (send ? media_send(mp, "VIDEO 1 %d %d %d\n", mp->vsend_w, mp->vsend_h, mp->vsend_kbps)
	         : media_send(mp, "VIDEO 0\n")) {
		mp->camera_sent = send;
		if (send)
			teams_call_log("video: camera sending %dx%d at %d kbit/s", mp->vsend_w, mp->vsend_h, mp->vsend_kbps);
		else
			teams_call_log("video: camera stopped");
	}
}

gboolean
teams_calling_set_camera(TeamsAccount *sa, gboolean on)
{
	TeamsMediaProc *mp = g_mproc;
	if (!mp || !mp->call || mp->call->sa != sa) return FALSE;
	mp->camera_wanted = on;
	if (on && !mp->our_vssrc) {
		video_event(mp, "VIDEOERR unavailable");
		return FALSE;
	}
	{
		/* The call's media is negotiated once our answer went out, or, in a call we placed, the
		 * far side's answer is applied; before that the first answer carries the camera. */
		gboolean negotiated = mp->video_answer || (mp->is_caller && mp->call->answer_applied);
		if (teams_video_needs_offer(on, mp->our_vssrc != 0, negotiated, mp->video_answer, mp->reneg_offer_pending)) {
			if (!send_reneg_offer(mp))
				teams_call_log("video: camera on, waiting for an offer that lets us send (answered %s)",
				               mp->video_answer ? mp->video_answer : "no video");
		} else if (on && mp->reneg_offer_pending) {
			teams_call_log("video: camera on, our offer is waiting for its answer");
		}
	}
	if (mp->video_answer) media_video_apply(mp);
	return TRUE;
}

/* Build the SDP answer from our media params + the offer (SDES-GCM path; the offer supports both
 * SDES a=crypto and DTLS, and our engine keys via SDES). Shape mirrors the web client's accepted
 * answer: BUNDLE + mid:audio_0/video_1 + rtcp-mux + label, a=crypto instead of DTLS fingerprint.
 * The video m-line always has to be there: the offer/answer m-line mirroring requirement means
 * leaving it out makes the peer reject the whole answer (FinalAnswerError 406/4122). Its direction
 * comes from media_video_answer() (above): a=inactive for a voice call. CAPTURED (teams.live.com
 * answering a call from the Teams Android app) the web client's accept and every
 * renegotiation answer have video a=inactive for that call's recvonly/inactive offers, and with
 * a=sendrecv the Android app shows that we are trying to send video. Our audio SSRC, and our video SSRC when
 * we send video, are declared with a=x-ssrc-range, as the web client declares the SSRC of each
 * stream it sends (its data stream in that capture).
 * Codec/fmtp/rtcp-fb values are the real ones from a captured live Teams video call (H264/90000
 * PT 107, rtx PT 99, packetization-mode=1, profile-level-id=42e01f). Shared by the initial answer
 * (media_send_answer, below) and any later mid-call renegotiation
 * (teams_calling_handle_renegotiation) - both reuse the SAME bundled ICE/crypto. Caller owns the
 * returned GString. */
/* Our m=video section (in our answer, and in our offer for a video call): H264 PT 107 with rtx
 * PT 99, direction dir, our video SSRC declared when we send, bundled on the audio's ICE and
 * SDES key. */
static void
append_video_mline(GString *a, TeamsMediaProc *mp, int port, const char *ip, const char *mid,
                   const char *dir)
{
	g_string_append_printf(a, "m=video %d RTP/SAVP 107 99\r\n", port);
	g_string_append_printf(a, "c=IN IP4 %s\r\n", ip);
	g_string_append(a, "a=rtpmap:107 H264/90000\r\n");
	g_string_append(a, "a=rtpmap:99 rtx/90000\r\n");
	g_string_append(a, "a=fmtp:107 level-asymmetry-allowed=1;packetization-mode=1;"
	                    "profile-level-id=42e01f;max-fs=8160;max-mbps=244800;max-fps=3000\r\n");
	g_string_append(a, "a=fmtp:99 apt=107\r\n");
	g_string_append(a, "a=rtcp-fb:107 goog-remb\r\n");
	g_string_append(a, "a=rtcp-fb:107 transport-cc\r\n");
	g_string_append(a, "a=rtcp-fb:107 nack\r\n");
	g_string_append(a, "a=rtcp-fb:107 nack pli\r\n");
	g_string_append_printf(a, "a=mid:%s\r\n", mid);
	g_string_append_printf(a, "a=%s\r\n", dir);
	if (mp->our_vssrc && teams_video_dir_we_send(dir))
		g_string_append_printf(a, "a=x-ssrc-range:%u-%u\r\n", mp->our_vssrc, mp->our_vssrc);
	g_string_append_printf(a, "a=ice-ufrag:%s\r\n", mp->our_ufrag);
	g_string_append_printf(a, "a=ice-pwd:%s\r\n", mp->our_pwd);
	g_string_append_printf(a, "a=crypto:4 AEAD_AES_256_GCM inline:%s|2^31\r\n", mp->our_txkey);
	g_string_append(a, "a=rtcp-mux\r\n");
	g_string_append(a, "a=rtcp-rsize\r\n");
	g_string_append(a, "a=label:main-video\r\n");
}

/* Our SDP for the call's media: the answer's shape, with video direction vdir. Our own
 * renegotiation offer (send_reneg_offer) is the same session with video sendrecv: the same
 * m-lines, ICE credentials and key (CAPTURED, teams.live.com: its renegotiate kept the
 * cpconv's ufrag and fingerprint, and the answers kept theirs). */
static GString *
build_sdp(TeamsMediaProc *mp, const char *vdir)
{
	GString *a;
	int our_port;
	gchar *our_ip = our_host_address(mp, &our_port);

	a = g_string_new("");
	g_string_append(a, "v=0\r\n");
	g_string_append_printf(a, "o=- %u 2 IN IP4 %s\r\n", g_random_int(), our_ip ? our_ip : "127.0.0.1");
	g_string_append(a, "s=-\r\n");
	g_string_append(a, "b=CT:4000\r\nt=0 0\r\n");
	g_string_append(a, "a=extmap-allow-mixed\r\n");
	g_string_append(a, "a=msid-semantic: WMS *\r\n");
	g_string_append(a, "a=group:BUNDLE audio_0 video_1\r\n");
	g_string_append_printf(a, "m=audio %d RTP/SAVP 102 9 0 8 101\r\n", our_port);
	g_string_append_printf(a, "c=IN IP4 %s\r\n", our_ip ? our_ip : "127.0.0.1");
	g_string_append(a, "a=rtpmap:102 opus/48000/2\r\n");
	g_string_append(a, "a=rtpmap:9 G722/8000\r\n");
	g_string_append(a, "a=rtpmap:0 PCMU/8000\r\n");
	g_string_append(a, "a=rtpmap:8 PCMA/8000\r\n");
	g_string_append(a, "a=rtpmap:101 telephone-event/8000\r\n");
	g_string_append(a, "a=fmtp:102 minptime=10;useinbandfec=1\r\n");
	g_string_append(a, "a=mid:audio_0\r\n");
	g_string_append(a, "a=sendrecv\r\n");
	if (mp->our_ssrc) g_string_append_printf(a, "a=x-ssrc-range:%u-%u\r\n", mp->our_ssrc, mp->our_ssrc);
	g_string_append_printf(a, "a=ice-ufrag:%s\r\n", mp->our_ufrag);
	g_string_append_printf(a, "a=ice-pwd:%s\r\n", mp->our_pwd);
	g_string_append_printf(a, "a=crypto:4 AEAD_AES_256_GCM inline:%s|2^31\r\n", mp->our_txkey);
	/* Emit UDP candidates only - Teams' NGC parser can reject the whole answer over ICE-TCP lines. */
	if (mp->our_cands) {
		gchar **cl = g_strsplit(mp->our_cands->str, "\n", -1); int i;
		for (i = 0; cl[i]; i++)
			if (cl[i][0] && strstr(cl[i], " UDP ")) g_string_append_printf(a, "a=%s\r\n", cl[i]);
		g_strfreev(cl);
	}
	g_string_append(a, "a=ice-options:trickle\r\n");
	g_string_append(a, "a=rtcp-mux\r\n");
	g_string_append(a, "a=label:main-audio\r\n");

	append_video_mline(a, mp, our_port, our_ip ? our_ip : "127.0.0.1", "video_1", vdir);
	/* A declined m-line is left out of the BUNDLE group above (RFC 8843). */
	if (mp->declined_mlines) g_string_append(a, mp->declined_mlines);

	g_free(our_ip);
	return a;
}

static GString *
build_answer_sdp(TeamsMediaProc *mp)
{
	return build_sdp(mp, media_video_answer(mp));   /* see the header comment above append_video_mline */
}

/* Kicks off the two-step media-controller handshake (attach -> parse acceptance link -> accept
 * w/ SDP) using build_answer_sdp() above. */
static void
media_send_answer(TeamsMediaProc *mp)
{
	TeamsCall *call = mp->call;
	GString *a;

	if (mp->answered || !mp->our_ufrag || !mp->our_pwd || !mp->our_txkey) return;
	mp->answered = TRUE;

	g_free(mp->declined_mlines);
	mp->declined_mlines = sdp_declined_mlines(call->sdp_offer);
	media_video_offer(mp, call->sdp_offer);
	a = build_answer_sdp(mp);
	g_free(call->our_answer_sdp);
	call->our_answer_sdp = g_string_free(a, FALSE);
	sdp_log_shape("answer", call->our_answer_sdp);
	teams_call_log("ANSWER SDP built (%d bytes) - starting attach->accept handshake",
	               (int) strlen(call->our_answer_sdp));
	teams_calling_post_answer(call);
	media_video_apply(mp);
}

/* The cpconv response (201) is the new conversation; CAPTURED (teams.live.com placing a call):
 * its top-level conversationController is the same kind of URL an incoming call's
 * conversationInvitation carries, so a hangup ends a placed call the way it ends an answered one.
 * u is a DialRef. If the call was hung up while this request was in flight, the conversation is
 * left now, or the callee would go on ringing; the DialRef keeps the ids that takes. */
typedef struct {
	CallRef ref;
	gchar  *endpoint_id;
	gchar  *participant_id;
} DialRef;

static void
cpconv_resp_cb(PurpleHttpConnection *hc, PurpleHttpResponse *resp, gpointer u)
{
	DialRef *dref = u;
	TeamsCall *call = call_ref_resolve(&dref->ref);
	TeamsAccount *sa = dref->ref.sa;
	int code; const gchar *data; size_t len = 0;
	JsonObject *root;
	const gchar *controller, *leave;

	flightproxy_resp_cb(hc, resp, NULL);
	code = purple_http_response_get_code(resp);
	data = purple_http_response_get_data(resp, &len);
	if (code < 200 || code >= 300 || !data) {
		if (call) end_call(sa, "error", FALSE);   /* the call was not placed */
		goto out;
	}
	root = json_decode_object(data, len);
	controller = sget(root, "conversationController");
	leave = sget(oget(root, "links"), "leave");
	if (!controller) {
		teams_call_log("dial: no conversationController in the cpconv response");
	} else if (call) {
		g_free(call->conversation_controller);
		call->conversation_controller = g_strdup(controller);
		g_free(call->link_leave);
		call->link_leave = leave ? g_strdup(leave) : teams_calling_leave_link(controller);
	} else if (teams_account_is_live(sa)) {
		gchar *link = leave ? g_strdup(leave) : teams_calling_leave_link(controller);
		teams_call_log("dial: the call was hung up while it was being placed - leaving it");
		post_leave(sa, link, dref->endpoint_id, dref->participant_id);
		g_free(link);
	}
	if (root) json_object_unref(root);
out:
	g_free(dref->endpoint_id);
	g_free(dref->participant_id);
	g_free(dref);
}

/* CALLER: build the OFFER SDP from our media params + POST the cpconv create request to place the
 * call (mirrors the teams.live.com web client's api/v2/cpconv flow). FIRST-ATTEMPT. */
static void
media_send_offer(TeamsMediaProc *mp)
{
	TeamsCall *call = mp->call;
	const char *agent = call->callagent_id;
	GString *sdp, *body;
	gchar *offer_q, *legid, *from_id, *from_q, *name_q, *epid_q, *to_q, *loc_q, *lang_q, *pid, *to_pid;
	gchar *our_ip;
	int our_port, i;
	gboolean video;
	if (mp->answered || !mp->our_ufrag || !mp->our_pwd || !mp->our_txkey) return;
	mp->answered = TRUE;

	our_ip = our_host_address(mp, &our_port);
	video = mp->camera_wanted && mp->our_vssrc;   /* a video call, and the engine has video */
	sdp = g_string_new("v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nb=CT:4000\r\nt=0 0\r\n");
	g_string_append(sdp, video ? "a=group:BUNDLE 0 1\r\n" : "a=group:BUNDLE 0\r\n");
	g_string_append_printf(sdp, "m=audio %d RTP/SAVP 102 9 0 8\r\n", our_port);
	g_string_append_printf(sdp, "c=IN IP4 %s\r\n", our_ip ? our_ip : "0.0.0.0");
	g_string_append(sdp, "a=rtpmap:102 opus/48000/2\r\na=rtpmap:9 G722/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n");
	g_string_append(sdp, "a=fmtp:102 minptime=10;useinbandfec=1\r\na=rtcp-mux\r\na=mid:0\r\na=sendrecv\r\na=label:main-audio\r\n");
	g_string_append_printf(sdp, "a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n", mp->our_ufrag, mp->our_pwd);
	g_string_append_printf(sdp, "a=crypto:4 AEAD_AES_256_GCM inline:%s|2^31\r\n", mp->our_txkey);
	/* Emit UDP candidates only - same as build_answer_sdp(): Teams' NGC parser can reject the
	 * WHOLE blob over ICE-TCP lines. */
	if (mp->our_cands) { gchar **cl = g_strsplit(mp->our_cands->str, "\n", -1);
		for (i = 0; cl[i]; i++) if (cl[i][0] && strstr(cl[i], " UDP ")) g_string_append_printf(sdp, "a=%s\r\n", cl[i]);
		g_strfreev(cl); }
	g_string_append(sdp, "a=ice-options:trickle\r\n");
	if (video)
		append_video_mline(sdp, mp, our_port, our_ip ? our_ip : "0.0.0.0", "1", "sendrecv");
	teams_call_log("video: offering %s", video ? "sendrecv" : "no video");
	g_free(our_ip);

	offer_q = teams_call_json_quote(sdp->str);
	legid = g_strdup_printf("%08X%08X%08X%08X", g_random_int(), g_random_int(), g_random_int(), g_random_int());
	/* The call's media leg: our own renegotiation offers name it again (CAPTURED, teams.live.com:
	 * the renegotiate's mediaLegId is the cpconv's). */
	g_free(call->media_leg_id);
	call->media_leg_id = g_strdup(legid);
	from_id = g_strconcat("8:", call->sa->username ? call->sa->username : "", NULL);
	from_q = teams_call_json_quote(from_id);
	name_q = teams_call_json_quote(self_display_name(call->sa));
	/* endpointId must be our REGISTERED calling endpoint so callAgent response frames route back. */
	epid_q = teams_call_json_quote(call->sa->endpoint);
	to_q = teams_call_json_quote(call->peer_mri);
	{ gchar *loc = client_location(); loc_q = teams_call_json_quote(loc); g_free(loc); }
	{ gchar *lang = language_id(); lang_q = teams_call_json_quote(lang); g_free(lang); }
	pid = purple_uuid_random(); to_pid = purple_uuid_random();
	/* Kept for leaving the conversation: a hang-up names the same endpoint and participant. */
	g_free(call->our_endpoint_id);
	call->our_endpoint_id = g_strdup(call->sa->endpoint ? call->sa->endpoint : "");
	g_free(call->our_participant_id);
	call->our_participant_id = g_strdup(pid);

/* append "name":"<callagent path>", to body for the given control kind (conversation|call) */
#define AGL(kind, nm) do { gchar *_p = callagent_path(call, agent, kind, nm); \
	g_string_append_printf(body, "\"%s\":\"%s\",", nm, _p); g_free(_p); } while (0)

	/* conversationRequest holds ONLY {type,subject,suppressDialout,applicationType,roster,properties,links};
	 * participants/callInvitation/endpoint* are TOP-LEVEL siblings of conversationRequest (not nested). */
	body = g_string_new("{\"conversationRequest\":{\"conversationType\":null,\"subject\":null,"
		"\"suppressDialout\":false,\"applicationType\":\"TFL\",");
	{ gchar *r = callagent_path(call, agent, "conversation", "rosterUpdate");
	  g_string_append_printf(body, "\"roster\":{\"type\":\"Delta\",\"rosterUpdate\":\"%s\"},", r); g_free(r); }
	g_string_append(body, "\"properties\":{\"allowConversationWithoutHost\":true,"
		"\"enableGroupCallEventMessages\":true,\"enableGroupCallUpgradeMessage\":false,"
		"\"enableGroupCallMeetupGeneration\":false},");
	g_string_append(body, "\"links\":{");
	AGL("conversation", "conversationEnd"); AGL("conversation", "conversationUpdate");
	AGL("conversation", "localParticipantUpdate"); AGL("conversation", "addParticipantSuccess");
	AGL("conversation", "addParticipantFailure"); AGL("conversation", "addModalitySuccess");
	AGL("conversation", "addModalityFailure"); AGL("conversation", "confirmUnmute");
	AGL("conversation", "receiveMessage");
	g_string_truncate(body, body->len - 1);   /* drop trailing comma */
	g_string_append(body, "}},");              /* close links, close conversationRequest */

	/* ---- top-level siblings ---- */
	g_string_append(body, "\"contentSharing\":null,");
	g_string_append_printf(body, "\"participants\":{\"from\":{\"id\":%s,\"displayName\":%s,"
		"\"endpointId\":%s,\"participantId\":\"%s\",\"languageId\":%s},",
		from_q, name_q, epid_q, pid, lang_q);
	g_string_append_printf(body, "\"to\":[{\"id\":%s,\"participantId\":\"%s\"}]},", to_q, to_pid);
	g_string_append(body, "\"capabilities\":null,\"endpointCapabilities\":73463,"
		"\"clientEndpointCapabilities\":42876960,\"endpointMetadata\":{\"holographicCapabilities\":3},"
		"\"groupContext\":null,\"groupChat\":null,\"meetingInfo\":null,\"meetingData\":null,"
		"\"endpointState\":{\"endpointStateSequenceNumber\":2,\"endpointProperties\":"
		"{\"additionalEndpointProperties\":{\"infoShownInReportMode\":\"FullInformation\"}}},");
	g_string_append_printf(body, "\"callInvitation\":{\"callModalities\":%s,\"replaces\":null,",
		video ? "[\"Audio\",\"Video\"]" : "[\"Audio\"]");
	g_string_append(body,
		"\"transferor\":null,\"clientTransferContext\":null,\"customContext\":null,\"links\":{");
	AGL("call", "progress"); AGL("call", "mediaAnswer"); AGL("call", "acceptance");
	AGL("call", "redirection"); AGL("call", "end");
	g_string_truncate(body, body->len - 1);
	g_string_append(body, "},\"clientContentForMediaController\":{");
	AGL("call", "controlVideoStreaming"); AGL("call", "csrcInfo");
	g_string_truncate(body, body->len - 1);
	g_string_append(body, "},\"pstnContent\":{\"emergencyCallCountry\":\"\","
		"\"platformName\":\"" TEAMS_SKYPE_CLIENT "\",\"publicApiCall\":false},\"emergencyContent\":null,");
	g_string_append_printf(body, "\"mediaContent\":{\"blob\":%s,\"contentType\":\"application/sdp-ngc-1.0\","
		"\"requiredFeatures\":\"nonByPass\",\"clientLocation\":%s,\"mediaLegId\":\"%s\"},",
		offer_q, loc_q, legid);
	g_string_append(body, "\"voicemailSettings\":{},\"locationContent\":null,"
		"\"networkContent\":null,\"areaContent\":null},");   /* close callInvitation */
	g_string_append(body, "\"debugContent\":{},\"participantPropertyBag\":{}}");   /* close outer */
#undef AGL

	teams_call_log("dial: OFFER built (%d bytes sdp, %d body), POSTing cpconv to place call to %s",
	               (int) sdp->len, (int) body->len, call->peer_mri ? call->peer_mri : "?");
	{
		DialRef *dref = g_new0(DialRef, 1);
		dref->ref.sa = call->sa;
		dref->ref.serial = call->serial;
		dref->endpoint_id = g_strdup(call->our_endpoint_id);
		dref->participant_id = g_strdup(call->our_participant_id);
		flightproxy_post_cb(call->sa, "https://api.flightproxy.skype.com/api/v2/cpconv", body->str,
		                    cpconv_resp_cb, dref);
	}

	g_string_free(sdp, TRUE); g_string_free(body, TRUE);
	g_free(offer_q); g_free(legid); g_free(from_id); g_free(from_q); g_free(name_q);
	g_free(epid_q); g_free(to_q); g_free(loc_q); g_free(lang_q); g_free(pid); g_free(to_pid);
}

/* Longest wait for our ICE candidates before the offer or answer goes out without them all. */
#define MEDIA_GATHER_LIMIT_MS 4000

/* Build + POST our offer (outgoing: places the call) or answer (incoming). Once per call. */
static void
media_send_now(TeamsMediaProc *mp)
{
	if (mp->sent_sdp) return;
	mp->sent_sdp = TRUE;
	if (mp->is_caller) media_send_offer(mp);
	else               media_send_answer(mp);
}

static gboolean
media_answer_timeout(gpointer user)
{
	TeamsMediaProc *mp = user;
	mp->answer_timer = 0;
	teams_call_log("media: candidates still gathering after %d ms; sending the %s anyway",
	               MEDIA_GATHER_LIMIT_MS, mp->is_caller ? "offer" : "answer");
	media_send_now(mp);
	return G_SOURCE_REMOVE;
}

/* Teams' media relay of the call (links.udpTransport) does not answer a plain STUN Binding
 * request: it wants MS-TURN credentials. Without a server that does, libnice gathers host
 * candidates only, the peer has no address to reach us through the NAT, and only the peer's audio
 * gets through (ICE connecting -> failed, then MediaError 410). Teams' own
 * relay service answers Binding requests without credentials; the web client is given it as its
 * TURN server. Must precede START. */
#define TEAMS_STUN_HOST "world.relay.skype.com"
#define TEAMS_STUN_PORT 3478

static void
media_send_stun(TeamsMediaProc *mp)
{
	media_send(mp, "RELAY stun %s %d\n", TEAMS_STUN_HOST, TEAMS_STUN_PORT);
	teams_call_log("media: STUN server %s:%d", TEAMS_STUN_HOST, TEAMS_STUN_PORT);
}

/* Build + POST a mid-call renegotiation answer using WHATEVER local ufrag/pwd/cands mp currently
 * holds. Shared by teams_calling_handle_renegotiation() (the no-restart-needed fallback, answered
 * immediately) and media_on_output()'s RESTARTED handler (answered only once the engine's fresh
 * post-restart local creds have actually arrived - see pending_reneg_answer_link's comment). */
/* The body of a renegotiation answer. CAPTURED (teams.live.com): the web client's
 * answer names its sender, gives a mediaAcknowledgement link (where the call controller then says
 * whether it took the answer), the media-controller links of its accept, and the offer's mediaLegId
 * and our clientLocation with the SDP. Ours had the SDP only; no mediaAcknowledgement ever came and
 * the same offer was pushed again and again. g_free() it. */
/* The modalities our acceptance and answers name: video too when the answer SDP just built sends
 * our video, so the two agree (declaring "Video" with an SDP that did not was answered 408, see
 * teams_calling_post_accept). A voice call stays ["Audio"], as the web client sends it. */
static const char *
call_modalities(TeamsCall *call)
{
	TeamsMediaProc *mp = g_mproc;
	return mp && mp->call == call && mp->our_vssrc && teams_video_dir_we_send(mp->video_answer)
	       ? "[\"Audio\",\"Video\"]" : "[\"Audio\"]";
}

static gchar *
reneg_answer_body(TeamsCall *call, const gchar *sdp, const gchar *leg_id)
{
	TeamsAccount *sa = call->sa;
	const char *agent = call->callagent_id;
	gchar *from_id = g_strconcat("8:", sa->username ? sa->username : "", NULL);
	gchar *from_q = teams_call_json_quote(from_id), *name_q = teams_call_json_quote(self_display_name(sa));
	gchar *epid_q = teams_call_json_quote(call->our_endpoint_id), *pid_q = teams_call_json_quote(call->our_participant_id);
	gchar *lang = language_id(), *lang_q = teams_call_json_quote(lang);
	gchar *loc = client_location(), *loc_q = teams_call_json_quote(loc);
	gchar *blob_q = teams_call_json_quote(sdp), *leg_q = teams_call_json_quote(leg_id);
	gchar *l_ack = callagent_path(call, agent, "call", "mediaAcknowledgement");
	gchar *cc_ctlvid = callagent_path(call, agent, "call", "controlVideoStreaming");
	gchar *cc_csrc = callagent_path(call, agent, "call", "csrcInfo");
	gchar *body = g_strdup_printf(
	    "{\"mediaAnswer\":{\"callModalities\":%s,"
	      "\"sender\":{\"id\":%s,\"displayName\":%s,\"endpointId\":%s,\"participantId\":%s,\"languageId\":%s},"
	      "\"links\":{\"mediaAcknowledgement\":\"%s\"},"
	      "\"clientContentForMediaController\":{\"controlVideoStreaming\":\"%s\",\"csrcInfo\":\"%s\"},"
	      "\"mediaContent\":{\"blob\":%s,\"contentType\":\"application/sdp-ngc-1.0\","
	        "\"clientLocation\":%s%s%s}}}",
	    call_modalities(call), from_q, name_q, epid_q, pid_q, lang_q, l_ack, cc_ctlvid, cc_csrc, blob_q, loc_q,
	    leg_id ? ",\"mediaLegId\":" : "", leg_id ? leg_q : "");
	g_free(from_id); g_free(from_q); g_free(name_q); g_free(epid_q); g_free(pid_q);
	g_free(lang); g_free(lang_q); g_free(loc); g_free(loc_q); g_free(blob_q); g_free(leg_q);
	g_free(l_ack); g_free(cc_ctlvid); g_free(cc_csrc);
	return body;
}

static void
send_reneg_answer(TeamsMediaProc *mp, const gchar *answer_link)
{
	TeamsCall *call = mp->call;
	GString *a = build_answer_sdp(mp);
	gchar *body;
	sdp_log_shape("renegotiation answer", a->str);
	body = reneg_answer_body(call, a->str, mp->reneg_leg_id);
	teams_call_log("renegotiate: POSTing updated answer (%d bytes) to %s", (int) strlen(body), answer_link);
	flightproxy_post_cb(call->sa, answer_link, body, flightproxy_resp_cb, NULL);
	g_free(body); g_string_free(a, TRUE);
	media_video_apply(mp);
}

/* ---- our own renegotiation offer ----------------------------------------------------------
 * Turning our camera on in a call whose answer so far does not let us send. CAPTURED
 * (teams.live.com turning its camera on mid-call): the web client POSTs
 * {"mediaNegotiation":{callModalities, sender, links{mediaAnswer, rejection}, mediaContent{blob,
 * contentType, requiredFeatures, clientLocation, negotiationTag, mediaLegId}}} to the far side's
 * mediaRenegotiation link (202); the answer comes as a mediaAnswer frame on the link given, the
 * web client acknowledges it on that frame's mediaAcknowledgement link, and the far side then
 * sends offers of its own, answered as before. */
#define RENEG_OFFER_WAIT_S 15

static gchar *
reneg_offer_body(TeamsCall *call, const gchar *sdp, const gchar *leg_id, const gchar *tag)
{
	TeamsAccount *sa = call->sa;
	const char *agent = call->callagent_id;
	gchar *sender = participant_from_json(sa, call->our_endpoint_id, call->our_participant_id);
	gchar *loc = client_location(), *loc_q = teams_call_json_quote(loc);
	gchar *blob_q = teams_call_json_quote(sdp), *leg_q = teams_call_json_quote(leg_id ? leg_id : "");
	gchar *tag_q = teams_call_json_quote(tag ? tag : "");
	gchar *l_ans = callagent_path(call, agent, "call", "mediaAnswer");
	gchar *l_rej = callagent_path(call, agent, "call", "rejection");
	gchar *body = g_strdup_printf(
	    "{\"mediaNegotiation\":{\"callModalities\":[\"Audio\",\"Video\"],\"sender\":%s,"
	      "\"links\":{\"mediaAnswer\":\"%s\",\"rejection\":\"%s\"},"
	      "\"mediaContent\":{\"blob\":%s,\"contentType\":\"application/sdp-ngc-1.0\","
	        "\"requiredFeatures\":\"nonByPass\",\"clientLocation\":%s,\"negotiationTag\":%s,"
	        "\"mediaLegId\":%s}}}",
	    sender, l_ans, l_rej, blob_q, loc_q, tag_q, leg_q);
	g_free(sender); g_free(loc); g_free(loc_q); g_free(blob_q); g_free(leg_q); g_free(tag_q);
	g_free(l_ans); g_free(l_rej);
	return body;
}

static void
reneg_offer_done(TeamsMediaProc *mp)
{
	mp->reneg_offer_pending = FALSE;
	if (mp->reneg_offer_timer) g_source_remove(mp->reneg_offer_timer);
	mp->reneg_offer_timer = 0;
}

static gboolean
reneg_offer_timeout(gpointer u)
{
	TeamsMediaProc *mp = u;
	mp->reneg_offer_timer = 0;
	mp->reneg_offer_pending = FALSE;
	teams_call_log("renegotiate: no answer to our offer after %d s", RENEG_OFFER_WAIT_S);
	return G_SOURCE_REMOVE;
}

static void
reneg_offer_resp_cb(PurpleHttpConnection *hc, PurpleHttpResponse *resp, gpointer u)
{
	CallRef *ref = u;
	TeamsCall *call = call_ref_resolve(ref);
	int code = purple_http_response_get_code(resp);
	g_free(ref);
	flightproxy_resp_cb(hc, resp, NULL);
	teams_call_log("renegotiate: our offer answered %d", code);
	if (call && g_mproc && g_mproc->call == call && (code < 200 || code >= 300))
		reneg_offer_done(g_mproc);
}

/* POST our offer: video sendrecv on the call's media. FALSE if it could not be sent. */
static gboolean
send_reneg_offer(TeamsMediaProc *mp)
{
	TeamsCall *call = mp->call;
	GString *sdp;
	gchar *tag, *body, *url, *host;
	const gchar *leg = call->media_leg_id ? call->media_leg_id : mp->reneg_leg_id;
	if (!call->link_peer_reneg || !mp->our_ufrag || !mp->our_pwd || !mp->our_txkey || !call->our_participant_id) {
		teams_call_log("renegotiate: cannot offer video (link=%d uf=%d pw=%d key=%d pid=%d)",
		               call->link_peer_reneg != NULL, mp->our_ufrag != NULL, mp->our_pwd != NULL,
		               mp->our_txkey != NULL, call->our_participant_id != NULL);
		return FALSE;
	}
	tag = teams_negotiation_tag(call->our_participant_id, call->reneg_offers + 1);
	if (!tag) return FALSE;
	call->reneg_offers++;
	sdp = build_sdp(mp, "sendrecv");
	sdp_log_shape("renegotiation offer of ours", sdp->str);
	body = reneg_offer_body(call, sdp->str, leg, tag);
	url = teams_calling_via_flightproxy(call->link_peer_reneg);
	host = url_host_for_log(url);
	teams_call_log("renegotiate: offering video sendrecv, v_%u (%d bytes) to %s", call->reneg_offers,
	               (int) strlen(body), host ? host : "?");
	mp->reneg_offer_pending = TRUE;
	if (mp->reneg_offer_timer) g_source_remove(mp->reneg_offer_timer);
	mp->reneg_offer_timer = g_timeout_add_seconds(RENEG_OFFER_WAIT_S, reneg_offer_timeout, mp);
	flightproxy_post_cb(call->sa, url, body, reneg_offer_resp_cb, call_ref_new(call));
	g_free(host); g_free(url); g_free(body); g_free(tag); g_string_free(sdp, TRUE);
	return TRUE;
}

/* The far side's answer to our offer (a mediaAnswer frame while one is waiting): acknowledge it
 * and send our camera if it lets us. The credentials stay the call's (see build_sdp); an answer
 * that changes them is logged, not applied. */
static void
handle_reneg_offer_answer(TeamsAccount *sa, TeamsCall *call, TeamsMediaProc *mp, JsonObject *body_obj)
{
	JsonObject *ma = oget(body_obj, "mediaAnswer"), *mc = ma ? oget(ma, "mediaContent") : NULL;
	JsonObject *links = ma ? oget(ma, "links") : NULL;
	const gchar *blob = mc ? sget(mc, "blob") : NULL;
	const gchar *ack_url = links ? sget(links, "mediaAcknowledgement") : NULL;
	const char *peer;
	reneg_offer_done(mp);
	if (ack_url && *ack_url) {
		gchar *url = teams_calling_via_flightproxy(ack_url);
		flightproxy_post_cb(sa, url, "{\"mediaAcknowledgement\":{\"code\":0,\"subCode\":0,"
		                    "\"reason\":\"noError\",\"phrase\":\"Success\"}}", flightproxy_resp_cb, NULL);
		g_free(url);
	}
	if (!blob) { teams_call_log("renegotiate: answer to our offer without SDP"); return; }
	{
		gchar *uf = sdp_line_val(blob, "a=ice-ufrag:");
		gchar *cur = mp->last_restarted_ufrag ? g_strdup(mp->last_restarted_ufrag)
		           : mp->answer_ufrag ? g_strdup(mp->answer_ufrag)
		           : call->sdp_offer ? sdp_line_val(call->sdp_offer, "a=ice-ufrag:") : NULL;
		teams_call_log("renegotiate: answer to our offer, ICE %s, acknowledged %s",
		               uf && cur && !strcmp(uf, cur) ? "unchanged" : "CHANGED (not applied)",
		               ack_url && *ack_url ? "yes" : "no (no link)");
		g_free(uf); g_free(cur);
	}
	peer = teams_sdp_video_direction(blob);
	mp->video_offer = NULL;
	mp->video_answer = teams_video_our_direction(peer);
	teams_video_send_params(blob, &mp->vsend_w, &mp->vsend_h, &mp->vsend_kbps);
	teams_call_log("video: answer to our offer %s, so we %s", peer ? peer : "none", mp->video_answer);
	video_event(mp, teams_video_dir_peer_sends(peer) ? "OFFERED 1" : "OFFERED 0");
	media_video_apply(mp);
}

/* read UFRAG/PWD/TXKEY/SSRC/VSSRC/CAND/READY/ANSWERED/RESTARTED/AUDIOD/ERR and the video lines
 * (VSHM/VPREVIEW/VTX/PEERVIDEO/VIDEOERR, passed to the front end) from teams_media's stdout */
static gboolean
media_on_output(GIOChannel *ch, GIOCondition cond, gpointer user)
{
	TeamsMediaProc *mp = user;
	gchar *line = NULL; gsize len = 0;
	while ((cond & G_IO_IN) &&
	       g_io_channel_read_line(ch, &line, &len, NULL, NULL) == G_IO_STATUS_NORMAL && line) {
		g_strchomp(line);
		if (g_str_has_prefix(line, "UFRAG ")) { g_free(mp->our_ufrag); mp->our_ufrag = g_strdup(line + 6); }
		else if (g_str_has_prefix(line, "PWD ")) { g_free(mp->our_pwd); mp->our_pwd = g_strdup(line + 4); }
		else if (g_str_has_prefix(line, "TXKEY ")) {
			if (mp->our_txkey) explicit_bzero(mp->our_txkey, strlen(mp->our_txkey));
			g_free(mp->our_txkey); mp->our_txkey = g_strdup(line + 6);
			explicit_bzero(line, strlen(line));
		}
		else if (g_str_has_prefix(line, "SSRC ")) mp->our_ssrc = (guint32) g_ascii_strtoull(line + 5, NULL, 10);
		else if (g_str_has_prefix(line, "VSSRC ")) mp->our_vssrc = (guint32) g_ascii_strtoull(line + 6, NULL, 10);
		else if (g_str_has_prefix(line, "VSHM ") || g_str_has_prefix(line, "VPREVIEW ") ||
		         g_str_has_prefix(line, "VTX ") || g_str_has_prefix(line, "PEERVIDEO ") ||
		         g_str_has_prefix(line, "VIDEOERR ")) {
			teams_call_log("media %s", line);
			if (g_str_has_prefix(line, "VIDEOERR tx")) mp->camera_sent = FALSE;   /* the engine stopped it */
			if (!strcmp(line, "VIDEOERR build")) mp->our_vssrc = 0;        /* the call stays voice only */
			video_event(mp, line);
		}
		else if (g_str_has_prefix(line, "CAND ")) g_string_append_printf(mp->our_cands, "%s\n", line + 5);
		else if (!strcmp(line, "RESTARTED")) {
			/* The RESTART's fresh UFRAG/PWD lines are always emitted BEFORE this marker (see
			 * teams_media.c), so mp->our_ufrag/our_pwd are already the new post-restart values
			 * by the time we get here - safe to answer now. */
			if (mp->pending_reneg_answer_link) {
				gchar *link = mp->pending_reneg_answer_link;
				mp->pending_reneg_answer_link = NULL;
				send_reneg_answer(mp, link);
				g_free(link);
			}
		}
		else if (!strcmp(line, "ANSWERED")) teams_call_log("media engine applied the peer's answer");
		else if (g_str_has_prefix(line, "ERR ")) {
			teams_call_log("media engine ERR: %s", line + 4);
			if (mp->pending_reneg_answer_link) {
				teams_call_log("renegotiate: engine restart failed, dropping pending answer");
				g_free(mp->pending_reneg_answer_link);
				mp->pending_reneg_answer_link = NULL;
			}
		}
		else if (!strcmp(line, "READY")) {
			/* The offer or answer goes out once our candidates are complete (GATHERED), so it
			 * carries the server-reflexive one; without that the peer has no address to reach us
			 * through the NAT, and the call has audio one way only. If gathering hangs - the STUN
			 * server does not answer - it goes out with what there is after a while. */
			teams_call_log("media engine READY; gathering candidates before %s",
			               mp->is_caller ? "offer" : "answer");
			if (mp->gathered)
				media_send_now(mp);
			else if (!mp->answer_timer)
				mp->answer_timer = g_timeout_add(MEDIA_GATHER_LIMIT_MS, media_answer_timeout, mp);
		}
		else if (!strcmp(line, "GATHERED")) {
			mp->gathered = TRUE;
			if (mp->answer_timer) {
				g_source_remove(mp->answer_timer);
				mp->answer_timer = 0;
				teams_call_log("media engine GATHERED; sending the %s", mp->is_caller ? "offer" : "answer");
				media_send_now(mp);
			}
		}
		else if (g_str_has_prefix(line, "AUDIOD ")) teams_call_log("media audiod %s", line + 7);
		g_free(line); line = NULL;
	}
	if (cond & (G_IO_HUP | G_IO_ERR)) {
		/* The engine closed its stdout; its exit is handled by media_child_exited(). */
		mp->out_watch = 0;
		return G_SOURCE_REMOVE;
	}
	return G_SOURCE_CONTINUE;
}

static gboolean
media_kill_cb(gpointer user)
{
	MediaReaper *r = user;
	r->kill_timer = 0;
	teams_call_log("media engine pid=%d did not stop; sending SIGTERM", (int) r->pid);
	kill(r->pid, SIGTERM);
	return G_SOURCE_REMOVE;
}

/* Reap an engine. If it belongs to the current call, the call has lost its media: end it. */
static void
media_child_exited(GPid pid, gint status, gpointer user)
{
	MediaReaper *r = user;
	GError *err = NULL;

	if (r->kill_timer) g_source_remove(r->kill_timer);
#if GLIB_CHECK_VERSION(2, 70, 0) && GLIB_VERSION_MIN_REQUIRED >= GLIB_VERSION_2_70
	if (!g_spawn_check_wait_status(status, &err)) {
#else
	if (!g_spawn_check_exit_status(status, &err)) {
#endif
		teams_call_log("media engine pid=%d: %s", (int) pid, err->message);
		g_error_free(err);
	}
	g_spawn_close_pid(pid);
	if (g_mproc && g_mproc->reaper == r) {
		TeamsCall *call = g_mproc->call;
		g_mproc->reaper = NULL;
		teams_call_log("media engine exited during the call; ending it");
		end_call(call->sa, "error", TRUE);
	}
	g_free(r);
}

/* Start an engine for call (none may be running): stdin is a socketpair, stdout a pipe, stderr
 * the service's own. The engine inherits our environment. */
static TeamsMediaProc *
media_spawn(TeamsCall *call, gboolean is_caller)
{
	const gchar *argv[] = { TEAMS_MEDIA_BIN, is_caller ? "--caller" : "--answer", NULL };
	int sv[2], outp[2];
	GPid pid;
	GError *err = NULL;
	TeamsMediaProc *mp;
	MediaReaper *r;

	if (g_mproc) {
		teams_call_log("media: an engine is already running for another call");
		return NULL;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
		teams_call_log("media: socketpair: %s", g_strerror(errno));
		return NULL;
	}
	if (!g_unix_open_pipe(outp, FD_CLOEXEC, &err)) {
		teams_call_log("media: pipe: %s", err->message);
		g_error_free(err);
		close(sv[0]); close(sv[1]);
		return NULL;
	}
	if (!g_spawn_async_with_fds(NULL, (gchar **) argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	                            &pid, sv[1], outp[1], -1, &err)) {
		teams_call_log("media: spawn %s failed: %s", TEAMS_MEDIA_BIN, err->message);
		g_error_free(err);
		close(sv[0]); close(sv[1]); close(outp[0]); close(outp[1]);
		return NULL;
	}
	close(sv[1]); close(outp[1]);

	r = g_new0(MediaReaper, 1);
	r->pid = pid;
	g_child_watch_add(pid, media_child_exited, r);

	mp = g_new0(TeamsMediaProc, 1);
	mp->call = call; mp->reaper = r; mp->in_fd = sv[0]; mp->is_caller = is_caller;
	mp->our_cands = g_string_new("");
	mp->out_ch = g_io_channel_unix_new(outp[0]);
	g_io_channel_set_close_on_unref(mp->out_ch, TRUE);
	g_io_channel_set_encoding(mp->out_ch, NULL, NULL);
	g_io_channel_set_flags(mp->out_ch, G_IO_FLAG_NONBLOCK, NULL);
	mp->out_watch = g_io_add_watch(mp->out_ch, G_IO_IN | G_IO_HUP | G_IO_ERR, media_on_output, mp);
	g_mproc = mp;
	teams_call_log("media: spawned %s %s pid=%d", TEAMS_MEDIA_BIN, argv[1], (int) pid);
	return mp;
}

/* Answerer: start an engine with the offer's keys, ICE credentials and candidates. */
static gboolean
teams_media_start(TeamsCall *call)
{
	TeamsMediaProc *mp;
	gchar *ruf, *rpw, *rxkey;
	int pt = sdp_opus_pt(call->sdp_offer);
	gboolean ok;

	ruf   = sdp_line_val(call->sdp_offer, "a=ice-ufrag:");
	rpw   = sdp_line_val(call->sdp_offer, "a=ice-pwd:");
	rxkey = sdp_gcm_key(call->sdp_offer);
	if (!ruf || !rpw || !rxkey) {
		teams_call_log("media_start: offer missing ice/crypto (uf=%d pw=%d key=%d) - cannot answer",
		               ruf != NULL, rpw != NULL, rxkey != NULL);
		g_free(ruf); g_free(rpw); g_free(rxkey);
		return FALSE;
	}
	mp = media_spawn(call, FALSE);
	if (!mp) { g_free(ruf); g_free(rpw); g_free(rxkey); return FALSE; }

	media_send_stun(mp);

	/* START <rx_master_b64> <remote_ufrag> <remote_pwd> <pt> */
	ok = media_send(mp, "START %s %s %s %d\n", rxkey, ruf, rpw, pt);
	if (ok) media_send_candidates(mp, call->sdp_offer);
	teams_call_log("media_start: START %s (pt=%d relay=%s)", ok ? "sent" : "failed", pt,
	               call->udp_transport ? call->udp_transport : "(none)");
	explicit_bzero(rxkey, strlen(rxkey));
	g_free(ruf); g_free(rpw); g_free(rxkey);
	return ok;
}

/* Stop the running engine: STOP, close its stdin, and leave the reaper to collect it (SIGTERM if
 * it has not gone after 5 s). */
static void
teams_media_stop(void)
{
	TeamsMediaProc *mp = g_mproc;
	if (!mp) return;
	video_event(mp, "");   /* the call's video is over */
	g_mproc = NULL;
	if (mp->answer_timer) g_source_remove(mp->answer_timer);
	if (mp->reneg_offer_timer) g_source_remove(mp->reneg_offer_timer);
	if (mp->in_fd >= 0) { media_send(mp, "STOP\n"); close(mp->in_fd); }
	if (mp->out_watch) g_source_remove(mp->out_watch);
	if (mp->out_ch) g_io_channel_unref(mp->out_ch);
	if (mp->reaper && !mp->reaper->kill_timer)
		mp->reaper->kill_timer = g_timeout_add_seconds(5, media_kill_cb, mp->reaper);
	g_string_free(mp->our_cands, TRUE);
	if (mp->our_txkey) explicit_bzero(mp->our_txkey, strlen(mp->our_txkey));
	g_free(mp->our_ufrag); g_free(mp->our_pwd); g_free(mp->our_txkey); g_free(mp->answer_ufrag);
	g_free(mp->pending_reneg_answer_link);
	g_free(mp->last_restarted_ufrag);
	g_free(mp->declined_mlines);
	g_free(mp->reneg_leg_id);
	g_free(mp);
	teams_call_log("media stopped");
}

/* Step 2: POST the accept (with our SDP answer) to the acceptance link parsed from the attach
 * response. Body = callAcceptance{acceptedBy, acceptedCallModalities, caps, mediaContent{blob,...}}.
 * acceptedCallModalities is ["Audio"] unless our answer sends video (call_modalities); ["Audio"]
 * has been accepted live with the answer's sendrecv video m-line. (Declaring "Video" while the SDP said otherwise was answered
 * with 408 "Call Controller timed out while waiting for acknowledgement".) */
static void
teams_calling_post_accept(TeamsCall *call, const gchar *acceptance_url)
{
	TeamsAccount *sa = call->sa;
	const char *agent = call->callagent_id;
	gchar *blob_q, *legid, *body, *from_id, *from_q, *name_q, *epid_q, *pid_q, *loc, *loc_q, *lang, *lang_q;
	gchar *l_reneg, *l_xfer, *l_repl, *l_bal, *l_retgt, *l_ctlvid, *l_updmd, *cc_ctlvid, *cc_csrc;
	if (!call->our_answer_sdp) { teams_call_log("accept: no answer SDP"); return; }
	blob_q = teams_call_json_quote(call->our_answer_sdp);
	legid = g_strdup_printf("%08X%08X%08X%08X", g_random_int(), g_random_int(), g_random_int(), g_random_int());
	from_id = g_strconcat("8:", sa->username ? sa->username : "", NULL);
	from_q = teams_call_json_quote(from_id);
	name_q = teams_call_json_quote(self_display_name(sa));
	epid_q = teams_call_json_quote(call->our_endpoint_id);
	pid_q = teams_call_json_quote(call->our_participant_id);
	loc = client_location();
	loc_q = teams_call_json_quote(loc);
	lang = language_id();
	lang_q = teams_call_json_quote(lang);
	l_reneg  = callagent_path(call, agent, "call", "mediaRenegotiation");
	l_xfer   = callagent_path(call, agent, "call", "transfer");
	l_repl   = callagent_path(call, agent, "call", "replacement");
	l_bal    = callagent_path(call, agent, "call", "balanceUpdate");
	l_retgt  = callagent_path(call, agent, "call", "retargetCompletion");
	l_ctlvid = callagent_path(call, agent, "call", "controlVideoStreaming");
	l_updmd  = callagent_path(call, agent, "call", "updateMediaDescriptions");
	cc_ctlvid = callagent_path(call, agent, "call", "controlVideoStreaming");
	cc_csrc   = callagent_path(call, agent, "call", "csrcInfo");
	body = g_strdup_printf(
		"{\"callAcceptance\":{"
		  "\"acceptedBy\":{\"id\":%s,\"displayName\":%s,\"endpointId\":%s,"
		    "\"participantId\":%s,\"languageId\":%s},"
		  "\"acceptedCallModalities\":%s,"
		  "\"capabilities\":null,\"endpointCapabilities\":73463,\"clientEndpointCapabilities\":42876960,"
		  "\"links\":{\"mediaRenegotiation\":\"%s\",\"transfer\":\"%s\",\"replacement\":\"%s\","
		    "\"balanceUpdate\":\"%s\",\"retargetCompletion\":\"%s\",\"controlVideoStreaming\":\"%s\","
		    "\"updateMediaDescriptions\":\"%s\"},"
		  "\"clientContentForMediaController\":{\"controlVideoStreaming\":\"%s\",\"csrcInfo\":\"%s\"},"
		  "\"mediaContent\":{\"blob\":%s,\"contentType\":\"application/sdp-ngc-1.0\","
		    "\"clientLocation\":%s,\"mediaLegId\":\"%s\"},"
		  "\"pstnContent\":{\"emergencyCallCountry\":\"\",\"platformName\":\"" TEAMS_SKYPE_CLIENT "\","
		    "\"publicApiCall\":false},"
		  "\"callKeepAliveInterval\":null,"
		  "\"applicationType\":\"TFL\"}}",
		from_q, name_q, epid_q, pid_q, lang_q, call_modalities(call),
		l_reneg, l_xfer, l_repl, l_bal, l_retgt, l_ctlvid, l_updmd, cc_ctlvid, cc_csrc,
		blob_q, loc_q, legid);
	teams_call_log("accept -> POST %d-byte body to acceptance link", (int) strlen(body));
	flightproxy_post_cb(sa, acceptance_url, body, accept_resp_cb, call_ref_new(call));
	g_free(blob_q); g_free(legid); g_free(body); g_free(from_id); g_free(from_q); g_free(name_q);
	g_free(epid_q); g_free(pid_q); g_free(loc); g_free(loc_q); g_free(lang); g_free(lang_q);
	g_free(l_reneg); g_free(l_xfer); g_free(l_repl); g_free(l_bal); g_free(l_retgt);
	g_free(l_ctlvid); g_free(l_updmd); g_free(cc_ctlvid); g_free(cc_csrc);
}

/* The member names of o (never values: they carry ids and links), for the log. */
static void
log_member_names(const gchar *what, JsonObject *o)
{
	GList *names, *l;
	GString *s;
	if (!o) { teams_call_log("%s: none", what); return; }
	names = json_object_get_members(o);
	s = g_string_new(NULL);
	for (l = names; l; l = l->next)
		g_string_append_printf(s, "%s%s", s->len ? "," : "", (const gchar *) l->data);
	teams_call_log("%s: %s", what, s->str);
	g_string_free(s, TRUE);
	g_list_free(names);
}

/* *dst = a copy of src when src is a non-empty string; left alone otherwise. */
static void
set_link(gchar **dst, const gchar *src)
{
	if (!src || !*src) return;
	g_free(*dst);
	*dst = g_strdup(src);
}

/* The accept's answer: once it is accepted, our endpoint's metadata goes to the conversation, as
 * the web client sends it (put_endpoint_metadata). u is a CallRef. */
static void
accept_resp_cb(PurpleHttpConnection *hc, PurpleHttpResponse *resp, gpointer u)
{
	CallRef *ref = u;
	TeamsCall *call = call_ref_resolve(ref);
	int code = purple_http_response_get_code(resp);
	g_free(ref);
	flightproxy_resp_cb(hc, resp, NULL);
	if (call && code >= 200 && code < 300) {
		/* Where our own renegotiation offers go in a call we answered. CAPTURED (teams.live.com
		 * answering the Teams Android app): the accept's response is a
		 * callAcceptanceAcknowledgement whose links name a mediaRenegotiation. */
		size_t len = 0;
		const gchar *data = purple_http_response_get_data(resp, &len);
		JsonObject *root = data && len && len <= G_MAXSSIZE ? json_decode_object(data, (gssize) len) : NULL;
		JsonObject *ack = root ? oget(root, "callAcceptanceAcknowledgement") : NULL;
		JsonObject *links = ack ? oget(ack, "links") : NULL;
		const gchar *reneg = links ? sget(links, "mediaRenegotiation") : NULL;
		if (reneg && *reneg) {
			g_free(call->link_peer_reneg);
			call->link_peer_reneg = g_strdup(reneg);
		}
		teams_call_log("accept: %s renegotiation link for our own offers", reneg && *reneg ? "a" : "no");
		if (root) json_object_unref(root);
		put_endpoint_metadata(call);
	}
}

static void post_ringing(TeamsCall *call);

/* The answer's part once both the attach response and our SDP answer are there: our endpoint
 * state to the conversation (the web client sends it between attach and accept), then the
 * accept. Runs once per call. */
static void
post_accept_now(TeamsCall *call)
{
	if (call->accept_sent || !call->link_acceptance || !call->our_answer_sdp) return;
	call->accept_wanted = FALSE;
	call->accept_sent = TRUE;
	if (call->link_leave) post_endpoint_state(call);
	teams_calling_post_accept(call, call->link_acceptance);
}

/* Step 1 response handler: keep callInvitation.links.acceptance from the attach response (and the
 * join's leave link), and POST the accept if the call was answered meanwhile. u is a CallRef; the
 * call may have ended meanwhile. */
static void
attach_resp_cb(PurpleHttpConnection *hc, PurpleHttpResponse *resp, gpointer u)
{
	CallRef *ref = u;
	TeamsCall *call = call_ref_resolve(ref);
	int code; const gchar *data; size_t len = 0;
	JsonObject *root, *ci, *links; const gchar *acc = NULL;
	(void) hc;
	g_free(ref);
	if (!call) { teams_call_log("attach resp for a call that has ended - ignored"); return; }
	code = purple_http_response_get_code(resp);
	data = purple_http_response_get_data(resp, &len);
	teams_call_log("attach resp code=%d (%d bytes) err=%s", code, (int) len,
	               purple_http_response_get_error(resp) ? purple_http_response_get_error(resp) : "(none)");
	if (code < 200 || code >= 300 || !data) {
		teams_call_log("attach FAILED: %.240s", data ? data : "(no body)");
		return;
	}
	root = json_decode_object(data, len);
	if (root && (ci = oget(root, "callInvitation")) && (links = oget(ci, "links")))
		acc = sget(links, "acceptance");
	/* The join that went with the attach answers with the conversation and its links, leave
	 * among them (additionalActionResponses[].output.links.leave). */
	if (root && json_object_has_member(root, "additionalActionResponses") &&
	    JSON_NODE_HOLDS_ARRAY(json_object_get_member(root, "additionalActionResponses"))) {
		JsonArray *actions = json_object_get_array_member(root, "additionalActionResponses");
		guint i, n = json_array_get_length(actions);
		for (i = 0; i < n; i++) {
			JsonNode *an = json_array_get_element(actions, i);
			JsonObject *el = an && JSON_NODE_HOLDS_OBJECT(an) ? json_node_get_object(an) : NULL;
			JsonObject *output = oget(el, "output");
			JsonObject *olinks = oget(output, "links");
			const gchar *leave = sget(olinks, "leave");
			log_member_names("attach: join response", el);
			log_member_names("attach: join output.links", olinks);
			if (leave) {
				g_free(call->link_leave);
				call->link_leave = g_strdup(leave);
				set_link(&call->link_endpoint_state, sget(olinks, "updateEndpointState"));
				set_link(&call->link_endpoint_metadata, sget(olinks, "updateEndpointMetadata"));
				break;
			}
		}
	}
	teams_call_log("attach: %s", call->link_leave ? "joined the conversation (leave link acquired)"
	                                               : "no leave link in the response");
	if (call->link_leave) {
		/* Not in the join's links: the web client's have the controller's shape (teams_calling_conv_link). */
		if (!call->link_endpoint_state)
			call->link_endpoint_state = teams_calling_conv_link(call->conversation_controller, "updateEndpointState");
		if (!call->link_endpoint_metadata)
			call->link_endpoint_metadata = teams_calling_conv_link(call->conversation_controller, "updateEndpointMetadata");
	}
	set_link(&call->link_acceptance, acc);
	if (!acc)
		teams_call_log("attach OK but no callInvitation.links.acceptance in response");
	else if (call->accept_wanted)
		teams_call_log("attach OK -> acceptance link acquired, answered already: posting accept");
	else
		teams_call_log("attach OK -> acceptance link acquired, ringing until answered");
	if (call->accept_wanted)
		post_accept_now(call);
	else if (call->state == TEAMS_CALL_INCOMING)
		post_ringing(call);
	if (root) json_object_unref(root);
}

/* The "join" that goes with the attach (NULL without a conversation controller to join).
 * CAPTURED (teams.live.com answering an incoming call): attach carries
 * additionalActions [{input:{...}, name:"join", url:<conversationInvitation.conversationController>,
 * waitForResponse:true}]; its input names our conversation callbacks and us. Joining is what gives
 * the call a conversation to leave: the attach response then holds links.leave, which a hang-up
 * needs. */
static gchar *
attach_join_action(TeamsCall *call)
{
	const char *agent = call->callagent_id;
	gchar *url_q, *from_id, *from_q, *name_q, *epid_q, *pid_q, *lang, *lang_q, *ret;
	gchar *roster, *l_end, *l_upd, *l_local, *l_addok, *l_addfail, *l_msg;

	if (!call->conversation_controller || !*call->conversation_controller) return NULL;
	url_q   = teams_call_json_quote(call->conversation_controller);
	from_id = g_strconcat("8:", call->sa->username ? call->sa->username : "", NULL);
	from_q  = teams_call_json_quote(from_id);
	name_q  = teams_call_json_quote(self_display_name(call->sa));
	epid_q  = teams_call_json_quote(call->our_endpoint_id);
	pid_q   = teams_call_json_quote(call->our_participant_id);
	lang    = language_id();
	lang_q  = teams_call_json_quote(lang);
	roster    = callagent_path(call, agent, "conversation", "rosterUpdate");
	l_end     = callagent_path(call, agent, "conversation", "conversationEnd");
	l_upd     = callagent_path(call, agent, "conversation", "conversationUpdate");
	l_local   = callagent_path(call, agent, "conversation", "localParticipantUpdate");
	l_addok   = callagent_path(call, agent, "conversation", "addParticipantSuccess");
	l_addfail = callagent_path(call, agent, "conversation", "addParticipantFailure");
	l_msg     = callagent_path(call, agent, "conversation", "receiveMessage");

	ret = g_strdup_printf(
		"{\"input\":{\"capabilities\":null,\"endpointCapabilities\":73463,"
		  "\"conversationRequest\":{\"applicationType\":\"TFL\","
		    "\"roster\":{\"type\":\"Delta\",\"rosterUpdate\":\"%s\"},"
		    "\"links\":{\"conversationEnd\":\"%s\",\"conversationUpdate\":\"%s\","
		      "\"localParticipantUpdate\":\"%s\",\"addParticipantSuccess\":\"%s\","
		      "\"addParticipantFailure\":\"%s\",\"receiveMessage\":\"%s\"}},"
		  "\"endpointMetadata\":{},"
		  "\"participants\":{\"from\":{\"id\":%s,\"displayName\":%s,\"endpointId\":%s,"
		    "\"participantId\":%s,\"languageId\":%s}}},"
		"\"name\":\"join\",\"url\":%s,\"waitForResponse\":true}",
		roster, l_end, l_upd, l_local, l_addok, l_addfail, l_msg,
		from_q, name_q, epid_q, pid_q, lang_q, url_q);

	g_free(url_q); g_free(from_id); g_free(from_q); g_free(name_q); g_free(epid_q); g_free(pid_q);
	g_free(lang); g_free(lang_q); g_free(roster); g_free(l_end); g_free(l_upd); g_free(l_local);
	g_free(l_addok); g_free(l_addfail); g_free(l_msg);
	return ret;
}

/* Incoming call, step 1 of the media-controller handshake: POST attach to the offer's link_attach;
 * the response yields the acceptance link (step 2, the accept). CAPTURED (teams.live.com):
 * the web client attaches 0.1-0.3 s after the call notification,
 * while it rings, and answers progress "ringing" right after. The attach names our call/end
 * link: without it the call controller cannot tell this client that the call was answered on
 * another device, and it went on ringing. Sent once per call. */
static void
teams_calling_ring_attach(TeamsCall *call)
{
	gchar *end_link, *join;
	GString *body;
	if (call->attach_sent) return;
	if (!call->link_attach) { teams_call_log("attach: no attach link"); return; }
	call->attach_sent = TRUE;

	/* generate our endpoint/participant/callAgent identity for this call (reused in accept) */
	if (!call->our_endpoint_id)    call->our_endpoint_id = g_strdup(call->sa->endpoint ? call->sa->endpoint : "");
	if (!call->our_participant_id) call->our_participant_id = purple_uuid_random();
	if (!call->callagent_id)       call->callagent_id = purple_uuid_random();
	end_link = callagent_path(call, call->callagent_id, "call", "end");

	body = g_string_new(NULL);
	g_string_append_printf(body,
		"{\"attach\":{\"requireMediaContent\":false,\"links\":{\"end\":\"%s\"},"
		  "\"locationContent\":null,\"networkContent\":null,\"areaContent\":null,"
		  "\"applicationType\":\"TFL\"},"
		"\"capabilities\":null,\"endpointCapabilities\":73463",
		end_link);
	join = attach_join_action(call);
	if (join) {
		g_string_append_printf(body, ",\"additionalActions\":[%s]", join);
		g_free(join);
	}
	g_string_append(body, "}");
	teams_call_log("attach (step 1/2)%s -> %d-byte body",
	               call->conversation_controller ? " with join" : "", (int) body->len);
	flightproxy_post_cb(call->sa, call->link_attach, body->str, attach_resp_cb, call_ref_new(call));
	g_free(end_link); g_string_free(body, TRUE);
}

/* Tell the caller's side that we ring, as the web client does right after its attach. CAPTURED
 * (teams.live.com): POST callNotification.links.progress
 * {"callProgress":{"sender":{id,displayName,endpointId,participantId,languageId},
 * "status":"ringing","phrase":"ringing"}} -> 202. */
static void
post_ringing(TeamsCall *call)
{
	gchar *from_id, *from_q, *name_q, *epid_q, *pid_q, *lang, *lang_q, *body;
	if (!call->link_progress || !call->our_endpoint_id || !call->our_participant_id) return;
	from_id = g_strconcat("8:", call->sa->username ? call->sa->username : "", NULL);
	from_q = teams_call_json_quote(from_id);
	name_q = teams_call_json_quote(self_display_name(call->sa));
	epid_q = teams_call_json_quote(call->our_endpoint_id);
	pid_q = teams_call_json_quote(call->our_participant_id);
	lang = language_id();
	lang_q = teams_call_json_quote(lang);
	body = g_strdup_printf(
		"{\"callProgress\":{\"sender\":{\"id\":%s,\"displayName\":%s,\"endpointId\":%s,"
		  "\"participantId\":%s,\"languageId\":%s},\"status\":\"ringing\",\"phrase\":\"ringing\"}}",
		from_q, name_q, epid_q, pid_q, lang_q);
	teams_call_log("progress: ringing");
	flightproxy_post_cb(call->sa, call->link_progress, body, flightproxy_resp_cb, NULL);
	g_free(from_id); g_free(from_q); g_free(name_q); g_free(epid_q); g_free(pid_q);
	g_free(lang); g_free(lang_q); g_free(body);
}

/* The incoming call was answered and our SDP answer is built (media_send_answer): accept now if
 * the attach response is in, else as soon as it comes (attach_resp_cb). An attach that was never
 * sent (no attach link while ringing) is sent now. */
static void
teams_calling_post_answer(TeamsCall *call)
{
	if (call->accept_sent) return;
	call->accept_wanted = TRUE;
	if (call->link_acceptance) {
		teams_call_log("answer: acceptance link from the attach while ringing, posting accept");
		post_accept_now(call);
	} else if (call->attach_sent) {
		teams_call_log("answer: attach response not in yet, accept follows it");
	} else {
		teams_calling_ring_attach(call);
	}
}

/* ------------------------------------------------------------------ TeamsCall */

static const char *
state_str(TeamsCallState s)
{
	switch (s) {
		case TEAMS_CALL_INCOMING:     return "incoming";
		case TEAMS_CALL_DIALING:      return "dialing";
		case TEAMS_CALL_ACTIVE:       return "active";
		case TEAMS_CALL_DISCONNECTED: return "disconnected";
		default:                      return ""; /* idle */
	}
}

static void
push_state(TeamsCall *call, const char *cause)
{
	if (!g_state_cb || !call) return;
	g_state_cb(call->sa, state_str(call->state),
	           call->peer_mri ? teams_strip_user_prefix(call->peer_mri) : NULL,
	           call->peer_name, call->is_outgoing, cause);
}

static TeamsCall *
teams_call_new(TeamsAccount *sa)
{
	TeamsCall *call = g_new0(TeamsCall, 1);
	call->sa = sa;
	if (++g_call_serial == 0) ++g_call_serial;
	call->serial = g_call_serial;
	return call;
}

static void
teams_call_free(TeamsCall *call)
{
	if (!call) return;
	if (g_mproc && g_mproc->call == call) teams_media_stop();
	g_free(call->call_id);
	g_free(call->peer_mri);
	g_free(call->peer_name);
	g_free(call->sdp_offer);
	g_free(call->media_leg_id);
	g_free(call->link_attach);
	g_free(call->link_media_answer);
	g_free(call->link_progress);
	g_free(call->link_reject);
	g_free(call->udp_transport);
	g_free(call->conversation_controller);
	g_free(call->link_leave);
	g_free(call->link_endpoint_state);
	g_free(call->link_endpoint_metadata);
	g_free(call->link_peer_reneg);
	g_free(call->our_answer_sdp);
	g_free(call->our_endpoint_id);
	g_free(call->our_participant_id);
	g_free(call->callagent_id);
	g_free(call->link_acceptance);
	g_free(call);
}

TeamsCall *
teams_calling_current(TeamsAccount *sa)
{
	return sa ? (TeamsCall *) sa->active_call : NULL;
}

/* Make call the account's current call; the previous one is freed, stopping its engine. */
static void
set_current(TeamsAccount *sa, TeamsCall *call)
{
	TeamsCall *old = (TeamsCall *) sa->active_call;
	sa->active_call = call;
	if (old && old != call) teams_call_free(old);
}

/* --------------------------------------------------------------- parse offer */

static TeamsCall *
parse_call_notification(TeamsAccount *sa, JsonObject *body_obj)
{
	JsonObject *cn = oget(body_obj, "callNotification");
	JsonObject *from, *to, *links, *media, *convInv, *debug;
	const gchar *fromId, *toId;
	TeamsCall *call;

	if (!cn) return NULL;

	from   = oget(cn, "from");
	to     = oget(cn, "to");
	links  = oget(cn, "links");
	media  = oget(cn, "mediaContent");
	convInv = oget(body_obj, "conversationInvitation");
	debug  = oget(body_obj, "debugContent");

	fromId = from ? sget(from, "id") : NULL;
	toId   = to ? sget(to, "id") : NULL;

	call = teams_call_new(sa);

	/* incoming vs outgoing: if WE are the caller it's an outgoing call notification (a fork
	 * / carbon of our own placed call), and the peer is the callee. */
	if (fromId && teams_is_user_self(sa, fromId)) {
		call->is_outgoing = TRUE;
		call->peer_mri  = g_strdup(toId);
		call->peer_name = g_strdup(to ? sget(to, "displayName") : NULL);
	} else {
		const gchar *our_pid = to ? sget(to, "participantId") : NULL;
		call->is_outgoing = FALSE;
		call->peer_mri  = g_strdup(fromId);
		call->peer_name = g_strdup(from ? sget(from, "displayName") : NULL);
		/* We are a participant the call controller already named. CAPTURED (teams.live.com):
		 * the web client answers, accepts, renegotiates and leaves as
		 * callNotification.to.participantId (= debugContent.participantId), and the call/end it
		 * then gets names it. With an id of our own (what this did before) the leave was
		 * answered at once but the call stayed up until the call controller timed it out,
		 * ~16 s, the caller meanwhile "reconnecting". */
		if (!our_pid || !*our_pid) our_pid = debug ? sget(debug, "participantId") : NULL;
		if (our_pid && *our_pid) call->our_participant_id = g_strdup(our_pid);
	}

	if (debug)  call->call_id = g_strdup(sget(debug, "callId"));

	if (media) {
		call->sdp_offer    = g_strdup(sget(media, "blob"));
		call->media_leg_id = g_strdup(sget(media, "mediaLegId"));
	}
	if (links) {
		call->link_attach       = g_strdup(sget(links, "attach"));
		call->link_media_answer = g_strdup(sget(links, "mediaAnswer"));
		call->link_progress     = g_strdup(sget(links, "progress"));
		call->link_reject       = g_strdup(sget(links, "reject"));
		call->udp_transport     = g_strdup(sget(links, "udpTransport"));
	}
	if (convInv)
		call->conversation_controller = g_strdup(sget(convInv, "conversationController"));

	return call;
}

/* --------------------------------------------------------------- HTTP control */

/* POST (empty or small body) to a full https URL from the notification's links. Splits the
 * URL into host + path for teams_post_or_get. Auth headers are added by teams_post_or_get
 * for skype/teams hosts. That is enough for the links of personal-account calls (attach, accept,
 * leave, renegotiation); calls on work/school accounts have not been tried. */
static void
call_http_post(TeamsAccount *sa, const gchar *full_url, const gchar *body)
{
	const gchar *p;
	gchar *host, *path;
	const gchar *slash;

	if (!full_url) return;
	if (g_str_has_prefix(full_url, "https://")) p = full_url + 8;
	else if (g_str_has_prefix(full_url, "http://")) p = full_url + 7;
	else { teams_call_log("http_post: non-http link (skipped)"); return; }

	slash = strchr(p, '/');
	if (slash) {
		host = g_strndup(p, slash - p);
		path = g_strdup(slash);
	} else {
		host = g_strdup(p);
		path = g_strdup("/");
	}
	teams_call_log("http_post host=%s body=%d bytes", host, body ? (int) strlen(body) : 0);
	teams_post_or_get(sa, TEAMS_METHOD_POST | TEAMS_METHOD_SSL, host, path, body, NULL, NULL, FALSE);
	g_free(host);
	g_free(path);
}

/* End the account's current call: tell Teams (if notify_remote), tell the front end, free it and
 * stop its engine. */
static void
end_call(TeamsAccount *sa, const char *cause, gboolean notify_remote)
{
	TeamsCall *call = teams_calling_current(sa);
	if (!call) return;
	/* An incoming call not yet answered is rejected; any other call leaves its conversation
	 * (post_leave), at the leave link the join or the cpconv response gave, or else the one the
	 * controller implies. A call we placed gets its controller from the cpconv response
	 * (cpconv_resp_cb); hung up before that arrives, the conversation is left when it does. */
	if (notify_remote) {
		if (call->state == TEAMS_CALL_INCOMING && call->link_reject) {
			call_http_post(sa, call->link_reject, NULL); /* reject is a bare POST, no body */
		} else if (call->link_leave || call->conversation_controller) {
			gchar *link = call->link_leave ? g_strdup(call->link_leave)
			                               : teams_calling_leave_link(call->conversation_controller);
			post_leave(sa, link, call->our_endpoint_id, call->our_participant_id);
			g_free(link);
		}
	}
	call->state = TEAMS_CALL_DISCONNECTED;
	push_state(call, cause);
	set_current(sa, NULL);
}

/* --------------------------------------------------------------- trouter entry */

/* Outgoing call: the callee accepted and Teams delivered their SDP answer on our callAgent
 * mediaAnswer link. Extract ice-ufrag/pwd + the a=crypto RX key + candidates, and feed them to the
 * caller media engine (ANSWER + RCAND) so it applies the peer's key, sets remote creds and connects
 * ICE. The exact frame shape isn't fully known yet, so probe a few likely blob locations. */
static void
teams_calling_handle_media_answer(TeamsAccount *sa, JsonObject *body_obj)
{
	TeamsCall *call = teams_calling_current(sa);
	TeamsMediaProc *mp = g_mproc;
	JsonObject *mc = NULL, *sub;
	const gchar *blob = NULL;
	gchar *ruf, *rpw, *rxkey;

	if (call && mp && mp->call == call && mp->reneg_offer_pending) {
		handle_reneg_offer_answer(sa, call, mp, body_obj);
		return;
	}
	if (!call || !mp || mp->call != call || !mp->is_caller) {
		teams_call_log("mediaAnswer: no outgoing caller engine to apply it to"); return;
	}
	if (call->answer_applied) {
		teams_call_log("mediaAnswer: answer already applied - repeat ignored"); return;
	}
	if ((mc = oget(body_obj, "mediaContent")))            blob = sget(mc, "blob");
	if (!blob && (sub = oget(body_obj, "mediaAnswer")) && (mc = oget(sub, "mediaContent"))) blob = sget(mc, "blob");
	if (!blob && (sub = oget(body_obj, "callNotification")) && (mc = oget(sub, "mediaContent"))) blob = sget(mc, "blob");
	if (!blob) { teams_call_log("mediaAnswer: no SDP blob found"); return; }

	ruf = sdp_line_val(blob, "a=ice-ufrag:");
	rpw = sdp_line_val(blob, "a=ice-pwd:");
	rxkey = sdp_gcm_key(blob);
	if (!ruf || !rpw || !rxkey) {
		teams_call_log("mediaAnswer: answer missing ice/crypto (uf=%d pw=%d key=%d)",
		               ruf != NULL, rpw != NULL, rxkey != NULL);
		g_free(ruf); g_free(rpw); g_free(rxkey); return;
	}
	/* The call controller waits for us, the offerer, to acknowledge the answer on the link it
	 * gives, as it acknowledges our answers on ours (/mediaAcknowledgement, below); without it the
	 * call ended after 30 s, "Call Controller timed out while waiting for acknowledgement" (408). */
	{
		JsonObject *links = oget(body_obj, "links");
		const gchar *ack_url;
		log_member_names("mediaAnswer frame", body_obj);
		if (!links && (sub = oget(body_obj, "mediaAnswer"))) {
			log_member_names("mediaAnswer frame mediaAnswer", sub);
			links = oget(sub, "links");
		}
		if (links) log_member_names("mediaAnswer frame links", links);
		ack_url = links ? sget(links, "mediaAcknowledgement") : NULL;
		if (ack_url && *ack_url) {
			gchar *url = teams_calling_via_flightproxy(ack_url), *host = url_host_for_log(url);
			teams_call_log("mediaAnswer: acknowledging to %s", host ? host : "?");
			flightproxy_post_cb(sa, url, "{\"mediaAcknowledgement\":{\"code\":0,\"subCode\":0,"
			                    "\"reason\":\"noError\",\"phrase\":\"Success\"}}", flightproxy_resp_cb, NULL);
			g_free(url); g_free(host);
		} else {
			teams_call_log("mediaAnswer: no mediaAcknowledgement link in the frame");
		}
	}
	teams_call_log("mediaAnswer: applying peer answer -> ANSWER + RCAND to caller engine");
	g_free(mp->answer_ufrag);
	mp->answer_ufrag = g_strdup(ruf);
	if (media_send(mp, "ANSWER %s %s %s\n", rxkey, ruf, rpw))
		media_send_candidates(mp, blob);
	explicit_bzero(rxkey, strlen(rxkey));
	g_free(ruf); g_free(rpw); g_free(rxkey);
	/* Not "active" yet: the callee's client answers the media while it still rings (early media;
	 * CAPTURED, teams.live.com placing a call: mediaAnswer 3.5 s after the call was
	 * placed, callAcceptance 2.1 s later). The call is up on the acceptance. */
	call->answer_applied = TRUE;
	if (mp->camera_wanted && mp->our_vssrc) {
		/* Our offer had video: the answer says what each side sends, and its fmtp how much. */
		const char *peer = teams_sdp_video_direction(blob);
		mp->video_offer = NULL;
		mp->video_answer = teams_video_our_direction(peer);
		teams_video_send_params(blob, &mp->vsend_w, &mp->vsend_h, &mp->vsend_kbps);
		teams_call_log("video: answer %s, so we %s", peer ? peer : "none", mp->video_answer);
		video_event(mp, teams_video_dir_peer_sends(peer) ? "OFFERED 1" : "OFFERED 0");
		media_video_apply(mp);
	}
}

/* Peer pushed a mid-call renegotiation offer, delivered via the mediaRenegotiation link we
 * generated and handed them in our own accept (teams_calling_post_accept's l_reneg). The answer goes to
 * the push's mediaNegotiation.links.mediaAnswer, as in a HAR of this flow. */
static void
teams_calling_handle_renegotiation(TeamsAccount *sa, JsonObject *body_obj)
{
	TeamsCall *call = teams_calling_current(sa);
	TeamsMediaProc *mp = g_mproc;
	JsonObject *mn, *mc, *links;
	const gchar *blob = NULL, *answer_link = NULL;
	gboolean sent_restart = FALSE;
	gchar *ruf, *rpw, *rxkey;

	if (!call || !mp || mp->call != call) { teams_call_log("renegotiate: no active call/engine"); return; }
	mn = oget(body_obj, "mediaNegotiation");
	if (!mn) { teams_call_log("renegotiate: no mediaNegotiation object"); return; }
	if ((mc = oget(mn, "mediaContent"))) blob = sget(mc, "blob");
	g_free(mp->reneg_leg_id);
	mp->reneg_leg_id = g_strdup(mc ? sget(mc, "mediaLegId") : NULL);
	if ((links = oget(mn, "links")))     answer_link = sget(links, "mediaAnswer");
	if (!blob) { teams_call_log("renegotiate: no SDP blob in mediaNegotiation"); return; }
	sdp_log_shape("renegotiation offer", blob);
	g_free(mp->declined_mlines);
	mp->declined_mlines = sdp_declined_mlines(blob);
	media_video_offer(mp, blob);

	/* CAPTURED LIVE: a renegotiation push commonly swaps the peer to a brand-new
	 * media leg - fresh ice-ufrag/pwd (and sometimes a whole new a=crypto key/mediaLegId/relay),
	 * not just a direction flip. Apply the new creds/key + candidates via RESTART/RCAND (see
	 * teams_media.c) before replying; otherwise the engine keeps trying to reach the STALE leg and
	 * Teams eventually kills the call as MediaError (code 410). */
	ruf = sdp_line_val(blob, "a=ice-ufrag:");
	rpw = sdp_line_val(blob, "a=ice-pwd:");
	rxkey = sdp_gcm_key(blob);
	if (ruf && rpw) {
		/* Dedup: Teams' trouter can redeliver the identical renegotiation push (same remote
		 * ufrag) - a real client only actually changes ICE creds when it genuinely moves to a
		 * new leg. Restarting the ICE agent on every redelivery never lets a session finish
		 * connectivity checks before being torn down again. */
		if (mp->last_restarted_ufrag && !strcmp(mp->last_restarted_ufrag, ruf)) {
			teams_call_log("renegotiate: same ufrag as last RESTART - skipping, ICE session already in progress");
		} else if (media_send(mp, "RESTART %s %s %s\n", rxkey ? rxkey : "-", ruf, rpw)) {
			media_send_candidates(mp, blob);
			teams_call_log("renegotiate: sent RESTART+cands to engine");
			g_free(mp->last_restarted_ufrag);
			mp->last_restarted_ufrag = g_strdup(ruf);
			sent_restart = TRUE;
		}
	} else {
		teams_call_log("renegotiate: offer missing ice-ufrag/pwd, cannot restart ICE (uf=%d pw=%d)",
		               ruf != NULL, rpw != NULL);
	}
	if (rxkey) explicit_bzero(rxkey, strlen(rxkey));
	g_free(ruf); g_free(rpw); g_free(rxkey);

	if (!answer_link || !mp->our_ufrag || !mp->our_pwd || !mp->our_txkey) {
		teams_call_log("renegotiate: missing answer link or media params (uf=%d pw=%d key=%d link=%d), "
		               "cannot respond", mp->our_ufrag != NULL, mp->our_pwd != NULL,
		               mp->our_txkey != NULL, answer_link != NULL);
		return;
	}

	if (sent_restart) {
		/* Engine's RESTART is in flight - it's about to regenerate OUR OWN local ice-ufrag/pwd
		 * (real RFC 5245 restart, see teams_media.c), so mp->our_ufrag/our_pwd are stale RIGHT
		 * NOW and answering with them would hand the peer credentials our own agent no longer
		 * recognizes. Defer: media_on_output() calls send_reneg_answer() once the engine's
		 * RESTARTED line confirms the fresh local creds have already landed in mp. A second
		 * renegotiation arriving before the first's RESTARTED comes back simply supersedes it. */
		g_free(mp->pending_reneg_answer_link);
		mp->pending_reneg_answer_link = g_strdup(answer_link);
		return;
	}
	send_reneg_answer(mp, answer_link);
}

/* The acknowledgement of a callee's acceptance. Our invitation only gave the controller the
 * links a caller needs before the answer (progress, mediaAnswer, acceptance, redirection, end);
 * the call-level links the callee gives in its callAcceptance (renegotiation, transfer, ...) the
 * caller gives here: {} was refused with 400 "The CallAcceptanceAcknowledgement field is
 * required.", {"callAcceptanceAcknowledgement":{}} with "The Links field is required.". The
 * same set our own callAcceptance sends. g_free() it. */
static gchar *
acceptance_ack_body(TeamsCall *call)
{
	static const char *const names[] = {
		"mediaRenegotiation", "transfer", "replacement", "balanceUpdate", "retargetCompletion",
		"controlVideoStreaming", "updateMediaDescriptions",
	};
	GString *body = g_string_new("{\"callAcceptanceAcknowledgement\":{\"links\":{");
	gsize i;

	for (i = 0; call && call->callagent_id && i < G_N_ELEMENTS(names); i++) {
		gchar *p = callagent_path(call, call->callagent_id, "call", names[i]);
		g_string_append_printf(body, "%s\"%s\":\"%s\"", i ? "," : "", names[i], p);
		g_free(p);
	}
	g_string_append(body, "}}}");
	return g_string_free(body, FALSE);
}

void
teams_calling_handle_trouter(TeamsAccount *sa, JsonObject *body_obj, const gchar *request_url)
{
	TeamsCall *cur = teams_calling_current(sa);
	const gchar *agent_frame = request_url ? strstr(request_url, "callAgent/") : NULL;

	if (agent_frame) {
		teams_call_log("callAgent frame: %s", agent_frame);
		/* A frame on another call's callAgent links (a call this one replaced, or a second call
		 * we turned away) is not about the current call. */
		if (cur && cur->callagent_id && !strstr(agent_frame, cur->callagent_id)) {
			teams_call_log("callAgent frame for another call - ignored");
			return;
		}
	}

	/* Outgoing call: the callee accepted. Like SIP's ACK to a 200 OK, the call controller waits
	 * for us to acknowledge the acceptance on its links.acknowledgement: without it the call
	 * ended 30 s later, "Call Controller timed out while waiting for acknowledgement" (408). The
	 * body is {"callAcceptanceAcknowledgement":{"links":{...}}} with our call links (see
	 * acceptance_ack_body); the controller's verdict is logged.
	 * Also logged, without values: whether the acceptance's SDP
	 * is the answer we applied and whether it came from the callee we dialled. */
	if (request_url && strstr(request_url, "/call/acceptance")) {
		JsonObject *acc = oget(body_obj, "callAcceptance"), *links = acc ? oget(acc, "links") : NULL;
		JsonObject *by = acc ? oget(acc, "acceptedBy") : NULL, *mc = acc ? oget(acc, "mediaContent") : NULL;
		const gchar *ack_url = links ? sget(links, "acknowledgement") : NULL;
		const gchar *blob = mc ? sget(mc, "blob") : NULL;
		log_member_names("outgoing: acceptance frame callAcceptance", acc);
		if (links) log_member_names("outgoing: acceptance frame links", links);
		/* Where our own renegotiation offers go. CAPTURED (teams.live.com turning its camera on
		 * in a call it placed): it POSTs them to this link. */
		if (cur && links && sget(links, "mediaRenegotiation") && *sget(links, "mediaRenegotiation")) {
			g_free(cur->link_peer_reneg);
			cur->link_peer_reneg = g_strdup(sget(links, "mediaRenegotiation"));
		}
		if (blob) {
			gchar *uf = sdp_line_val(blob, "a=ice-ufrag:");
			teams_call_log("outgoing: acceptance SDP %s the answer we applied (%s)",
			               g_mproc && g_mproc->answer_ufrag && uf && !strcmp(uf, g_mproc->answer_ufrag)
			               ? "is" : "is NOT", teams_sdp_video_direction(blob) ? teams_sdp_video_direction(blob) : "no video");
			g_free(uf);
		}
		teams_call_log("outgoing: accepted by the callee we dialled: %s",
		               by && cur && cur->peer_mri && sget(by, "id") && !strcmp(sget(by, "id"), cur->peer_mri)
		               ? "yes" : "no");
		/* The callee picked up: the call is up now, not on the earlier media answer. An
		 * acceptance with no media answer before it carries the answer itself. */
		if (cur && cur->is_outgoing && cur->state == TEAMS_CALL_DIALING) {
			if (!cur->answer_applied && blob) {
				teams_call_log("outgoing: no media answer before the acceptance - applying its SDP");
				teams_calling_handle_media_answer(sa, acc);
			}
			cur->state = TEAMS_CALL_ACTIVE;
			push_state(cur, NULL);
		}
		if (ack_url && *ack_url) {
			gchar *url = teams_calling_via_flightproxy(ack_url), *host = url_host_for_log(url);
			teams_call_log("outgoing: acknowledging the acceptance to %s", host ? host : "?");
			gchar *ack = acceptance_ack_body(cur);
			flightproxy_post_cb(sa, url, ack, flightproxy_resp_cb, NULL);
			g_free(ack); g_free(url); g_free(host);
		}
		return;
	}
	/* Outgoing call: callee is ringing (progress) or has answered (mediaAnswer). */
	if (request_url && (strstr(request_url, "/mediaAnswer") || strstr(request_url, "/mediaanswer"))) {
		teams_call_log("outgoing: MEDIA ANSWER frame received");
		teams_calling_handle_media_answer(sa, body_obj);
		return;
	}
	/* The far side turned our renegotiation offer down (the rejection link reneg_offer_body gave). */
	if (request_url && strstr(request_url, "/call/rejection")) {
		log_member_names("renegotiate: our offer rejected", body_obj);
		if (g_mproc && cur && g_mproc->call == cur) reneg_offer_done(g_mproc);
		return;
	}
	/* The call controller's verdict on a renegotiation answer, on the link reneg_answer_body gave. */
	if (request_url && strstr(request_url, "/mediaAcknowledgement")) {
		JsonObject *ack = oget(body_obj, "mediaAcknowledgement");
		teams_call_log("renegotiation answer acknowledged: code=%d subCode=%d reason=%s phrase=%s",
		               ack && json_object_has_member(ack, "code") ? (int) json_object_get_int_member(ack, "code") : -1,
		               ack && json_object_has_member(ack, "subCode") ? (int) json_object_get_int_member(ack, "subCode") : -1,
		               ack && sget(ack, "reason") ? sget(ack, "reason") : "-",
		               ack && sget(ack, "phrase") ? sget(ack, "phrase") : "-");
		return;
	}
	/* Mid-call renegotiation push on the mediaRenegotiation link we generated in our own accept
	 * - see teams_calling_post_accept's l_reneg. */
	if (request_url && strstr(request_url, "/mediaRenegotiation")) {
		teams_call_log("RENEGOTIATION frame received");
		teams_calling_handle_renegotiation(sa, body_obj);
		return;
	}
	if (request_url && strstr(request_url, "/progress")) {
		teams_call_log("outgoing: PROGRESS frame (callee ringing)");
		if (cur) push_state(cur, "ringing");
		return;
	}

	/* Call ended */
	if (request_url && (strstr(request_url, "/call/end") || g_str_has_suffix(request_url, "/end")
	                    || g_str_has_suffix(request_url, "/end/"))) {
		if (cur) {
			JsonObject *ce = oget(body_obj, "callEnd");
			const gchar *phrase = ce ? sget(ce, "phrase") : NULL;
			const gchar *reason = ce ? sget(ce, "reason") : NULL;
			gint64 code = ce && json_object_has_member(ce, "code") ? json_object_get_int_member(ce, "code") : 0;
			/* Map the Teams callEnd to the cause the front end gets with "disconnected": "normal",
			 * "rejected", "missed", "busy", "error" or "answeredElsewhere" (rather than raw phrases
			 * such as "LocalUserInitiated"). A normal hang-up (either side) or a connected call that
			 * ended is "normal"; declines and timeouts map accordingly. */
			const gchar *cause = "normal";
			log_member_names("call ended: callEnd", ce);
			/* Taken on another of the user's devices while it rang here. CAPTURED (answered on
			 * teams.live.com): reason clientError, code 487, phrase "Call
			 * cancelled as it was accepted by another fork." 487 alone is SIP's "request
			 * terminated", which a caller giving up may get too, so the phrase decides.
			 * "answeredElsewhere" lets a front end count the call as answered, not missed. */
			if (cur->state == TEAMS_CALL_INCOMING && phrase && strstr(phrase, "accepted by another fork"))
				cause = "answeredElsewhere";
			else if (phrase && (strstr(phrase, "Decline") || strstr(phrase, "Reject")))      cause = "rejected";
			else if (phrase && (strstr(phrase, "Unanswer") || strstr(phrase, "Timeout") ||
			                    strstr(phrase, "NoAnswer") || strstr(phrase, "Ring")))   cause = "missed";
			else if (phrase && strstr(phrase, "Busy"))                                   cause = "busy";
			else if (phrase && (strstr(phrase, "UserInitiated") || strstr(phrase, "Success"))) cause = "normal";
			else if (g_strcmp0(reason, "clientError") == 0 && code != 0 && code != 200 &&
			         cur->state != TEAMS_CALL_ACTIVE)                                     cause = "error";
			teams_call_log("call ended: phrase=%s reason=%s code=%d -> cause=%s",
			               phrase ? phrase : "(none)", reason ? reason : "(none)", (int) code, cause);
			end_call(sa, cause, FALSE);
		}
		return;
	}

	/* The conversation's own frames (rosterUpdate, conversationEnd, ...) on the links our join
	 * gave: not modeled; logged by name and shape (never values) to see what the conversation says. */
	if (request_url && strstr(request_url, "/conversation/")) {
		gchar *what = g_strdup_printf("conversation frame %s", strstr(request_url, "/conversation/"));
		log_member_names(what, body_obj);
		g_free(what);
		return;
	}

	/* Roster update mid-call - not modeled. */
	if (request_url && g_str_has_suffix(request_url, "/rosterUpdate"))
		return;

	/* Incoming/outgoing call setup (callNotification present). */
	if (json_object_has_member(body_obj, "callNotification")) {
		TeamsCall *call = parse_call_notification(sa, body_obj);
		if (!call) return;

		/* A call this user placed: one from another of their devices (this client has no part in it,
		 * so it is not shown as dialing here), or a carbon of the one we are dialing, whose
		 * conversation controller we may not have yet. */
		if (call->is_outgoing) {
			if (cur && cur->is_outgoing && cur->state == TEAMS_CALL_DIALING &&
			    !cur->conversation_controller && call->conversation_controller &&
			    !g_strcmp0(cur->peer_mri, call->peer_mri)) {
				teams_call_log("dial: conversation controller taken from the call notification");
				cur->conversation_controller = g_strdup(call->conversation_controller);
			} else {
				teams_call_log("call placed from another device - ignored");
			}
			teams_call_free(call);
			return;
		}

		if (cur) {
			/* Busy. A repeat of the current call's notification changes nothing, and a second
			 * incoming call is turned away. Without both call ids it cannot be told whether this
			 * is a repeat, so it is left alone. */
			if (!call->call_id || !cur->call_id || !strcmp(call->call_id, cur->call_id))
				teams_call_log("call notification while a call is in progress - ignored");
			else if (call->link_reject) {
				teams_call_log("busy: turning away a second incoming call");
				call_http_post(sa, call->link_reject, NULL);
			}
			teams_call_free(call);
			return;
		}

		call->state = TEAMS_CALL_INCOMING;
		set_current(sa, call);

		teams_call_log("INCOMING call  peer=%s (%s)  sdp=%d bytes  relay=%s  reject=%s",
		               call->peer_mri ? call->peer_mri : "?",
		               call->peer_name ? call->peer_name : "?",
		               call->sdp_offer ? (int) strlen(call->sdp_offer) : 0,
		               call->udp_transport ? call->udp_transport : "?",
		               call->link_reject ? "yes" : "no");
		sdp_log_shape("incoming offer", call->sdp_offer);

		/* Ring the front end, and attach while it rings (teams_calling_ring_attach). */
		push_state(call, NULL);
		teams_calling_ring_attach(call);
		return;
	}
}

/* --------------------------------------------------------- actions (front end) */

gboolean
teams_calling_answer(TeamsAccount *sa)
{
	TeamsCall *call = teams_calling_current(sa);
	if (!call || call->state != TEAMS_CALL_INCOMING) {
		teams_call_log("answer: no incoming call");
		return FALSE;
	}
	teams_call_log("answer: starting media for call with %s", call->peer_mri ? call->peer_mri : "?");

	/* The engine reports READY with our ICE credentials and TX key; media_on_output() then waits
	 * for candidates and media_send_answer() posts the attach -> accept with our SDP answer. */
	if (!teams_media_start(call)) {
		end_call(sa, "error", TRUE);
		return FALSE;
	}
	call->state = TEAMS_CALL_ACTIVE;
	push_state(call, NULL);
	return TRUE;
}

gboolean
teams_calling_reject(TeamsAccount *sa)
{
	TeamsCall *call = teams_calling_current(sa);
	if (!call) { teams_call_log("reject: no call"); return FALSE; }
	teams_call_log("reject: rejecting call from %s", call->peer_mri ? call->peer_mri : "?");

	if (call->link_reject)
		call_http_post(sa, call->link_reject, NULL); /* reject is a bare POST, no body */
	end_call(sa, "rejected", FALSE);
	return TRUE;
}

gboolean
teams_calling_hangup(TeamsAccount *sa)
{
	TeamsCall *call = teams_calling_current(sa);
	if (!call) { teams_call_log("hangup: no call"); return FALSE; }
	teams_call_log("hangup: ending call with %s", call->peer_mri ? call->peer_mri : "?");
	end_call(sa, "normal", TRUE);
	return TRUE;
}

gboolean
teams_calling_dial(TeamsAccount *sa, const gchar *peer_mri, gboolean video)
{
	/* Outgoing (caller): spawn teams_media --caller to gather our ICE + generate the offer's SRTP
	 * key, then media_send_offer() builds the SDP offer and POSTs the cpconv create request (which
	 * makes the peer ring). The answer comes back over the trouter callAgent path. FIRST-ATTEMPT. */
	TeamsCall *call;
	TeamsMediaProc *mp;

	if (!sa || !peer_mri || !*peer_mri) return FALSE;
	if (teams_calling_current(sa)) { teams_call_log("dial: a call is already in progress"); return FALSE; }
	if (!sa->trouter_surl) { teams_call_log("dial: no trouter surl - cannot place call"); return FALSE; }

	call = teams_call_new(sa);
	call->is_outgoing = TRUE;
	call->state = TEAMS_CALL_DIALING;
	call->peer_mri = g_str_has_prefix(peer_mri, "8:") ? g_strdup(peer_mri) : g_strdup_printf("8:%s", peer_mri);
	call->callagent_id = purple_uuid_random();
	set_current(sa, call);

	mp = media_spawn(call, TRUE);
	if (mp) mp->camera_wanted = video;   /* the offer carries video; the answer decides the camera */
	if (mp) media_send_stun(mp);
	/* CALLER START: no rx key (we produce the offer). pt=102 for opus. */
	if (!mp || !media_send(mp, "START 102\n")) {
		set_current(sa, NULL);
		return FALSE;
	}
	teams_call_log("dial: calling %s (callAgent=%s)", call->peer_mri, call->callagent_id);
	push_state(call, NULL);   /* dialing */
	return TRUE;
}

void
teams_calling_close(TeamsAccount *sa)
{
	TeamsCall *call = teams_calling_current(sa);
	if (call) {
		teams_call_log("account closing: dropping the call");
		call->state = TEAMS_CALL_DISCONNECTED;
		push_state(call, "error");
		set_current(sa, NULL);
	}
	if (g_closing_cb) g_closing_cb(sa);
}
