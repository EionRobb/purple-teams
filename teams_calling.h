/*
 * Teams Plugin for libpurple/Pidgin - NGC (NextGenCalling) 1:1 calls.
 *
 * Microsoft Teams 1:1 voice calls use "NGC" (NextGenCalling / SkypeNgc), the legacy
 * Skype media stack Teams inherited - NOT browser WebRTC. An incoming call arrives as
 * a Trouter notification on /NGCallManagerWin (or /SkypeSpacesWeb) carrying:
 *   - mediaContent.blob : an "application/sdp-ngc-0.5" SDP offer (RTP/SAVP, SDES-SRTP)
 *   - udpKey.sessionKey : the SRTP master keying material (base64; RFC 3711 AES-CM)
 *   - udpKey.ticket     : the MRAS token that authenticates to the MS-TURN media relay
 *   - links.udpTransport: udp://<relay-ip>:3478/   (the MS-TURN relay)
 *   - links.{attach,mediaAnswer("cc://ma"),progress,reject} : the HTTP control plane
 *
 * This module parses the notification into a TeamsCall, tracks call state, drives the call
 * control plane (answer/reject/hangup/dial) over the links, and hands the media parameters to
 * the separate media engine (TEAMS_MEDIA_BIN), which carries the audio and video. Calls are 1:1,
 * voice or video. docs/CALLING.md describes the signalling and the engine's line protocol.
 *
 * A front end (a UI that rings, shows and drives calls) registers the callbacks below and calls
 * the actions. Without one, an incoming call is announced as a message, as before.
 */

#ifndef TEAMS_CALLING_H
#define TEAMS_CALLING_H

#include "libteams.h"
#include <json-glib/json-glib.h>

typedef enum {
	TEAMS_CALL_IDLE = 0,
	TEAMS_CALL_INCOMING,
	TEAMS_CALL_DIALING,
	TEAMS_CALL_ACTIVE,
	TEAMS_CALL_DISCONNECTED
} TeamsCallState;

typedef struct _TeamsCall {
	TeamsAccount *sa;
	guint serial;       /* identifies this call to async HTTP callbacks; see CallRef in teams_calling.c */

	gchar *call_id;
	gchar *peer_mri;    /* the OTHER party's id, e.g. "8:orgid:..." (prefix-stripped for display) */
	gchar *peer_name;   /* resolved display name, may be NULL */
	gboolean is_outgoing;
	TeamsCallState state;

	/* --- media offer (callNotification.mediaContent) --- */
	gchar *sdp_offer;       /* the raw application/sdp-ngc-0.5 blob (plaintext SDP) */
	gchar *media_leg_id;

	/* --- control-plane links (callNotification.links) --- */
	gchar *link_attach;
	gchar *link_media_answer;  /* "cc://ma" - where the SDP answer is posted */
	gchar *link_progress;
	gchar *link_reject;
	gchar *udp_transport;      /* "udp://<ip>:3478/" MS-TURN relay */
	gchar *conversation_controller; /* conversationInvitation.conversationController */
	gchar *link_leave;         /* the conversation's links.leave: where a hang-up is POSTed */
	gchar *link_endpoint_state;    /* <conversation>/updateEndpointState, after the join */
	gchar *link_endpoint_metadata; /* <conversation>/updateEndpointMetadata, after the accept */
	gchar *link_peer_reneg;    /* where our own renegotiation offers go: the far side's mediaRenegotiation
	                            * link (the callee's callAcceptance, or the acknowledgement of ours) */
	guint reneg_offers;        /* our renegotiation offers so far (their negotiationTag's v_<n>) */

	/* --- answer flow (incoming): the media controller answer is a two-step handshake -
	 * POST attach (offer's link_attach) -> parse callInvitation.links.acceptance from the
	 * response -> POST accept (callAcceptance.mediaContent.blob = our SDP answer). --- */
	gchar *our_answer_sdp;     /* the SDP answer our media engine produced (held across attach->accept) */
	gchar *our_endpoint_id;    /* our calling endpoint id (= sa->endpoint), used in acceptedBy */
	gchar *our_participant_id; /* our participantId (generated), reused in attach join + acceptedBy */
	gchar *callagent_id;       /* generated callAgent id for our control paths (end link, etc.) */

	/* --- attach while ringing: the web client attaches as soon as the call rings, which gives
	 * the call controller our end link, so the call stops ringing here when it is answered on
	 * another device or the caller gives up. The answer then only posts the accept. --- */
	gchar *link_acceptance;    /* callInvitation.links.acceptance from the attach response */
	gboolean attach_sent;      /* the attach is posted (its response may still be in flight) */
	gboolean accept_wanted;    /* answered: post the accept as soon as the acceptance link is there */
	gboolean accept_sent;      /* the accept is posted: never a second one */
	gboolean answer_applied;   /* outgoing: the callee's media answer is applied (it may come before the pickup) */
} TeamsCall;

/* Called from teams_trouter.c's /NGCallManagerWin handler with the decoded callNotification
 * container (body_obj). Parses it, tracks call state and notifies the front end.
 * request_url distinguishes the notification kind (/NGCallManagerWin incoming/outgoing, /end,
 * /rosterUpdate). */
void teams_calling_handle_trouter(TeamsAccount *sa, JsonObject *body_obj, const gchar *request_url);

/* The front end registers this to receive call-state transitions. state is one of
 * "incoming"/"dialing"/"active"/"disconnected"/"" (idle). Registering it is what makes a front end
 * present (teams_calling_has_frontend()). */
typedef void (*TeamsCallStateCb)(TeamsAccount *sa, const char *state, const char *peerAddress,
                                 const char *peerName, gboolean isOutgoing, const char *cause);
void teams_calling_set_state_cb(TeamsCallStateCb cb);

/* The front end registers this for the call's video: the engine's video lines (VSHM, VPREVIEW,
 * VTX, PEERVIDEO, VIDEOERR; see teams_media.c) as they come, and "OFFERED 0|1" when an offer has
 * the far side sending video or not. "" (empty) means the call's video is over. */
typedef void (*TeamsCallVideoCb)(TeamsAccount *sa, const char *line);
void teams_calling_set_video_cb(TeamsCallVideoCb cb);

/* Our camera on or off in the current call (changeMedia outgoingVideo). It is sent once our
 * answer lets us send video; until then it is kept for the next answer. FALSE: no call. */
gboolean teams_calling_set_camera(TeamsAccount *sa, gboolean on);

/* Actions for the front end. Return FALSE if no such call / not
 * possible. answer/dial spin up the media engine; reject/hangup tear down + POST control. */
gboolean teams_calling_answer(TeamsAccount *sa);
gboolean teams_calling_reject(TeamsAccount *sa);
gboolean teams_calling_hangup(TeamsAccount *sa);
/* video: offer video too and send our camera when the far side's answer lets us. */
gboolean teams_calling_dial(TeamsAccount *sa, const gchar *peer_mri, gboolean video);

/* The account is going away (teams_close): end its call, if any, locally and stop the media
 * engine, so nothing is left pointing at the freed account. Tells the front end last. */
void teams_calling_close(TeamsAccount *sa);

/* The front end's account hooks: connected runs once the account is signed in and can take and
 * place calls, closing when it goes away (from teams_calling_close). Either may be NULL. */
typedef void (*TeamsCallAccountCb)(TeamsAccount *sa);
void teams_calling_set_account_cbs(TeamsCallAccountCb connected, TeamsCallAccountCb closing);

/* Called by libteams.c once the account is signed in. */
void teams_calling_account_connected(TeamsAccount *sa);

/* Whether a front end has registered (a state callback is set). */
gboolean teams_calling_has_frontend(void);

/* The account's current call (or NULL). */
TeamsCall *teams_calling_current(TeamsAccount *sa);

/* s (NULL: "") as a JSON string literal, quotes included; g_free() it. */
gchar *teams_call_json_quote(const char *s);

/* A conversation controller URL's leave link ("…/conv/<id>?q" -> "…/conv/<id>/leave?q");
 * NULL for NULL or "". g_free() it. */
gchar *teams_calling_leave_link(const gchar *controller);

/* The same for another conversation action ("…/conv/<id>?q" -> "…/conv/<id>/<action>?q");
 * NULL for NULL or "" controller or action. g_free() it. */
gchar *teams_calling_conv_link(const gchar *controller, const gchar *action);

/* Call tracing, to the purple debug log. printf-style. Without TEAMS_CALLING
 * teams_calling.c is not linked in, so the trace calls in teams_trouter.c / teams_messages.c
 * compile to nothing; the plugin must not be left with an unresolved symbol, which would stop
 * libpurple from loading it at all. */
#ifdef TEAMS_CALLING
void teams_call_log(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
#else
static inline void G_GNUC_PRINTF(1, 2)
teams_call_log(const char *fmt, ...)
{
	(void) fmt;
}
#endif

#endif /* TEAMS_CALLING_H */
