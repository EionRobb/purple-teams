/* SDP rules for the video of a 1:1 Teams call: which direction to answer an offer with, what
 * our camera may send, when turning it on needs an offer of our own, and the negotiationTag of
 * such an offer. GLib only. */
#ifndef TEAMS_CALL_SDP_H
#define TEAMS_CALL_SDP_H

#include <glib.h>

/* The direction of an SDP's first m=video section ("sendrecv", "sendonly", "recvonly" or
 * "inactive"; the session-level one when the section names none, else sendrecv), or NULL if it
 * has none or that m-line is declined (port 0). */
const char *teams_sdp_video_direction(const char *sdp);

/* Our answer's direction for the video m-line (RFC 3264 6.1), from the offer's direction, whether
 * the engine has video at all and whether our camera is to send. */
const char *teams_video_answer_direction(const char *offer_dir, gboolean engine_video, gboolean camera);

/* The size and bitrate our camera may send on H264 PT 107: the largest standard camcorder size
 * (640x480, 352x288, 320x240, 176x144, at the camera's 30 fps) within the first m=video
 * section's a=fmtp:107 max-fs and max-mbps, and 800 kbit/s or its max-br if lower. The Teams
 * Android app offers max-fs=240;max-mbps=3600;max-br=208: 176x144 at 208 kbit/s. FALSE, and all
 * three 0, when the limits leave none of them (smaller than 176x144 at 30 fps, or a max-br
 * below 32 kbit/s): our camera is not to be sent. */
gboolean teams_video_send_params(const char *sdp, int *w, int *h, int *kbps);

/* Our direction once the far side answered our sendrecv video offer: the mirror of its answer's
 * direction (its recvonly means we only send), "inactive" for none or a declined m-line. */
const char *teams_video_our_direction(const char *answer_dir);

/* Whether a direction of ours lets us send / lets the far side send to us. */
gboolean teams_video_dir_we_send(const char *answer_dir);
gboolean teams_video_dir_peer_sends(const char *offer_dir);

/* Whether turning our camera on or off needs an offer of our own (the web client's mid-call
 * .../renegotiate): the call's media is negotiated, no offer of ours is waiting for its answer,
 * and our current direction does not match the camera - it does not let us send while the camera
 * is wanted and the engine has video, or it still lets us send while the camera is off. Without
 * the second, the far side keeps showing our last frame (the Teams Android app does). */
gboolean teams_video_needs_offer(gboolean camera, gboolean engine_video, gboolean negotiated,
                                 const char *our_dir, gboolean offer_pending);

/* The negotiationTag of our n-th renegotiation offer in a call: "<participantId>;v_<n>". CAPTURED
 * (teams.live.com turning its camera on mid-call): the uuid is the participantId of the
 * cpconv that placed the call, and the first offer of each call is v_1. g_free() it; NULL without
 * a participant id or for n 0. */
/* The video direction of that offer: "sendrecv" with the camera on, "recvonly" with it off.
 * CAPTURED (the Teams Android app turning its camera off and on mid-call): its offers keep the
 * m=video line and port, with a=recvonly and callModalities ["audio"] while its camera is off,
 * and sendrecv with ["audio","video"] once it is back on. */
const char *teams_video_offer_direction(gboolean camera);

gchar *teams_negotiation_tag(const char *participant_id, guint n);

/* The first m=<media> section of sdp ("audio", "video"): from its m= line up to the next m=
 * line, as it is in sdp. NULL if there is none or that m-line is declined (port 0). g_free() it.
 * An unbundled engine (one ICE stream per session) takes each section's ICE credentials, key and
 * candidates from here. */
gchar *teams_sdp_section(const char *sdp, const char *media);

/* The same, a declined m-line's (port 0) too: for its a=mid, which an answer repeats. */
gchar *teams_sdp_section_all(const char *sdp, const char *media);

/* Whether the first m=video section is declined (port 0): an answer keeps it at port 0. */
gboolean teams_sdp_video_declined(const char *sdp);

/* Whether the first m=video line comes before the first m=audio line: an answer has its m-lines
 * in the offer's order (RFC 3264 6). */
gboolean teams_sdp_video_first(const char *sdp);

/* The value of the audio's a=<name> attribute (e.g. "ice-ufrag"): the first m=audio section's,
 * else the session-level one (before the first m= line). NULL if neither has it. g_free() it. */
gchar *teams_sdp_audio_attr(const char *sdp, const char *name);

/* Whether the first m=video section has ICE credentials of its own: an a=ice-ufrag and
 * a=ice-pwd, its ufrag other than the audio's (teams_sdp_audio_attr). The Teams Android app's offers do,
 * though they name BUNDLE; an offer whose sections share one ufrag means one transport for all,
 * which an unbundled answer cannot give the video. */
gboolean teams_sdp_video_ice_own(const char *sdp);

/* One ICE candidate, as an SDP a=candidate line has it (RFC 5245 15.1):
 * "candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <type>
 * [raddr <ip> rport <port>] [<name> <value>]...". */
typedef struct {
	gchar   foundation[33];
	guint   component;
	gboolean udp;             /* the transport is UDP (TCP candidates are left alone) */
	guint32 priority;
	gchar   ip[64];
	guint   port;
	gchar   type[8];          /* "host", "srflx", "prflx" or "relay" */
	gchar   raddr[64];        /* "" when the line has none */
	guint   rport;
} TeamsIceCand;

/* Parse a candidate line, with or without its "a=" (an engine's CAND/RCAND line). FALSE if it is
 * not one: a field missing or out of range, an unknown type, or an extension name without its
 * value. */
gboolean teams_ice_candidate_parse(const char *line, TeamsIceCand *c);

/* The "candidate:..." line for c, without "a=", in the order libnice writes it. g_free() it. */
gchar *teams_ice_candidate_format(const TeamsIceCand *c);

#endif
