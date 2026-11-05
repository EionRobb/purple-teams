/* SDP rules for the video of a 1:1 Teams call: which direction to answer an offer with, what
 * our camera may send, when turning it on needs an offer of our own, and the negotiationTag of
 * such an offer. GLib only. */
#ifndef TEAMS_CALL_SDP_H
#define TEAMS_CALL_SDP_H

#include <glib.h>

/* The direction of an SDP's first m=video section ("sendrecv", "sendonly", "recvonly" or
 * "inactive"; sendrecv when it names none), or NULL if it has none or that m-line is declined
 * (port 0). */
const char *teams_sdp_video_direction(const char *sdp);

/* Our answer's direction for the video m-line (RFC 3264 6.1), from the offer's direction, whether
 * the engine has video at all and whether our camera is to send. */
const char *teams_video_answer_direction(const char *offer_dir, gboolean engine_video, gboolean camera);

/* The size and bitrate our camera may send on H264 PT 107: the largest standard camcorder size
 * (640x480, 352x288, 320x240, 176x144, at the camera's 30 fps) within the first m=video
 * section's a=fmtp:107 max-fs and max-mbps, and 800 kbit/s or its max-br if lower. The Teams
 * Android app offers max-fs=240;max-mbps=3600;max-br=208: 176x144 at 208 kbit/s. */
void teams_video_send_params(const char *sdp, int *w, int *h, int *kbps);

/* Our direction once the far side answered our sendrecv video offer: the mirror of its answer's
 * direction (its recvonly means we only send), "inactive" for none or a declined m-line. */
const char *teams_video_our_direction(const char *answer_dir);

/* Whether a direction of ours lets us send / lets the far side send to us. */
gboolean teams_video_dir_we_send(const char *answer_dir);
gboolean teams_video_dir_peer_sends(const char *offer_dir);

/* Whether turning our camera on needs an offer of our own (the web client's mid-call
 * .../renegotiate): the camera is wanted, the engine has video, the call's media is negotiated,
 * our current direction does not let us send, and no offer of ours is waiting for its answer. */
gboolean teams_video_needs_offer(gboolean camera, gboolean engine_video, gboolean negotiated,
                                 const char *our_dir, gboolean offer_pending);

/* The negotiationTag of our n-th renegotiation offer in a call: "<participantId>;v_<n>". CAPTURED
 * (teams.live.com turning its camera on mid-call): the uuid is the participantId of the
 * cpconv that placed the call, and the first offer of each call is v_1. g_free() it; NULL without
 * a participant id or for n 0. */
gchar *teams_negotiation_tag(const char *participant_id, guint n);

#endif
