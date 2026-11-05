/* SDP rules for the video of a 1:1 Teams call (see teams_call_sdp.h). GLib only, so
 * tests/test_call_sdp.c runs them on their own. */

#include "teams_call_sdp.h"
#include <stdlib.h>
#include <string.h>

const char *
teams_sdp_video_direction(const char *sdp)
{
	gchar **lines;
	const char *dir = NULL;
	gboolean in_video = FALSE, found = FALSE;
	int i;
	if (!sdp)
		return NULL;
	lines = g_strsplit(sdp, "\n", -1);
	for (i = 0; lines[i]; i++) {
		gchar *l = g_strstrip(lines[i]);
		if (g_str_has_prefix(l, "m=")) {
			if (found)
				break;                      /* the first video section only */
			in_video = g_str_has_prefix(l, "m=video ");
			if (in_video) {
				found = TRUE;
				if (g_str_has_prefix(l, "m=video 0 "))
					break;                  /* declined: dir stays NULL */
				dir = "sendrecv";
			}
		} else if (in_video) {
			if (!strcmp(l, "a=sendrecv")) dir = "sendrecv";
			else if (!strcmp(l, "a=sendonly")) dir = "sendonly";
			else if (!strcmp(l, "a=recvonly")) dir = "recvonly";
			else if (!strcmp(l, "a=inactive")) dir = "inactive";
		}
	}
	g_strfreev(lines);
	return dir;
}

const char *
teams_video_answer_direction(const char *offer_dir, gboolean engine_video, gboolean camera)
{
	gboolean peer_sends, peer_receives;
	if (!offer_dir || !engine_video)
		return "inactive";
	peer_sends = !strcmp(offer_dir, "sendrecv") || !strcmp(offer_dir, "sendonly");
	peer_receives = !strcmp(offer_dir, "sendrecv") || !strcmp(offer_dir, "recvonly");
	camera = camera && peer_receives;
	if (peer_sends && camera) return "sendrecv";
	if (peer_sends) return "recvonly";
	if (camera) return "sendonly";
	return "inactive";
}

const char *
teams_video_our_direction(const char *answer_dir)
{
	if (!answer_dir) return "inactive";
	if (!strcmp(answer_dir, "sendrecv")) return "sendrecv";
	if (!strcmp(answer_dir, "recvonly")) return "sendonly";
	if (!strcmp(answer_dir, "sendonly")) return "recvonly";
	return "inactive";
}

gboolean
teams_video_dir_we_send(const char *answer_dir)
{
	return answer_dir && (!strcmp(answer_dir, "sendrecv") || !strcmp(answer_dir, "sendonly"));
}

gboolean
teams_video_dir_peer_sends(const char *offer_dir)
{
	return offer_dir && (!strcmp(offer_dir, "sendrecv") || !strcmp(offer_dir, "sendonly"));
}

/* A numeric "name=value" parameter of an fmtp line, or -1. */
static long
fmtp_param(const char *fmtp, const char *name)
{
	gsize nl = strlen(name);
	const char *p = fmtp;
	while (p && *p) {
		while (*p == ' ' || *p == ';') p++;
		if (!g_ascii_strncasecmp(p, name, nl) && p[nl] == '=') {
			char *end;
			long v = strtol(p + nl + 1, &end, 10);
			return end != p + nl + 1 && v >= 0 ? v : -1;
		}
		p = strchr(p, ';');
	}
	return -1;
}

void
teams_video_send_params(const char *sdp, int *w, int *h, int *kbps)
{
	static const int sizes[][2] = { { 640, 480 }, { 352, 288 }, { 320, 240 }, { 176, 144 } };
	long max_fs = -1, max_mbps = -1, max_br = -1;
	gchar **lines = sdp ? g_strsplit(sdp, "\n", -1) : NULL;
	gboolean in_video = FALSE, seen_video = FALSE;
	gsize i;
	for (i = 0; lines && lines[i]; i++) {
		gchar *l = g_strstrip(lines[i]);
		if (g_str_has_prefix(l, "m=")) {
			if (seen_video) break;
			in_video = seen_video = g_str_has_prefix(l, "m=video ");
		} else if (in_video && g_str_has_prefix(l, "a=fmtp:107 ")) {
			max_fs = fmtp_param(l + 11, "max-fs");
			max_mbps = fmtp_param(l + 11, "max-mbps");
			max_br = fmtp_param(l + 11, "max-br");
		}
	}
	g_strfreev(lines);
	*w = 176; *h = 144;
	for (i = 0; i < G_N_ELEMENTS(sizes); i++) {
		long fs = (long) ((sizes[i][0] + 15) / 16) * ((sizes[i][1] + 15) / 16);
		if ((max_fs < 0 || fs <= max_fs) && (max_mbps < 0 || fs * 30 <= max_mbps)) {
			*w = sizes[i][0]; *h = sizes[i][1];
			break;
		}
	}
	*kbps = 800;
	if (max_br >= 32 && max_br < *kbps) *kbps = (int) max_br;
}

gboolean
teams_video_needs_offer(gboolean camera, gboolean engine_video, gboolean negotiated,
                        const char *our_dir, gboolean offer_pending)
{
	return camera && engine_video && negotiated && !teams_video_dir_we_send(our_dir) && !offer_pending;
}

gchar *
teams_negotiation_tag(const char *participant_id, guint n)
{
	if (!participant_id || !*participant_id || !n) return NULL;
	return g_strdup_printf("%s;v_%u", participant_id, n);
}
