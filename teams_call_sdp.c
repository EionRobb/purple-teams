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
	if (!negotiated || offer_pending) return FALSE;
	if (camera) return engine_video && !teams_video_dir_we_send(our_dir);
	return teams_video_dir_we_send(our_dir);
}

const char *
teams_video_offer_direction(gboolean camera)
{
	return camera ? "sendrecv" : "recvonly";
}

gchar *
teams_negotiation_tag(const char *participant_id, guint n)
{
	if (!participant_id || !*participant_id || !n) return NULL;
	return g_strdup_printf("%s;v_%u", participant_id, n);
}

static gboolean
parse_uint(const char *s, guint64 max, guint64 *out)
{
	gchar *end = NULL;
	guint64 v;
	if (!s || !g_ascii_isdigit(*s)) return FALSE;
	v = g_ascii_strtoull(s, &end, 10);
	if (!end || *end || v > max) return FALSE;
	*out = v;
	return TRUE;
}

gboolean
teams_ice_candidate_parse(const char *line, TeamsIceCand *c)
{
	gchar **t;
	guint64 v;
	gboolean ok = FALSE;
	int n, i;
	if (!line || !c) return FALSE;
	memset(c, 0, sizeof *c);
	if (g_str_has_prefix(line, "a=")) line += 2;
	if (!g_str_has_prefix(line, "candidate:")) return FALSE;
	t = g_strsplit_set(line + strlen("candidate:"), " \t\r\n", -1);
	/* drop the empty fields that repeated blanks leave */
	for (i = 0, n = 0; t[i]; i++) {
		if (*t[i]) t[n++] = t[i];
		else g_free(t[i]);
	}
	t[n] = NULL;
	if (n < 8 || strcmp(t[6], "typ")) goto out;
	if (!*t[0] || strlen(t[0]) >= sizeof c->foundation) goto out;
	g_strlcpy(c->foundation, t[0], sizeof c->foundation);
	if (!parse_uint(t[1], 256, &v) || v == 0) goto out;
	c->component = (guint) v;
	c->udp = !g_ascii_strcasecmp(t[2], "UDP");
	if (!parse_uint(t[3], G_MAXUINT32, &v)) goto out;
	c->priority = (guint32) v;
	if (!*t[4] || strlen(t[4]) >= sizeof c->ip) goto out;
	g_strlcpy(c->ip, t[4], sizeof c->ip);
	if (!parse_uint(t[5], 65535, &v)) goto out;
	c->port = (guint) v;
	if (strcmp(t[7], "host") && strcmp(t[7], "srflx") && strcmp(t[7], "prflx") && strcmp(t[7], "relay"))
		goto out;
	g_strlcpy(c->type, t[7], sizeof c->type);
	for (i = 8; i + 1 < n; i += 2) {
		if (!strcmp(t[i], "raddr")) {
			if (strlen(t[i + 1]) >= sizeof c->raddr) goto out;
			g_strlcpy(c->raddr, t[i + 1], sizeof c->raddr);
		} else if (!strcmp(t[i], "rport")) {
			if (!parse_uint(t[i + 1], 65535, &v)) goto out;
			c->rport = (guint) v;
		}
	}
	ok = TRUE;
out:
	g_strfreev(t);
	if (!ok) memset(c, 0, sizeof *c);
	return ok;
}

gchar *
teams_ice_candidate_format(const TeamsIceCand *c)
{
	GString *s = g_string_new("");
	g_string_append_printf(s, "candidate:%s %u %s %u %s %u typ %s", c->foundation, c->component,
	                       c->udp ? "UDP" : "TCP", (unsigned) c->priority, c->ip, c->port, c->type);
	if (c->raddr[0])
		g_string_append_printf(s, " raddr %s rport %u", c->raddr, c->rport);
	return g_string_free(s, FALSE);
}

gchar *
teams_sdp_section(const char *sdp, const char *media)
{
	const char *p, *start = NULL, *end;
	gsize ml;
	if (!sdp || !media) return NULL;
	ml = strlen(media);
	for (p = sdp; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
		if (p[0] == 'm' && p[1] == '=' && !strncmp(p + 2, media, ml) && p[2 + ml] == ' ') {
			start = p;
			break;
		}
	}
	if (!start) return NULL;
	if (!strncmp(start + 2 + ml, " 0 ", 3)) return NULL;   /* declined */
	for (end = strchr(start, '\n'); end && end[1] && !(end[1] == 'm' && end[2] == '='); end = strchr(end + 1, '\n'))
		;
	return end && end[1] ? g_strndup(start, (gsize) (end + 1 - start)) : g_strdup(start);
}

/* the value of the section's first "a=<name>:" line, trimmed; NULL if none. g_free() it. */
static gchar *
section_attr(const char *sec, const char *name)
{
	gchar *key = g_strdup_printf("a=%s:", name), **lines, *ret = NULL;
	int i;
	if (!sec) { g_free(key); return NULL; }
	lines = g_strsplit(sec, "\n", -1);
	for (i = 0; lines[i] && !ret; i++) {
		gchar *l = g_strstrip(lines[i]);
		if (g_str_has_prefix(l, key) && l[strlen(key)]) ret = g_strdup(l + strlen(key));
	}
	g_strfreev(lines);
	g_free(key);
	return ret;
}

gboolean
teams_sdp_video_ice_own(const char *sdp)
{
	gchar *a = teams_sdp_section(sdp, "audio"), *v = teams_sdp_section(sdp, "video");
	gchar *auf = section_attr(a, "ice-ufrag"), *vuf = section_attr(v, "ice-ufrag"), *vpw = section_attr(v, "ice-pwd");
	gboolean r = vuf && vpw && g_strcmp0(auf, vuf);
	g_free(a); g_free(v); g_free(auf); g_free(vuf); g_free(vpw);
	return r;
}
