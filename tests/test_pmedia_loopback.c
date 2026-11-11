/* Loopback test of the in-process PurpleMedia engine (teams_call_pmedia.c): two engines in one
 * process, one placing the call and one answering it, driven over the teams_media line protocol
 * the way teams_calling.c drives them, with ICE between them on this host. Needs libpurple built
 * with voice and video, Farstream, and GStreamer's nice, srtp, rtpmanager, opus, audiotestsrc
 * and fakesink. Run it with TEAMS_PMEDIA_SRC=audiotestsrc TEAMS_PMEDIA_SINK=fakesink so that it
 * is silent (the script that runs it sets them).
 *
 * It checks:
 *   1. both sides print TXKEY, UFRAG, PWD, READY, CAND and GATHERED, and AUDIOD 1 once ICE pairs
 *   2. audio gets through, SRTP AEAD_AES_256_GCM, both ways: each fakesink gets decoded buffers
 *   3. RESTART is answered ERR, and the call goes on
 *   4. a START whose key has the wrong length gives ERR, and the engine closes its output
 *   5. STOP and teams_pmedia_free end it all without a crash (ASan/valgrind runs check leaks)
 *   6. a fourth engine, given a STUN server first (RELAY stun) as every real call is, starts
 *      without a crash: stun-ip is a string, and libpurple takes the stream parameters' values
 *      over and unsets them itself, so a second unset in the engine is a double free (ASan
 *      catches it). Nothing answers on that server, which slows ICE down, so the call in 1-3
 *      has none: its answerer's first RTP packet, which gives its SSRC, would come too late.
 *   7. video: both sides add a video session (VSTART, VANSWER, VRCAND) on an ICE stream of its
 *      own, print VUFRAG/VPWD/VCAND and VSSRC, and GATHERED only once both sessions have their
 *      candidates; the caller sends a test picture (TEAMS_PMEDIA_VSRC) as H264, and the answerer
 *      decodes it into its gst-shm socket (TEAMS_PMEDIA_VIDEO_SHM), says VSHM and PEERVIDEO 1,
 *      and its RTCP carries REMB to the caller (counted on the caller's RTP session). Both say
 *      VCAMERA 1 (the session can send), and the caller sends only once its camera is on
 *      (VIDEO 1). At 5 s the answerer turns its camera on too: the caller gets its picture
 *      (PEERVIDEO 1). Each prints VTX 1 and VPREVIEW, its self-view socket gets frames, and
 *      STATS counts the frames into Farstream (vtxf). After 8 the answerer turns it off (VTX 0).
 *   8. VRESTART: the video moves to new ICE credentials, as the Teams Android app does on a call
 *      we placed. B (the far side) makes a new video session (VRESTART), then A replaces its own
 *      for B's new credentials and candidates (VRESTART, VRCAND), and B takes A's answer
 *      (VANSWER). Each prints new VUFRAG/VPWD/VCAND, then VRESTARTED, and the old sessions'
 *      signals change nothing; the video gets through again on the new sessions (B publishes
 *      more frames), and the audio goes on.
 *  10. the camera off and at once on again (as a front end's camera button does): A's camera
 *      head gets frames again (counted on its pmvout queue), and VTX 0 and VTX 1 again.
 *   9. a camera error does not end the call: an error posted from A's running camera source
 *      (as droidcamsrc posts one when another user takes the camera) gives VTX 0 and
 *      VIDEOERR tx-camera, no ERR, and the audio goes on.
 * Video needs an H264 encoder Farstream can pick, and avdec_h264; the script sets
 * TEAMS_PMEDIA_VSRC=1 and TEAMS_PMEDIA_VIDEO_SHM. With PMTEST_H264_CLIP=<an Annex B H264 file,
 * one access unit per frame, each starting with an access unit delimiter, SPS and PPS in it> the test registers an
 * encoder of its own (pmtestenc, ranked above every other): for each raw frame it is given it
 * pushes the clip's next access unit, with that frame's timestamps, so that no hardware encoder
 * (droidvenc) takes part. The clip loops, so it should start with an IDR and have a few more.
 */
#include "teams_call_pmedia.h"

#include <core.h>
#include <debug.h>
#include <eventloop.h>
#include <mediamanager.h>
#include <media-gst.h>
#include <util.h>

#include <gst/gst.h>
#include <gst/rtp/gstrtcpbuffer.h>
#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- pmtestenc: an "encoder" that sends a recorded clip (PMTEST_H264_CLIP) ----
 * It puts out stream-format=avc as droidvenc does: Farstream keeps one H264 blueprint, the one
 * whose payloader caps say avc, and a byte-stream encoder would not be in it. */
static GPtrArray *clip_aus;   /* GBytes, one access unit each: 4-byte lengths, no delimiters */
static GBytes *clip_avcc;     /* codec_data, from the clip's first SPS and PPS */

/* the next NAL unit of d[0..n) at or after *pos: its start and length; FALSE at the end */
static gboolean clip_next_nal(const guint8 *d, gsize n, gsize *pos, gsize *start, gsize *len)
{
	gsize i = *pos, s;
	while (i + 3 <= n && !(d[i] == 0 && d[i + 1] == 0 && d[i + 2] == 1)) i++;
	if (i + 3 > n) return FALSE;
	s = i + 3;
	i = s;
	while (i + 3 <= n && !(d[i] == 0 && d[i + 1] == 0 && (d[i + 2] == 1 || (d[i + 2] == 0 && i + 3 < n && d[i + 3] == 1)))) i++;
	if (i + 3 > n) i = n;
	*start = s;
	*len = i - s;
	*pos = i;
	return *len > 0;
}

static gboolean clip_load(const char *path)
{
	gchar *raw = NULL;
	gsize n = 0, pos = 0, st, len;
	const guint8 *d;
	GByteArray *au = NULL;
	const guint8 *sps = NULL, *pps = NULL;
	gsize sps_len = 0, pps_len = 0;
	if (!g_file_get_contents(path, &raw, &n, NULL)) return FALSE;
	d = (const guint8 *) raw;
	clip_aus = g_ptr_array_new_with_free_func((GDestroyNotify) g_bytes_unref);
	while (clip_next_nal(d, n, &pos, &st, &len)) {
		guint8 t = d[st] & 0x1f, be[4];
		if (t == 9) {   /* an access unit delimiter: the last one is complete */
			if (au && au->len) g_ptr_array_add(clip_aus, g_byte_array_free_to_bytes(au));
			else if (au) g_byte_array_unref(au);
			au = g_byte_array_new();
			continue;
		}
		if (t == 7 && !sps) { sps = d + st; sps_len = len; }
		if (t == 8 && !pps) { pps = d + st; pps_len = len; }
		if (!au) au = g_byte_array_new();
		be[0] = (guint8) (len >> 24); be[1] = (guint8) (len >> 16); be[2] = (guint8) (len >> 8); be[3] = (guint8) len;
		g_byte_array_append(au, be, 4);
		g_byte_array_append(au, d + st, (guint) len);
	}
	if (au && au->len) g_ptr_array_add(clip_aus, g_byte_array_free_to_bytes(au));
	else if (au) g_byte_array_unref(au);
	if (sps && pps && sps_len >= 4 && sps_len < 65536 && pps_len < 65536) {
		GByteArray *c = g_byte_array_new();
		guint8 h[8] = { 1, sps[1], sps[2], sps[3], 0xff, 0xe1, (guint8) (sps_len >> 8), (guint8) sps_len };
		guint8 p[3] = { 1, (guint8) (pps_len >> 8), (guint8) pps_len };
		g_byte_array_append(c, h, 8);
		g_byte_array_append(c, sps, (guint) sps_len);
		g_byte_array_append(c, p, 3);
		g_byte_array_append(c, pps, (guint) pps_len);
		clip_avcc = g_byte_array_free_to_bytes(c);
	}
	g_free(raw);
	return clip_aus->len > 0 && clip_avcc;
}

/* whether an access unit (4-byte lengths) holds an IDR slice */
static gboolean clip_au_is_idr(GBytes *au)
{
	gsize n, i = 0;
	const guint8 *d = g_bytes_get_data(au, &n);
	while (i + 5 <= n) {
		guint32 l = ((guint32) d[i] << 24) | ((guint32) d[i + 1] << 16) | ((guint32) d[i + 2] << 8) | d[i + 3];
		if ((d[i + 4] & 0x1f) == 5) return TRUE;
		if (l > n - i - 4) break;
		i += 4 + l;
	}
	return FALSE;
}

typedef struct { GstElement parent; GstPad *sink, *src; guint next; gboolean caps_sent; } PmTestEnc;
typedef struct { GstElementClass parent_class; } PmTestEncClass;
GType pm_test_enc_get_type(void);
G_DEFINE_TYPE(PmTestEnc, pm_test_enc, GST_TYPE_ELEMENT)

static GstStaticPadTemplate enc_sink_t = GST_STATIC_PAD_TEMPLATE("sink", GST_PAD_SINK, GST_PAD_ALWAYS,
	GST_STATIC_CAPS("video/x-raw"));
static GstStaticPadTemplate enc_src_t = GST_STATIC_PAD_TEMPLATE("src", GST_PAD_SRC, GST_PAD_ALWAYS,
	GST_STATIC_CAPS("video/x-h264, stream-format=(string)avc, alignment=(string)au, "
	                "profile=(string)constrained-baseline, width=(int)320, height=(int)240, framerate=(fraction)15/1"));

static GstFlowReturn pm_test_enc_chain(GstPad *pad, GstObject *parent, GstBuffer *in)
{
	PmTestEnc *e = (PmTestEnc *) parent;
	GBytes *au = g_ptr_array_index(clip_aus, e->next % clip_aus->len);
	GstBuffer *out = gst_buffer_new_wrapped_bytes(au);
	(void) pad;
	GST_BUFFER_PTS(out) = GST_BUFFER_PTS(in);
	GST_BUFFER_DTS(out) = GST_BUFFER_PTS(in);
	GST_BUFFER_DURATION(out) = GST_BUFFER_DURATION(in);
	if (!clip_au_is_idr(au)) GST_BUFFER_FLAG_SET(out, GST_BUFFER_FLAG_DELTA_UNIT);
	e->next++;
	gst_buffer_unref(in);
	return gst_pad_push(e->src, out);
}

static gboolean pm_test_enc_sink_event(GstPad *pad, GstObject *parent, GstEvent *ev)
{
	PmTestEnc *e = (PmTestEnc *) parent;
	/* the raw caps stay here; the src side gets the clip's caps in their place, so they still
	 * come between stream-start and segment */
	if (GST_EVENT_TYPE(ev) == GST_EVENT_CAPS) {
		gst_event_unref(ev);
		if (!e->caps_sent) {
			GstCaps *c = gst_caps_make_writable(gst_static_pad_template_get_caps(&enc_src_t));
			GstBuffer *cd = gst_buffer_new_wrapped_bytes(clip_avcc);
			gst_caps_set_simple(c, "codec_data", GST_TYPE_BUFFER, cd, NULL);
			gst_buffer_unref(cd);
			e->caps_sent = gst_pad_push_event(e->src, gst_event_new_caps(c));
			gst_caps_unref(c);
		}
		return TRUE;
	}
	return gst_pad_event_default(pad, parent, ev);
}

static void pm_test_enc_init(PmTestEnc *e)
{
	e->sink = gst_pad_new_from_static_template(&enc_sink_t, "sink");
	e->src = gst_pad_new_from_static_template(&enc_src_t, "src");
	gst_pad_set_chain_function(e->sink, pm_test_enc_chain);
	gst_pad_set_event_function(e->sink, pm_test_enc_sink_event);
	GST_PAD_SET_PROXY_ALLOCATION(e->sink);
	gst_pad_use_fixed_caps(e->src);
	gst_element_add_pad(GST_ELEMENT(e), e->sink);
	gst_element_add_pad(GST_ELEMENT(e), e->src);
}

static void pm_test_enc_class_init(PmTestEncClass *k)
{
	GstElementClass *ek = GST_ELEMENT_CLASS(k);
	gst_element_class_add_static_pad_template(ek, &enc_sink_t);
	gst_element_class_add_static_pad_template(ek, &enc_src_t);
	gst_element_class_set_static_metadata(ek, "pmtest H264 clip", "Codec/Encoder/Video",
		"Sends a recorded H264 clip, one access unit per raw frame", "pmtest");
}

static gboolean pm_test_enc_plugin_init(GstPlugin *p)
{
	return gst_element_register(p, "pmtestenc", GST_RANK_PRIMARY + 100, pm_test_enc_get_type());
}

static int failures;
#define CHECK(c) do { if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
                      else fprintf(stderr, "ok   %s\n", #c); } while (0)

/* ---- the GLib event loop for libpurple ---- */
typedef struct { PurpleInputFunction fn; gpointer data; } IoClosure;
static gboolean io_cb(GIOChannel *s, GIOCondition c, gpointer d)
{
	IoClosure *cl = d;
	int cond = 0;
	if (c & (G_IO_IN | G_IO_HUP | G_IO_ERR)) cond |= PURPLE_INPUT_READ;
	if (c & (G_IO_OUT | G_IO_HUP | G_IO_ERR)) cond |= PURPLE_INPUT_WRITE;
	cl->fn(cl->data, g_io_channel_unix_get_fd(s), cond);
	return TRUE;
}
static guint io_add(gint fd, PurpleInputCondition c, PurpleInputFunction fn, gpointer data)
{
	IoClosure *cl = g_new0(IoClosure, 1);
	GIOChannel *ch = g_io_channel_unix_new(fd);
	int cond = 0;
	guint id;
	cl->fn = fn; cl->data = data;
	if (c & PURPLE_INPUT_READ) cond |= G_IO_IN | G_IO_HUP | G_IO_ERR;
	if (c & PURPLE_INPUT_WRITE) cond |= G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	id = g_io_add_watch_full(ch, G_PRIORITY_DEFAULT, cond, io_cb, cl, g_free);
	g_io_channel_unref(ch);
	return id;
}
static PurpleEventLoopUiOps loop_ops = {
	g_timeout_add, g_source_remove, io_add, g_source_remove, NULL, g_timeout_add_seconds,
	NULL, NULL, NULL
};

/* ---- one engine, seen from the plugin's side ---- */
typedef struct {
	const char  *name;
	TeamsPMedia *pm;
	int          cmd;      /* our end: commands go in */
	int          out;      /* our end: its lines come out */
	GString     *in;
	gchar       *txkey, *ufrag, *pwd;
	GString     *cands;
	gboolean     ready, gathered, audiod, answered, closed;
	int          errs;
	gchar       *last_err;
	guint        ssrc;
	gchar       *vufrag, *vpwd, *vshm, *stats;
	GString     *vcands;
	guint        vssrc;
	gboolean     peervideo, vtx_err;
	gboolean     vcreds_before_ready;   /* VUFRAG came before READY */
	int          vrestarted;            /* VRESTARTED lines */
	gboolean     vcamera;               /* VCAMERA 1: the video session can send */
	int          vtx_on, vtx_off;       /* VTX 1 / VTX 0 lines */
	gboolean     cam_err;               /* VIDEOERR tx-camera */
	gchar       *vpreview;              /* the last VPREVIEW line */
} Side;

static GMainLoop *loop;

static void side_send(Side *s, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
static void side_send(Side *s, const char *fmt, ...)
{
	va_list ap;
	gchar *l;
	va_start(ap, fmt);
	l = g_strdup_vprintf(fmt, ap);
	va_end(ap);
	if (send(s->cmd, l, strlen(l), MSG_NOSIGNAL) != (ssize_t) strlen(l))
		fprintf(stderr, "%s: send: %s\n", s->name, g_strerror(errno));
	g_free(l);
}

static void side_line(Side *s, const char *l)
{
	if (g_str_has_prefix(l, "TXKEY ")) { g_free(s->txkey); s->txkey = g_strdup(l + 6); fprintf(stderr, "%s: TXKEY (%d chars)\n", s->name, (int) strlen(l + 6)); return; }
	fprintf(stderr, "%s: %s\n", s->name, l ? l : "");
	if (g_str_has_prefix(l, "UFRAG ")) { g_free(s->ufrag); s->ufrag = g_strdup(l + 6); }
	else if (g_str_has_prefix(l, "PWD ")) { g_free(s->pwd); s->pwd = g_strdup(l + 4); }
	else if (g_str_has_prefix(l, "CAND ")) g_string_append_printf(s->cands, "%s\n", l + 5);
	else if (g_str_has_prefix(l, "SSRC ")) s->ssrc = (guint) g_ascii_strtoull(l + 5, NULL, 10);
	else if (g_str_has_prefix(l, "VUFRAG ")) { g_free(s->vufrag); s->vufrag = g_strdup(l + 7); s->vcreds_before_ready |= !s->ready; }   /* the first: 8 makes more */
	else if (g_str_has_prefix(l, "VPWD ")) { g_free(s->vpwd); s->vpwd = g_strdup(l + 5); }
	else if (g_str_has_prefix(l, "VCAND ")) g_string_append_printf(s->vcands, "%s\n", l + 6);
	else if (g_str_has_prefix(l, "VSSRC ")) s->vssrc = (guint) g_ascii_strtoull(l + 6, NULL, 10);
	else if (g_str_has_prefix(l, "VSHM ")) { gchar **t = g_strsplit(l + 5, " ", 2); g_free(s->vshm); s->vshm = g_strdup(t[0]); g_strfreev(t); }
	else if (!strcmp(l, "PEERVIDEO 1")) s->peervideo = TRUE;
	else if (!strcmp(l, "VIDEOERR tx")) s->vtx_err = TRUE;
	else if (!strcmp(l, "VIDEOERR tx-camera")) s->cam_err = TRUE;
	else if (!strcmp(l, "VRESTARTED")) s->vrestarted++;
	else if (!strcmp(l, "VCAMERA 1")) s->vcamera = TRUE;
	else if (!strcmp(l, "VTX 1")) s->vtx_on++;
	else if (!strcmp(l, "VTX 0")) s->vtx_off++;
	else if (g_str_has_prefix(l, "VPREVIEW ")) { g_free(s->vpreview); s->vpreview = g_strdup(l + 9); }
	else if (g_str_has_prefix(l, "STATS ")) { g_free(s->stats); s->stats = g_strdup(l + 6); }
	else if (!strcmp(l, "READY")) s->ready = TRUE;
	else if (!strcmp(l, "GATHERED")) s->gathered = TRUE;
	else if (!strcmp(l, "AUDIOD 1")) s->audiod = TRUE;
	else if (!strcmp(l, "ANSWERED")) s->answered = TRUE;
	else if (g_str_has_prefix(l, "ERR ")) { s->errs++; g_free(s->last_err); s->last_err = g_strdup(l + 4); }
}

static gboolean side_readable(GIOChannel *ch, GIOCondition c, gpointer u)
{
	Side *s = u;
	char buf[4096];
	ssize_t n = read(s->out, buf, sizeof buf);
	(void) ch; (void) c;
	if (n <= 0) { s->closed = TRUE; fprintf(stderr, "%s: output closed\n", s->name); return G_SOURCE_REMOVE; }
	g_string_append_len(s->in, buf, n);
	for (;;) {
		char *nl = memchr(s->in->str, '\n', s->in->len);
		gchar *l;
		if (!nl) break;
		l = g_strndup(s->in->str, nl - s->in->str);
		g_string_erase(s->in, 0, nl - s->in->str + 1);
		side_line(s, l);
		g_free(l);
	}
	return G_SOURCE_CONTINUE;
}

static void side_start(Side *s, const char *name, PurpleAccount *test_account, gboolean caller)
{
	int a[2], b[2];
	GIOChannel *ch;
	memset(s, 0, sizeof *s);
	s->name = name;
	s->in = g_string_new("");
	s->cands = g_string_new("");
	s->vcands = g_string_new("");
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, a) || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, b))
		abort();
	s->cmd = a[0]; s->out = b[0];
	s->pm = teams_pmedia_start(test_account, caller, a[1], b[1]);
	ch = g_io_channel_unix_new(s->out);
	g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR, side_readable, s);
	g_io_channel_unref(ch);
}

static void side_send_cands(Side *to, const Side *from)
{
	gchar **cl = g_strsplit(from->cands->str, "\n", -1);
	int i;
	for (i = 0; cl[i]; i++) if (*cl[i]) side_send(to, "RCAND %s\n", cl[i]);
	g_strfreev(cl);
	cl = g_strsplit(from->vcands->str, "\n", -1);
	for (i = 0; cl[i]; i++) if (*cl[i]) side_send(to, "VRCAND %s\n", cl[i]);
	g_strfreev(cl);
}

/* A STATS field's value, -1 if it is not there. */
static long stat_field(const Side *s, const char *key)
{
	gchar *k = g_strdup_printf(" %s=", key);
	const char *p = s->stats ? strstr(s->stats, k) : NULL;
	long v = p ? strtol(p + strlen(k), NULL, 10) : -1;
	g_free(k);
	return v;
}

/* an unsigned 32-bit field of the last STATS line (an SSRC), 0 if none */
static guint stat_u32(const Side *s, const char *key)
{
	gchar *k = g_strdup_printf(" %s=", key);
	const char *p = s->stats ? strstr(s->stats, k) : NULL;
	guint v = p ? (guint) g_ascii_strtoull(p + strlen(k), NULL, 10) : 0;
	g_free(k);
	return v;
}

static void side_free(Side *s)
{
	if (s->cmd >= 0) close(s->cmd);
	teams_pmedia_free(s->pm);
	g_source_remove_by_user_data(s);
	close(s->out);
	g_string_free(s->in, TRUE); g_string_free(s->cands, TRUE); g_string_free(s->vcands, TRUE);
	g_free(s->txkey); g_free(s->ufrag); g_free(s->pwd); g_free(s->last_err);
	g_free(s->vufrag); g_free(s->vpwd); g_free(s->vshm); g_free(s->stats); g_free(s->vpreview);
}

/* ---- counting what reaches the sinks ---- */
static GHashTable *counts;   /* GstElement* (a reference) -> buffers: our receive sinks (TEAMS_PMEDIA_SINK);
                              * referenced, so the results can name them after a media ended */
static GMutex counts_lock;   /* counts: the probes count from streaming threads; NULL once torn down */

static GstPadProbeReturn count_probe(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	gpointer k = u;
	(void) pad; (void) info;
	g_mutex_lock(&counts_lock);
	if (counts)
		g_hash_table_insert(counts, k, GUINT_TO_POINTER(GPOINTER_TO_UINT(g_hash_table_lookup(counts, k)) + 1));
	g_mutex_unlock(&counts_lock);
	return GST_PAD_PROBE_OK;
}

static gint n_bufs, n_lists;
static gint shm_bufs;        /* frames into a shmsink: the answerer's published video */
static gint remb_seen, pli_seen;   /* feedback an RTP session got */
static GHashTable *sess_seen;

static GstPadProbeReturn shm_probe(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	(void) pad; (void) info; (void) u;
	g_atomic_int_inc(&shm_bufs);
	return GST_PAD_PROBE_OK;
}
static gint preview_bufs;     /* frames into a self-view socket */
static GstPadProbeReturn preview_probe(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	(void) pad; (void) info; (void) u;
	g_atomic_int_inc(&preview_bufs);
	return GST_PAD_PROBE_OK;
}

static void on_feedback(GObject *sess, guint type, guint fbtype, guint sender, guint media, GstBuffer *fci, gpointer u)
{
	guint8 h[4];
	(void) sess; (void) sender; (void) media; (void) u;
	if (type == GST_RTCP_TYPE_PSFB && fbtype == GST_RTCP_PSFB_TYPE_PLI) g_atomic_int_inc(&pli_seen);
	if (type == GST_RTCP_TYPE_PSFB && fbtype == GST_RTCP_PSFB_TYPE_AFB && fci &&
	    gst_buffer_extract(fci, 0, h, 4) == 4 && !memcmp(h, "REMB", 4))
		g_atomic_int_inc(&remb_seen);
}
static GHashTable *nice_seen;
static GstPadProbeReturn nice_probe(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	(void) pad; (void) u;
	if (info->type & GST_PAD_PROBE_TYPE_BUFFER_LIST) g_atomic_int_inc(&n_lists);
	else g_atomic_int_inc(&n_bufs);
	return GST_PAD_PROBE_OK;
}

/* libpurple's receive chain ends queue ! volume ! level ! <sink>; Farstream's own bins hold
 * fakesinks too, which are not the far side's audio. */
static gboolean fed_by_level(GstElement *sink)
{
	GstPad *p = gst_element_get_static_pad(sink, "sink"), *peer = p ? gst_pad_get_peer(p) : NULL;
	GstElement *up = peer ? gst_pad_get_parent_element(peer) : NULL;
	GstElementFactory *f = up ? gst_element_get_factory(up) : NULL;
	gboolean r = f && !strcmp(GST_OBJECT_NAME(f), "level");
	if (up) gst_object_unref(up);
	if (peer) gst_object_unref(peer);
	if (p) gst_object_unref(p);
	return r;
}

static gint vout_bufs;                  /* 10: frames out of the camera heads (pmvout) */
static gint vout_at_toggle, vout_after_toggle;

static GstPadProbeReturn vout_probe(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	(void) pad; (void) info; (void) u;
	g_atomic_int_inc(&vout_bufs);
	return GST_PAD_PROBE_OK;
}

/* PMTEST_DUMP_RTP=<file>: every H264 RTP packet an RTP session sends, as a 4-byte big-endian
 * length and the packet, for a look at what our encoder and payloader make. */
static FILE *rtp_dump;
static GMutex rtp_dump_lock;

static void dump_rtp(GstBuffer *b)
{
	GstMapInfo m;
	if (!gst_buffer_map(b, &m, GST_MAP_READ)) return;
	if (m.size >= 12 && (m.data[1] & 0x7f) == 107) {
		guint8 len[4] = { (guint8) (m.size >> 24), (guint8) (m.size >> 16), (guint8) (m.size >> 8), (guint8) m.size };
		g_mutex_lock(&rtp_dump_lock);
		fwrite(len, 1, 4, rtp_dump);
		fwrite(m.data, 1, m.size, rtp_dump);
		g_mutex_unlock(&rtp_dump_lock);
	}
	gst_buffer_unmap(b, &m);
}

static GstPadProbeReturn dump_probe(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	(void) pad; (void) u;
	if (info->type & GST_PAD_PROBE_TYPE_BUFFER_LIST) {
		GstBufferList *l = GST_PAD_PROBE_INFO_BUFFER_LIST(info);
		guint i;
		for (i = 0; i < gst_buffer_list_length(l); i++) dump_rtp(gst_buffer_list_get(l, i));
	} else if (GST_PAD_PROBE_INFO_BUFFER(info)) {
		dump_rtp(GST_PAD_PROBE_INFO_BUFFER(info));
	}
	return GST_PAD_PROBE_OK;
}

static void probe_sinks(void)
{
	GstElement *pipe = purple_media_manager_get_pipeline(purple_media_manager_get());
	GstIterator *it;
	GValue v = G_VALUE_INIT;
	gboolean done = FALSE, counted;
	if (!pipe) return;
	it = gst_bin_iterate_recurse(GST_BIN(pipe));
	while (!done) {
		switch (gst_iterator_next(it, &v)) {
		case GST_ITERATOR_OK: {
			GstElement *e = g_value_get_object(&v);
			GstElementFactory *f = gst_element_get_factory(e);
			if (getenv("PMTEST_NICE") && f && !strcmp(GST_OBJECT_NAME(f), "nicesrc") && !g_hash_table_contains(nice_seen, e)) {
				GstPad *p = gst_element_get_static_pad(e, "src");
				g_hash_table_add(nice_seen, e);
				if (p) { gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST, nice_probe, NULL, NULL); gst_object_unref(p); }
			}
			if (f && !strcmp(GST_OBJECT_NAME(f), "shmsink") && !g_hash_table_contains(sess_seen, e)) {
				/* the far side's picture; our self-view's (pmpreview) apart */
				gboolean pv = g_str_has_prefix(GST_OBJECT_NAME(e), "pmpreview");
				GstPad *p = gst_element_get_static_pad(e, "sink");
				g_hash_table_add(sess_seen, e);
				if (p) { gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER, pv ? preview_probe : shm_probe, NULL, NULL); gst_object_unref(p); }
			}
			if (f && !strcmp(GST_OBJECT_NAME(f), "queue") && !strcmp(GST_OBJECT_NAME(e), "pmvout") &&
			    !g_hash_table_contains(sess_seen, e)) {
				GstPad *p = gst_element_get_static_pad(e, "src");
				g_hash_table_add(sess_seen, e);
				if (p) { gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER, vout_probe, NULL, NULL); gst_object_unref(p); }
			}
			if (f && !strcmp(GST_OBJECT_NAME(f), "rtpsession") && !g_hash_table_contains(sess_seen, e)) {
				GObject *sess = NULL;
				g_hash_table_add(sess_seen, e);
				g_object_get(e, "internal-session", &sess, NULL);
				if (sess) { g_signal_connect(sess, "on-feedback-rtcp", G_CALLBACK(on_feedback), NULL); g_object_unref(sess); }
			}
			if (g_getenv("PMTEST_DUMP_RTP") && f && !strcmp(GST_OBJECT_NAME(f), "rtpsession") &&
			    !g_hash_table_contains(nice_seen, e)) {
				/* its send side comes when Farstream links it: looked for again each tick */
				GstPad *p;
				if (!rtp_dump) rtp_dump = fopen(g_getenv("PMTEST_DUMP_RTP"), "wb");
				p = rtp_dump ? gst_element_get_static_pad(e, "send_rtp_src") : NULL;
				if (p) {
					g_hash_table_add(nice_seen, e);
					gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST, dump_probe, NULL, NULL);
					gst_object_unref(p);
				}
			}
			g_mutex_lock(&counts_lock);
			counted = g_hash_table_contains(counts, e);
			g_mutex_unlock(&counts_lock);
			if (f && !strcmp(GST_OBJECT_NAME(f), "fakesink") && !counted && fed_by_level(e)) {
				GstPad *p = gst_element_get_static_pad(e, "sink");
				g_mutex_lock(&counts_lock);
				g_hash_table_insert(counts, gst_object_ref(e), GUINT_TO_POINTER(0));
				g_mutex_unlock(&counts_lock);
				if (p) gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER, count_probe, e, NULL);
				{
					GString *path = g_string_new(GST_OBJECT_NAME(e));
					GstObject *o = GST_OBJECT_PARENT(e);
					GstPad *peer = p ? gst_pad_get_peer(p) : NULL;
					for (; o; o = GST_OBJECT_PARENT(o)) g_string_prepend(g_string_prepend(path, "/"), GST_OBJECT_NAME(o));
					fprintf(stderr, "probe on %s (fed by %s:%s)\n", path->str,
					        peer && GST_PAD_PARENT(peer) ? GST_OBJECT_NAME(GST_PAD_PARENT(peer)) : "?",
					        peer ? GST_PAD_NAME(peer) : "?");
					if (peer) gst_object_unref(peer);
					g_string_free(path, TRUE);
				}
				if (p) gst_object_unref(p);
			}
			g_value_reset(&v);
			break;
		}
		case GST_ITERATOR_RESYNC: gst_iterator_resync(it); break;
		default: done = TRUE;
		}
	}
	g_value_unset(&v);
	gst_iterator_free(it);
}

/* Whether some RTP session in the pipeline sends with ssrc (its internal-session's
 * internal-ssrc): our SDP declares what is really sent. */
static gboolean session_sends_ssrc(guint ssrc)
{
	GstElement *pipe = purple_media_manager_get_pipeline(purple_media_manager_get());
	GstIterator *it = gst_bin_iterate_recurse(GST_BIN(pipe));
	GValue v = G_VALUE_INIT;
	gboolean done = FALSE, found = FALSE;
	while (!done) {
		switch (gst_iterator_next(it, &v)) {
		case GST_ITERATOR_OK: {
			GstElement *e = g_value_get_object(&v);
			GstElementFactory *f = gst_element_get_factory(e);
			if (f && !strcmp(GST_OBJECT_NAME(f), "rtpsession")) {
				GObject *sess = NULL;
				guint s = 0;
				g_object_get(e, "internal-session", &sess, NULL);
				if (sess) { g_object_get(sess, "internal-ssrc", &s, NULL); g_object_unref(sess); }
				fprintf(stderr, "rtpsession %s sends as %u\n", GST_OBJECT_NAME(e), s);
				if (s == ssrc) found = TRUE;
			}
			g_value_reset(&v);
			break;
		}
		case GST_ITERATOR_RESYNC: gst_iterator_resync(it); break;
		default: done = TRUE;
		}
	}
	g_value_unset(&v);
	gst_iterator_free(it);
	return found;
}
static gboolean ssrc_a_ok, ssrc_b_ok;

/* 9: the camera source that runs (pm_make_vcam's "pmcam", not in locked state), or NULL */
static GstElement *running_camera(void)
{
	GstElement *pipe = purple_media_manager_get_pipeline(purple_media_manager_get()), *found = NULL;
	GstIterator *it = gst_bin_iterate_recurse(GST_BIN(pipe));
	GValue v = G_VALUE_INIT;
	gboolean done = FALSE;
	int n = 0;
	while (!done) {
		switch (gst_iterator_next(it, &v)) {
		case GST_ITERATOR_OK: {
			GstElement *e = g_value_get_object(&v);
			if (!strcmp(GST_OBJECT_NAME(e), "pmcam") && !gst_element_is_locked_state(e)) {
				n++;
				if (!found) found = gst_object_ref(e);
			}
			g_value_reset(&v);
			break;
		}
		case GST_ITERATOR_RESYNC: gst_iterator_resync(it); break;
		default: done = TRUE;
		}
	}
	g_value_unset(&v);
	gst_iterator_free(it);
	if (n != 1 && found) { gst_object_unref(found); found = NULL; }   /* only A's may run */
	fprintf(stderr, "running cameras: %d\n", n);
	return found;
}
static gboolean cam_error_posted;

static gint audio_at_cam_error, audio_after_cam_error;

/* 8: a side's video credentials and candidates before VRESTART, and what went on after it */
static gchar *a_vufrag0, *b_vufrag0;
static gint shm_before_vrestart, shm_after_vrestart, audio_before_vrestart, audio_after_vrestart;
static guint vrestart_gap;   /* ticks the video took to come back */

/* the frames A's receive sink (audio) got: the call's audio goes on */
static gint audio_bufs(void)
{
	GHashTableIter hi;
	gpointer k, v;
	gint n = 0;
	g_mutex_lock(&counts_lock);
	g_hash_table_iter_init(&hi, counts);
	while (g_hash_table_iter_next(&hi, &k, &v)) n += (gint) GPOINTER_TO_UINT(v);
	g_mutex_unlock(&counts_lock);
	return n;
}

static void side_forget_video(Side *s, gchar **old)
{
	g_free(*old);
	*old = s->vufrag;
	s->vufrag = NULL;
	g_free(s->vpwd); s->vpwd = NULL;
	g_string_truncate(s->vcands, 0);
}

static void side_send_vcands(Side *to, const Side *from)
{
	gchar **cl = g_strsplit(from->vcands->str, "\n", -1);
	int i;
	for (i = 0; cl[i]; i++) if (*cl[i]) side_send(to, "VRCAND %s\n", cl[i]);
	g_strfreev(cl);
}

/* ---- the test ---- */
static Side A, B, C, D;
static int step;
static guint ticks;
static PurpleAccount *test_account;

static gboolean tick(gpointer u)
{
	(void) u;
	ticks++;
	probe_sinks();
	switch (step) {
	case 0:   /* A places the call, with video */
		side_send(&A, "START 102\n");
		side_send(&A, "VSTART\n");
		step = 1;
		break;
	case 1:   /* A's offer is complete: B answers it, video too (the same key: our m-lines share it) */
		if (A.gathered && A.txkey && A.ufrag && A.pwd && A.vufrag && A.vpwd) {
			side_send(&B, "START %s %s %s 102\n", A.txkey, A.ufrag, A.pwd);
			side_send(&B, "VSTART %s %s %s\n", A.txkey, A.vufrag, A.vpwd);
			side_send_cands(&B, &A);
			step = 2;
		}
		break;
	case 2:   /* B's answer is complete: A takes it */
		if (B.gathered && B.txkey && B.ufrag && B.pwd && B.vufrag && B.vpwd) {
			side_send(&A, "ANSWER %s %s %s\n", B.txkey, B.ufrag, B.pwd);
			side_send(&A, "VANSWER %s %s %s\n", B.txkey, B.vufrag, B.vpwd);
			side_send_cands(&A, &B);
			side_send(&A, "VIDEO 1 320 240 300\n");
			step = 3; ticks = 0;
		}
		break;
	case 3:   /* let audio and video run for 8 s, then VIDEO 1 and a RESTART */
		if (ticks == 3) side_send(&A, "VIDEO 0\n");                 /* 10 */
		if (ticks == 4) { side_send(&A, "VIDEO 1 320 240 300\n"); vout_at_toggle = g_atomic_int_get(&vout_bufs); }
		if (ticks == 9) vout_after_toggle = g_atomic_int_get(&vout_bufs);
		if (ticks == 10) side_send(&B, "VIDEO 1 640 480 800\n");
		if (ticks >= 16) {
			ssrc_a_ok = session_sends_ssrc(A.ssrc);
			ssrc_b_ok = session_sends_ssrc(B.ssrc);
			step = 30; ticks = 0;
		}
		break;
	case 30:   /* 8: the far side (B) moves its video to new ICE */
		shm_before_vrestart = g_atomic_int_get(&shm_bufs);
		audio_before_vrestart = audio_bufs();
		side_send(&B, "VRESTART %s %s %s\n", A.txkey, A.vufrag, A.vpwd);
		side_forget_video(&B, &b_vufrag0);
		step = 31; ticks = 0;
		break;
	case 31:   /* its offer is complete: A replaces its video session for it */
		if (B.vrestarted == 1 && B.vufrag && B.vpwd && B.vcands->len) {
			side_send(&A, "VRESTART %s %s %s\n", B.txkey, B.vufrag, B.vpwd);
			side_send_vcands(&A, &B);
			side_forget_video(&A, &a_vufrag0);
			step = 32; ticks = 0;
		}
		break;
	case 32:   /* A's answer is complete: B takes it */
		if (A.vrestarted == 1 && A.vufrag && A.vpwd && A.vcands->len) {
			side_send(&B, "VANSWER %s %s %s\n", A.txkey, A.vufrag, A.vpwd);
			side_send_vcands(&B, &A);
			shm_after_vrestart = g_atomic_int_get(&shm_bufs);
			step = 33; ticks = 0;
		}
		break;
	case 33:   /* video again, for up to 10 s, then the RESTART of 3 */
		if (!vrestart_gap && g_atomic_int_get(&shm_bufs) > shm_after_vrestart + 30) vrestart_gap = ticks;
		if (vrestart_gap ? ticks >= vrestart_gap + 4 : ticks >= 20) {
			audio_after_vrestart = audio_bufs();
			side_send(&B, "VIDEO 0\n");
			step = 34; ticks = 0;
		}
		break;
	case 34:   /* 9: B's camera is off; A's camera source fails */
		if (B.vtx_off == 1 || ticks >= 6) {
			GstElement *cam = running_camera();
			if (cam) {
				GError *err = g_error_new_literal(GST_RESOURCE_ERROR, GST_RESOURCE_ERROR_BUSY, "pmtest: camera taken");
				cam_error_posted = gst_element_post_message(cam, gst_message_new_error(GST_OBJECT(cam), err, "pmtest"));
				g_error_free(err);
				gst_object_unref(cam);
			}
			audio_at_cam_error = audio_bufs();
			step = 35; ticks = 0;
		}
		break;
	case 35:   /* the call goes on: then the RESTART of 3 */
		if (ticks >= 6) {
			audio_after_cam_error = audio_bufs();
			side_send(&B, "RESTART - x y\n"); step = 4; ticks = 0;
		}
		break;
	case 4:   /* a third engine with a bad key */
		if (ticks >= 2) {
			side_start(&C, "C", test_account, FALSE);
			side_send(&C, "START AAAA uf pw 102\n");
			step = 5; ticks = 0;
		}
		break;
	case 5:   /* a fourth engine, with a STUN server */
		if (ticks >= 4) {
			side_start(&D, "D", test_account, TRUE);
			side_send(&D, "RELAY stun 127.0.0.1 3478\n");
			side_send(&D, "START 102\n");
			step = 6; ticks = 0;
		}
		break;
	case 6:
		if (D.txkey || ticks >= 10) { g_main_loop_quit(loop); return G_SOURCE_REMOVE; }
		break;
	}
	if (ticks > 120) { fprintf(stderr, "timed out at step %d\n", step); g_main_loop_quit(loop); return G_SOURCE_REMOVE; }
	return G_SOURCE_CONTINUE;
}

/* PMTEST_ABORT_ON=<text>: abort on a log message holding it, for a stack under ASan
 * (handle_abort=1) or a core; every other message goes out as usual. */
static GLogWriterOutput abort_on_writer(GLogLevelFlags level, const GLogField *f, gsize n, gpointer u)
{
	gsize i;
	for (i = 0; i < n; i++)
		if (!strcmp(f[i].key, "MESSAGE") && f[i].length < 0 && strstr(f[i].value, (const char *) u)) {
			g_log_writer_default(level, f, n, NULL);
			abort();
		}
	return g_log_writer_default(level, f, n, NULL);
}

int main(int argc, char **argv)
{
	gchar *home = g_build_filename(g_get_current_dir(), "pmtest-home", NULL);
	GHashTableIter hi;
	gpointer k, v;
	guint sinks = 0, fed = 0;
	(void) argc; (void) argv;

	if (g_getenv("PMTEST_ABORT_ON"))
		g_log_set_writer_func(abort_on_writer, g_strdup(g_getenv("PMTEST_ABORT_ON")), g_free);
	if (!g_getenv("TEAMS_PMEDIA_SINK")) { fprintf(stderr, "set TEAMS_PMEDIA_SRC/TEAMS_PMEDIA_SINK\n"); return 2; }
	counts = g_hash_table_new(NULL, NULL);
	sess_seen = g_hash_table_new(NULL, NULL);
	nice_seen = g_hash_table_new(NULL, NULL);
	purple_util_set_user_dir(home);
	purple_debug_set_enabled(g_getenv("PMTEST_DEBUG") != NULL);
	purple_eventloop_set_ui_ops(&loop_ops);
	if (g_getenv("PMTEST_H264_CLIP")) {
		gst_init(NULL, NULL);
		if (!clip_load(g_getenv("PMTEST_H264_CLIP")) ||
		    !gst_plugin_register_static(GST_VERSION_MAJOR, GST_VERSION_MINOR, "pmtestenc", "pmtest H264 clip",
		                                pm_test_enc_plugin_init, "1.0", "LGPL", "pmtest", "pmtest", "pmtest")) {
			fprintf(stderr, "cannot load %s\n", g_getenv("PMTEST_H264_CLIP"));
			return 2;
		}
	}
	if (!purple_core_init("pmtest")) { fprintf(stderr, "purple_core_init failed\n"); return 2; }
	test_account = purple_account_new("pmtest@localhost", "prpl-pmtest");
	/* not added to the account list: without its protocol plugin, libpurple cannot destroy it
	 * cleanly (purple_presence_destroy), so it is left for the process exit */
	loop = g_main_loop_new(NULL, FALSE);

	side_start(&A, "A", test_account, TRUE);
	side_start(&B, "B", test_account, FALSE);
	g_timeout_add(500, tick, NULL);
	g_main_loop_run(loop);

	fprintf(stderr, "--- results\n");
	if (getenv("PMTEST_NICE")) fprintf(stderr, "nicesrc: %d buffers, %d buffer lists\n", n_bufs, n_lists);
	CHECK(A.ready && A.gathered && A.txkey && A.ufrag && A.pwd && A.cands->len);
	CHECK(B.ready && B.gathered && B.txkey && B.ufrag && B.pwd && B.cands->len);
	CHECK(A.answered);
	CHECK(A.ssrc && B.ssrc && A.ssrc != B.ssrc);   /* each its own session's */
	CHECK(ssrc_a_ok && ssrc_b_ok);                  /* and what they really send with */
	CHECK(A.audiod && B.audiod);
	g_mutex_lock(&counts_lock);
	g_hash_table_iter_init(&hi, counts);
	while (g_hash_table_iter_next(&hi, &k, &v)) {
		sinks++;
		fprintf(stderr, "sink %s: %u buffers\n", GST_OBJECT_NAME(k), GPOINTER_TO_UINT(v));
		if (GPOINTER_TO_UINT(v) > 50) fed++;
	}
	g_mutex_unlock(&counts_lock);
	CHECK(sinks == 2);            /* A's and B's receive sink */
	CHECK(fed == 2);              /* audio both ways, decrypted and decoded */
	CHECK(B.errs == 1 && B.last_err && strstr(B.last_err, "restart"));
	CHECK(!B.closed && !A.closed);
	CHECK(A.errs == 0);
	CHECK(C.errs >= 1 && C.closed);
	CHECK(D.txkey && D.errs == 0 && !D.closed);
	/* 7: video */
	CHECK(A.vufrag && A.vpwd && A.vcands->len && B.vufrag && B.vpwd && B.vcands->len);
	CHECK(g_strcmp0(A.vufrag, A.ufrag) && g_strcmp0(B.vufrag, B.ufrag));   /* streams of their own */
	CHECK(A.vcreds_before_ready && B.vcreds_before_ready);                 /* READY waited for them */
	CHECK(A.vssrc && B.vssrc && A.vssrc != A.ssrc && B.vssrc != B.ssrc);
	fprintf(stderr, "B video: shm %s, %d frames published, stats: %s\n", B.vshm ? B.vshm : "-",
	        g_atomic_int_get(&shm_bufs), B.stats ? B.stats : "-");
	fprintf(stderr, "feedback seen: %d REMB, %d PLI\n", g_atomic_int_get(&remb_seen), g_atomic_int_get(&pli_seen));
	CHECK(B.vshm && g_file_test(B.vshm, G_FILE_TEST_EXISTS));
	CHECK(B.peervideo);
	CHECK(g_atomic_int_get(&shm_bufs) > 30);
	CHECK(stat_field(&B, "vrx") > 50 && stat_field(&B, "vdec") > 30);
	CHECK(stat_field(&B, "vremb") > 2 && g_atomic_int_get(&remb_seen) > 2);
	/* the audio stats count the audio jitterbuffer only, not the video session's next to it */
	CHECK(stat_field(&B, "jb_pushed") > 0 && stat_field(&B, "jb_pushed") <= stat_field(&B, "rx") + 25);
	/* our camera */
	fprintf(stderr, "camera: A vtxf=%ld, B vtxf=%ld, %d self-view frames; previews A %s, B %s\n",
	        stat_field(&A, "vtxf"), stat_field(&B, "vtxf"), g_atomic_int_get(&preview_bufs),
	        A.vpreview ? A.vpreview : "-", B.vpreview ? B.vpreview : "-");
	CHECK(A.vcamera && B.vcamera);
	CHECK(!A.vtx_err && !B.vtx_err);
	CHECK(A.vtx_on == 3 && B.vtx_on == 2);   /* on, (A: on again, 10), and on in the new session (8) */
	CHECK(A.vtx_off == 2 && B.vtx_off == 1);  /* A's: 10, and the camera error of 9 */
	fprintf(stderr, "camera off and on: %d frames out of the heads, %d at VIDEO 1, %d 2.5 s later\n",
	        g_atomic_int_get(&vout_bufs), vout_at_toggle, vout_after_toggle);
	CHECK(vout_after_toggle > vout_at_toggle + 15);   /* 10 */
	CHECK(A.peervideo && A.vshm);            /* B's camera reached A */
	CHECK(A.vpreview && B.vpreview && g_strcmp0(A.vpreview, B.vpreview));
	CHECK(g_atomic_int_get(&preview_bufs) > 30);
	CHECK(stat_field(&A, "vtxf") > 30 && stat_field(&B, "vtxf") > 30);
	/* our H264 goes with the SSRC VSSRC announced: Teams forwards video by it */
	fprintf(stderr, "video SSRC: A sends %u, announced %u; B sends %u, announced %u\n", stat_u32(&A, "vtxssrc"),
	        A.vssrc, stat_u32(&B, "vtxssrc"), B.vssrc);
	CHECK(A.vssrc && stat_u32(&A, "vtxssrc") == A.vssrc);
	CHECK(B.vssrc && stat_u32(&B, "vtxssrc") == B.vssrc);
	/* SPS and PPS go with every keyframe, not once only: B sent several keyframes in 8 (the
	 * first can go before the engine counts RTP: its probe is put on at the next tick) */
	fprintf(stderr, "B: %ld keyframes, %ld RTP packets with an SPS; PLI %ld\n", stat_field(&B, "vtxk"),
	        stat_field(&B, "vtxsps"), stat_field(&A, "vrpli"));
	CHECK(stat_field(&B, "vtxk") > 2 && stat_field(&B, "vtxsps") + 1 >= stat_field(&B, "vtxk"));
	/* packets small enough for Teams' relays: 1200 bytes at most */
	fprintf(stderr, "largest video RTP packet: A %ld, B %ld bytes\n", stat_field(&A, "vtxmax"), stat_field(&B, "vtxmax"));
	CHECK(stat_field(&B, "vtxmax") > 1000 && stat_field(&B, "vtxmax") <= 1200);
	/* 8: VRESTART */
	fprintf(stderr, "VRESTART: shm frames %d before, %d at the answer, %d at the end (back after %u ticks); "
	        "audio buffers %d -> %d\n", shm_before_vrestart, shm_after_vrestart, g_atomic_int_get(&shm_bufs),
	        vrestart_gap, audio_before_vrestart, audio_after_vrestart);
	CHECK(A.vrestarted == 1 && B.vrestarted == 1);
	CHECK(A.vufrag && B.vufrag && a_vufrag0 && b_vufrag0);
	CHECK(g_strcmp0(A.vufrag, a_vufrag0) && g_strcmp0(B.vufrag, b_vufrag0));   /* new ICE */
	CHECK(A.vcands->len && B.vcands->len);
	CHECK(vrestart_gap > 0);                                                   /* video again */
	CHECK(audio_after_vrestart > audio_before_vrestart + 100);                 /* audio went on */
	/* 9: a camera error */
	fprintf(stderr, "camera error: posted %d, audio buffers %d -> %d\n", cam_error_posted,
	        audio_at_cam_error, audio_after_cam_error);
	CHECK(cam_error_posted);
	CHECK(A.cam_err && !B.cam_err);
	CHECK(audio_after_cam_error > audio_at_cam_error + 100);

	side_send(&A, "STOP\n");
	side_free(&A);
	side_free(&B);
	side_free(&C);
	side_free(&D);
	purple_core_quit();
	g_main_loop_unref(loop);
	{
		/* a probe still left on a sink finds no table from here on */
		GHashTable *t;
		g_mutex_lock(&counts_lock);
		t = counts;
		counts = NULL;
		g_mutex_unlock(&counts_lock);
		g_hash_table_iter_init(&hi, t);
		while (g_hash_table_iter_next(&hi, &k, NULL)) gst_object_unref(k);
		g_hash_table_destroy(t);
	}
	if (clip_aus) g_ptr_array_unref(clip_aus);
	if (clip_avcc) g_bytes_unref(clip_avcc);
	g_free(home);
	g_free(a_vufrag0); g_free(b_vufrag0);
	if (rtp_dump) fclose(rtp_dump);
	if (failures) { fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	printf("PASS test_pmedia_loopback\n");
	return 0;
}
