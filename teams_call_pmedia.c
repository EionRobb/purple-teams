/* The in-process media engine for 1:1 calls: PurpleMedia (libpurple's Farstream backend) behind
 * teams_media's line protocol (see teams_call_pmedia.h and teams_media.c's header).
 *
 * What it does with the commands:
 *   RELAY stun <host> <port>   resolves the name (asynchronously; later commands wait for it),
 *                              given to Farstream's nice transmitter as stun-ip/stun-port
 *   START <rxkey> <ufrag> <pwd> <pt>  (answering) / START [pt] (placing the call)
 *                              one "audio" session to one participant over ICE (RFC 5245, UDP
 *                              only), RTCP muxed on the RTP component, Opus on the given PT,
 *                              SRTP AEAD_AES_256_GCM both ways: our key random, theirs from the
 *                              offer's a=crypto (SDES, the way teams_media keys)
 *   ANSWER <rxkey> <ufrag> <pwd>  (placing the call) the far side's key and ICE credentials
 *   RCAND <candidate:...>      a remote candidate; only UDP ones on component 1 are used, as the
 *                              far side muxes RTCP
 *   RESTART ...                answered ERR: an ICE restart needs a new nice stream, which
 *                              PurpleMedia does not offer
 *   VIDEO ...                  ignored: this engine has no video, and says so by never printing
 *                              VSSRC (teams_calling.c then declines the video m-line)
 *   STOP, or the command socket closing: the media ends
 * and what it prints: TXKEY at START, UFRAG/PWD/SSRC and READY once the first local candidate is
 * there (libnice gives every candidate of a stream the same credentials), CAND for each local
 * UDP candidate of component 1, GATHERED when Farstream has all of them, AUDIOD 1 when ICE has a
 * pair, ERR for failures. A failure that loses the media closes the output socket, which
 * teams_calling.c takes as the engine having stopped.
 *
 * Audio goes through PulseAudio's call devices, as teams_media's does: capture from webcall,
 * playback to voipcall (palm-policy routes those for a call). */

#include "teams_call_pmedia.h"
#include "teams_call_sdp.h"

#include <debug.h>
#include <media.h>
#include <mediamanager.h>
#include <media-gst.h>

#include <gio/gio.h>
#include <gmodule.h>
#include <gst/gst.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#define PM_SESSION   "audio"
#define PM_PEER      "teams-peer"
#define PM_CIPHER    "aes-256-gcm"
#define PM_AUTH      "null"           /* AEAD: the cipher authenticates */
#define PM_KEY_LEN   44               /* AES-256 key + 96-bit salt (RFC 7714) */
#define PM_OPUS_RATE 48000
#define PM_PLAYBACK_DEVICE "voipcall"
#define PM_CAPTURE_DEVICE  "webcall"
#define PM_SRC_ID  "teams-pulsesrc"
#define PM_SINK_ID "teams-pulsesink"

struct _TeamsPMedia {
	PurpleAccount *account;
	gboolean       caller;
	int            cmd_fd, out_fd;
	GIOChannel    *cmd_ch;
	guint          cmd_watch;
	GString       *inbuf;          /* command bytes not yet ended by a newline */
	GString       *outq;           /* output not yet written (the pipe was full) */
	guint          out_watch;
	gboolean       stopped;        /* STOP, EOF or a fatal error: no more commands */

	PurpleMedia   *media;          /* NULL until START, and once ended */
	GCancellable  *resolving;      /* a STUN name lookup in flight */
	GQueue         held;           /* command lines that came in during it */
	gchar         *stun_ip;
	guint          stun_port;

	int            pt;
	guchar         txkey[PM_KEY_LEN];
	gchar         *ruf, *rpw;      /* the far side's ICE credentials */
	GList         *rcands_held;    /* PurpleMediaCandidate: before the credentials were known */
	gboolean       creds_sent, ready_sent, gathered, paired;
	guint          ssrc;           /* what our SDP declares (the SSRC line); 0 = none */
	guint          ssrc_check;
	guint          ssrc_poll;      /* waiting for our first RTP packet, which carries the SSRC */
	guint          ssrc_waited_ms;
	struct PmWire *wire;           /* shared with the pad probe that sees that packet */
	GstPad        *wire_pad;
	gulong         wire_probe;
	GHashTable    *other_sessions; /* rtpsession elements that were there before our stream */
	GstElement    *rtpsession;     /* ours, once found (a weak pointer) */
	guint          stats_timer;    /* the STATS line every PM_STATS_SECONDS */
	gint64         stats_t0;
	gdouble        mic_max;        /* loudest send level (RMS, 0-1) since the last STATS line */
};

/* libpurple's media-gst.h calls, looked up when first needed: a libpurple built without voice
 * and video (USE_VV) does not have them at all, and the plug-in has to load there too (and use
 * teams_media). The rest of the media API is in every libpurple 2, as stubs without USE_VV. */
static struct {
	gboolean     looked_up, ok;
	GType      (*element_info_get_type)(void);
	gboolean   (*register_element)(PurpleMediaManager *, PurpleMediaElementInfo *);
	gboolean   (*set_active_element)(PurpleMediaManager *, PurpleMediaElementInfo *);
	GstElement *(*get_pipeline)(PurpleMediaManager *);
} pm_vv;

static gboolean
pm_vv_available(void)
{
	GModule *self;
	if (pm_vv.looked_up) return pm_vv.ok;
	pm_vv.looked_up = TRUE;
	self = g_module_open(NULL, G_MODULE_BIND_LAZY);
	if (!self) return FALSE;
	pm_vv.ok = g_module_symbol(self, "purple_media_element_info_get_type", (gpointer *) &pm_vv.element_info_get_type) &&
	           g_module_symbol(self, "purple_media_manager_register_element", (gpointer *) &pm_vv.register_element) &&
	           g_module_symbol(self, "purple_media_manager_set_active_element", (gpointer *) &pm_vv.set_active_element) &&
	           g_module_symbol(self, "purple_media_manager_get_pipeline", (gpointer *) &pm_vv.get_pipeline);
	g_module_close(self);
	return pm_vv.ok;
}

static void pm_handle_line(TeamsPMedia *pm, gchar *line);
static void pm_wire_stop(TeamsPMedia *pm);
static void pm_stats_emit(TeamsPMedia *pm);
static guint pm_find_ssrc(TeamsPMedia *pm);

static void
pm_log(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
static void
pm_log(const char *fmt, ...)
{
	va_list ap;
	gchar *s;
	va_start(ap, fmt);
	s = g_strdup_vprintf(fmt, ap);
	va_end(ap);
	purple_debug_info("teams", "call: purplemedia: %s\n", s);
	g_free(s);
}

/* ---- output -------------------------------------------------------------------------------- */

static void pm_flush(TeamsPMedia *pm);

static gboolean
pm_out_ready(GIOChannel *ch, GIOCondition cond, gpointer u)
{
	TeamsPMedia *pm = u;
	(void) ch; (void) cond;
	pm->out_watch = 0;
	pm_flush(pm);
	return G_SOURCE_REMOVE;
}

/* Write what is queued; what the pipe does not take now waits for it to drain. The out fd is
 * non-blocking, as its reader runs on this same main loop. */
static void
pm_flush(TeamsPMedia *pm)
{
	while (pm->out_fd >= 0 && pm->outq->len) {
		ssize_t n = send(pm->out_fd, pm->outq->str, pm->outq->len, MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (!pm->out_watch) {
				GIOChannel *ch = g_io_channel_unix_new(pm->out_fd);
				pm->out_watch = g_io_add_watch(ch, G_IO_OUT | G_IO_ERR | G_IO_HUP, pm_out_ready, pm);
				g_io_channel_unref(ch);
			}
			return;
		}
		if (n <= 0) {
			pm_log("output: %s", n < 0 ? g_strerror(errno) : "closed");
			close(pm->out_fd);
			pm->out_fd = -1;
			break;
		}
		g_string_erase(pm->outq, 0, n);
	}
	if (pm->out_fd < 0 && pm->outq->len) {
		explicit_bzero(pm->outq->str, pm->outq->len);
		g_string_truncate(pm->outq, 0);
	}
}

static void pm_emit(TeamsPMedia *pm, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
static void
pm_emit(TeamsPMedia *pm, const char *fmt, ...)
{
	va_list ap;
	gchar *s;
	if (pm->out_fd < 0) return;
	va_start(ap, fmt);
	s = g_strdup_vprintf(fmt, ap);
	va_end(ap);
	g_string_append(pm->outq, s);
	explicit_bzero(s, strlen(s));    /* TXKEY */
	g_free(s);
	pm_flush(pm);
}

/* ---- media teardown ------------------------------------------------------------------------- */

static void
pm_free_held_cands(TeamsPMedia *pm)
{
	g_list_free_full(pm->rcands_held, g_object_unref);
	pm->rcands_held = NULL;
}

static void
pm_end_media(TeamsPMedia *pm)
{
	PurpleMedia *media = pm->media;
	if (pm->stats_timer) {
		g_source_remove(pm->stats_timer);
		pm->stats_timer = 0;
		pm_stats_emit(pm);     /* the call's last numbers */
	}
	if (pm->ssrc_check) { g_source_remove(pm->ssrc_check); pm->ssrc_check = 0; }
	pm_wire_stop(pm);
	if (pm->rtpsession) {
		g_object_remove_weak_pointer(G_OBJECT(pm->rtpsession), (gpointer *) &pm->rtpsession);
		pm->rtpsession = NULL;
	}
	if (pm->other_sessions) { g_hash_table_destroy(pm->other_sessions); pm->other_sessions = NULL; }
	if (!media) return;
	g_signal_handlers_disconnect_matched(media, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, pm);
	/* purple_media_end() drops the media's last reference once it has no sessions left, which
	 * is not so if adding the stream failed: then it is dropped here. */
	g_object_add_weak_pointer(G_OBJECT(media), (gpointer *) &pm->media);
	purple_media_end(media, NULL, NULL);
	if (pm->media) {
		g_object_remove_weak_pointer(G_OBJECT(media), (gpointer *) &pm->media);
		pm->media = NULL;
		g_object_unref(media);
	}
	pm_log("media ended");
}

/* Stop taking commands. */
static void
pm_stop_input(TeamsPMedia *pm)
{
	pm->stopped = TRUE;
	if (pm->cmd_watch) { g_source_remove(pm->cmd_watch); pm->cmd_watch = 0; }
	if (pm->resolving) { g_cancellable_cancel(pm->resolving); g_clear_object(&pm->resolving); }
	{
		gchar *l;
		while ((l = g_queue_pop_head(&pm->held))) { explicit_bzero(l, strlen(l)); g_free(l); }
	}
}

/* The media is lost: say why, end it and close the output, which ends the call. */
static void
pm_fatal(TeamsPMedia *pm, const char *why)
{
	pm_log("fatal: %s", why);
	pm_emit(pm, "ERR %s\n", why);
	pm_stop_input(pm);
	pm_end_media(pm);
	if (pm->out_fd >= 0 && !pm->outq->len) { close(pm->out_fd); pm->out_fd = -1; }
}

/* ---- statistics ---------------------------------------------------------------------------- */

/* Every PM_STATS_SECONDS a STATS line in the form teams_media prints too (tm_stats_line in
 * teams_media.c), so the two engines can be compared on real calls:
 *   STATS t=<s> tx=<RTP packets sent> rx=<RTP packets received> jb_pushed= jb_lost= jb_late=
 *         jb_dup= jb_jitter_us= (the audio jitterbuffers' own counts) peer_lost= peer_frac=
 *         (the far side's last RTCP report about our audio; -1 = none yet) rtt_ms= (from that
 *         report; -1 = none) mic_rms= (loudest send level in the interval, 0-1)
 * From our RTP session's source statistics and the jitterbuffers next to it in its rtpbin. */
#define PM_STATS_SECONDS 5

static void
pm_jb_add(GstElement *jb, guint64 *v)
{
	GstStructure *st = NULL;
	guint64 x;
	g_object_get(jb, "stats", &st, NULL);
	if (!st) return;
	if (gst_structure_get_uint64(st, "num-pushed", &x)) v[0] += x;
	if (gst_structure_get_uint64(st, "num-lost", &x)) v[1] += x;
	if (gst_structure_get_uint64(st, "num-late", &x)) v[2] += x;
	if (gst_structure_get_uint64(st, "num-duplicates", &x)) v[3] += x;
	if (gst_structure_get_uint64(st, "avg-jitter", &x) && x > v[4]) v[4] = x;   /* ns; the worst */
	gst_structure_free(st);
}

G_GNUC_BEGIN_IGNORE_DEPRECATIONS   /* GValueArray: what rtpsession's source-stats is */
static void
pm_stats_emit(TeamsPMedia *pm)
{
	guint64 tx = 0, rx = 0, jb[5] = { 0, 0, 0, 0, 0 };
	gint peer_lost = -1, peer_frac = -1, rtt_ms = -1;
	GstStructure *st = NULL;
	GstObject *bin;

	if (!pm->rtpsession) pm_find_ssrc(pm);    /* finds our rtpsession */
	if (!pm->rtpsession) return;
	g_object_get(pm->rtpsession, "stats", &st, NULL);
	if (st) {
		const GValue *v = gst_structure_get_value(st, "source-stats");
		GValueArray *a = v && G_VALUE_HOLDS_BOXED(v) ? g_value_get_boxed(v) : NULL;
		guint i;
		for (i = 0; a && i < a->n_values; i++) {
			const GstStructure *ss = gst_value_get_structure(g_value_array_get_nth(a, i));
			gboolean internal = FALSE, have_rb = FALSE;
			guint64 n;
			if (!ss) continue;
			gst_structure_get_boolean(ss, "internal", &internal);
			if (internal) {
				guint frac = 0, rt = 0;
				gint lost = 0;
				if (gst_structure_get_uint64(ss, "packets-sent", &n)) tx += n;
				if (gst_structure_get_boolean(ss, "have-rb", &have_rb) && have_rb &&
				    gst_structure_get_uint(ss, "rb-fractionlost", &frac) &&
				    gst_structure_get_int(ss, "rb-packetslost", &lost)) {
					peer_frac = (gint) frac;
					peer_lost = lost;
					/* 1/65536 s units (RFC 3550 6.4.1) */
					if (gst_structure_get_uint(ss, "rb-round-trip", &rt) && rt)
						rtt_ms = (gint) (((guint64) rt * 1000) >> 16);
				}
			} else if (gst_structure_get_uint64(ss, "packets-received", &n)) {
				rx += n;
			}
		}
		gst_structure_free(st);
	}
	bin = gst_object_get_parent(GST_OBJECT(pm->rtpsession));    /* the rtpbin */
	if (bin && GST_IS_BIN(bin)) {
		GstIterator *it = gst_bin_iterate_elements(GST_BIN(bin));
		GValue v = G_VALUE_INIT;
		gboolean done = FALSE;
		while (!done) {
			switch (gst_iterator_next(it, &v)) {
			case GST_ITERATOR_OK: {
				GstElement *e = g_value_get_object(&v);
				GstElementFactory *f = gst_element_get_factory(e);
				if (f && !strcmp(GST_OBJECT_NAME(f), "rtpjitterbuffer")) pm_jb_add(e, jb);
				g_value_reset(&v);
				break;
			}
			case GST_ITERATOR_RESYNC: gst_iterator_resync(it); break;
			default: done = TRUE; break;
			}
		}
		g_value_unset(&v);
		gst_iterator_free(it);
	}
	if (bin) gst_object_unref(bin);
	pm_emit(pm, "STATS t=%" G_GINT64_FORMAT " tx=%" G_GUINT64_FORMAT " rx=%" G_GUINT64_FORMAT
	        " jb_pushed=%" G_GUINT64_FORMAT " jb_lost=%" G_GUINT64_FORMAT " jb_late=%" G_GUINT64_FORMAT
	        " jb_dup=%" G_GUINT64_FORMAT " jb_jitter_us=%" G_GUINT64_FORMAT
	        " peer_lost=%d peer_frac=%d rtt_ms=%d mic_rms=%.4f\n",
	        (g_get_monotonic_time() - pm->stats_t0) / G_USEC_PER_SEC, tx, rx,
	        jb[0], jb[1], jb[2], jb[3], jb[4] / 1000, peer_lost, peer_frac, rtt_ms, pm->mic_max);
	pm->mic_max = 0;
}
G_GNUC_END_IGNORE_DEPRECATIONS

static gboolean
pm_stats_tick(gpointer u)
{
	pm_stats_emit(u);
	return G_SOURCE_CONTINUE;
}

/* libpurple's level signal: who NULL is our microphone (backend-fs2's sendlevel_), as RMS 0-1 */
static void
pm_on_level(PurpleMedia *media, gchar *sid, gchar *who, double level, gpointer u)
{
	TeamsPMedia *pm = u;
	(void) media; (void) sid;
	if (!who && level > pm->mic_max) pm->mic_max = level;
}

/* ---- audio elements ------------------------------------------------------------------------- */

/* TEAMS_PMEDIA_SRC / TEAMS_PMEDIA_SINK name other GStreamer elements to use (a test runs with
 * audiotestsrc and fakesink, so it is silent); NULL when not set. */
static GstElement *
pm_make_override(const char *env)
{
	const char *f = g_getenv(env);
	GstElement *e;
	if (!f || !*f) return NULL;
	e = gst_element_factory_make(f, NULL);
	if (!e) { pm_log("%s=%s: no such element", env, f); return NULL; }
	if (g_object_class_find_property(G_OBJECT_GET_CLASS(e), "is-live"))
		g_object_set(e, "is-live", TRUE, NULL);
	if (g_object_class_find_property(G_OBJECT_GET_CLASS(e), "sync"))
		g_object_set(e, "sync", FALSE, NULL);
	return e;
}

static GstElement *
pm_make_src(PurpleMedia *media, const gchar *sid, const gchar *who)
{
	GstElement *e = pm_make_override("TEAMS_PMEDIA_SRC");
	(void) media; (void) sid; (void) who;
	if (e) return e;
	e = gst_element_factory_make("pulsesrc", NULL);
	if (!e) return gst_element_factory_make("autoaudiosrc", NULL);
	/* teams_media's capture settings: a 200 ms ring, and not the pipeline's clock */
	g_object_set(e, "device", PM_CAPTURE_DEVICE, "buffer-time", (gint64) 200000,
	             "latency-time", (gint64) 20000, "provide-clock", FALSE, NULL);
	return e;
}

static GstElement *
pm_make_sink(PurpleMedia *media, const gchar *sid, const gchar *who)
{
	GstElement *e = pm_make_override("TEAMS_PMEDIA_SINK");
	(void) media; (void) sid; (void) who;
	if (e) return e;
	e = gst_element_factory_make("pulsesink", NULL);
	if (!e) return gst_element_factory_make("autoaudiosink", NULL);
	g_object_set(e, "device", PM_PLAYBACK_DEVICE, "sync", FALSE, NULL);
	return e;
}

/* Make our PulseAudio elements the media manager's audio source and sink. They are registered
 * once per process; the manager keeps them. */
static void
pm_use_call_devices(PurpleMediaManager *manager)
{
	static PurpleMediaElementInfo *src, *sink;
	if (!src) {
		src = g_object_new(pm_vv.element_info_get_type(), "id", PM_SRC_ID, "name", "Teams call microphone",
		                   "type", PURPLE_MEDIA_ELEMENT_AUDIO | PURPLE_MEDIA_ELEMENT_SRC | PURPLE_MEDIA_ELEMENT_ONE_SRC,
		                   "create-cb", pm_make_src, NULL);
		sink = g_object_new(pm_vv.element_info_get_type(), "id", PM_SINK_ID, "name", "Teams call playback",
		                    "type", PURPLE_MEDIA_ELEMENT_AUDIO | PURPLE_MEDIA_ELEMENT_SINK | PURPLE_MEDIA_ELEMENT_ONE_SINK,
		                    "create-cb", pm_make_sink, NULL);
		if (!pm_vv.register_element(manager, src)) pm_log("could not register the source");
		if (!pm_vv.register_element(manager, sink)) pm_log("could not register the sink");
	}
	pm_vv.set_active_element(manager, src);
	pm_vv.set_active_element(manager, sink);
}

/* ---- our SSRC -------------------------------------------------------------------------------- */

/* Each rtpsession element in libpurple's pipeline (every call's media lives in it), to fn. */
static void
pm_each_rtpsession(void (*fn)(GstElement *e, gpointer u), gpointer u)
{
	GstElement *pipe = pm_vv.ok ? pm_vv.get_pipeline(purple_media_manager_get()) : NULL;
	GstIterator *it;
	GValue v = G_VALUE_INIT;
	gboolean done = FALSE;
	if (!pipe || !GST_IS_BIN(pipe)) return;
	it = gst_bin_iterate_recurse(GST_BIN(pipe));
	while (!done) {
		switch (gst_iterator_next(it, &v)) {
		case GST_ITERATOR_OK: {
			GstElement *e = g_value_get_object(&v);
			GstElementFactory *f = gst_element_get_factory(e);
			if (f && !strcmp(GST_OBJECT_NAME(f), "rtpsession")) fn(e, u);
			g_value_reset(&v);
			break;
		}
		case GST_ITERATOR_RESYNC: gst_iterator_resync(it); break;
		default: done = TRUE; break;
		}
	}
	g_value_unset(&v);
	gst_iterator_free(it);
}

static void
pm_note_session(GstElement *e, gpointer u)
{
	g_hash_table_insert(u, e, e);
}

static void
pm_pick_session(GstElement *e, gpointer u)
{
	TeamsPMedia *pm = u;
	if (pm->rtpsession || g_hash_table_lookup(pm->other_sessions, e)) return;
	pm->rtpsession = e;
	g_object_add_weak_pointer(G_OBJECT(e), (gpointer *) &pm->rtpsession);
}

/* The SSRC our audio goes out with: the internal-ssrc of the RTP session (the rtpsession
 * element's internal-session) Farstream made for our stream - the one that was not in the
 * pipeline before it; Farstream keeps its FsRtpSession's "ssrc" equal to it. 0 if it is not
 * there (yet). */
static guint
pm_find_ssrc(TeamsPMedia *pm)
{
	GObject *sess = NULL;
	guint ssrc = 0;
	if (!pm->rtpsession && pm->other_sessions) pm_each_rtpsession(pm_pick_session, pm);
	if (!pm->rtpsession || !g_object_class_find_property(G_OBJECT_GET_CLASS(pm->rtpsession), "internal-session"))
		return 0;
	g_object_get(pm->rtpsession, "internal-session", &sess, NULL);
	if (sess && g_object_class_find_property(G_OBJECT_GET_CLASS(sess), "internal-ssrc"))
		g_object_get(sess, "internal-ssrc", &ssrc, NULL);
	if (sess) g_object_unref(sess);
	return ssrc;
}

/* What the streaming thread's pad probe saw, for the main loop: the SSRC of our first RTP
 * packet. Reference-counted, as the probe may still run while the engine is being freed. */
struct PmWire {
	gint refs;
	gint ssrc_seen;     /* 0 until set */
	guint ssrc;
};

static struct PmWire *
pm_wire_ref(struct PmWire *w)
{
	g_atomic_int_inc(&w->refs);
	return w;
}

static void
pm_wire_unref(gpointer p)
{
	struct PmWire *w = p;
	if (w && g_atomic_int_dec_and_test(&w->refs)) g_free(w);
}

static GstPadProbeReturn
pm_wire_probe(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	struct PmWire *w = u;
	GstBuffer *b = GST_PAD_PROBE_INFO_BUFFER(info);
	guint8 h[12];
	(void) pad;
	/* RTP version 2, then the SSRC at bytes 8-11 (RFC 3550 5.1) */
	if (!b || gst_buffer_extract(b, 0, h, sizeof h) != sizeof h || (h[0] >> 6) != 2)
		return GST_PAD_PROBE_OK;
	w->ssrc = ((guint) h[8] << 24) | ((guint) h[9] << 16) | ((guint) h[10] << 8) | h[11];
	g_atomic_int_set(&w->ssrc_seen, 1);
	return GST_PAD_PROBE_REMOVE;
}

static void
pm_wire_stop(TeamsPMedia *pm)
{
	if (pm->ssrc_poll) { g_source_remove(pm->ssrc_poll); pm->ssrc_poll = 0; }
	if (pm->wire_pad) {
		if (pm->wire_probe) gst_pad_remove_probe(pm->wire_pad, pm->wire_probe);
		gst_object_unref(pm->wire_pad);
		pm->wire_pad = NULL;
		pm->wire_probe = 0;
	}
	pm_wire_unref(pm->wire);
	pm->wire = NULL;
}

static void pm_maybe_ready(TeamsPMedia *pm);
static gboolean pm_ssrc_recheck(gpointer u);

#define PM_SSRC_POLL_MS 50
#define PM_SSRC_WAIT_MS 2000

/* Until our first RTP packet has gone into the RTP session: find the session's send pad, watch it,
 * and take the SSRC the packet has. The session's own internal-ssrc is not it - it takes the
 * payloader's random one once audio flows - so the SDP declares the packet's. Without a packet
 * in PM_SSRC_WAIT_MS, the SDP goes out without one. */
static gboolean
pm_ssrc_poll(gpointer u)
{
	TeamsPMedia *pm = u;
	pm->ssrc_waited_ms += PM_SSRC_POLL_MS;
	if (!pm->wire_pad) {
		pm_find_ssrc(pm);    /* finds our rtpsession */
		if (pm->rtpsession) {
			GstPad *p = gst_element_get_static_pad(pm->rtpsession, "send_rtp_src");
			if (p) {
				pm->wire_pad = p;
				pm->wire_probe = gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER, pm_wire_probe,
				                                   pm_wire_ref(pm->wire), pm_wire_unref);
			}
		}
	}
	if (g_atomic_int_get(&pm->wire->ssrc_seen)) {
		pm->ssrc = pm->wire->ssrc;
		pm->ssrc_poll = 0;
		pm->wire_probe = 0;    /* it removed itself */
		pm_wire_stop(pm);
		pm_log("our SSRC %u (from our first RTP packet, after %u ms)", pm->ssrc, pm->ssrc_waited_ms);
		pm_maybe_ready(pm);
		return G_SOURCE_REMOVE;
	}
	if (pm->ssrc_waited_ms >= PM_SSRC_WAIT_MS) {
		pm->ssrc_poll = 0;
		pm_wire_stop(pm);
		pm_log("no RTP packet of ours after %u ms: the SDP goes out without our SSRC", pm->ssrc_waited_ms);
		pm_maybe_ready(pm);
		return G_SOURCE_REMOVE;
	}
	return G_SOURCE_CONTINUE;
}

/* READY once our ICE credentials are out and our SSRC is known or waited for. */
static void
pm_maybe_ready(TeamsPMedia *pm)
{
	if (pm->ready_sent || !pm->creds_sent || pm->ssrc_poll) return;
	if (pm->ssrc) pm_emit(pm, "SSRC %u\n", pm->ssrc);
	pm->ready_sent = TRUE;
	pm_emit(pm, "READY\n");
	if (pm->paired && pm->ssrc && !pm->ssrc_check)   /* ICE paired before the SSRC was known */
		pm->ssrc_check = g_timeout_add_seconds(5, pm_ssrc_recheck, pm);
}

/* A few seconds into the call: has the session's SSRC moved off what our SDP declared? */
static gboolean
pm_ssrc_recheck(gpointer u)
{
	TeamsPMedia *pm = u;
	guint now = pm_find_ssrc(pm);
	pm->ssrc_check = 0;
	if (now != pm->ssrc) pm_log("SSRC is now %u, the SDP declared %u", now, pm->ssrc);
	else pm_log("SSRC %u as declared", now);
	return G_SOURCE_REMOVE;
}

/* ---- media signals ------------------------------------------------------------------------- */

static const char *
pm_cand_type(PurpleMediaCandidateType t)
{
	switch (t) {
	case PURPLE_MEDIA_CANDIDATE_TYPE_HOST:  return "host";
	case PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX: return "srflx";
	case PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX: return "prflx";
	case PURPLE_MEDIA_CANDIDATE_TYPE_RELAY: return "relay";
	default:                                return NULL;
	}
}

static void
pm_on_new_candidate(PurpleMedia *media, gchar *sid, gchar *who, PurpleMediaCandidate *cand, gpointer u)
{
	TeamsPMedia *pm = u;
	TeamsIceCand c;
	const char *type = pm_cand_type(purple_media_candidate_get_candidate_type(cand));
	gchar *foundation, *ip, *base_ip, *line;
	(void) media; (void) sid; (void) who;

	if (purple_media_candidate_get_component_id(cand) != PURPLE_MEDIA_COMPONENT_RTP ||
	    purple_media_candidate_get_protocol(cand) != PURPLE_MEDIA_NETWORK_PROTOCOL_UDP || !type)
		return;   /* RTCP is muxed; Teams' parser rejects an answer over TCP lines */
	if (!pm->creds_sent) {
		gchar *uf = purple_media_candidate_get_username(cand);
		gchar *pw = purple_media_candidate_get_password(cand);
		if (!uf || !pw || !*uf || !*pw) {
			g_free(uf); g_free(pw);
			pm_fatal(pm, "local candidate without ICE credentials");
			return;
		}
		pm_emit(pm, "UFRAG %s\nPWD %s\n", uf, pw);
		g_free(uf); g_free(pw);
		pm->creds_sent = TRUE;
		pm_maybe_ready(pm);
	}
	memset(&c, 0, sizeof c);
	foundation = purple_media_candidate_get_foundation(cand);
	ip = purple_media_candidate_get_ip(cand);
	base_ip = purple_media_candidate_get_base_ip(cand);
	g_strlcpy(c.foundation, foundation ? foundation : "1", sizeof c.foundation);
	c.component = 1;
	c.udp = TRUE;
	c.priority = purple_media_candidate_get_priority(cand);
	g_strlcpy(c.ip, ip ? ip : "", sizeof c.ip);
	c.port = purple_media_candidate_get_port(cand);
	g_strlcpy(c.type, type, sizeof c.type);
	if (strcmp(type, "host") && base_ip && *base_ip) {
		g_strlcpy(c.raddr, base_ip, sizeof c.raddr);
		c.rport = purple_media_candidate_get_base_port(cand);
	}
	g_free(foundation); g_free(ip); g_free(base_ip);
	if (!c.ip[0] || !c.port) return;
	line = teams_ice_candidate_format(&c);
	pm_log("local candidate %s", line);
	pm_emit(pm, "CAND %s\n", line);
	g_free(line);
}

static void
pm_on_candidates_prepared(PurpleMedia *media, gchar *sid, gchar *who, gpointer u)
{
	TeamsPMedia *pm = u;
	(void) media; (void) sid; (void) who;
	if (pm->gathered) return;
	pm->gathered = TRUE;
	if (!pm->creds_sent) { pm_fatal(pm, "no local UDP candidates"); return; }
	pm_log("local candidates complete");
	pm_emit(pm, "GATHERED\n");
}

static void
pm_on_pair(PurpleMedia *media, gchar *sid, gchar *who, PurpleMediaCandidate *local,
           PurpleMediaCandidate *remote, gpointer u)
{
	TeamsPMedia *pm = u;
	gchar *lip = purple_media_candidate_get_ip(local), *rip = purple_media_candidate_get_ip(remote);
	(void) media; (void) sid; (void) who;
	pm_log("ICE pair %s:%u <-> %s:%u", lip ? lip : "?", purple_media_candidate_get_port(local),
	       rip ? rip : "?", purple_media_candidate_get_port(remote));
	g_free(lip); g_free(rip);
	if (!pm->paired) {
		pm->paired = TRUE;
		pm_emit(pm, "AUDIOD 1\n");
		if (pm->ssrc && !pm->ssrc_check) pm->ssrc_check = g_timeout_add_seconds(5, pm_ssrc_recheck, pm);
	}
}

static void
pm_on_error(PurpleMedia *media, gchar *msg, gpointer u)
{
	TeamsPMedia *pm = u;
	(void) media;
	pm_log("error: %s", msg ? msg : "?");
	pm_emit(pm, "ERR media: %s\n", msg ? msg : "?");
}

static void
pm_on_state(PurpleMedia *media, PurpleMediaState state, gchar *sid, gchar *who, gpointer u)
{
	TeamsPMedia *pm = u;
	(void) media;
	pm_log("state %d session %s participant %s", (int) state, sid ? sid : "-", who ? who : "-");
	if (state == PURPLE_MEDIA_STATE_END && !sid && !who) {
		/* libpurple ended it on its own (it does not on a call of ours, but if it did) */
		g_signal_handlers_disconnect_matched(pm->media, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, pm);
		pm->media = NULL;    /* it is dropping its last reference */
		pm_fatal(pm, "the media ended");
	}
}

static void
pm_on_codecs(PurpleMedia *media, gchar *sid, gpointer u)
{
	GList *l, *codecs = purple_media_get_codecs(media, sid);
	GString *s = g_string_new("");
	(void) u;
	for (l = codecs; l; l = l->next) {
		gchar *c = purple_media_codec_to_string(l->data);
		g_string_append_printf(s, "%s%s", s->len ? ", " : "", c);
		g_free(c);
	}
	pm_log("codecs: %s", s->str);
	g_string_free(s, TRUE);
	purple_media_codec_list_free(codecs);
}

/* ---- commands -------------------------------------------------------------------------------- */

/* The far side's master key and salt from its base64 (an a=crypto inline value). */
static gboolean
pm_set_rx_key(TeamsPMedia *pm, const char *b64)
{
	gchar *tmp = g_strdup(b64), *bar = strchr(tmp, '|');
	guchar *key;
	gsize len = 0;
	gboolean ok;
	if (bar) *bar = '\0';
	key = g_base64_decode(tmp, &len);
	explicit_bzero(tmp, strlen(tmp));
	g_free(tmp);
	ok = key && len == PM_KEY_LEN &&
	     purple_media_set_decryption_parameters(pm->media, PM_SESSION, PM_PEER, PM_CIPHER, PM_AUTH,
	                                            (const gchar *) key, len);
	if (key) { explicit_bzero(key, len); g_free(key); }
	if (!ok) pm_log("the far side's key was not taken (%u bytes)", (unsigned) len);
	return ok;
}

static void
pm_add_remote_cands(TeamsPMedia *pm, GList *cands)
{
	GList *l;
	for (l = cands; l; l = l->next)
		g_object_set(l->data, "username", pm->ruf, "password", pm->rpw, NULL);
	purple_media_add_remote_candidates(pm->media, PM_SESSION, PM_PEER, cands);
}

static void
pm_set_remote_creds(TeamsPMedia *pm, const char *ruf, const char *rpw)
{
	g_free(pm->ruf); g_free(pm->rpw);
	pm->ruf = g_strdup(ruf); pm->rpw = g_strdup(rpw);
	if (pm->rcands_held && pm->media) {
		pm_add_remote_cands(pm, pm->rcands_held);
		pm_log("%u held remote candidate(s) added", g_list_length(pm->rcands_held));
	}
	pm_free_held_cands(pm);
}

static void
pm_rcand(TeamsPMedia *pm, const char *line)
{
	TeamsIceCand c;
	PurpleMediaCandidateType type;
	PurpleMediaCandidate *pc;
	if (!teams_ice_candidate_parse(line, &c)) { pm_log("remote candidate not understood"); return; }
	if (!c.udp || c.component != 1) return;
	type = !strcmp(c.type, "host")  ? PURPLE_MEDIA_CANDIDATE_TYPE_HOST
	     : !strcmp(c.type, "srflx") ? PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX
	     : !strcmp(c.type, "prflx") ? PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX
	     :                            PURPLE_MEDIA_CANDIDATE_TYPE_RELAY;
	pc = purple_media_candidate_new(c.foundation, PURPLE_MEDIA_COMPONENT_RTP, type,
	                                PURPLE_MEDIA_NETWORK_PROTOCOL_UDP, c.ip, c.port);
	g_object_set(pc, "priority", (guint) c.priority, NULL);
	if (c.raddr[0]) g_object_set(pc, "base-ip", c.raddr, "base-port", c.rport, NULL);
	if (!pm->media || !pm->ruf) {
		pm->rcands_held = g_list_append(pm->rcands_held, pc);
		return;
	}
	{
		GList one = { pc, NULL, NULL };
		pm_add_remote_cands(pm, &one);
	}
	g_object_unref(pc);
}

G_GNUC_BEGIN_IGNORE_DEPRECATIONS
/* Create the media, its audio stream and keys. rxkey/ruf/rpw: the far side's, when answering. */
static void
pm_start(TeamsPMedia *pm, const char *rxkey, const char *ruf, const char *rpw)
{
	PurpleMediaManager *manager = purple_media_manager_get();
	GParameter params[4];
	guint n = 0, i;
	PurpleMediaCodec *opus;
	GList *codecs;
	gboolean ok;
	gchar *tx;

	if (pm->media) { pm_emit(pm, "ERR already started\n"); return; }
	if (!manager || !pm_vv_available()) {
		pm_fatal(pm, "libpurple was built without voice and video");
		return;
	}
	pm_use_call_devices(manager);
	pm->media = purple_media_manager_create_private_media(manager, pm->account, "fsrtpconference",
	                                                      PM_PEER, pm->caller);
	if (!pm->media) {
		pm_fatal(pm, "PurpleMedia could not be created (libpurple built without voice and video?)");
		return;
	}
	g_signal_connect(pm->media, "new-candidate", G_CALLBACK(pm_on_new_candidate), pm);
	g_signal_connect(pm->media, "candidates-prepared", G_CALLBACK(pm_on_candidates_prepared), pm);
	g_signal_connect(pm->media, "candidate-pair-established", G_CALLBACK(pm_on_pair), pm);
	g_signal_connect(pm->media, "error", G_CALLBACK(pm_on_error), pm);
	g_signal_connect(pm->media, "state-changed", G_CALLBACK(pm_on_state), pm);
	g_signal_connect(pm->media, "codecs-changed", G_CALLBACK(pm_on_codecs), pm);
	g_signal_connect(pm->media, "level", G_CALLBACK(pm_on_level), pm);

	/* RFC 5245 ICE (NICE_COMPATIBILITY_RFC5245 is 0) over UDP; libpurple adds controlling-mode
	 * from the initiator flag. */
	memset(params, 0, sizeof params);
	params[n].name = "compatibility-mode";
	g_value_init(&params[n].value, G_TYPE_UINT); g_value_set_uint(&params[n].value, 0); n++;
	params[n].name = "ice-tcp";
	g_value_init(&params[n].value, G_TYPE_BOOLEAN); g_value_set_boolean(&params[n].value, FALSE); n++;
	if (pm->stun_ip) {
		params[n].name = "stun-ip";
		/* Static: libpurple's create_stream copies the GValues and unsets them itself, so the
		 * string must not be freed by either unset (pm owns it, and Farstream copies it). */
		g_value_init(&params[n].value, G_TYPE_STRING);
		g_value_set_static_string(&params[n].value, pm->stun_ip); n++;
		params[n].name = "stun-port";
		g_value_init(&params[n].value, G_TYPE_UINT); g_value_set_uint(&params[n].value, pm->stun_port); n++;
	}
	pm->other_sessions = g_hash_table_new(NULL, NULL);
	pm_each_rtpsession(pm_note_session, pm->other_sessions);
	ok = purple_media_add_stream(pm->media, PM_SESSION, PM_PEER, PURPLE_MEDIA_AUDIO, pm->caller,
	                             "nice", n, params);
	/* For the paths where libpurple returns before create_stream; a no-op for the others, as
	 * nothing here owns any memory. */
	for (i = 0; i < n; i++) g_value_unset(&params[i].value);
	if (!ok) { pm_fatal(pm, "the audio stream could not be added"); return; }

	purple_media_set_send_rtcp_mux(pm->media, PM_SESSION, PM_PEER, TRUE);
	purple_media_set_require_encryption(pm->media, PM_SESSION, PM_PEER, TRUE);
	if (getrandom(pm->txkey, sizeof pm->txkey, 0) != (ssize_t) sizeof pm->txkey) {
		pm_fatal(pm, "no random bytes for our key");
		return;
	}
	if (!purple_media_set_encryption_parameters(pm->media, PM_SESSION, PM_CIPHER, PM_AUTH,
	                                            (const gchar *) pm->txkey, sizeof pm->txkey)) {
		pm_fatal(pm, "our SRTP key was not taken");
		return;
	}
	/* Opus on the offer's payload type, as the far side sends it (opus/48000/2) */
	opus = purple_media_codec_new(pm->pt, "OPUS", PURPLE_MEDIA_AUDIO, PM_OPUS_RATE);
	g_object_set(opus, "channels", 2, NULL);
	codecs = g_list_append(NULL, opus);
	if (!purple_media_set_remote_codecs(pm->media, PM_SESSION, PM_PEER, codecs))
		pm_log("Opus/%d was not taken as the remote codec", pm->pt);
	purple_media_codec_list_free(codecs);

	tx = g_base64_encode(pm->txkey, sizeof pm->txkey);
	pm_emit(pm, "TXKEY %s\n", tx);
	explicit_bzero(tx, strlen(tx));
	g_free(tx);

	if (rxkey) {
		if (!pm_set_rx_key(pm, rxkey)) { pm_fatal(pm, "the far side's SRTP key was not taken"); return; }
		pm_set_remote_creds(pm, ruf, rpw);
		purple_media_stream_info(pm->media, PURPLE_MEDIA_INFO_ACCEPT, PM_SESSION, PM_PEER, TRUE);
	}
	if (!getenv("TEAMS_PMEDIA_NO_SSRC")) {
		pm->wire = g_new0(struct PmWire, 1);
		pm->wire->refs = 1;
		pm->ssrc_poll = g_timeout_add(PM_SSRC_POLL_MS, pm_ssrc_poll, pm);
	}
	pm->stats_t0 = g_get_monotonic_time();
	pm->stats_timer = g_timeout_add_seconds(PM_STATS_SECONDS, pm_stats_tick, pm);
	pm_log("started as %s, Opus PT %d, STUN %s:%u", pm->caller ? "caller" : "answerer", pm->pt,
	       pm->stun_ip ? pm->stun_ip : "(none)", pm->stun_ip ? pm->stun_port : 0);
}
G_GNUC_END_IGNORE_DEPRECATIONS

static void
pm_resolved(GObject *src, GAsyncResult *res, gpointer u)
{
	TeamsPMedia *pm = u;
	GError *err = NULL;
	GList *addrs = g_resolver_lookup_by_name_finish(G_RESOLVER(src), res, &err), *l;
	gchar *line;
	if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free(err);    /* pm may be gone */
		return;
	}
	g_clear_object(&pm->resolving);
	if (err) {
		pm_log("STUN server not resolved: %s; going on without it", err->message);
		g_error_free(err);
	}
	for (l = addrs; l; l = l->next) {
		if (g_inet_address_get_family(l->data) == G_SOCKET_FAMILY_IPV4) {
			pm->stun_ip = g_inet_address_to_string(l->data);
			break;
		}
	}
	g_resolver_free_addresses(addrs);
	while (!pm->resolving && !pm->stopped && (line = g_queue_pop_head(&pm->held))) {
		pm_handle_line(pm, line);
		explicit_bzero(line, strlen(line));
		g_free(line);
	}
}

static void
pm_relay(TeamsPMedia *pm, gchar **t, int n)
{
	GInetAddress *ip;
	guint64 port;
	if (n < 4 || strcmp(t[1], "stun")) {
		pm_log("RELAY %s left alone (only STUN is used)", n > 1 ? t[1] : "?");
		return;
	}
	port = g_ascii_strtoull(t[3], NULL, 10);
	if (!port || port > 65535) { pm_log("RELAY stun: bad port"); return; }
	pm->stun_port = (guint) port;
	g_free(pm->stun_ip); pm->stun_ip = NULL;
	ip = g_inet_address_new_from_string(t[2]);
	if (ip) {
		pm->stun_ip = g_strdup(t[2]);
		g_object_unref(ip);
		return;
	}
	{
		GResolver *r = g_resolver_get_default();
		pm->resolving = g_cancellable_new();
		g_resolver_lookup_by_name_async(r, t[2], pm->resolving, pm_resolved, pm);
		g_object_unref(r);
	}
}

static void
pm_handle_line(TeamsPMedia *pm, gchar *line)
{
	gchar **t;
	int n;
	if (pm->resolving) {           /* in order, after the STUN server's address */
		g_queue_push_tail(&pm->held, g_strdup(line));
		return;
	}
	if (g_str_has_prefix(line, "RCAND ")) { pm_rcand(pm, line + 6); return; }
	t = g_strsplit(line, " ", -1);
	n = (int) g_strv_length(t);
	if (!n) { g_strfreev(t); return; }
	if (!strcmp(t[0], "RELAY")) {
		pm_relay(pm, t, n);
	} else if (!strcmp(t[0], "START")) {
		if (!pm->caller && n >= 5) {
			pm->pt = atoi(t[4]);
			if (pm->pt <= 0 || pm->pt > 127) pm->pt = 102;
			pm_start(pm, t[1], t[2], t[3]);
		} else if (pm->caller) {
			pm->pt = n >= 2 ? atoi(t[1]) : 102;
			if (pm->pt <= 0 || pm->pt > 127) pm->pt = 102;
			pm_start(pm, NULL, NULL, NULL);
		} else {
			pm_fatal(pm, "START without the far side's key and ICE credentials");
		}
	} else if (!strcmp(t[0], "ANSWER") && n >= 4) {
		if (!pm->media) pm_emit(pm, "ERR ANSWER before START\n");
		else if (!pm_set_rx_key(pm, t[1])) pm_fatal(pm, "the far side's SRTP key was not taken");
		else {
			pm_set_remote_creds(pm, t[2], t[3]);
			purple_media_stream_info(pm->media, PURPLE_MEDIA_INFO_ACCEPT, PM_SESSION, PM_PEER, TRUE);
			pm_emit(pm, "ANSWERED\n");
		}
	} else if (!strcmp(t[0], "RESTART")) {
		pm_log("RESTART: an ICE restart is not supported");
		pm_emit(pm, "ERR restart is not supported by the PurpleMedia engine\n");
	} else if (!strcmp(t[0], "VIDEO")) {
		pm_log("VIDEO %s: this engine has no video", n > 1 ? t[1] : "?");
	} else if (!strcmp(t[0], "STOP")) {
		pm_stop_input(pm);
		pm_end_media(pm);
	} else {
		pm_log("unknown command %s", t[0]);
	}
	/* the keys */
	for (n = 0; t[n]; n++) explicit_bzero(t[n], strlen(t[n]));
	g_strfreev(t);
}

static gboolean
pm_on_cmd(GIOChannel *ch, GIOCondition cond, gpointer u)
{
	TeamsPMedia *pm = u;
	char buf[1024];
	(void) ch;
	for (;;) {
		const gchar *nl;
		ssize_t n = read(pm->cmd_fd, buf, sizeof buf);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
		if (n <= 0) {                     /* the plugin closed its end: the call is over */
			pm->cmd_watch = 0;
			explicit_bzero(buf, sizeof buf);
			pm_stop_input(pm);
			pm_end_media(pm);
			return G_SOURCE_REMOVE;
		}
		g_string_append_len(pm->inbuf, buf, n);
		while (!pm->stopped && (nl = memchr(pm->inbuf->str, '\n', pm->inbuf->len))) {
			gsize len = (gsize) (nl - pm->inbuf->str);
			gchar *line = g_strndup(pm->inbuf->str, len);
			g_strchomp(line);
			explicit_bzero(pm->inbuf->str, len + 1);
			g_string_erase(pm->inbuf, 0, len + 1);
			pm_handle_line(pm, line);
			explicit_bzero(line, strlen(line));
			g_free(line);
		}
		if (pm->stopped) { pm->cmd_watch = 0; explicit_bzero(buf, sizeof buf); return G_SOURCE_REMOVE; }
	}
	explicit_bzero(buf, sizeof buf);
	if (cond & (G_IO_HUP | G_IO_ERR)) {
		pm->cmd_watch = 0;
		pm_stop_input(pm);
		pm_end_media(pm);
		return G_SOURCE_REMOVE;
	}
	return G_SOURCE_CONTINUE;
}

/* ---- life ------------------------------------------------------------------------------------ */

static gboolean
pm_set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL);
	return fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

TeamsPMedia *
teams_pmedia_start(PurpleAccount *account, gboolean caller, int cmd_fd, int out_fd)
{
	TeamsPMedia *pm;
	if (cmd_fd < 0 || out_fd < 0 || !pm_set_nonblock(cmd_fd) || !pm_set_nonblock(out_fd)) {
		if (cmd_fd >= 0) close(cmd_fd);
		if (out_fd >= 0) close(out_fd);
		return NULL;
	}
	pm = g_new0(TeamsPMedia, 1);
	pm->account = account;
	pm->caller = caller;
	pm->cmd_fd = cmd_fd;
	pm->out_fd = out_fd;
	pm->pt = 102;
	pm->inbuf = g_string_new("");
	pm->outq = g_string_new("");
	g_queue_init(&pm->held);
	pm->cmd_ch = g_io_channel_unix_new(cmd_fd);
	pm->cmd_watch = g_io_add_watch(pm->cmd_ch, G_IO_IN | G_IO_HUP | G_IO_ERR, pm_on_cmd, pm);
	pm_log("engine started (%s)", caller ? "caller" : "answerer");
	return pm;
}

void
teams_pmedia_free(TeamsPMedia *pm)
{
	if (!pm) return;
	pm_stop_input(pm);
	pm_end_media(pm);
	pm_free_held_cands(pm);
	if (pm->out_watch) g_source_remove(pm->out_watch);
	if (pm->cmd_ch) g_io_channel_unref(pm->cmd_ch);
	if (pm->cmd_fd >= 0) close(pm->cmd_fd);
	if (pm->out_fd >= 0) close(pm->out_fd);
	explicit_bzero(pm->inbuf->str, pm->inbuf->len);
	g_string_free(pm->inbuf, TRUE);
	explicit_bzero(pm->outq->str, pm->outq->len);
	g_string_free(pm->outq, TRUE);
	explicit_bzero(pm->txkey, sizeof pm->txkey);
	g_free(pm->stun_ip);
	g_free(pm->ruf);
	g_free(pm->rpw);
	g_free(pm);
}
