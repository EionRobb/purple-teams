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
 *   VSTART <rxkey> <ufrag> <pwd>  (answering, right after START) / VSTART (placing the call)
 *                              a second, "video" session on an ICE stream of its own (Farstream
 *                              has no BUNDLE): H264 on PT 107 received, its key the video
 *                              m-line's ("-": the audio's), our key the same as the audio's
 *   VANSWER <rxkey> <ufrag> <pwd>  (placing the call) the far side's for the video session
 *   VRCAND <candidate:...>     a remote candidate for the video session
 *   VRESTART <rxkey> <ufrag> <pwd>  a renegotiation moved the far side's video to new ICE:
 *                              the video session is replaced by a new one answering it, whose
 *                              VUFRAG/VPWD/VCAND lines follow, then VSSRC and VRESTARTED
 *   VIDEO 1 <w> <h> <kbps>     our camera on: the video session's camera head starts (front
 *                              camera, turned upright, NV12 into Farstream's H264 encoder,
 *                              droidvenc at kbps), the stream sends, VTX 1, and VPREVIEW once
 *                              the self-view has a frame; VIDEOERR tx when there is no camera
 *   VIDEO 0                    our camera off: the stream stops sending, the camera is let go
 *                              (VTX 0)
 *   STOP, or the command socket closing: the media ends
 * and what it prints: TXKEY at START, UFRAG/PWD/SSRC and READY once the first local candidate is
 * there (libnice gives every candidate of a stream the same credentials), CAND for each local
 * UDP candidate of component 1, GATHERED when Farstream has all of them, AUDIOD 1 when ICE has a
 * pair, ERR for failures. A failure that loses the media closes the output socket, which
 * teams_calling.c takes as the engine having stopped. With a video session, READY waits for its
 * credentials too (VUFRAG/VPWD, then VSSRC: its RTCP's SSRC), its candidates are VCAND lines,
 * and GATHERED waits for both sessions; the video lines teams_media prints (VSHM, PEERVIDEO) come
 * once the far side's picture arrives. VCAMERA 1 right after VSTART (and VRESTART) says the
 * session can send our camera (see pm_camera_usable), before the credentials.
 *
 * Audio goes through PulseAudio's call devices, as teams_media's does: capture from webcall,
 * playback to voipcall (palm-policy routes those for a call). The far side's video is decoded
 * (avdec_h264: the HAL decoder is ranked out of Farstream's choice, see pm_video_start) and
 * published as I420 on a gst-shm socket for the Phone app, as teams_media publishes it. Farstream
 * gets no RTCP feedback parameters through libpurple, so the engine adds what a WebRTC-style
 * sender needs itself: a PLI when the decoder needs a keyframe, and REMB in every report. */

#include "teams_call_pmedia.h"
#include "teams_call_sdp.h"

#include <debug.h>
#include <media.h>
#include <mediamanager.h>
#include <media-gst.h>

#include <gio/gio.h>
#include <gmodule.h>
#include <gst/gst.h>
#include <gst/rtp/gstrtcpbuffer.h>

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

#define PM_VSESSION     "video"
#define PM_VSINK_ID     "teams-videoshm"
#define PM_VSRC_ID      "teams-camera"
#define PM_PREVIEW_SHM  "/tmp/teams-preview"   /* device-side socket: the Phone app opens it */
#define PM_PREVIEW_W    320
#define PM_PREVIEW_H    240
#define PM_VIDEO_MTU    1200    /* our video's RTP packets at most (bytes, before SRTP) */
#define PM_VIDEO_KBPS   800
#define PM_H264_PT      107
#define PM_VIDEO_W      640
#define PM_VIDEO_H      480
#define PM_VIDEO_SHM    "/tmp/teams-video"     /* device-side socket: the Phone app opens it */
#define PM_SHM_SIZE     (8u << 20)
#define PM_VTICK_MS     100
#define PM_PLI_GAP_US   500000                 /* at most two keyframe requests a second */
#define PM_PEER_GONE_US 2000000                /* no decoded frame for 2 s: PEERVIDEO 0 */
#define PM_KEY_LATE_US  1000000                /* packets, but nothing decoded for 1 s: PLI */
#define PM_REMB_BPS     1500000u
#define PM_VX_KEY       "teams-pmedia-video"

/* The video session's state that its streaming threads (pad probes, rtpsession's RTCP thread)
 * share with the main loop. Reference-counted: a probe or signal handler can still be running
 * while the engine ends the media. */
typedef struct {
	gint        refs;
	GMutex      lock;                 /* the times, the size and the size filter */
	gint64      first_pkt, last_pkt, last_dec, last_pli;   /* monotonic us, 0 = never */
	GstElement *size_filter;          /* our sink's capsfilter (a reference) */
	gint        w, h;                 /* what the far side's picture is published at */
	gchar      *shm_path;             /* where shmsink really listens, once a frame reached it */
	gint        peer_ssrc;            /* atomic (a guint32): the far side's H264 SSRC */
	gint        our_ssrc;             /* atomic: our video RTCP's SSRC, the one VSSRC announces */
	gpointer    conf;                 /* the Farstream conference the session is in: compared only */
	gint        pli_wanted;           /* atomic */
	gint        announce;             /* atomic: 1 = a VSHM line is due */
	gint        rx_pkts, decoded, pli_sent, remb_sent;   /* atomic counts for STATS */
	/* our camera head (pm_make_vcam), main loop only: its source, locked in NULL while the
	 * camera is off, and the capsfilter that fixes the size we send */
	GstElement *cam, *send_caps;
	gboolean    sized;                /* send_caps was set from a VIDEO 1 */
	gint        cw;                   /* quarter turns clockwise the head turns the picture */
	gboolean    mirrored;             /* the self-view is the front camera's: shown mirrored */
	gint        pv_w, pv_h;           /* the self-view's size */
	gchar      *pv_path;              /* under lock: where its shmsink really listens */
	gint        pv_announce;          /* atomic: 1 = a VPREVIEW line is due */
	gint        tx_frames;            /* atomic: frames of our camera into Farstream */
	gint        tx_enc, tx_key;       /* atomic: frames out of the encoder, and keyframes of them */
	gint        tx_pkts;              /* atomic: our H264 RTP packets out of the video rtpsession */
	gint        tx_ssrc;              /* atomic (a guint32): the SSRC they go with */
	gint        tx_sr;                /* atomic: our video RTCP reports that were sender reports */
	gint        tx_sps;               /* atomic: our RTP packets that carry an SPS */
	gint        tx_max;               /* atomic: the largest of our RTP packets (bytes, before SRTP) */
	gint        rx_pli, rx_fir, rx_nack;   /* atomic: the far side's requests about our video */
	gint        tx_bps;               /* atomic: the encoder's target bitrate */
	GstElement *venc;                 /* under lock: Farstream's droidvenc (a reference) */
	gboolean    latency_due;          /* main loop: the pipeline's latency to be redistributed */
	gint        frames_at_on;         /* main loop: tx_frames when the camera last went on */
	gint        cam_failed;           /* atomic: 1 = our camera head posted an error (PmCamBin) */
	gchar      *cam_error;            /* under lock: that error's text */
} PmVideo;

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
	gboolean       creds_sent, ready_sent, gathered, gathered_sent, paired;
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

	/* the video session (VSTART); vx NULL without one */
	PmVideo       *vx;
	gchar         *vsid;           /* its libpurple session id: "video", then "video2", ... */
	guint          vgen;           /* how many video sessions the call has had */
	GPtrArray     *vnice;          /* its nicesink elements (references), see pm_video_restart */
	gboolean       vrestarting;    /* VRESTART: VRESTARTED is due once its candidates are complete */
	gboolean       cam_on;         /* VIDEO 1 (until VIDEO 0): a new video session sends too */
	gint           cam_w, cam_h, cam_kbps;   /* what that VIDEO 1 asked for */
	gchar         *vruf, *vrpw;
	GList         *vrcands_held;
	gboolean       vcreds_sent, vgathered, vpaired;
	GstElement    *vrtpsession;    /* its rtpsession element (a weak pointer) */
	GObject       *vsess;          /* that element's RTPSession (a reference) */
	GstPad        *vrx_pad;        /* its recv_rtp_sink, watched for the far side's packets */
	gulong         vrx_probe;
	GstPad        *vtx_pad;        /* its send_rtp_src, watched for our packets */
	gulong         vtx_probe;
	GstElement    *vpipe;          /* libpurple's pipeline, for deep-element-added */
	gulong         vadded_id;
	guint          vtick;
	gint           peer_video;     /* the last PEERVIDEO said; -1 none */
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
static void pm_video_stop(TeamsPMedia *pm);
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
	g_list_free_full(pm->vrcands_held, g_object_unref);
	pm->vrcands_held = NULL;
}

/* The call's ICE transport, released before libpurple takes the call down. nicesink waits,
 * with no timeout, when it is given a packet for a component with no selected pair yet (an
 * unanswered call, or ICE that never connected): non-reliable libnice says WOULD_BLOCK, and
 * nicesink waits for a "writable" that only reliable agents signal. Its upstream streaming
 * thread (the microphone's, rtpsession's RTCP) then holds its stream lock for good, and
 * libpurple, which stops the source before the conference, hangs in gst_pad_stop_task().
 * Stopping each nicesink first unlocks it (it returns FLUSHING); locking its state keeps the
 * conference's own state changes off it until the conference goes. */
/* The call's FsRtpConference: the bin above our audio rtpsession. A reference, or NULL. */
static GstElement *
pm_conference(TeamsPMedia *pm)
{
	GstElement *e = pm->rtpsession ? gst_object_ref(pm->rtpsession) : NULL;
	while (e && g_strcmp0(G_OBJECT_TYPE_NAME(e), "FsRtpConference")) {
		GstObject *up = gst_object_get_parent(GST_OBJECT(e));
		gst_object_unref(e);
		e = up && GST_IS_ELEMENT(up) ? GST_ELEMENT(up) : NULL;
		if (up && !e) gst_object_unref(up);
	}
	return e;
}

/* The conference's nicesink elements, each with a reference (the table's keys). */
static GHashTable *
pm_nicesinks(TeamsPMedia *pm)
{
	GHashTable *t = g_hash_table_new_full(NULL, NULL, gst_object_unref, NULL);
	GstElement *conf = pm_conference(pm);
	GstIterator *it;
	GValue v = G_VALUE_INIT;
	if (!conf) return t;
	it = gst_bin_iterate_recurse(GST_BIN(conf));
	for (;;) {
		GstIteratorResult r = gst_iterator_next(it, &v);
		if (r == GST_ITERATOR_RESYNC) { gst_iterator_resync(it); continue; }
		if (r != GST_ITERATOR_OK) break;
		GstElement *s = g_value_get_object(&v);
		GstElementFactory *f = gst_element_get_factory(s);
		if (f && !g_strcmp0(GST_OBJECT_NAME(f), "nicesink") && !g_hash_table_contains(t, s))
			g_hash_table_add(t, gst_object_ref(s));
		g_value_reset(&v);
	}
	g_value_unset(&v);
	gst_iterator_free(it);
	gst_object_unref(conf);
	return t;
}

/* Stop a nicesink for good: it returns FLUSHING to whoever is blocked in it, and its state is
 * locked so that the conference's own state changes leave it alone. */
static void
pm_stop_nicesink(gpointer e, gpointer unused, gpointer u)
{
	(void) unused; (void) u;
	gst_element_set_locked_state(e, TRUE);
	gst_element_set_state(e, GST_STATE_NULL);
}

/* The call's ICE transport, released before libpurple takes the call down. nicesink waits,
 * with no timeout, when it is given a packet for a component with no selected pair yet (an
 * unanswered call, or ICE that never connected): non-reliable libnice says WOULD_BLOCK, and
 * nicesink waits for a "writable" that only reliable agents signal. Its upstream streaming
 * thread (the microphone's, rtpsession's RTCP) then holds its stream lock for good, and
 * libpurple, which stops the source before the conference, hangs in gst_pad_stop_task().
 * Stopping each nicesink first unlocks it. */
static void
pm_release_transport(TeamsPMedia *pm)
{
	GHashTable *t = pm_nicesinks(pm);
	g_hash_table_foreach(t, pm_stop_nicesink, NULL);
	g_hash_table_destroy(t);
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
	pm_video_stop(pm);
	pm_wire_stop(pm);
	if (media) pm_release_transport(pm);
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

/* The element upstream of e's sink pad (a new reference), or NULL. */
static GstElement *
pm_upstream(GstElement *e)
{
	GstPad *p = gst_element_get_static_pad(e, "sink"), *peer = p ? gst_pad_get_peer(p) : NULL;
	GstElement *up = peer ? gst_pad_get_parent_element(peer) : NULL;
	if (peer) gst_object_unref(peer);
	if (p) gst_object_unref(p);
	return up;
}

/* Whether jitterbuffer jb takes the packets of rtpsession sess: within a few elements upstream
 * of it (rtpbin puts rtpstorage and an rtpssrcdemux between them). The rtpbin holds the video
 * session's jitterbuffers too; their caps do not say media=video yet when the first stats are
 * taken. */
static gboolean
pm_jb_of(GstElement *jb, GstElement *sess)
{
	GstElement *e = gst_object_ref(jb), *up;
	gboolean r = FALSE;
	int i;
	for (i = 0; i < 4 && e && !r; i++) {
		up = pm_upstream(e);
		gst_object_unref(e);
		e = up;
		r = e && e == sess;
	}
	if (e) gst_object_unref(e);
	return r;
}

static void
pm_jb_add(GstElement *jb, GstElement *sess, guint64 *v)
{
	GstStructure *st = NULL;
	guint64 x;
	if (!pm_jb_of(jb, sess)) return;
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
				if (f && !strcmp(GST_OBJECT_NAME(f), "rtpjitterbuffer")) pm_jb_add(e, pm->rtpsession, jb);
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
	{
		/* the video session's: packets in, frames decoded, PLIs and REMBs sent */
		gchar *v = pm->vx ? g_strdup_printf(" vrx=%d vdec=%d vpli=%d vremb=%d vtxf=%d vtxe=%d vtxk=%d vtxp=%d vtxssrc=%u vsr=%d"
		                                    " vtxsps=%d vrpli=%d vrfir=%d vrnack=%d vtxmax=%d",
		                                    g_atomic_int_get(&pm->vx->rx_pkts),
		                                    g_atomic_int_get(&pm->vx->decoded), g_atomic_int_get(&pm->vx->pli_sent),
		                                    g_atomic_int_get(&pm->vx->remb_sent), g_atomic_int_get(&pm->vx->tx_frames),
		                                    g_atomic_int_get(&pm->vx->tx_enc), g_atomic_int_get(&pm->vx->tx_key),
		                                    g_atomic_int_get(&pm->vx->tx_pkts), (guint) g_atomic_int_get(&pm->vx->tx_ssrc),
		                                    g_atomic_int_get(&pm->vx->tx_sr), g_atomic_int_get(&pm->vx->tx_sps),
		                                    g_atomic_int_get(&pm->vx->rx_pli), g_atomic_int_get(&pm->vx->rx_fir),
		                                    g_atomic_int_get(&pm->vx->rx_nack), g_atomic_int_get(&pm->vx->tx_max))
		                  : g_strdup("");
		pm_emit(pm, "STATS t=%" G_GINT64_FORMAT " tx=%" G_GUINT64_FORMAT " rx=%" G_GUINT64_FORMAT
		        " jb_pushed=%" G_GUINT64_FORMAT " jb_lost=%" G_GUINT64_FORMAT " jb_late=%" G_GUINT64_FORMAT
		        " jb_dup=%" G_GUINT64_FORMAT " jb_jitter_us=%" G_GUINT64_FORMAT
		        " peer_lost=%d peer_frac=%d rtt_ms=%d mic_rms=%.4f%s\n",
		        (g_get_monotonic_time() - pm->stats_t0) / G_USEC_PER_SEC, tx, rx,
		        jb[0], jb[1], jb[2], jb[3], jb[4] / 1000, peer_lost, peer_frac, rtt_ms, pm->mic_max, v);
		g_free(v);
	}
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

/* READY once our ICE credentials are out (the video session's too, when there is one) and our
 * SSRC is known or waited for. */
static void
pm_maybe_ready(TeamsPMedia *pm)
{
	if (pm->ready_sent || !pm->creds_sent || pm->ssrc_poll || (pm->vx && !pm->vcreds_sent)) return;
	if (pm->ssrc) pm_emit(pm, "SSRC %u\n", pm->ssrc);
	if (pm->vx && g_atomic_int_get(&pm->vx->our_ssrc))
		pm_emit(pm, "VSSRC %u\n", (guint) g_atomic_int_get(&pm->vx->our_ssrc));
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

/* ---- video ------------------------------------------------------------------------------------
 * The far side's H264 arrives on the "video" session, Farstream depayloads and decodes it, and
 * libpurple links what comes out (queue ! videoconvert ! videoscale) to the media manager's video
 * sink, which is ours: capsfilter (I420 at the published size) ! leaky queue ! shmsink, as
 * teams_media's receive branch ends. Around Farstream's elements the engine watches:
 *   - the rtpsession's recv_rtp_sink: the far side's packets (SSRC, when they come)
 *   - rtph264depay: asks upstream for a keyframe when it lost data (request-keyframe) -> PLI
 *   - avdec_h264's src: frames decoded, and their size, which sets the published size
 *   - the RTPSession's on-sending-rtcp: adds REMB to every report and a PLI when one is wanted
 *   - a main-loop tick: a PLI while packets come and nothing decodes, PEERVIDEO, VSHM
 * Farstream sets the session's minimum RTCP interval to 5 s; Teams wants a report (and so a
 * REMB) every second, as teams_media sends them, so it is put back to 1 s whenever it changes. */

static PmVideo *
pm_vx_ref(PmVideo *vx)
{
	g_atomic_int_inc(&vx->refs);
	return vx;
}

static void
pm_vx_unref(gpointer p)
{
	PmVideo *vx = p;
	if (!vx || !g_atomic_int_dec_and_test(&vx->refs)) return;
	if (vx->size_filter) gst_object_unref(vx->size_filter);
	if (vx->cam) gst_object_unref(vx->cam);
	if (vx->send_caps) gst_object_unref(vx->send_caps);
	if (vx->venc) gst_object_unref(vx->venc);
	g_free(vx->shm_path);
	g_free(vx->pv_path);
	g_free(vx->cam_error);
	g_mutex_clear(&vx->lock);
	g_free(vx);
}

static void
pm_vx_closure_unref(gpointer p, GClosure *c)
{
	(void) c;
	pm_vx_unref(p);
}

static GstCaps *
pm_i420_caps(gint w, gint h)
{
	return gst_caps_new_simple("video/x-raw", "format", G_TYPE_STRING, "I420", "width", G_TYPE_INT, w,
	                           "height", G_TYPE_INT, h, "pixel-aspect-ratio", GST_TYPE_FRACTION, 1, 1, NULL);
}

/* The size the far side's picture is published at, for a decoded w x h: its own shape, the long
 * side at most 640, in even numbers (teams_media's tm_rx_frame_size: a phone's picture is often
 * 360x640, and a fixed 640x480 box gave it borders and made it small on the screen). */
static void
pm_rx_frame_size(gint w, gint h, gint *ow, gint *oh)
{
	const gint64 lim = MAX(PM_VIDEO_W, PM_VIDEO_H);
	gint64 lw = MAX(w, 2), lh = MAX(h, 2), lng = MAX(lw, lh);
	if (lng > lim) {
		lw = (lw * lim + lng / 2) / lng;
		lh = (lh * lim + lng / 2) / lng;
	}
	*ow = (gint) MAX(lw & ~(gint64) 1, 2);
	*oh = (gint) MAX(lh & ~(gint64) 1, 2);
}

/* shmsink would answer the allocation query with its shared memory, and when the Phone app does
 * not read, the whole chain then blocks ahead of the leaky queue (teams_media's
 * tm_no_shm_allocation): no allocation query, so upstream allocates and shmsink copies. */
static GstPadProbeReturn
pm_no_shm_allocation(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	GstQuery *q = GST_PAD_PROBE_INFO_QUERY(info);
	(void) pad; (void) u;
	return q && GST_QUERY_TYPE(q) == GST_QUERY_ALLOCATION ? GST_PAD_PROBE_DROP : GST_PAD_PROBE_OK;
}

/* Streaming thread: a frame on its way into the socket. The first one at a size has the main
 * loop say where the picture is (shmsink may have taken another path than the one asked for). */
static GstPadProbeReturn
pm_probe_shm(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	PmVideo *vx = u;
	gboolean due;
	(void) info;
	g_mutex_lock(&vx->lock);
	due = vx->shm_path == NULL;    /* the first frame, or the first at a new size */
	g_mutex_unlock(&vx->lock);
	if (due) {
		GstElement *shm = gst_pad_get_parent_element(pad);
		gchar *path = NULL;
		if (shm) {
			g_object_get(shm, "socket-path", &path, NULL);
			gst_object_unref(shm);
		}
		g_mutex_lock(&vx->lock);
		g_free(vx->shm_path);
		vx->shm_path = path ? path : g_strdup(PM_VIDEO_SHM);
		g_mutex_unlock(&vx->lock);
		g_atomic_int_set(&vx->announce, 1);
	}
	return GST_PAD_PROBE_OK;
}

/* libpurple's video sink for our media: capsfilter ! queue ! shmsink in a bin with a "sink"
 * pad (libpurple looks the pad up by that name). TEAMS_PMEDIA_VIDEO_SHM names another socket. */
static GstElement *
pm_make_vsink(PurpleMedia *media, const gchar *sid, const gchar *who)
{
	PmVideo *vx = media ? g_object_get_data(G_OBJECT(media), PM_VX_KEY) : NULL;
	const char *path = g_getenv("TEAMS_PMEDIA_VIDEO_SHM");
	GstElement *bin = gst_bin_new(NULL);
	GstElement *cf = gst_element_factory_make("capsfilter", NULL);
	GstElement *q = gst_element_factory_make("queue", NULL);
	GstElement *shm = gst_element_factory_make("shmsink", NULL);
	GstCaps *caps;
	GstPad *p;
	(void) sid; (void) who;
	if (!cf || !q || !shm) {
		pm_log("video sink: %s missing; the picture is dropped", !cf ? "capsfilter" : !q ? "queue" : "shmsink");
		if (cf) gst_object_unref(cf);
		if (q) gst_object_unref(q);
		if (shm) gst_object_unref(shm);
		shm = gst_element_factory_make("fakesink", NULL);
		g_object_set(shm, "sync", FALSE, "async", FALSE, NULL);
		gst_bin_add(GST_BIN(bin), shm);
		p = gst_element_get_static_pad(shm, "sink");
		gst_element_add_pad(bin, gst_ghost_pad_new("sink", p));
		gst_object_unref(p);
		return bin;
	}
	caps = pm_i420_caps(PM_VIDEO_W, PM_VIDEO_H);
	g_object_set(cf, "caps", caps, NULL);
	gst_caps_unref(caps);
	g_object_set(q, "leaky", 2 /* downstream */, "max-size-buffers", 2, "max-size-time", (guint64) 0,
	             "max-size-bytes", 0, NULL);
	g_object_set(shm, "socket-path", path && *path ? path : PM_VIDEO_SHM, "shm-size", (guint) PM_SHM_SIZE,
	             "wait-for-connection", FALSE, "sync", FALSE, "async", FALSE, "enable-last-sample", FALSE, NULL);
	gst_bin_add_many(GST_BIN(bin), cf, q, shm, NULL);
	gst_element_link_many(cf, q, shm, NULL);
	p = gst_element_get_static_pad(shm, "sink");
	gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_QUERY_DOWNSTREAM, pm_no_shm_allocation, NULL, NULL);
	if (vx) gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER, pm_probe_shm, pm_vx_ref(vx), pm_vx_unref);
	gst_object_unref(p);
	p = gst_element_get_static_pad(cf, "sink");
	gst_element_add_pad(bin, gst_ghost_pad_new("sink", p));
	gst_object_unref(p);
	if (vx) {
		g_mutex_lock(&vx->lock);
		if (vx->size_filter) gst_object_unref(vx->size_filter);
		vx->size_filter = gst_object_ref(cf);
		vx->w = PM_VIDEO_W;
		vx->h = PM_VIDEO_H;
		g_mutex_unlock(&vx->lock);
	}
	return bin;
}

/* Quarter turns clockwise that make a picture upright, for a sensor orientation in degrees. */
static gint
pm_cw_for_degrees(gint deg)
{
	return (((deg % 360) + 360 + 45) / 90) & 3;
}

/* Quarter turns clockwise for the front camera's picture (teams_media's tm_camera_cw):
 * TEAMS_PMEDIA_VIDEO_ROTATION, else the sensor orientation of a droidcamsrc that is never
 * started (it has it from the HAL's camera list; sargo: 270), else 0. */
static gint
pm_camera_cw(void)
{
	const char *env = g_getenv("TEAMS_PMEDIA_VIDEO_ROTATION");
	GstElement *cam;
	gint deg = 0;
	if (env && *env) return (gint) (g_ascii_strtoll(env, NULL, 10) & 3);
	cam = gst_element_factory_make("droidcamsrc", NULL);
	if (cam) {
		gst_object_ref_sink(cam);
		if (g_object_class_find_property(G_OBJECT_GET_CLASS(cam), "sensor-orientation")) {
			g_object_set(cam, "camera-device", 1, NULL);
			g_object_get(cam, "sensor-orientation", &deg, NULL);
		}
		gst_object_unref(cam);
	}
	return pm_cw_for_degrees(deg);
}

static gboolean
pm_have(const char *factory)
{
	GstElementFactory *f = gst_element_factory_find(factory);
	if (f) gst_object_unref(f);
	return f != NULL;
}

/* Whether droidvenc takes raw NV12 (gst-droid's raw-input patch): Farstream's H264 encoder then,
 * fed the camera's frames turned upright. Teams sends no rotation with the video, so the camera's
 * own H264 (which comes as the sensor lies, a quarter turn off) is not used. */
static gboolean
pm_encoder_takes_nv12(void)
{
	GstElementFactory *enc = gst_element_factory_find("droidvenc");
	GstCaps *want;
	const GList *l;
	gboolean raw = FALSE;
	if (!enc) return FALSE;
	want = gst_caps_from_string("video/x-raw,format=NV12");
	for (l = gst_element_factory_get_static_pad_templates(enc); l && !raw; l = l->next) {
		GstStaticPadTemplate *t = l->data;
		GstCaps *caps;
		if (t->direction != GST_PAD_SINK) continue;
		caps = gst_static_pad_template_get_caps(t);
		raw = gst_caps_can_intersect(caps, want);
		gst_caps_unref(caps);
	}
	gst_caps_unref(want);
	gst_object_unref(enc);
	return raw;
}

/* Whether a video session can send our camera: TEAMS_PMEDIA_VSRC (the loopback test, a test
 * picture), else the front camera (droidcamsrc) with droidvenc taking raw frames and the elements
 * the head is made of. TEAMS_PMEDIA_CAMERA=0 turns it off. */
static gboolean
pm_camera_usable(void)
{
	static const char *const need[] = { "droidcamsrc", "videoflip", "videoconvert", "videoscale", "tee",
	                                    "queue", "shmsink", "fakesink" };
	const char *env = g_getenv("TEAMS_PMEDIA_CAMERA");
	gsize i;
	if (g_getenv("TEAMS_PMEDIA_VSRC")) return TRUE;
	if (env && !strcmp(env, "0")) return FALSE;
	for (i = 0; i < G_N_ELEMENTS(need); i++)
		if (!pm_have(need[i])) { pm_log("no %s: our camera cannot be sent", need[i]); return FALSE; }
	if (!pm_encoder_takes_nv12()) { pm_log("droidvenc does not take raw frames: our camera cannot be sent"); return FALSE; }
	return TRUE;
}

/* Streaming thread: a frame of our camera on its way into Farstream. */
static GstPadProbeReturn
pm_probe_vtx(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	PmVideo *vx = u;
	(void) pad; (void) info;
	g_atomic_int_inc(&vx->tx_frames);
	return GST_PAD_PROBE_OK;
}

/* Streaming thread: a self-view frame. The first since the camera started has the main loop say
 * where the picture is (shmsink may have taken another path than the one asked for). */
static GstPadProbeReturn
pm_probe_preview(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	PmVideo *vx = u;
	gboolean due;
	(void) info;
	g_mutex_lock(&vx->lock);
	due = vx->pv_path == NULL;
	g_mutex_unlock(&vx->lock);
	if (due) {
		GstElement *shm = gst_pad_get_parent_element(pad);
		gchar *path = NULL;
		if (shm) {
			g_object_get(shm, "socket-path", &path, NULL);
			gst_object_unref(shm);
		}
		g_mutex_lock(&vx->lock);
		g_free(vx->pv_path);
		vx->pv_path = path ? path : g_strdup(PM_PREVIEW_SHM);
		g_mutex_unlock(&vx->lock);
		g_atomic_int_set(&vx->pv_announce, 1);
	}
	return GST_PAD_PROBE_OK;
}

/* libpurple's video source for a session that can send (pm_camera_usable): the camera head, in
 * a bin with a "src" pad. The front camera's viewfinder (droidcamsrc vfsrc; its image and video
 * pads go nowhere), turned upright (videoflip, cw quarter turns) and scaled to NV12 at the size
 * we send (send_caps), then through a tee: into Farstream (whose H264 encoder is droidvenc), and
 * through leaky queues, never holding that up, scaled into the self-view socket
 * (TEAMS_PMEDIA_PREVIEW_SHM, else /tmp/teams-preview). With TEAMS_PMEDIA_VSRC the source is
 * videotestsrc instead (NV12 320x240 at 15/s, for the loopback test). The source is locked in
 * NULL until VIDEO 1 (pm_camera_set): the camera is opened only while the user has it on. The
 * viewfinder caps are fully fixed: droidcamsrc fixes only size and frame rate of its viewfinder,
 * and leaves the pixel aspect ratio a range it then cannot negotiate (teams_media). Without a
 * head it is a queue with nothing in front: the session receives, and VIDEO 1 gets VIDEOERR tx. */
/* Streaming or main thread: a flush out of droidcamsrc's viewfinder. droidcamsrc sends
 * FLUSH_START downstream when it stops (to unblock its loop) and no FLUSH_STOP when it starts
 * again: with the rest of the pipeline playing, the camera head behind it would stay flushing,
 * and after the camera button's off and on not one frame would get through ("error flushing
 * pushing buffer"). Its loop cannot block downstream: a leaky queue follows. */
static GstPadProbeReturn
pm_probe_cam_flush(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	GstEvent *ev = GST_PAD_PROBE_INFO_EVENT(info);
	(void) pad; (void) u;
	if (ev && (GST_EVENT_TYPE(ev) == GST_EVENT_FLUSH_START || GST_EVENT_TYPE(ev) == GST_EVENT_FLUSH_STOP))
		return GST_PAD_PROBE_DROP;
	return GST_PAD_PROBE_OK;
}

/* PmCamBin: the bin our camera head goes in. An error from inside it (the camera taken by
 * another user, its stream not negotiated) would reach libpurple's bus watch, which ends the
 * whole media for it ("Error with your webcam"); the call goes on without our camera instead:
 * the error is kept from the pipeline and pm_vtick turns the camera off with VIDEOERR tx-camera.
 * The type stays registered for the life of the process, as GStreamer's own do. */
typedef struct {
	GstBin   parent;
	PmVideo *vx;                      /* a reference, or NULL */
} PmCamBin;

typedef struct {
	GstBinClass parent_class;
} PmCamBinClass;

static GType pm_cam_bin_get_type(void);
G_DEFINE_TYPE(PmCamBin, pm_cam_bin, GST_TYPE_BIN)

/* Any thread: a message from inside the camera head on its way to the pipeline. */
static void
pm_cam_bin_handle_message(GstBin *bin, GstMessage *msg)
{
	PmVideo *vx = ((PmCamBin *) bin)->vx;
	if (GST_MESSAGE_TYPE(msg) == GST_MESSAGE_ERROR) {
		GError *err = NULL;
		gchar *dbg = NULL;
		gst_message_parse_error(msg, &err, &dbg);
		if (vx) {
			g_mutex_lock(&vx->lock);
			if (!vx->cam_error)
				vx->cam_error = g_strdup_printf("%s: %s (%s)", GST_MESSAGE_SRC_NAME(msg),
				                                err ? err->message : "?", dbg ? dbg : "");
			g_mutex_unlock(&vx->lock);
			g_atomic_int_set(&vx->cam_failed, 1);
		}
		g_clear_error(&err);
		g_free(dbg);
		gst_message_unref(msg);
		return;
	}
	GST_BIN_CLASS(pm_cam_bin_parent_class)->handle_message(bin, msg);
}

static void
pm_cam_bin_finalize(GObject *o)
{
	PmCamBin *b = (PmCamBin *) o;
	if (b->vx) pm_vx_unref(b->vx);
	b->vx = NULL;
	G_OBJECT_CLASS(pm_cam_bin_parent_class)->finalize(o);
}

static void
pm_cam_bin_class_init(PmCamBinClass *k)
{
	G_OBJECT_CLASS(k)->finalize = pm_cam_bin_finalize;
	GST_BIN_CLASS(k)->handle_message = pm_cam_bin_handle_message;
}

static void
pm_cam_bin_init(PmCamBin *b)
{
	b->vx = NULL;
}

static GstElement *
pm_make_vcam(PurpleMedia *media, const gchar *sid, const gchar *who)
{
	static const char *const direction[] = { "identity", "90r", "180", "90l" };
	PmVideo *vx = media ? g_object_get_data(G_OBJECT(media), PM_VX_KEY) : NULL;
	gboolean test = g_getenv("TEAMS_PMEDIA_VSRC") != NULL;
	const char *pv = g_getenv("TEAMS_PMEDIA_PREVIEW_SHM");
	gint cw = test ? 0 : pm_camera_cw(), w = PM_VIDEO_W, h = PM_VIDEO_H, pw = PM_PREVIEW_W, ph = PM_PREVIEW_H;
	gchar *desc, *head;
	GstElement *bin, *e, *outer;
	GError *err = NULL;
	GstPad *p;
	(void) sid; (void) who;
	if (test) { w = 320; h = 240; pw = 160; ph = 120; }
	if (cw & 1) { gint t = w; w = h; h = t; t = pw; pw = ph; ph = t; }
	head = test
	    ? g_strdup("videotestsrc name=pmcam is-live=true ! "
	               "video/x-raw,format=NV12,width=320,height=240,framerate=15/1,pixel-aspect-ratio=1/1")
	    : g_strdup_printf("droidcamsrc name=pmcam camera-device=1 "
	                      "pmcam.imgsrc ! fakesink async=false pmcam.vidsrc ! fakesink async=false "
	                      "pmcam.vfsrc ! video/x-raw,format=NV21,width=%d,height=%d,framerate=30/1,"
	                      "pixel-aspect-ratio=1/1 ! queue leaky=downstream max-size-buffers=2 ! "
	                      "videoflip video-direction=%s ! videoconvert ! videoscale",
	                      PM_VIDEO_W, PM_VIDEO_H, direction[cw & 3]);
	desc = g_strdup_printf("%s ! capsfilter name=pmsendcaps caps=video/x-raw,format=NV12,width=%d,height=%d,"
	                       "pixel-aspect-ratio=1/1 ! tee name=pmvt "
	                       "pmvt. ! queue name=pmvout leaky=downstream max-size-buffers=2 "
	                       "pmvt. ! queue leaky=downstream max-size-buffers=2 ! videoconvert ! videoscale ! "
	                       "video/x-raw,format=I420,width=%d,height=%d,pixel-aspect-ratio=1/1 ! "
	                       "queue leaky=downstream max-size-buffers=2 ! shmsink name=pmpreview",
	                       head, w, h, pw, ph);
	g_free(head);
	bin = gst_parse_bin_from_description(desc, FALSE, &err);
	if (!bin) {
		pm_log("our camera head '%s' could not be made: %s", desc, err ? err->message : "?");
		g_clear_error(&err);
		g_free(desc);
		bin = gst_bin_new(NULL);
		e = gst_element_factory_make("queue", "pmvout");
		gst_bin_add(GST_BIN(bin), e);
	} else {
		g_clear_error(&err);
		g_free(desc);
		if (vx && (e = gst_bin_get_by_name(GST_BIN(bin), "pmcam"))) {
			if ((p = gst_element_get_static_pad(e, "vfsrc"))) {
				gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_EVENT_FLUSH, pm_probe_cam_flush, NULL, NULL);
				gst_object_unref(p);
			}
			gst_element_set_locked_state(e, TRUE);
			if (vx->cam) gst_object_unref(vx->cam);
			vx->cam = e;
		}
		if (vx && (e = gst_bin_get_by_name(GST_BIN(bin), "pmsendcaps"))) {
			if (vx->send_caps) gst_object_unref(vx->send_caps);
			vx->send_caps = e;
		}
		if ((e = gst_bin_get_by_name(GST_BIN(bin), "pmpreview"))) {
			g_object_set(e, "socket-path", pv && *pv ? pv : PM_PREVIEW_SHM, "shm-size", (guint) PM_SHM_SIZE,
			             "wait-for-connection", FALSE, "sync", FALSE, "async", FALSE, "enable-last-sample", FALSE, NULL);
			p = gst_element_get_static_pad(e, "sink");
			gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_QUERY_DOWNSTREAM, pm_no_shm_allocation, NULL, NULL);
			if (vx) gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER, pm_probe_preview, pm_vx_ref(vx), pm_vx_unref);
			gst_object_unref(p);
			gst_object_unref(e);
		}
		if (vx) {
			vx->cw = cw;
			vx->mirrored = !test;
			vx->pv_w = pw;
			vx->pv_h = ph;
		}
	}
	e = gst_bin_get_by_name(GST_BIN(bin), "pmvout");
	p = gst_element_get_static_pad(e, "src");
	if (vx) gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER, pm_probe_vtx, pm_vx_ref(vx), pm_vx_unref);
	gst_object_unref(e);
	outer = g_object_new(pm_cam_bin_get_type(), NULL);
	((PmCamBin *) outer)->vx = vx ? pm_vx_ref(vx) : NULL;
	gst_bin_add(GST_BIN(outer), bin);
	gst_element_add_pad(outer, gst_ghost_pad_new("src", p));
	gst_object_unref(p);
	return outer;
}

static void
pm_use_video_elements(PurpleMediaManager *manager, gboolean send)
{
	static PurpleMediaElementInfo *sink, *src;
	if (!sink) {
		sink = g_object_new(pm_vv.element_info_get_type(), "id", PM_VSINK_ID, "name", "Teams call video",
		                    "type", PURPLE_MEDIA_ELEMENT_VIDEO | PURPLE_MEDIA_ELEMENT_SINK | PURPLE_MEDIA_ELEMENT_ONE_SINK,
		                    "create-cb", pm_make_vsink, NULL);
		if (!pm_vv.register_element(manager, sink)) pm_log("could not register the video sink");
	}
	pm_vv.set_active_element(manager, sink);
	if (send) {
		if (!src) {
			/* not UNIQUE: each session gets a head of its own (libpurple would put a shared
			 * one behind its own videoscale and caps) */
			src = g_object_new(pm_vv.element_info_get_type(), "id", PM_VSRC_ID, "name", "Teams camera",
			                   "type", PURPLE_MEDIA_ELEMENT_VIDEO | PURPLE_MEDIA_ELEMENT_SRC | PURPLE_MEDIA_ELEMENT_ONE_SRC,
			                   "create-cb", pm_make_vcam, NULL);
			if (!pm_vv.register_element(manager, src)) pm_log("could not register the camera source");
		}
		pm_vv.set_active_element(manager, src);
	}
}

/* Streaming thread: RTP into the video session (decrypted; buffer lists from nicesrc). */
static void
pm_vrx_packet(PmVideo *vx, GstBuffer *b)
{
	guint8 h[12];
	gint64 now;
	if (gst_buffer_extract(b, 0, h, sizeof h) != sizeof h || (h[0] >> 6) != 2 || (h[1] & 0x7f) != PM_H264_PT)
		return;   /* not RTP, or not the H264 (RTCP shares the component) */
	g_atomic_int_set(&vx->peer_ssrc, (gint) (((guint32) h[8] << 24) | ((guint32) h[9] << 16) |
	                                         ((guint32) h[10] << 8) | h[11]));
	g_atomic_int_inc(&vx->rx_pkts);
	now = g_get_monotonic_time();
	g_mutex_lock(&vx->lock);
	if (!vx->first_pkt) vx->first_pkt = now;
	vx->last_pkt = now;
	g_mutex_unlock(&vx->lock);
}

static GstPadProbeReturn
pm_probe_vrx(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	(void) pad;
	if (info->type & GST_PAD_PROBE_TYPE_BUFFER_LIST) {
		GstBufferList *l = GST_PAD_PROBE_INFO_BUFFER_LIST(info);
		guint i;
		for (i = 0; i < gst_buffer_list_length(l); i++) pm_vrx_packet(u, gst_buffer_list_get(l, i));
	} else if (GST_PAD_PROBE_INFO_BUFFER(info)) {
		pm_vrx_packet(u, GST_PAD_PROBE_INFO_BUFFER(info));
	}
	return GST_PAD_PROBE_OK;
}

/* Streaming thread: what our video rtpsession sends (RTP only: its RTCP has a pad of its own). */
static void
pm_vtx_packet(PmVideo *vx, GstBuffer *b)
{
	guint8 h[12];
	if (gst_buffer_extract(b, 0, h, sizeof h) != sizeof h || (h[0] >> 6) != 2 || (h[1] & 0x7f) != PM_H264_PT)
		return;
	g_atomic_int_set(&vx->tx_ssrc, (gint) (((guint32) h[8] << 24) | ((guint32) h[9] << 16) |
	                                       ((guint32) h[10] << 8) | h[11]));
	g_atomic_int_inc(&vx->tx_pkts);
	{
		gint n = (gint) gst_buffer_get_size(b), m;
		do m = g_atomic_int_get(&vx->tx_max); while (n > m && !g_atomic_int_compare_and_exchange(&vx->tx_max, m, n));
	}
	{
		/* an SPS in it: a NAL of its own, or a unit of a STAP-A (RFC 6184) */
		gsize len = gst_buffer_get_size(b), off = 12 + 4 * (gsize) (h[0] & 0x0f);
		guint8 x[4];
		if ((h[0] & 0x10) && gst_buffer_extract(b, off, x, 4) == 4) off += 4 + 4 * (gsize) ((x[2] << 8) | x[3]);
		if (off < len && gst_buffer_extract(b, off, x, 1) == 1) {
			guint t = x[0] & 0x1f;
			gboolean sps = t == 7;
			if (t == 24)
				for (off += 1; !sps && off + 3 <= len && gst_buffer_extract(b, off, x, 3) == 3;
				     off += 2 + (gsize) ((x[0] << 8) | x[1]))
					sps = (x[2] & 0x1f) == 7;
			if (sps) g_atomic_int_inc(&vx->tx_sps);
		}
	}
}

static GstPadProbeReturn
pm_probe_vtx_rtp(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	(void) pad;
	if (info->type & GST_PAD_PROBE_TYPE_BUFFER_LIST) {
		GstBufferList *l = GST_PAD_PROBE_INFO_BUFFER_LIST(info);
		guint i;
		for (i = 0; i < gst_buffer_list_length(l); i++) pm_vtx_packet(u, gst_buffer_list_get(l, i));
	} else if (GST_PAD_PROBE_INFO_BUFFER(info)) {
		pm_vtx_packet(u, GST_PAD_PROBE_INFO_BUFFER(info));
	}
	return GST_PAD_PROBE_OK;
}

/* Streaming thread: a frame out of the encoder. */
static GstPadProbeReturn
pm_probe_venc_out(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	PmVideo *vx = u;
	GstBuffer *b = GST_PAD_PROBE_INFO_BUFFER(info);
	(void) pad;
	if (b) {
		g_atomic_int_inc(&vx->tx_enc);
		if (!GST_BUFFER_FLAG_IS_SET(b, GST_BUFFER_FLAG_DELTA_UNIT)) g_atomic_int_inc(&vx->tx_key);
	}
	return GST_PAD_PROBE_OK;
}

/* rtph264depay asks upstream for a keyframe (GstForceKeyUnit) when it lost data. rtpsession
 * would send the PLI itself if the codec's caps had rtcp-fb-nack-pli, which libpurple does not
 * pass on, so the engine sends it. */
static GstPadProbeReturn
pm_probe_vkey(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	PmVideo *vx = u;
	GstEvent *ev = GST_PAD_PROBE_INFO_EVENT(info);
	(void) pad;
	if (ev && GST_EVENT_TYPE(ev) == GST_EVENT_CUSTOM_UPSTREAM && gst_event_has_name(ev, "GstForceKeyUnit"))
		g_atomic_int_set(&vx->pli_wanted, 1);
	return GST_PAD_PROBE_OK;
}

static GstPadProbeReturn
pm_probe_vdec(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	PmVideo *vx = u;
	(void) pad;
	if (info->type & GST_PAD_PROBE_TYPE_BUFFER) {
		g_atomic_int_inc(&vx->decoded);
		g_mutex_lock(&vx->lock);
		vx->last_dec = g_get_monotonic_time();
		g_mutex_unlock(&vx->lock);
	} else {
		GstEvent *ev = GST_PAD_PROBE_INFO_EVENT(info);
		GstCaps *caps = NULL;
		const GstStructure *st;
		gint w = 0, h = 0, ow, oh;
		if (!ev || GST_EVENT_TYPE(ev) != GST_EVENT_CAPS) return GST_PAD_PROBE_OK;
		gst_event_parse_caps(ev, &caps);
		st = caps && gst_caps_get_size(caps) > 0 ? gst_caps_get_structure(caps, 0) : NULL;
		if (!st || !gst_structure_get_int(st, "width", &w) || !gst_structure_get_int(st, "height", &h) ||
		    w <= 0 || h <= 0)
			return GST_PAD_PROBE_OK;
		pm_rx_frame_size(w, h, &ow, &oh);
		g_mutex_lock(&vx->lock);
		if (ow != vx->w || oh != vx->h) {
			vx->w = ow;
			vx->h = oh;
			if (vx->size_filter) {
				GstCaps *vc = pm_i420_caps(ow, oh);
				g_object_set(vx->size_filter, "caps", vc, NULL);
				gst_caps_unref(vc);
			}
			g_free(vx->shm_path);    /* the next frame announces the new size */
			vx->shm_path = NULL;
		}
		g_mutex_unlock(&vx->lock);
	}
	return GST_PAD_PROBE_OK;
}

static void
pm_set_prop(GstElement *e, const char *name, gboolean v)
{
	if (g_object_class_find_property(G_OBJECT_GET_CLASS(e), name)) g_object_set(e, name, v, NULL);
}

/* Streaming thread: a caps query on droidvenc's sink. gst-droid's droidvenc, once it has been
 * configured (out_state set), answers one with EMPTY: gst_droidvenc_getcaps() intersects the
 * filter with its H264 output caps. Farstream's send path queries again when it links the codec
 * bin and mid-stream, so our camera's stream would stop with not-negotiated. The query is
 * answered with the caps the pad already has, or with the sink template while it has none. */
static GstPadProbeReturn
pm_probe_venc_caps(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	GstQuery *q = GST_PAD_PROBE_INFO_QUERY(info);
	GstCaps *cur, *filter = NULL, *res;
	(void) u;
	if (!q || GST_QUERY_TYPE(q) != GST_QUERY_CAPS) return GST_PAD_PROBE_OK;
	if (!(cur = gst_pad_get_current_caps(pad)) && !(cur = gst_pad_get_pad_template_caps(pad))) return GST_PAD_PROBE_OK;
	gst_query_parse_caps(q, &filter);
	res = filter ? gst_caps_intersect(cur, filter) : gst_caps_ref(cur);
	gst_query_set_caps_result(q, res);
	gst_caps_unref(res);
	gst_caps_unref(cur);
	return GST_PAD_PROBE_HANDLED;
}

/* Any thread: an element went into libpurple's pipeline. Farstream makes the receive codec bin
 * when the first H264 packet comes. */
static void
pm_on_deep_added(GstBin *bin, GstBin *sub, GstElement *e, gpointer u)
{
	PmVideo *vx = u;
	GstElementFactory *f = gst_element_get_factory(e);
	const char *n = f ? GST_OBJECT_NAME(f) : NULL;
	GstPad *p;
	(void) bin; (void) sub;
	if (!n) return;
	if (f) {
		/* Farstream's video encoder, whichever it picked: count what it makes */
		const char *klass = gst_element_factory_get_metadata(f, GST_ELEMENT_METADATA_KLASS);
		if (klass && strstr(klass, "Encoder") && strstr(klass, "Video") &&
		    (p = gst_element_get_static_pad(e, "src"))) {
			gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER, pm_probe_venc_out, pm_vx_ref(vx), pm_vx_unref);
			gst_object_unref(p);
		}
	}
	if (!strcmp(n, "rtph264pay") && vx->conf && gst_object_has_as_ancestor(GST_OBJECT(e), vx->conf)) {
		/* our camera's payloader: it would pick an SSRC of its own (Farstream does not pass
		 * the session's on), and Teams forwards video by the SSRC the SDP announces (VSSRC):
		 * with any other one the far side never sees our picture */
		guint ssrc = (guint) g_atomic_int_get(&vx->our_ssrc);
		if (ssrc && g_object_class_find_property(G_OBJECT_GET_CLASS(e), "ssrc")) g_object_set(e, "ssrc", ssrc, NULL);
		/* SPS and PPS before every keyframe, as WebRTC senders do: a receiver that starts its
		 * decoder again (Teams Android does on a renegotiation) cannot decode without them,
		 * and by default they go out once, at the start */
		if (g_object_class_find_property(G_OBJECT_GET_CLASS(e), "config-interval")) g_object_set(e, "config-interval", -1, NULL);
		/* packets of at most PM_VIDEO_MTU bytes, as teams_media sends them: on the way through
		 * Teams' relays bigger ones (rtph264pay's default 1400, with SRTP's tag and the relay's
		 * headers on top) are lost, and with them every keyframe; the far side then asks for
		 * one after another (PLI) and shows nothing past the first small frames */
		if (g_object_class_find_property(G_OBJECT_GET_CLASS(e), "mtu")) g_object_set(e, "mtu", (guint) PM_VIDEO_MTU, NULL);
	} else if (!strcmp(n, "rtph264depay")) {
		pm_set_prop(e, "request-keyframe", TRUE);
		pm_set_prop(e, "wait-for-keyframe", TRUE);
		if ((p = gst_element_get_static_pad(e, "sink"))) {
			gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_EVENT_UPSTREAM, pm_probe_vkey, pm_vx_ref(vx), pm_vx_unref);
			gst_object_unref(p);
		}
	} else if (!strcmp(n, "droidvenc")) {
		/* Farstream's encoder for our camera */
		g_object_set(e, "target-bitrate", g_atomic_int_get(&vx->tx_bps), NULL);
		if ((p = gst_element_get_static_pad(e, "sink"))) {
			gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_QUERY_DOWNSTREAM, pm_probe_venc_caps, NULL, NULL);
			gst_object_unref(p);
		}
		g_mutex_lock(&vx->lock);
		if (vx->venc) gst_object_unref(vx->venc);
		vx->venc = gst_object_ref(e);
		g_mutex_unlock(&vx->lock);
	} else if (!strcmp(n, "avdec_h264") || !strcmp(n, "droidvdec")) {
		pm_set_prop(e, "output-corrupt", FALSE);
		if ((p = gst_element_get_static_pad(e, "src"))) {
			gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM, pm_probe_vdec,
			                  pm_vx_ref(vx), pm_vx_unref);
			gst_object_unref(p);
		}
	}
}

/* The RTCP thread: feedback in the far side's RTCP. Counted when it is about our video: PLI
 * and FIR (it wants a keyframe), NACK (it lost packets). */
static void
pm_on_feedback_rtcp(GObject *sess, guint type, guint fbtype, guint sender, guint media, GstBuffer *fci, gpointer u)
{
	PmVideo *vx = u;
	(void) sess; (void) sender; (void) fci;
	if (media != (guint) g_atomic_int_get(&vx->our_ssrc) && !(type == GST_RTCP_TYPE_PSFB && fbtype == GST_RTCP_PSFB_TYPE_FIR))
		return;   /* a FIR names its SSRC in the FCI, not in media */
	if (type == GST_RTCP_TYPE_PSFB && fbtype == GST_RTCP_PSFB_TYPE_PLI) g_atomic_int_inc(&vx->rx_pli);
	else if (type == GST_RTCP_TYPE_PSFB && fbtype == GST_RTCP_PSFB_TYPE_FIR) g_atomic_int_inc(&vx->rx_fir);
	else if (type == GST_RTCP_TYPE_RTPFB && fbtype == GST_RTCP_RTPFB_TYPE_NACK) g_atomic_int_inc(&vx->rx_nack);
}

/* The RTCP thread, before our video RTCP goes out: REMB in every one, a PLI when one is due. */
static gboolean
pm_on_sending_rtcp(GObject *sess, GstBuffer *buf, gboolean early, gpointer u)
{
	PmVideo *vx = u;
	guint32 peer = (guint32) g_atomic_int_get(&vx->peer_ssrc), ours = (guint32) g_atomic_int_get(&vx->our_ssrc);
	GstRTCPBuffer rtcp = GST_RTCP_BUFFER_INIT;
	GstRTCPPacket p;
	gboolean pli = FALSE, added = FALSE;
	gint64 now = g_get_monotonic_time();
	(void) sess; (void) early;
	if (!peer || !gst_rtcp_buffer_map(buf, GST_MAP_READWRITE, &rtcp)) return FALSE;
	if (gst_rtcp_buffer_get_first_packet(&rtcp, &p)) {
		/* what this report goes out as */
		if (gst_rtcp_packet_get_type(&p) == GST_RTCP_TYPE_RR) ours = gst_rtcp_packet_rr_get_ssrc(&p);
		else if (gst_rtcp_packet_get_type(&p) == GST_RTCP_TYPE_SR) {
			gst_rtcp_packet_sr_get_sender_info(&p, &ours, NULL, NULL, NULL, NULL);
			g_atomic_int_inc(&vx->tx_sr);
		}
	}
	if (gst_rtcp_buffer_add_packet(&rtcp, GST_RTCP_TYPE_PSFB, &p)) {
		/* REMB (draft-alvestrand-rmcat-remb): "REMB", one SSRC, the bitrate as 6-bit exponent
		 * and 18-bit mantissa, the SSRC */
		guint8 *fci;
		guint exp = 0, mant;
		gst_rtcp_packet_fb_set_type(&p, GST_RTCP_PSFB_TYPE_AFB);
		gst_rtcp_packet_fb_set_sender_ssrc(&p, ours);
		gst_rtcp_packet_fb_set_media_ssrc(&p, 0);
		if (gst_rtcp_packet_fb_set_fci_length(&p, 3) && (fci = gst_rtcp_packet_fb_get_fci(&p))) {
			while ((PM_REMB_BPS >> exp) > 0x3ffffu && exp < 31) exp++;   /* a 32-bit value: never shift by 32 or more */
			mant = (PM_REMB_BPS >> exp) & 0x3ffffu;
			memcpy(fci, "REMB", 4);
			fci[4] = 1;
			fci[5] = (guint8) ((exp << 2) | (mant >> 16));
			fci[6] = (guint8) (mant >> 8);
			fci[7] = (guint8) mant;
			GST_WRITE_UINT32_BE(fci + 8, peer);
			g_atomic_int_inc(&vx->remb_sent);
			added = TRUE;
		} else {
			gst_rtcp_packet_remove(&p);
		}
	}
	g_mutex_lock(&vx->lock);
	if (g_atomic_int_get(&vx->pli_wanted) && now - vx->last_pli >= PM_PLI_GAP_US) {
		pli = TRUE;
		vx->last_pli = now;
	}
	g_mutex_unlock(&vx->lock);
	if (pli && gst_rtcp_buffer_add_packet(&rtcp, GST_RTCP_TYPE_PSFB, &p)) {
		gst_rtcp_packet_fb_set_type(&p, GST_RTCP_PSFB_TYPE_PLI);
		gst_rtcp_packet_fb_set_sender_ssrc(&p, ours);
		gst_rtcp_packet_fb_set_media_ssrc(&p, peer);
		g_atomic_int_set(&vx->pli_wanted, 0);
		g_atomic_int_inc(&vx->pli_sent);
		added = TRUE;
	}
	gst_rtcp_buffer_unmap(&rtcp);
	return added;
}

/* Farstream sets rtcp-min-interval from its codecs (5 s without trr-int); keep it at 1 s. */
static void
pm_on_rtcp_interval(GObject *sess, GParamSpec *ps, gpointer u)
{
	guint64 v = 0;
	(void) ps; (void) u;
	g_object_get(sess, "rtcp-min-interval", &v, NULL);
	if (v != GST_SECOND) g_object_set(sess, "rtcp-min-interval", (guint64) GST_SECOND, NULL);
}

static void
pm_note_new_session(GstElement *e, gpointer u)
{
	GstElement **found = ((gpointer *) u)[1];
	if (!*found && !g_hash_table_contains(((gpointer *) u)[0], e)) *found = e;
}

static gboolean pm_camera_set(TeamsPMedia *pm, gboolean on);

/* Main loop, every PM_VTICK_MS: the parts of the video session that wait for something. */
static gboolean
pm_vtick(gpointer u)
{
	TeamsPMedia *pm = u;
	PmVideo *vx = pm->vx;
	gint64 now = g_get_monotonic_time(), last_pkt, since;
	gint arriving;
	if (!pm->vrx_pad && pm->vrtpsession) {
		/* rtpbin makes the pad when Farstream links the stream's receive side */
		GstPad *p = gst_element_get_static_pad(pm->vrtpsession, "recv_rtp_sink");
		if (p) {
			pm->vrx_pad = p;
			pm->vrx_probe = gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST,
			                                  pm_probe_vrx, pm_vx_ref(vx), pm_vx_unref);
		}
	}
	if (!pm->vtx_pad && pm->vrtpsession) {
		/* rtpsession makes it when Farstream links the stream's send side */
		GstPad *p = gst_element_get_static_pad(pm->vrtpsession, "send_rtp_src");
		if (p) {
			pm->vtx_pad = p;
			pm->vtx_probe = gst_pad_add_probe(p, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST,
			                                  pm_probe_vtx_rtp, pm_vx_ref(vx), pm_vx_unref);
		}
	}
	g_mutex_lock(&vx->lock);
	last_pkt = vx->last_pkt;
	since = vx->last_dec ? vx->last_dec : vx->first_pkt;
	arriving = vx->last_dec && now - vx->last_dec < PM_PEER_GONE_US;
	g_mutex_unlock(&vx->lock);
	/* packets arrive and nothing has decoded for a while: the keyframe was lost, or never sent
	 * (a WebRTC-style sender sends one only when asked) */
	if (last_pkt && now - last_pkt <= PM_KEY_LATE_US && since && now - since >= PM_KEY_LATE_US)
		g_atomic_int_set(&vx->pli_wanted, 1);
	if (g_atomic_int_compare_and_exchange(&vx->announce, 1, 0)) {
		gchar *path;
		gint w, h;
		g_mutex_lock(&vx->lock);
		path = g_strdup(vx->shm_path);
		w = vx->w; h = vx->h;
		g_mutex_unlock(&vx->lock);
		if (path) {
			pm_log("the far side's picture: %s %dx%d", path, w, h);
			pm_emit(pm, "VSHM %s %d %d\n", path, w, h);
		}
		g_free(path);
	}
	if (vx->latency_due && pm->vpipe && g_atomic_int_get(&vx->tx_frames) > vx->frames_at_on) {
		/* Our camera's frames reach the session: have the pipeline hand out its latency again.
		 * A session added to the running pipeline (VRESTART) is not given it otherwise, and
		 * its rtpsession then knows no running time for what it sends ("Can't determine running
		 * time ... without knowing configured latency"), so it can make no sender report and
		 * sends no RTCP at all: none of our REMB or PLI. */
		vx->latency_due = FALSE;
		if (!gst_bin_recalculate_latency(GST_BIN(pm->vpipe))) pm_log("the pipeline's latency was not recalculated");
	}
	if (g_atomic_int_compare_and_exchange(&vx->cam_failed, 1, 0)) {
		gchar *what;
		g_mutex_lock(&vx->lock);
		what = vx->cam_error;
		vx->cam_error = NULL;
		g_mutex_unlock(&vx->lock);
		pm_log("our camera failed: %s", what ? what : "?");
		g_free(what);
		if (vx->cam) {
			/* off as for VIDEO 0, and the call goes on; a VIDEO 1 may try it again */
			pm_camera_set(pm, FALSE);
			pm->cam_on = FALSE;
			pm_emit(pm, "VIDEOERR tx-camera\n");
		}
	}
	if (g_atomic_int_compare_and_exchange(&vx->pv_announce, 1, 0)) {
		gchar *path;
		g_mutex_lock(&vx->lock);
		path = g_strdup(vx->pv_path);
		g_mutex_unlock(&vx->lock);
		if (path) {
			/* the head turns the picture upright already: no turns left for the Phone app */
			pm_log("our camera's picture: %s %dx%d", path, vx->pv_w, vx->pv_h);
			pm_emit(pm, "VPREVIEW %s %d %d 0 %d\n", path, vx->pv_w, vx->pv_h, vx->mirrored ? 1 : 0);
		}
		g_free(path);
	}
	if (arriving != pm->peer_video && (arriving || pm->peer_video == 1)) {
		pm->peer_video = arriving;
		pm_log("the far side's video %s", arriving ? "arrives" : "stopped");
		pm_emit(pm, "PEERVIDEO %d\n", arriving);
	}
	return G_SOURCE_CONTINUE;
}

static void
pm_video_stop(TeamsPMedia *pm)
{
	if (pm->vx && pm->vx->cam) {
		/* the camera can be open once only: let go of it before a new session's head wants it */
		gst_element_set_locked_state(pm->vx->cam, TRUE);
		gst_element_set_state(pm->vx->cam, GST_STATE_NULL);
	}
	if (pm->vtick) { g_source_remove(pm->vtick); pm->vtick = 0; }
	if (pm->vrx_pad) {
		/* a request pad of the rtpbin: once released (libpurple ended the session first), its
		 * probes went with it */
		GstObject *parent = gst_object_get_parent(GST_OBJECT(pm->vrx_pad));
		if (parent && pm->vrx_probe) gst_pad_remove_probe(pm->vrx_pad, pm->vrx_probe);
		if (parent) gst_object_unref(parent);
		gst_object_unref(pm->vrx_pad);
		pm->vrx_pad = NULL;
		pm->vrx_probe = 0;
	}
	if (pm->vtx_pad) {
		GstObject *parent = gst_object_get_parent(GST_OBJECT(pm->vtx_pad));
		if (parent && pm->vtx_probe) gst_pad_remove_probe(pm->vtx_pad, pm->vtx_probe);
		if (parent) gst_object_unref(parent);
		gst_object_unref(pm->vtx_pad);
		pm->vtx_pad = NULL;
		pm->vtx_probe = 0;
	}
	if (pm->vpipe) {
		if (pm->vadded_id) g_signal_handler_disconnect(pm->vpipe, pm->vadded_id);
		gst_object_unref(pm->vpipe);
		pm->vpipe = NULL;
		pm->vadded_id = 0;
	}
	if (pm->vsess) {
		g_signal_handlers_disconnect_matched(pm->vsess, G_SIGNAL_MATCH_FUNC, 0, 0, NULL, pm_on_sending_rtcp, NULL);
		g_signal_handlers_disconnect_matched(pm->vsess, G_SIGNAL_MATCH_FUNC, 0, 0, NULL, pm_on_rtcp_interval, NULL);
		g_object_unref(pm->vsess);
		pm->vsess = NULL;
	}
	if (pm->vrtpsession) {
		g_object_remove_weak_pointer(G_OBJECT(pm->vrtpsession), (gpointer *) &pm->vrtpsession);
		pm->vrtpsession = NULL;
	}
	if (pm->vnice) { g_ptr_array_unref(pm->vnice); pm->vnice = NULL; }
	if (pm->media) g_object_set_data(G_OBJECT(pm->media), PM_VX_KEY, NULL);
	pm_vx_unref(pm->vx);
	pm->vx = NULL;
}

/* Our camera on or off for the video session (VIDEO 1/0, and a new session while it is on): the
 * camera head's source started or stopped and let go of, the stream sending or not (libpurple's
 * PAUSE/UNPAUSE, which sets the Farstream stream's direction). The size we send is fixed at the
 * first start: the encoder is not asked to take another one later. */
static gboolean
pm_camera_set(TeamsPMedia *pm, gboolean on)
{
	PmVideo *vx = pm->vx;
	GstElement *venc;
	gboolean running;
	if (!vx || !vx->cam || !pm->media || !pm->vsid) {
		if (on) {
			pm_log("VIDEO 1: the video session has no camera");
			pm_emit(pm, "VIDEOERR tx\n");
		}
		return FALSE;
	}
	running = !gst_element_is_locked_state(vx->cam);
	if (!on) {
		purple_media_stream_info(pm->media, PURPLE_MEDIA_INFO_PAUSE, pm->vsid, PM_PEER, TRUE);
		gst_element_set_locked_state(vx->cam, TRUE);
		gst_element_set_state(vx->cam, GST_STATE_NULL);
		if (running) {
			pm_log("our camera off");
			pm_emit(pm, "VTX 0\n");
		}
		return FALSE;
	}
	g_atomic_int_set(&vx->tx_bps, (pm->cam_kbps > 0 ? pm->cam_kbps : PM_VIDEO_KBPS) * 1000);
	if (running) {
		/* on already: only the bitrate */
		g_mutex_lock(&vx->lock);
		venc = vx->venc ? gst_object_ref(vx->venc) : NULL;
		g_mutex_unlock(&vx->lock);
		if (venc) {
			g_object_set(venc, "target-bitrate", g_atomic_int_get(&vx->tx_bps), NULL);
			gst_object_unref(venc);
		}
		return TRUE;
	}
	g_mutex_lock(&vx->lock);
	venc = vx->venc ? gst_object_ref(vx->venc) : NULL;
	g_free(vx->pv_path);
	vx->pv_path = NULL;             /* VPREVIEW again on the self-view's first frame */
	g_mutex_unlock(&vx->lock);
	if (venc) {
		g_object_set(venc, "target-bitrate", g_atomic_int_get(&vx->tx_bps), NULL);
		gst_object_unref(venc);
	}
	if (!vx->sized && vx->send_caps && pm->cam_w > 0 && pm->cam_h > 0 && !g_getenv("TEAMS_PMEDIA_VSRC")) {
		/* what the far side lets us send, its long side on the picture's long side */
		gint w = pm->cam_w, h = pm->cam_h;
		GstCaps *caps;
		if ((vx->cw & 1) != (h > w)) { gint t = w; w = h; h = t; }
		caps = gst_caps_new_simple("video/x-raw", "format", G_TYPE_STRING, "NV12", "width", G_TYPE_INT, w & ~1,
		                           "height", G_TYPE_INT, h & ~1, "pixel-aspect-ratio", GST_TYPE_FRACTION, 1, 1, NULL);
		g_object_set(vx->send_caps, "caps", caps, NULL);
		gst_caps_unref(caps);
	}
	vx->sized = TRUE;
	gst_element_set_locked_state(vx->cam, FALSE);
	if (!gst_element_sync_state_with_parent(vx->cam) ||
	    gst_element_get_state(vx->cam, NULL, NULL, 0) == GST_STATE_CHANGE_FAILURE) {
		gst_element_set_locked_state(vx->cam, TRUE);
		gst_element_set_state(vx->cam, GST_STATE_NULL);
		pm_log("VIDEO 1: our camera did not start");
		pm_emit(pm, "VIDEOERR tx-camera\n");
		return FALSE;
	}
	purple_media_stream_info(pm->media, PURPLE_MEDIA_INFO_UNPAUSE, pm->vsid, PM_PEER, TRUE);
	vx->latency_due = TRUE;
	vx->frames_at_on = g_atomic_int_get(&vx->tx_frames);
	pm_log("our camera on, turned %d, %d kbit/s", vx->cw, g_atomic_int_get(&vx->tx_bps) / 1000);
	pm_emit(pm, "VTX 1\n");
	return TRUE;
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

/* Which of our sessions sid is: 0 audio, 1 the current video one, -1 neither (a video session
 * pm_video_restart ended, still signalling on its way out). */
static int
pm_sid_kind(const TeamsPMedia *pm, const char *sid)
{
	if (!g_strcmp0(sid, PM_SESSION)) return 0;
	return pm->vsid && !g_strcmp0(sid, pm->vsid) ? 1 : -1;
}

static void
pm_on_new_candidate(PurpleMedia *media, gchar *sid, gchar *who, PurpleMediaCandidate *cand, gpointer u)
{
	TeamsPMedia *pm = u;
	TeamsIceCand c;
	const char *type = pm_cand_type(purple_media_candidate_get_candidate_type(cand));
	gchar *foundation, *ip, *base_ip, *line;
	int kind = pm_sid_kind(pm, sid);
	gboolean video = kind == 1;
	gboolean *creds_sent = video ? &pm->vcreds_sent : &pm->creds_sent;
	(void) media; (void) who;
	if (kind < 0) return;

	if (purple_media_candidate_get_component_id(cand) != PURPLE_MEDIA_COMPONENT_RTP ||
	    purple_media_candidate_get_protocol(cand) != PURPLE_MEDIA_NETWORK_PROTOCOL_UDP || !type)
		return;   /* RTCP is muxed; Teams' parser rejects an answer over TCP lines */
	if (!*creds_sent) {
		gchar *uf = purple_media_candidate_get_username(cand);
		gchar *pw = purple_media_candidate_get_password(cand);
		if (!uf || !pw || !*uf || !*pw) {
			g_free(uf); g_free(pw);
			pm_fatal(pm, "local candidate without ICE credentials");
			return;
		}
		pm_emit(pm, video ? "VUFRAG %s\nVPWD %s\n" : "UFRAG %s\nPWD %s\n", uf, pw);
		g_free(uf); g_free(pw);
		*creds_sent = TRUE;
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
	pm_log("local %scandidate %s", video ? "video " : "", line);
	pm_emit(pm, "%s %s\n", video ? "VCAND" : "CAND", line);
	g_free(line);
}

/* GATHERED once every session has all its candidates. */
static void
pm_maybe_gathered(TeamsPMedia *pm)
{
	if (pm->gathered_sent || !pm->gathered || (pm->vx && !pm->vgathered)) return;
	pm->gathered_sent = TRUE;
	pm_log("local candidates complete");
	pm_emit(pm, "GATHERED\n");
}

static void
pm_on_candidates_prepared(PurpleMedia *media, gchar *sid, gchar *who, gpointer u)
{
	TeamsPMedia *pm = u;
	int kind = pm_sid_kind(pm, sid);
	gboolean video = kind == 1;
	(void) media; (void) who;
	if (kind < 0 || (video ? pm->vgathered : pm->gathered)) return;
	if (video) pm->vgathered = TRUE; else pm->gathered = TRUE;
	if (video && pm->vrestarting) {
		/* the new video session's credentials and candidates are out: the answer can go */
		pm->vrestarting = FALSE;
		if (!pm->vcreds_sent) {
			pm_log("the new video session has no local UDP candidates; the call stays voice only");
			pm_emit(pm, "VIDEOERR build\n");
			return;
		}
		if (pm->vx && g_atomic_int_get(&pm->vx->our_ssrc))
			pm_emit(pm, "VSSRC %u\n", (guint) g_atomic_int_get(&pm->vx->our_ssrc));
		pm_emit(pm, "VRESTARTED\n");
		return;
	}
	if (!(video ? pm->vcreds_sent : pm->creds_sent)) {
		pm_fatal(pm, video ? "no local UDP candidates for video" : "no local UDP candidates");
		return;
	}
	pm_maybe_gathered(pm);
}

static void
pm_on_pair(PurpleMedia *media, gchar *sid, gchar *who, PurpleMediaCandidate *local,
           PurpleMediaCandidate *remote, gpointer u)
{
	TeamsPMedia *pm = u;
	gchar *lip, *rip;
	int kind = pm_sid_kind(pm, sid);
	gboolean video = kind == 1;
	(void) media; (void) who;
	if (kind < 0) return;
	lip = purple_media_candidate_get_ip(local);
	rip = purple_media_candidate_get_ip(remote);
	pm_log("%sICE pair %s:%u <-> %s:%u", video ? "video " : "", lip ? lip : "?",
	       purple_media_candidate_get_port(local), rip ? rip : "?", purple_media_candidate_get_port(remote));
	g_free(lip); g_free(rip);
	if (video) {
		pm->vpaired = TRUE;
	} else if (!pm->paired) {
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
pm_set_rx_key(TeamsPMedia *pm, const char *sid, const char *b64)
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
	     purple_media_set_decryption_parameters(pm->media, sid, PM_PEER, PM_CIPHER, PM_AUTH,
	                                            (const gchar *) key, len);
	if (key) { explicit_bzero(key, len); g_free(key); }
	if (!ok) pm_log("the far side's %s key was not taken (%u bytes)", sid, (unsigned) len);
	return ok;
}

static void
pm_add_remote_cands(TeamsPMedia *pm, const char *sid, const char *ruf, const char *rpw, GList *cands)
{
	GList *l;
	for (l = cands; l; l = l->next)
		g_object_set(l->data, "username", ruf, "password", rpw, NULL);
	purple_media_add_remote_candidates(pm->media, sid, PM_PEER, cands);
}

static void
pm_set_remote_creds(TeamsPMedia *pm, const char *ruf, const char *rpw)
{
	g_free(pm->ruf); g_free(pm->rpw);
	pm->ruf = g_strdup(ruf); pm->rpw = g_strdup(rpw);
	if (pm->rcands_held && pm->media) {
		pm_add_remote_cands(pm, PM_SESSION, pm->ruf, pm->rpw, pm->rcands_held);
		pm_log("%u held remote candidate(s) added", g_list_length(pm->rcands_held));
	}
	g_list_free_full(pm->rcands_held, g_object_unref);
	pm->rcands_held = NULL;
}

static void
pm_set_remote_vcreds(TeamsPMedia *pm, const char *ruf, const char *rpw)
{
	g_free(pm->vruf); g_free(pm->vrpw);
	pm->vruf = g_strdup(ruf); pm->vrpw = g_strdup(rpw);
	if (pm->vrcands_held && pm->media && pm->vx) {
		pm_add_remote_cands(pm, pm->vsid, pm->vruf, pm->vrpw, pm->vrcands_held);
		pm_log("%u held remote video candidate(s) added", g_list_length(pm->vrcands_held));
	}
	g_list_free_full(pm->vrcands_held, g_object_unref);
	pm->vrcands_held = NULL;
}

/* A remote candidate for the audio session, or the video one: added now, or held until the
 * session and its credentials are there. */
static void
pm_rcand(TeamsPMedia *pm, const char *line, gboolean video)
{
	TeamsIceCand c;
	PurpleMediaCandidateType type;
	PurpleMediaCandidate *pc;
	const char *uf = video ? pm->vruf : pm->ruf, *pw = video ? pm->vrpw : pm->rpw;
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
	if (!pm->media || !uf || (video && !pm->vx)) {
		if (video) pm->vrcands_held = g_list_append(pm->vrcands_held, pc);
		else pm->rcands_held = g_list_append(pm->rcands_held, pc);
		return;
	}
	{
		GList one = { pc, NULL, NULL };
		pm_add_remote_cands(pm, video ? pm->vsid : PM_SESSION, uf, pw, &one);
	}
	g_object_unref(pc);
}

G_GNUC_BEGIN_IGNORE_DEPRECATIONS
/* One stream of ours to the far side, over ICE as RFC 5245 has it (NICE_COMPATIBILITY_RFC5245 is
 * 0), UDP only, with the STUN server if there is one; libpurple adds controlling-mode from the
 * initiator flag. */
static gboolean
pm_add_stream(TeamsPMedia *pm, const char *sid, PurpleMediaSessionType type, gboolean initiator)
{
	GParameter params[4];
	guint n = 0, i;
	gboolean ok;
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
	ok = purple_media_add_stream(pm->media, sid, PM_PEER, type, initiator, "nice", n, params);
	/* For the paths where libpurple returns before create_stream; a no-op for the others, as
	 * nothing here owns any memory. */
	for (i = 0; i < n; i++) g_value_unset(&params[i].value);
	return ok;
}
G_GNUC_END_IGNORE_DEPRECATIONS

/* The rtpsession element a session just added made: the one not in before. NULL if none. */
static GstElement *
pm_new_rtpsession(GHashTable *before)
{
	GstElement *found = NULL;
	gpointer u[2] = { before, &found };
	pm_each_rtpsession(pm_note_new_session, u);
	return found;
}

/* VSTART: the video session, on its own ICE stream. Our SRTP key is the audio's (our answer
 * gives every m-line the same a=crypto); the far side's (rxkey, with its ICE credentials) comes
 * from its video m-line when answering, with VANSWER when placing the call. Send and receive
 * when our camera can be sent (pm_camera_usable): its head is the session's source, and the
 * stream sends only while the camera is on (pm_camera_set); receive only otherwise. */
static void
pm_video_build(TeamsPMedia *pm, const char *rxkey, const char *ruf, const char *rpw, gboolean initiator)
{
	PurpleMediaManager *manager = purple_media_manager_get();
	gboolean send = pm_camera_usable();
	GHashTable *before;
	PurpleMediaCodec *h264;
	GList *codecs;
	GObject *sess = NULL;

	GHashTable *nice_before;
	if (!g_getenv("TEAMS_PMEDIA_HW_DECODE")) {
		/* droidvdec (sargo) ranks above avdec_h264, so Farstream would decode with it; the
		 * decoder teams_media uses, and the Phone app's picture has been tested with, is
		 * avdec_h264. Process-wide, and only GStreamer's calls use it here. */
		GstPluginFeature *f = gst_registry_lookup_feature(gst_registry_get(), "droidvdec");
		if (f) {
			gst_plugin_feature_set_rank(f, GST_RANK_NONE);
			gst_object_unref(f);
		}
	}
	pm->vx = g_new0(PmVideo, 1);
	pm->vx->refs = 1;
	pm->vx->tx_bps = (pm->cam_kbps > 0 ? pm->cam_kbps : PM_VIDEO_KBPS) * 1000;
	g_mutex_init(&pm->vx->lock);
	pm->peer_video = -1;
	pm_use_video_elements(manager, send);
	g_object_set_data_full(G_OBJECT(pm->media), PM_VX_KEY, pm_vx_ref(pm->vx), pm_vx_unref);

	before = g_hash_table_new(NULL, NULL);
	pm_each_rtpsession(pm_note_session, before);
	nice_before = pm_nicesinks(pm);
	if (!pm_add_stream(pm, pm->vsid, send ? PURPLE_MEDIA_VIDEO : PURPLE_MEDIA_RECV_VIDEO, initiator)) {
		g_hash_table_destroy(before);
		g_hash_table_destroy(nice_before);
		pm_log("the video stream could not be added; the call stays voice only");
		pm_emit(pm, "VIDEOERR build\n");
		pm_video_stop(pm);
		return;
	}
	pm->vrtpsession = pm_new_rtpsession(before);
	g_hash_table_destroy(before);
	{
		/* this session's nicesinks: the ones it added (Farstream makes them with the stream) */
		GHashTable *now = pm_nicesinks(pm);
		GHashTableIter hi;
		gpointer k;
		pm->vnice = g_ptr_array_new_with_free_func(gst_object_unref);
		g_hash_table_iter_init(&hi, now);
		while (g_hash_table_iter_next(&hi, &k, NULL))
			if (!g_hash_table_contains(nice_before, k)) g_ptr_array_add(pm->vnice, gst_object_ref(k));
		g_hash_table_destroy(now);
		g_hash_table_destroy(nice_before);
	}
	if (pm->vrtpsession) {
		g_object_add_weak_pointer(G_OBJECT(pm->vrtpsession), (gpointer *) &pm->vrtpsession);
		if (pm->other_sessions) g_hash_table_insert(pm->other_sessions, pm->vrtpsession, pm->vrtpsession);
		if (g_object_class_find_property(G_OBJECT_GET_CLASS(pm->vrtpsession), "internal-session"))
			g_object_get(pm->vrtpsession, "internal-session", &sess, NULL);
	}
	if (pm->vrtpsession) {
		/* the conference it is in: whose payloader is ours (pm_on_deep_added) */
		GstObject *o = GST_OBJECT(pm->vrtpsession);
		while (o && !GST_IS_PIPELINE(o)) {
			GstElementFactory *f = GST_IS_ELEMENT(o) ? gst_element_get_factory(GST_ELEMENT(o)) : NULL;
			if (f && !strcmp(GST_OBJECT_NAME(f), "fsrtpconference")) { pm->vx->conf = o; break; }
			o = GST_OBJECT_PARENT(o);
		}
		if (!pm->vx->conf) pm_log("the video session's conference was not found: our video goes with an SSRC of its own");
	}
	if (sess) {
		guint ssrc = 0;
		pm->vsess = sess;
		g_object_get(sess, "internal-ssrc", &ssrc, NULL);
		g_atomic_int_set(&pm->vx->our_ssrc, (gint) ssrc);
		g_signal_connect_data(sess, "on-sending-rtcp", G_CALLBACK(pm_on_sending_rtcp), pm_vx_ref(pm->vx),
		                      pm_vx_closure_unref, 0);
		g_signal_connect(sess, "notify::rtcp-min-interval", G_CALLBACK(pm_on_rtcp_interval), NULL);
		g_signal_connect_data(sess, "on-feedback-rtcp", G_CALLBACK(pm_on_feedback_rtcp), pm_vx_ref(pm->vx),
		                      pm_vx_closure_unref, 0);
		pm_on_rtcp_interval(sess, NULL, NULL);
	} else {
		pm_log("the video session's RTP session was not found: no PLI or REMB from us");
	}
	pm->vpipe = pm_vv.get_pipeline(manager);
	if (pm->vpipe) {
		gst_object_ref(pm->vpipe);
		pm->vadded_id = g_signal_connect_data(pm->vpipe, "deep-element-added", G_CALLBACK(pm_on_deep_added),
		                                      pm_vx_ref(pm->vx), pm_vx_closure_unref, 0);
	}

	purple_media_set_send_rtcp_mux(pm->media, pm->vsid, PM_PEER, TRUE);
	purple_media_set_require_encryption(pm->media, pm->vsid, PM_PEER, TRUE);
	if (!purple_media_set_encryption_parameters(pm->media, pm->vsid, PM_CIPHER, PM_AUTH,
	                                            (const gchar *) pm->txkey, sizeof pm->txkey)) {
		pm_log("our SRTP key was not taken for video; the call stays voice only");
		pm_emit(pm, "VIDEOERR build\n");
		purple_media_end(pm->media, pm->vsid, NULL);
		pm_video_stop(pm);
		return;
	}
	/* H264 on PT 107, packetization-mode 1, constrained baseline 3.1: what Teams offers and our
	 * answer takes (teams_calling.c's append_video_mline) */
	h264 = purple_media_codec_new(PM_H264_PT, "H264", PURPLE_MEDIA_VIDEO, 90000);
	purple_media_codec_add_optional_parameter(h264, "packetization-mode", "1");
	purple_media_codec_add_optional_parameter(h264, "profile-level-id", "42e01f");
	codecs = g_list_append(NULL, h264);
	if (!purple_media_set_remote_codecs(pm->media, pm->vsid, PM_PEER, codecs))
		pm_log("H264/%d was not taken as the remote video codec", PM_H264_PT);
	purple_media_codec_list_free(codecs);
	purple_media_set_output_window(pm->media, pm->vsid, PM_PEER, 0);

	if (ruf && rpw) {
		if (!rxkey || !pm_set_rx_key(pm, pm->vsid, rxkey)) {
			pm_log("the far side's video key was not taken; the call stays voice only");
			pm_emit(pm, "VIDEOERR build\n");
			purple_media_end(pm->media, pm->vsid, NULL);
			pm_video_stop(pm);
			return;
		}
		pm_set_remote_vcreds(pm, ruf, rpw);
		purple_media_stream_info(pm->media, PURPLE_MEDIA_INFO_ACCEPT, pm->vsid, PM_PEER, TRUE);
	}
	pm->vtick = g_timeout_add(PM_VTICK_MS, pm_vtick, pm);
	pm_log("video session %s started (%s), H264 PT %d, our RTCP SSRC %u", pm->vsid,
	       send && pm->vx->cam ? "send and receive" : "receive", PM_H264_PT, (guint) g_atomic_int_get(&pm->vx->our_ssrc));
	if (send && pm->vx->cam) {
		/* sending only while our camera is on; a new session (VRESTART) picks it up again */
		pm_emit(pm, "VCAMERA 1\n");
		if (pm->cam_on) pm->cam_on = pm_camera_set(pm, TRUE);
		else purple_media_stream_info(pm->media, PURPLE_MEDIA_INFO_PAUSE, pm->vsid, PM_PEER, TRUE);
	}
}

static void
pm_video_start(TeamsPMedia *pm, const char *rxkey, const char *ruf, const char *rpw)
{
	if (!pm->media) { pm_emit(pm, "ERR VSTART before START\n"); return; }
	if (pm->vx) { pm_emit(pm, "ERR video already started\n"); return; }
	if (pm->ready_sent) { pm_emit(pm, "ERR VSTART after READY\n"); return; }
	pm->vgen = 1;
	g_free(pm->vsid);
	pm->vsid = g_strdup(PM_VSESSION);
	pm_video_build(pm, rxkey, ruf, rpw, pm->caller);
}

/* VRESTART: the far side moved its video to new ICE credentials (a renegotiation that brings
 * the m=video back after dropping it, as Teams does after accepting a call we placed). Farstream
 * would restart ICE for a stream given no candidates, but libpurple always hands it every remote
 * candidate it was given, so the stream cannot take new credentials. Instead the video session
 * is replaced: the old one's nicesinks stopped (they may be blocked, see pm_release_transport),
 * the session ended, and a new one made under the next id, answering the far side's offer. Its
 * credentials and candidates go out as at the start (VUFRAG, VPWD, VCAND), then VRESTARTED. */
static void
pm_video_restart(TeamsPMedia *pm, const char *rxkey, const char *ruf, const char *rpw)
{
	gchar *old;
	if (!pm->media || !pm->vx || !pm->vsid) { pm_emit(pm, "ERR VRESTART without a video session\n"); return; }
	old = pm->vsid;
	pm->vsid = NULL;    /* its signals from here on are an ended session's (pm_sid_kind) */
	if (pm->vnice) {
		guint i;
		for (i = 0; i < pm->vnice->len; i++) pm_stop_nicesink(g_ptr_array_index(pm->vnice, i), NULL, NULL);
	}
	pm_video_stop(pm);
	purple_media_end(pm->media, old, NULL);
	pm_log("video session %s ended for the far side's new ICE", old);
	g_free(old);
	g_free(pm->vruf); g_free(pm->vrpw);
	pm->vruf = pm->vrpw = NULL;
	g_list_free_full(pm->vrcands_held, g_object_unref);
	pm->vrcands_held = NULL;
	pm->vcreds_sent = pm->vgathered = pm->vpaired = FALSE;
	pm->vgen++;
	pm->vsid = g_strdup_printf("%s%u", PM_VSESSION, pm->vgen);
	pm->vrestarting = TRUE;
	pm_video_build(pm, rxkey, ruf, rpw, FALSE);
	if (!pm->vx) pm->vrestarting = FALSE;   /* it failed, and said so (VIDEOERR build) */
}

G_GNUC_BEGIN_IGNORE_DEPRECATIONS
/* Create the media, its audio stream and keys. rxkey/ruf/rpw: the far side's, when answering. */
static void
pm_start(TeamsPMedia *pm, const char *rxkey, const char *ruf, const char *rpw)
{
	PurpleMediaManager *manager = purple_media_manager_get();
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

	pm->other_sessions = g_hash_table_new(NULL, NULL);
	pm_each_rtpsession(pm_note_session, pm->other_sessions);
	ok = pm_add_stream(pm, PM_SESSION, PURPLE_MEDIA_AUDIO, pm->caller);
	if (!ok) { pm_fatal(pm, "the audio stream could not be added"); return; }
	/* ours now, before a video session adds a second one (pm_find_ssrc looks again if not) */
	pm_each_rtpsession(pm_pick_session, pm);

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
		if (!pm_set_rx_key(pm, PM_SESSION, rxkey)) { pm_fatal(pm, "the far side's SRTP key was not taken"); return; }
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
	if (g_str_has_prefix(line, "RCAND ")) { pm_rcand(pm, line + 6, FALSE); return; }
	if (g_str_has_prefix(line, "VRCAND ")) { pm_rcand(pm, line + 7, TRUE); return; }
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
		else if (!pm_set_rx_key(pm, PM_SESSION, t[1])) pm_fatal(pm, "the far side's SRTP key was not taken");
		else {
			pm_set_remote_creds(pm, t[2], t[3]);
			purple_media_stream_info(pm->media, PURPLE_MEDIA_INFO_ACCEPT, PM_SESSION, PM_PEER, TRUE);
			pm_emit(pm, "ANSWERED\n");
		}
	} else if (!strcmp(t[0], "RESTART")) {
		pm_log("RESTART: an ICE restart is not supported");
		pm_emit(pm, "ERR restart is not supported by the PurpleMedia engine\n");
	} else if (!strcmp(t[0], "VSTART")) {
		if (n >= 4) pm_video_start(pm, t[1], t[2], t[3]);
		else if (pm->caller) pm_video_start(pm, NULL, NULL, NULL);
		else pm_emit(pm, "ERR VSTART without the far side's key and ICE credentials\n");
	} else if (!strcmp(t[0], "VANSWER") && n >= 4) {
		if (!pm->vx) pm_emit(pm, "ERR VANSWER without a video session\n");
		else if (!pm_set_rx_key(pm, pm->vsid, t[1])) pm_emit(pm, "VIDEOERR rx key\n");
		else {
			pm_set_remote_vcreds(pm, t[2], t[3]);
			purple_media_stream_info(pm->media, PURPLE_MEDIA_INFO_ACCEPT, pm->vsid, PM_PEER, TRUE);
		}
	} else if (!strcmp(t[0], "VRESTART") && n >= 4) {
		pm_video_restart(pm, t[1], t[2], t[3]);
	} else if (!strcmp(t[0], "VIDEO") && n > 1) {
		gboolean on = !strcmp(t[1], "1");
		if (on && n >= 5) {
			pm->cam_w = (gint) g_ascii_strtoll(t[2], NULL, 10);
			pm->cam_h = (gint) g_ascii_strtoll(t[3], NULL, 10);
			pm->cam_kbps = (gint) g_ascii_strtoll(t[4], NULL, 10);
		}
		if (on) {
			pm->cam_on = pm_camera_set(pm, TRUE);
		} else if (pm->cam_on) {
			pm->cam_on = FALSE;
			pm_camera_set(pm, FALSE);
		}
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
	g_free(pm->vruf);
	g_free(pm->vrpw);
	g_free(pm->vsid);
	g_free(pm);
}
