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
 */
#include "teams_call_pmedia.h"

#include <core.h>
#include <debug.h>
#include <eventloop.h>
#include <mediamanager.h>
#include <media-gst.h>
#include <util.h>

#include <gst/gst.h>
#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
}

static void side_free(Side *s)
{
	if (s->cmd >= 0) close(s->cmd);
	teams_pmedia_free(s->pm);
	g_source_remove_by_user_data(s);
	close(s->out);
	g_string_free(s->in, TRUE); g_string_free(s->cands, TRUE);
	g_free(s->txkey); g_free(s->ufrag); g_free(s->pwd); g_free(s->last_err);
}

/* ---- counting what reaches the sinks ---- */
static GHashTable *counts;   /* GstElement* -> buffers: our receive sinks (TEAMS_PMEDIA_SINK) */

static GstPadProbeReturn count_probe(GstPad *pad, GstPadProbeInfo *info, gpointer u)
{
	gpointer k = u;
	(void) pad; (void) info;
	g_hash_table_insert(counts, k, GUINT_TO_POINTER(GPOINTER_TO_UINT(g_hash_table_lookup(counts, k)) + 1));
	return GST_PAD_PROBE_OK;
}

static gint n_bufs, n_lists;
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

static void probe_sinks(void)
{
	GstElement *pipe = purple_media_manager_get_pipeline(purple_media_manager_get());
	GstIterator *it;
	GValue v = G_VALUE_INIT;
	gboolean done = FALSE;
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
			if (f && !strcmp(GST_OBJECT_NAME(f), "fakesink") && !g_hash_table_contains(counts, e) &&
			    fed_by_level(e)) {
				GstPad *p = gst_element_get_static_pad(e, "sink");
				g_hash_table_insert(counts, e, GUINT_TO_POINTER(0));
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
	case 0:   /* A places the call */
		side_send(&A, "START 102\n");
		step = 1;
		break;
	case 1:   /* A's offer is complete: B answers it */
		if (A.gathered && A.txkey && A.ufrag && A.pwd) {
			side_send(&B, "START %s %s %s 102\n", A.txkey, A.ufrag, A.pwd);
			side_send_cands(&B, &A);
			step = 2;
		}
		break;
	case 2:   /* B's answer is complete: A takes it */
		if (B.gathered && B.txkey && B.ufrag && B.pwd) {
			side_send(&A, "ANSWER %s %s %s\n", B.txkey, B.ufrag, B.pwd);
			side_send_cands(&A, &B);
			step = 3; ticks = 0;
		}
		break;
	case 3:   /* let audio run for 6 s, then a RESTART */
		if (ticks >= 12) {
			ssrc_a_ok = session_sends_ssrc(A.ssrc);
			ssrc_b_ok = session_sends_ssrc(B.ssrc);
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

int main(int argc, char **argv)
{
	gchar *home = g_build_filename(g_get_current_dir(), "pmtest-home", NULL);
	GHashTableIter hi;
	gpointer k, v;
	guint sinks = 0, fed = 0;
	(void) argc; (void) argv;

	if (!g_getenv("TEAMS_PMEDIA_SINK")) { fprintf(stderr, "set TEAMS_PMEDIA_SRC/TEAMS_PMEDIA_SINK\n"); return 2; }
	counts = g_hash_table_new(NULL, NULL);
	nice_seen = g_hash_table_new(NULL, NULL);
	purple_util_set_user_dir(home);
	purple_debug_set_enabled(g_getenv("PMTEST_DEBUG") != NULL);
	purple_eventloop_set_ui_ops(&loop_ops);
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
	g_hash_table_iter_init(&hi, counts);
	while (g_hash_table_iter_next(&hi, &k, &v)) {
		sinks++;
		fprintf(stderr, "sink %s: %u buffers\n", GST_OBJECT_NAME(k), GPOINTER_TO_UINT(v));
		if (GPOINTER_TO_UINT(v) > 50) fed++;
	}
	CHECK(sinks == 2);            /* A's and B's receive sink */
	CHECK(fed == 2);              /* audio both ways, decrypted and decoded */
	CHECK(B.errs == 1 && B.last_err && strstr(B.last_err, "restart"));
	CHECK(!B.closed && !A.closed);
	CHECK(A.errs == 0);
	CHECK(C.errs >= 1 && C.closed);
	CHECK(D.txkey && D.errs == 0 && !D.closed);

	side_send(&A, "STOP\n");
	side_free(&A);
	side_free(&B);
	side_free(&C);
	side_free(&D);
	purple_core_quit();
	g_main_loop_unref(loop);
	g_hash_table_destroy(counts);
	g_free(home);
	if (failures) { fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	printf("PASS test_pmedia_loopback\n");
	return 0;
}
