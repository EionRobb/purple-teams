/* The PurpleMedia engine on a libpurple built without voice and video (no USE_VV): it has to
 * load (it links no libpurple call that such a libpurple lacks) and refuse a call cleanly - an ERR
 * line and its output closed, which teams_calling.c takes as the media being lost. Run against
 * that libpurple; against one with voice and video it fails (the START is then taken). */
#include "teams_call_pmedia.h"

#include <core.h>
#include <debug.h>
#include <eventloop.h>
#include <util.h>

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;
#define CHECK(c) do { if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
                      else fprintf(stderr, "ok   %s\n", #c); } while (0)

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

static GMainLoop *loop;
static GString *got;
static gboolean closed;

static gboolean readable(GIOChannel *ch, GIOCondition c, gpointer u)
{
	char buf[1024];
	ssize_t n = read(g_io_channel_unix_get_fd(ch), buf, sizeof buf);
	(void) c; (void) u;
	if (n <= 0) { closed = TRUE; g_main_loop_quit(loop); return G_SOURCE_REMOVE; }
	g_string_append_len(got, buf, n);
	return G_SOURCE_CONTINUE;
}

static gboolean give_up(gpointer u)
{
	(void) u;
	g_main_loop_quit(loop);
	return G_SOURCE_REMOVE;
}

int main(void)
{
	/* a 44-byte key, as Teams sends: 32 key + 12 salt bytes (made up) */
	static const char start[] = "START AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKis= uf pw 102\n";
	gchar *home = g_build_filename(g_get_current_dir(), "pmtest-home", NULL);
	int a[2], b[2];
	TeamsPMedia *pm;
	PurpleAccount *account;
	GIOChannel *ch;

	got = g_string_new("");
	purple_util_set_user_dir(home);
	purple_debug_set_enabled(FALSE);
	purple_eventloop_set_ui_ops(&loop_ops);
	if (!purple_core_init("pmtest")) { fprintf(stderr, "purple_core_init failed\n"); return 2; }
	account = purple_account_new("pmtest@localhost", "prpl-pmtest");
	loop = g_main_loop_new(NULL, FALSE);
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, a) || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, b))
		return 2;
	pm = teams_pmedia_start(account, FALSE, a[1], b[1]);
	CHECK(pm != NULL);
	ch = g_io_channel_unix_new(b[0]);
	g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR, readable, NULL);
	g_io_channel_unref(ch);
	CHECK(send(a[0], start, strlen(start), MSG_NOSIGNAL) == (ssize_t) strlen(start));
	g_timeout_add_seconds(10, give_up, NULL);
	g_main_loop_run(loop);

	fprintf(stderr, "engine said: %s", got->str);
	CHECK(strstr(got->str, "ERR libpurple was built without voice and video") != NULL);
	CHECK(strstr(got->str, "TXKEY") == NULL);    /* nothing was started */
	CHECK(closed);

	close(a[0]);
	teams_pmedia_free(pm);
	close(b[0]);
	purple_core_quit();
	g_main_loop_unref(loop);
	g_string_free(got, TRUE);
	g_free(home);
	if (failures) { fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	printf("PASS test_pmedia_novv\n");
	return 0;
}
