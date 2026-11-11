/* The in-process media engine for 1:1 calls: libpurple's PurpleMedia (Farstream) in place of the
 * teams_media process. It takes the same command lines teams_media reads on its stdin and writes
 * the same lines teams_media prints (see teams_media.c), over two socketpairs, so
 * teams_calling.c drives both engines the same way. Video goes on an ICE stream of its own
 * (VSTART, VSSRC): the far side's is received, and our camera is sent where the system has one
 * the engine can use (VCAMERA 1). A renegotiation that moves the video to new ICE replaces the
 * video session (VRESTART); the audio has no ICE restart (RESTART answers ERR). Built with
 * TEAMS_PURPLEMEDIA, for libpurple 2 built with voice and video (USE_VV); without that, starting
 * a call with it fails cleanly. */
#ifndef TEAMS_CALL_PMEDIA_H
#define TEAMS_CALL_PMEDIA_H

#include <glib.h>
#include <account.h>

typedef struct _TeamsPMedia TeamsPMedia;

/* Start the engine for a call on account: it reads commands from cmd_fd and writes its lines to
 * out_fd, and owns and closes both. caller: we place the call (teams_media --caller). NULL if it
 * could not start; the fds are closed then too. */
TeamsPMedia *teams_pmedia_start(PurpleAccount *account, gboolean caller, int cmd_fd, int out_fd);

/* End the call's media and free the engine (NULL is ignored). */
void teams_pmedia_free(TeamsPMedia *pm);

#endif
