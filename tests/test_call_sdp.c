/* Unit test for teams_call_sdp.c (GLib only): make check */
#include "teams_call_sdp.h"
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(c) do { if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)


/* The m=video shapes of the captured Teams offers (masked: ports, keys and SSRCs made up). */
static const char *OFFER_ANDROID =
	"v=0\r\nm=audio 50000 RTP/SAVP 102 101\r\na=sendrecv\r\na=mid:1\r\n"
	"m=video 50001 RTP/SAVP 119 100 122 125 107 99 114 115 123\r\na=x-ssrc-range:1-100\r\n"
	"a=recvonly\r\na=mid:2\r\nm=application 50002 RTP/SAVP 127\r\na=sendrecv\r\n";
static const char *OFFER_RENEG =
	"v=0\r\nm=audio 1 RTP/SAVP 102\r\na=sendrecv\r\nm=video 1 RTP/SAVP 107 99\r\na=inactive\r\n";
static const char *OFFER_VIDEO =
	"v=0\r\nm=audio 1 RTP/SAVP 102\r\na=recvonly\r\nm=video 1 RTP/SAVP 107 99\r\na=label:main-video\r\n";
static const char *OFFER_SENDONLY =
	"v=0\r\nm=audio 1 RTP/SAVP 102\r\nm=video 1 RTP/SAVP 107\r\na=sendonly\r\n";
static const char *OFFER_DECLINED =
	"v=0\r\nm=audio 1 RTP/SAVP 102\r\nm=video 0 RTP/SAVP 107\r\na=sendrecv\r\n";
/* a second video section (screen sharing) does not count for the main video */
static const char *OFFER_TWO_VIDEO =
	"v=0\r\nm=audio 1 RTP/SAVP 102\r\nm=video 1 RTP/SAVP 107\r\na=inactive\r\na=label:main-video\r\n"
	"m=video 1 RTP/SAVP 107\r\na=sendrecv\r\na=label:applicationsharing-video\r\n";
static const char *OFFER_AUDIO = "v=0\r\nm=audio 1 RTP/SAVP 102\r\na=sendonly\r\n";
/* a direction at the session level holds for a section that names none (RFC 4566 6) */
static const char *OFFER_SESSION_DIR =
	"v=0\r\na=recvonly\r\nm=audio 1 RTP/SAVP 102\r\nm=video 1 RTP/SAVP 107\r\n";
static const char *OFFER_SESSION_DIR_OVERRIDDEN =
	"v=0\r\na=inactive\r\nm=audio 1 RTP/SAVP 102\r\nm=video 1 RTP/SAVP 107\r\na=sendonly\r\n";

static void test_sdp_direction(void)
{
	CHECK(!g_strcmp0(teams_sdp_video_direction(OFFER_ANDROID), "recvonly"));
	CHECK(!g_strcmp0(teams_sdp_video_direction(OFFER_RENEG), "inactive"));
	CHECK(!g_strcmp0(teams_sdp_video_direction(OFFER_VIDEO), "sendrecv"));   /* none named */
	CHECK(!g_strcmp0(teams_sdp_video_direction(OFFER_SENDONLY), "sendonly"));
	CHECK(teams_sdp_video_direction(OFFER_DECLINED) == NULL);
	CHECK(teams_sdp_video_direction(OFFER_AUDIO) == NULL);
	CHECK(!g_strcmp0(teams_sdp_video_direction(OFFER_TWO_VIDEO), "inactive"));
	CHECK(teams_sdp_video_direction(NULL) == NULL);
	CHECK(!g_strcmp0(teams_sdp_video_direction(OFFER_SESSION_DIR), "recvonly"));
	CHECK(!g_strcmp0(teams_sdp_video_direction(OFFER_SESSION_DIR_OVERRIDDEN), "sendonly"));
	/* the audio section's own direction is not the session's */
	CHECK(!g_strcmp0(teams_sdp_video_direction(OFFER_VIDEO), "sendrecv"));
}

static void test_answer_direction(void)
{
	/* camera off: receive what the far side sends, else inactive (what 0019 always answered) */
	CHECK(!strcmp(teams_video_answer_direction("recvonly", TRUE, FALSE), "inactive"));
	CHECK(!strcmp(teams_video_answer_direction("inactive", TRUE, FALSE), "inactive"));
	CHECK(!strcmp(teams_video_answer_direction("sendrecv", TRUE, FALSE), "recvonly"));
	CHECK(!strcmp(teams_video_answer_direction("sendonly", TRUE, FALSE), "recvonly"));
	/* camera on */
	CHECK(!strcmp(teams_video_answer_direction("sendrecv", TRUE, TRUE), "sendrecv"));
	CHECK(!strcmp(teams_video_answer_direction("recvonly", TRUE, TRUE), "sendonly"));
	CHECK(!strcmp(teams_video_answer_direction("sendonly", TRUE, TRUE), "recvonly"));
	CHECK(!strcmp(teams_video_answer_direction("inactive", TRUE, TRUE), "inactive"));
	/* an engine without video, or no video m-line: inactive */
	CHECK(!strcmp(teams_video_answer_direction("sendrecv", FALSE, TRUE), "inactive"));
	CHECK(!strcmp(teams_video_answer_direction(NULL, TRUE, TRUE), "inactive"));

	CHECK(teams_video_dir_we_send("sendrecv") && teams_video_dir_we_send("sendonly"));
	CHECK(!teams_video_dir_we_send("recvonly") && !teams_video_dir_we_send("inactive") && !teams_video_dir_we_send(NULL));
	CHECK(teams_video_dir_peer_sends("sendrecv") && teams_video_dir_peer_sends("sendonly"));
	CHECK(!teams_video_dir_peer_sends("recvonly") && !teams_video_dir_peer_sends("inactive") && !teams_video_dir_peer_sends(NULL));

	/* our sendrecv offer answered: the mirror of the answer */
	CHECK(!strcmp(teams_video_our_direction("sendrecv"), "sendrecv"));
	CHECK(!strcmp(teams_video_our_direction("recvonly"), "sendonly"));
	CHECK(!strcmp(teams_video_our_direction("sendonly"), "recvonly"));
	CHECK(!strcmp(teams_video_our_direction("inactive"), "inactive"));
	CHECK(!strcmp(teams_video_our_direction(NULL), "inactive"));
}

/* Our own offer when the camera comes on or goes off mid-call, and its negotiationTag. */
static void test_needs_offer(void)
{
	gchar *t;
	CHECK(teams_video_needs_offer(TRUE, TRUE, TRUE, "recvonly", FALSE));
	CHECK(teams_video_needs_offer(TRUE, TRUE, TRUE, "inactive", FALSE));
	CHECK(teams_video_needs_offer(TRUE, TRUE, TRUE, NULL, FALSE));      /* a voice call we placed */
	CHECK(!teams_video_needs_offer(TRUE, TRUE, TRUE, "sendrecv", FALSE)); /* already sending */
	CHECK(!teams_video_needs_offer(TRUE, TRUE, TRUE, "sendonly", FALSE));
	CHECK(!teams_video_needs_offer(FALSE, TRUE, TRUE, "recvonly", FALSE)); /* camera off, not sending */
	CHECK(!teams_video_needs_offer(FALSE, TRUE, TRUE, "inactive", FALSE));
	CHECK(!teams_video_needs_offer(FALSE, TRUE, TRUE, NULL, FALSE));
	CHECK(teams_video_needs_offer(FALSE, TRUE, TRUE, "sendrecv", FALSE));   /* camera off while sending */
	CHECK(teams_video_needs_offer(FALSE, TRUE, TRUE, "sendonly", FALSE));
	CHECK(teams_video_needs_offer(FALSE, FALSE, TRUE, "sendrecv", FALSE));
	CHECK(!teams_video_needs_offer(FALSE, TRUE, FALSE, "sendrecv", FALSE)); /* not negotiated yet */
	CHECK(!teams_video_needs_offer(FALSE, TRUE, TRUE, "sendrecv", TRUE));   /* one already waiting */
	CHECK(!strcmp(teams_video_offer_direction(TRUE), "sendrecv"));
	CHECK(!strcmp(teams_video_offer_direction(FALSE), "recvonly"));
	CHECK(!teams_video_needs_offer(TRUE, FALSE, TRUE, "recvonly", FALSE)); /* engine without video */
	CHECK(!teams_video_needs_offer(TRUE, TRUE, FALSE, "recvonly", FALSE)); /* the first answer carries it */
	CHECK(!teams_video_needs_offer(TRUE, TRUE, TRUE, "recvonly", TRUE));   /* one already waiting */

	t = teams_negotiation_tag("0b1c2d3e-0000-4000-8000-000000000001", 1);
	CHECK(t && !strcmp(t, "0b1c2d3e-0000-4000-8000-000000000001;v_1"));
	g_free(t);
	t = teams_negotiation_tag("p", 12);
	CHECK(t && !strcmp(t, "p;v_12"));
	g_free(t);
	CHECK(!teams_negotiation_tag(NULL, 1));
	CHECK(!teams_negotiation_tag("", 1));
	CHECK(!teams_negotiation_tag("p", 0));
}

static void test_send_params(void)
{
	int w, h, k;
	static const char *ANDROID =
		"v=0\r\nm=audio 1 RTP/SAVP 102\r\na=fmtp:107 max-fs=1\r\nm=video 1 RTP/SAVP 107 99\r\n"
		"a=fmtp:107 profile-level-id=42C02A;packetization-mode=1;max-mbps=3600;max-fs=240;max-br=208;max-fps=1500\r\n";
	static const char *WEB =
		"v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 level-asymmetry-allowed=1;packetization-mode=1;"
		"profile-level-id=42e01f;max-fs=8160;max-mbps=244800;max-fps=3000\r\n";
	static const char *CIF = "v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=396;max-br=500\r\n";
	static const char *QVGA = "v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=1200;max-mbps=9000\r\n";
	/* limits none of our settings fit: no camera */
	static const char *TOO_SMALL = "v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=10;max-br=8\r\n";
	static const char *FS_TOO_SMALL = "v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=98\r\n";
	static const char *MBPS_TOO_SMALL = "v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-mbps=2969\r\n";
	/* a size that fits, and a rate below what we send at */
	static const char *BR_TOO_SMALL = "v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=8160;max-br=31\r\n";
	/* the smallest of each that is still ours */
	static const char *LOWEST = "v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=99;max-mbps=2970;max-br=32\r\n";
	/* only the first video section's fmtp counts */
	static const char *TWO = "v=0\r\nm=video 1 RTP/SAVP 107\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=99\r\n";
	CHECK(teams_video_send_params(ANDROID, &w, &h, &k));
	CHECK(w == 176 && h == 144 && k == 208);
	CHECK(teams_video_send_params(WEB, &w, &h, &k));
	CHECK(w == 640 && h == 480 && k == 800);
	CHECK(teams_video_send_params(CIF, &w, &h, &k));
	CHECK(w == 352 && h == 288 && k == 500);
	CHECK(teams_video_send_params(QVGA, &w, &h, &k));     /* 640x480 fits the size, not the rate */
	CHECK(w == 320 && h == 240 && k == 800);
	CHECK(!teams_video_send_params(TOO_SMALL, &w, &h, &k));
	CHECK(w == 0 && h == 0 && k == 0);
	w = h = k = -1;
	CHECK(!teams_video_send_params(FS_TOO_SMALL, &w, &h, &k));
	CHECK(w == 0 && h == 0 && k == 0);
	CHECK(!teams_video_send_params(MBPS_TOO_SMALL, &w, &h, &k));
	CHECK(!teams_video_send_params(BR_TOO_SMALL, &w, &h, &k));
	CHECK(w == 0 && h == 0 && k == 0);
	CHECK(teams_video_send_params(LOWEST, &w, &h, &k));
	CHECK(w == 176 && h == 144 && k == 32);
	CHECK(teams_video_send_params(TWO, &w, &h, &k));
	CHECK(w == 640 && h == 480);
	CHECK(teams_video_send_params(NULL, &w, &h, &k));
	CHECK(w == 640 && h == 480 && k == 800);
}

static void test_ice_candidate(void)
{
	TeamsIceCand c;
	gchar *f;
	/* libnice's own shape (teams_media's CAND lines) */
	CHECK(teams_ice_candidate_parse("candidate:1 1 UDP 2015363327 192.168.1.5 50523 typ host", &c));
	CHECK(!strcmp(c.foundation, "1") && c.component == 1 && c.udp && c.priority == 2015363327u);
	CHECK(!strcmp(c.ip, "192.168.1.5") && c.port == 50523 && !strcmp(c.type, "host") && !c.raddr[0]);
	f = teams_ice_candidate_format(&c);
	CHECK(!strcmp(f, "candidate:1 1 UDP 2015363327 192.168.1.5 50523 typ host"));
	g_free(f);
	/* a Teams offer's, with a=, raddr/rport and trailing attributes (addresses made up) */
	CHECK(teams_ice_candidate_parse("a=candidate:3 1 UDP 1694498815 203.0.113.7 3480 typ srflx "
	                                "raddr 10.0.0.2 rport 3480 generation 0\r", &c));
	CHECK(!strcmp(c.type, "srflx") && !strcmp(c.raddr, "10.0.0.2") && c.rport == 3480 && c.port == 3480);
	f = teams_ice_candidate_format(&c);
	CHECK(!strcmp(f, "candidate:3 1 UDP 1694498815 203.0.113.7 3480 typ srflx raddr 10.0.0.2 rport 3480"));
	g_free(f);
	/* the TCP ones Teams sends are parsed, and marked */
	CHECK(teams_ice_candidate_parse("candidate:4 1 TCP-ACT 1 203.0.113.7 3478 typ relay", &c) && !c.udp);
	CHECK(teams_ice_candidate_parse("candidate:2  2 udp 5 ::1 9 typ relay", &c) && c.udp && c.component == 2);
	/* not candidates */
	CHECK(!teams_ice_candidate_parse(NULL, &c));
	CHECK(!teams_ice_candidate_parse("a=ice-ufrag:abc", &c));
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP 5 1.2.3.4 70000 typ host", &c));   /* port */
	CHECK(!teams_ice_candidate_parse("candidate:1 0 UDP 5 1.2.3.4 7 typ host", &c));       /* component */
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP 4294967296 1.2.3.4 7 typ host", &c));
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP 5 1.2.3.4 7 typ bogus", &c));
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP 5 1.2.3.4 7 host", &c));
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP 5 1.2.3.4", &c));
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP -5 1.2.3.4 7 typ host", &c));
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP 5 1.2.3.4 7 typ host raddr 1.2.3.4 rport x", &c));
	CHECK(c.port == 0 && !c.ip[0]);   /* left cleared on failure */
	/* an extension name without its value */
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP 5 1.2.3.4 7 typ srflx raddr 10.0.0.2 rport", &c));
	CHECK(c.port == 0 && !c.raddr[0]);
	CHECK(!teams_ice_candidate_parse("candidate:1 1 UDP 5 1.2.3.4 7 typ host generation", &c));
	CHECK(teams_ice_candidate_parse("candidate:1 1 UDP 5 1.2.3.4 7 typ host generation 0", &c));
}


/* The Teams Android app's offer: BUNDLE named, yet each section has its own ICE (masked). */
static const char *OFFER_OWN_ICE =
	"v=0\r\na=group:BUNDLE audio_0 video_1\r\n"
	"m=audio 3480 RTP/SAVP 102\r\na=ice-ufrag:AUDIOuf\r\na=ice-pwd:audiopwd\r\n"
	"a=candidate:1 1 UDP 1 10.0.0.1 3480 typ host\r\na=mid:audio_0\r\n"
	"m=video 3480 RTP/SAVP 107 99\r\na=ice-ufrag:VIDEOuf\r\na=ice-pwd:videopwd\r\n"
	"a=candidate:2 1 UDP 1 10.0.0.1 3480 typ host\r\na=mid:video_1\r\n"
	"m=application 9 RTP/SAVP 127\r\na=mid:data_2\r\n";
static const char *OFFER_SHARED_ICE =
	"v=0\r\nm=audio 1 RTP/SAVP 102\r\na=ice-ufrag:same\r\na=ice-pwd:p\r\n"
	"m=video 1 RTP/SAVP 107\r\na=ice-ufrag:same\r\na=ice-pwd:p\r\n";
static const char *OFFER_VIDEO_NO_PWD =
	"v=0\r\nm=audio 1 RTP/SAVP 102\r\na=ice-ufrag:a\r\na=ice-pwd:p\r\n"
	"m=video 1 RTP/SAVP 107\r\na=ice-ufrag:v\r\n";

/* Audio's ICE credentials at the session level only: the video's own differ from those. */
static const char *OFFER_SESSION_ICE =
	"v=0\r\na=ice-ufrag:SESSIONuf\r\na=ice-pwd:sessionpwd\r\n"
	"m=audio 1 RTP/SAVP 102\r\na=mid:0\r\n"
	"m=video 1 RTP/SAVP 107\r\na=ice-ufrag:VIDEOuf\r\na=ice-pwd:videopwd\r\na=mid:1\r\n";
/* ... and the video's the same as those: one transport */
static const char *OFFER_SESSION_ICE_SHARED =
	"v=0\r\na=ice-ufrag:SESSIONuf\r\na=ice-pwd:sessionpwd\r\n"
	"m=audio 1 RTP/SAVP 102\r\n"
	"m=video 1 RTP/SAVP 107\r\na=ice-ufrag:SESSIONuf\r\na=ice-pwd:sessionpwd\r\n";
/* video before audio, each with ICE of its own */
static const char *OFFER_VIDEO_FIRST =
	"v=0\r\nm=video 1 RTP/SAVP 107\r\na=ice-ufrag:VIDEOuf\r\na=ice-pwd:videopwd\r\na=mid:0\r\n"
	"m=audio 1 RTP/SAVP 102\r\na=ice-ufrag:AUDIOuf\r\na=ice-pwd:audiopwd\r\na=mid:1\r\n";
static const char *OFFER_DECLINED_MID =
	"v=0\r\nm=audio 1 RTP/SAVP 102\r\na=mid:1\r\nm=video 0 RTP/SAVP 107\r\na=mid:2\r\n";

static void test_audio_attr(void)
{
	gchar *v;
	v = teams_sdp_audio_attr(OFFER_OWN_ICE, "ice-ufrag");
	CHECK(v && !strcmp(v, "AUDIOuf"));
	g_free(v);
	v = teams_sdp_audio_attr(OFFER_VIDEO_FIRST, "ice-ufrag");   /* not the first in the SDP */
	CHECK(v && !strcmp(v, "AUDIOuf"));
	g_free(v);
	v = teams_sdp_audio_attr(OFFER_VIDEO_FIRST, "ice-pwd");
	CHECK(v && !strcmp(v, "audiopwd"));
	g_free(v);
	v = teams_sdp_audio_attr(OFFER_SESSION_ICE, "ice-ufrag");   /* the session level's */
	CHECK(v && !strcmp(v, "SESSIONuf"));
	g_free(v);
	v = teams_sdp_audio_attr(OFFER_SESSION_ICE, "ice-pwd");
	CHECK(v && !strcmp(v, "sessionpwd"));
	g_free(v);
	/* the video's is not the session's */
	CHECK(teams_sdp_audio_attr("v=0\r\nm=audio 1 RTP/SAVP 102\r\nm=video 1 RTP/SAVP 107\r\na=ice-ufrag:v\r\n",
	                           "ice-ufrag") == NULL);
	CHECK(teams_sdp_audio_attr(OFFER_AUDIO, "ice-ufrag") == NULL);
	CHECK(teams_sdp_audio_attr(NULL, "ice-ufrag") == NULL);

	CHECK(teams_sdp_video_ice_own(OFFER_SESSION_ICE));
	CHECK(!teams_sdp_video_ice_own(OFFER_SESSION_ICE_SHARED));
	CHECK(teams_sdp_video_ice_own(OFFER_VIDEO_FIRST));

	CHECK(teams_sdp_video_first(OFFER_VIDEO_FIRST));
	CHECK(!teams_sdp_video_first(OFFER_OWN_ICE));
	CHECK(!teams_sdp_video_first(OFFER_AUDIO));
	CHECK(!teams_sdp_video_first(NULL));
}

static void test_declined(void)
{
	gchar *v = teams_sdp_section_all(OFFER_DECLINED_MID, "video");
	CHECK(v && !strcmp(v, "m=video 0 RTP/SAVP 107\r\na=mid:2\r\n"));
	g_free(v);
	CHECK(teams_sdp_section(OFFER_DECLINED_MID, "video") == NULL);
	v = teams_sdp_section_all(OFFER_OWN_ICE, "video");
	CHECK(v && g_str_has_prefix(v, "m=video 3480 "));
	g_free(v);
	CHECK(teams_sdp_section_all(OFFER_AUDIO, "video") == NULL);
	CHECK(teams_sdp_video_declined(OFFER_DECLINED_MID));
	CHECK(teams_sdp_video_declined(OFFER_DECLINED));
	CHECK(!teams_sdp_video_declined(OFFER_OWN_ICE));
	CHECK(!teams_sdp_video_declined(OFFER_AUDIO));
	CHECK(!teams_sdp_video_declined(NULL));
}

static void test_sections(void)
{
	gchar *a = teams_sdp_section(OFFER_OWN_ICE, "audio"), *v = teams_sdp_section(OFFER_OWN_ICE, "video");
	gchar *x = teams_sdp_section(OFFER_OWN_ICE, "application"), *last = teams_sdp_section(OFFER_AUDIO, "audio");
	CHECK(a && g_str_has_prefix(a, "m=audio 3480 ") && strstr(a, "AUDIOuf") && !strstr(a, "VIDEOuf"));
	CHECK(a && g_str_has_suffix(a, "a=mid:audio_0\r\n"));
	CHECK(v && g_str_has_prefix(v, "m=video 3480 ") && strstr(v, "VIDEOuf") && !strstr(v, "data_2"));
	CHECK(x && !strcmp(x, "m=application 9 RTP/SAVP 127\r\na=mid:data_2\r\n"));   /* the last one */
	CHECK(last && !strcmp(last, "m=audio 1 RTP/SAVP 102\r\na=sendonly\r\n"));
	CHECK(teams_sdp_section(OFFER_DECLINED, "video") == NULL);
	CHECK(teams_sdp_section(OFFER_AUDIO, "video") == NULL);
	CHECK(teams_sdp_section(NULL, "video") == NULL);
	g_free(a); g_free(v); g_free(x); g_free(last);
	/* "m=video" must not match "m=videox" */
	CHECK(teams_sdp_section("v=0\r\nm=videox 1 RTP/SAVP 1\r\n", "video") == NULL);

	CHECK(teams_sdp_video_ice_own(OFFER_OWN_ICE));
	CHECK(!teams_sdp_video_ice_own(OFFER_SHARED_ICE));
	CHECK(!teams_sdp_video_ice_own(OFFER_VIDEO_NO_PWD));
	CHECK(!teams_sdp_video_ice_own(OFFER_DECLINED));
	CHECK(!teams_sdp_video_ice_own(OFFER_AUDIO));
	CHECK(!teams_sdp_video_ice_own(NULL));
}

int main(void)
{
	test_ice_candidate();
	test_send_params();
	test_sdp_direction();
	test_answer_direction();
	test_needs_offer();
	test_sections();
	test_audio_attr();
	test_declined();
	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("PASS test_call_sdp\n");
	return 0;
}
