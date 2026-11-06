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
	static const char *TOO_SMALL = "v=0\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=10;max-br=8\r\n";
	/* only the first video section's fmtp counts */
	static const char *TWO = "v=0\r\nm=video 1 RTP/SAVP 107\r\nm=video 1 RTP/SAVP 107\r\na=fmtp:107 max-fs=99\r\n";
	teams_video_send_params(ANDROID, &w, &h, &k);
	CHECK(w == 176 && h == 144 && k == 208);
	teams_video_send_params(WEB, &w, &h, &k);
	CHECK(w == 640 && h == 480 && k == 800);
	teams_video_send_params(CIF, &w, &h, &k);
	CHECK(w == 352 && h == 288 && k == 500);
	teams_video_send_params(QVGA, &w, &h, &k);     /* 640x480 fits the size, not the rate */
	CHECK(w == 320 && h == 240 && k == 800);
	teams_video_send_params(TOO_SMALL, &w, &h, &k);
	CHECK(w == 176 && h == 144 && k == 800);
	teams_video_send_params(TWO, &w, &h, &k);
	CHECK(w == 640 && h == 480);
	teams_video_send_params(NULL, &w, &h, &k);
	CHECK(w == 640 && h == 480 && k == 800);
}

int main(void)
{
	test_send_params();
	test_sdp_direction();
	test_answer_direction();
	test_needs_offer();
	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("PASS test_call_sdp\n");
	return 0;
}
