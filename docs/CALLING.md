# 1:1 calls

The plug-in can take and place 1:1 Teams calls, voice and video, on personal (Teams for Life)
accounts. It does the signalling; the audio and video run in a separate media engine, and a front
end (a UI) rings, shows and drives the calls. Both are replaceable.

Tested with a personal account against the Teams Android app, in both directions, with audio and
video. Not tested yet: turning the camera on in a call that started without video. A video call
we place rings as a voice call on the Android app. Calls on work/school accounts have not been
tried, and group calls are not supported.

## Building

    make libteams-personal.so TEAMS_CALLING=1 TEAMS_MEDIA_BIN=/usr/libexec/teams_media

This adds `teams_calling.c` and `teams_call_sdp.c` to the personal plug-in. Calls need a Unix-like
system and GLib 2.58 or newer. Without a front end an incoming call is still announced as a
message, as without `TEAMS_CALLING`.

`TEAMS_MEDIA_BIN` is the engine the plug-in starts, one process per call. A working engine
(GStreamer and libnice, GPL-3.0-or-later) is `teams_media` in
<https://github.com/webOS-ports/luneos-synergy-connectors>, `im/teams/calling/media/`. It plays and
records through PulseAudio devices of its own naming, so it needs adapting to a desktop.

`TEAMS_CALL_DEBUG=1` in the environment copies the call log lines to stderr. They never contain
SRTP keys, ICE passwords or TURN credentials; SDPs are logged by shape only.

## Front-end API (`teams_calling.h`)

A front end registers:

* `teams_calling_set_state_cb()`: call-state changes, with the state (`"incoming"`, `"dialing"`,
  `"active"`, `"disconnected"`, or `""` for idle), the peer's address and name, the direction and,
  on `"disconnected"`, a cause: `"normal"`, `"rejected"`, `"missed"`, `"busy"`, `"error"` or
  `"answeredElsewhere"`. Registering it is what makes a front end present.
* `teams_calling_set_video_cb()`: the engine's video lines as they come (see below), `"OFFERED 0|1"`
  when an offer has the far side sending video or not, and `""` when the call's video is over.
* `teams_calling_set_account_cbs()`: an account became able to take and place calls, or is going
  away.

and calls `teams_calling_answer()`, `teams_calling_reject()`, `teams_calling_hangup()`,
`teams_calling_dial(sa, peer_mri, video)` and `teams_calling_set_camera()`.

## Signalling

Everything below was read from the teams.live.com web client's traffic and is what the plug-in
does.

### Registration

Personal accounts have no `NextGenCalling` endpoint. The calling endpoint is `SkypeSpacesWeb`,
registered at `https://teams.microsoft.com/registrar/prod/v2/registrations` with templateKey
`TFLSkypeSpacesWeb_2.0`, transport context `TFL` and the base trouter surl as path. The web client
registers it twice: under the epid with the surl as given, and under the epid plus `-gg` with the
surl's trailing `/` dropped. With only the first, a call from the Android app reached the web
client but not the plug-in.

Every response to a trouter request carries the headers the web client sends: the request's
`MS-CV` plus `.0`, its `trouter-request` copied as it came, and `trouter-client` `{"cd":<ms>}`.
Without them the trouter redelivered the same frames and the conversation sent no roster updates.

Frames that carry a gzip body name it with `X-Microsoft-Skype-Content-Encoding` in either case.

### Incoming call

1. A `callNotification` arrives on `/callAgent/...` (or the base surl). It holds the offer
   (`mediaContent.blob`, `application/sdp-ngc-0.5`), the media relay (`links.udpTransport`) and the
   control links (`attach`, `progress`, `reject`, ...).
2. While it rings: POST `attach` with a `join` of the conversation in `additionalActions`. The
   response gives `callInvitation.links.acceptance` and the conversation's `leave` link. Then POST
   `progress` (`callProgress`, ringing). Attaching early is what makes the call stop ringing here
   when it is answered on another device.
3. On answer: two POSTs to `<conversation>/updateEndpointState` (muted, then unmuted with
   `endpointProperties`), then POST `acceptance` with `callAcceptance` (our SDP answer,
   `acceptedCallModalities` matching what the answer sends). Once that is accepted,
   PUT `<conversation>/updateEndpointMetadata`.

### Outgoing call

POST `api/v2/cpconv` with our offer. The callee's answer arrives on our `callAgent` `mediaAnswer`
link and goes to the engine (`ANSWER`, `RCAND`). The callee's acceptance is acknowledged on the
link it gives; the call is up when the callee picks up.

### During the call

* The far side's renegotiation offers come on the `mediaRenegotiation` link we gave in the accept;
  they are answered at the push's `mediaNegotiation.links.mediaAnswer`. A new media leg (new ICE
  credentials, maybe a new key) goes to the engine as `RESTART` without rebuilding its pipeline.
* Turning our camera on in a call that did not send video needs an offer of our own
  (`.../renegotiate`) with video `sendrecv`, the same ICE credentials and key, and negotiationTag
  `<participantId>;v_<n>`: the participantId of the call's cpconv, n counting from 1 per call.
* m-lines other than audio and video (e.g. `m=x-data`) are declined (port 0).

### Ending

* Hang-up: POST the conversation's `leave` link; it is answered 204.
* `callEnd` maps to the causes above. A call taken on another of the user's devices ends with
  reason `clientError`, code 487 and the phrase "Call cancelled as it was accepted by another
  fork."; the phrase decides, since a caller giving up may get 487 as well.

### Media

* SDP: `RTP/SAVP`, SDES keying with `a=crypto` `AEAD_AES_256_GCM`, Opus (Teams uses PT 102), H.264
  PT 107 with RTX PT 99, video bundled on the audio's ICE transport and key.
* The call's relay (`links.udpTransport`) does not answer a plain STUN Binding request. The
  engine is given `world.relay.skype.com:3478` as STUN server, which does; without it only host
  candidates are gathered and audio flows one way only.
* Our camera sends the largest of 640x480, 352x288, 320x240 and 176x144 within the far side's
  `a=fmtp:107` `max-fs` and `max-mbps`, at 800 kbit/s or its `max-br` if lower.

## Engine protocol

The plug-in starts `TEAMS_MEDIA_BIN --answer` (incoming) or `--caller` (outgoing) with stdin a
socket and stdout a pipe, and talks one line per message. stderr is passed through for
diagnostics.

To the engine:

    START <rx_master_b64> <remote_ufrag> <remote_pwd> <pt>   (--answer)
    START [pt]                                              (--caller)
    ANSWER <rx_master_b64> <remote_ufrag> <remote_pwd>       (--caller: the far side's answer)
    RELAY turn <ip> <port> <user> <pass> <udp|tcp|tls>       (optional)
    RELAY stun <host|ip> <port>                             (before START)
    RCAND <a=candidate line>                                (repeatable)
    RESTART <rx_master_b64|-> <remote_ufrag> <remote_pwd>    (new media leg; then RCAND)
    VIDEO <0|1> [<w> <h> <kbps>]                            (our camera off/on)
    STOP

From the engine:

    UFRAG <ufrag>          PWD <pwd>          our ICE credentials for the SDP
    TXKEY <b64>            our a=crypto inline key
    SSRC <n>               our audio SSRC
    VSSRC <n>              our video SSRC, only when the engine can do video
    CAND <a=candidate line>
    GATHERED               local candidates complete
    READY | ANSWERED | RESTARTED | ERR <msg>
    VSHM <path> <w> <h>               the far side's picture (a gst-shm socket)
    VPREVIEW <path> <w> <h> <q> <m>   our camera's picture (q quarter turns, m mirrored 0/1)
    VTX <0|1>                         our camera is sending / stopped
    PEERVIDEO <0|1>                   the far side's video is arriving / stopped for 2 s
    VIDEOERR <what>                   a video part could not be built; the call goes on
                                      ("build": no video at all, "tx...": our camera stopped)
    AUDIOD <0|1>                      engine specific; only logged

The video lines are passed to the front end unchanged. Any other line is ignored. The offer or
answer goes out at `GATHERED`, or after 4 s if gathering takes longer.
