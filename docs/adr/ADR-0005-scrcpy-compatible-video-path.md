# ADR-0005 — Reuse the scrcpy-compatible H.264 path for video

| Field | Value |
| ----- | ----- |
| Status | Accepted |
| Date | 2025-01-01 |
| Deciders | DroidLab maintainers |

## Context

The mirror feature must deliver an interactive, low-latency view of the device
screen. There is a well-trodden way to do this on Android: `MediaProjection`
gives a `Surface` fed by the compositor, `MediaCodec` encodes it to H.264, and
the access units are shipped to the peer, which decodes with a hardware decoder.
The open-source project `scrcpy` implements exactly this shape, and its design
choices — encode on the device, ship access units, decode on the host with
hardware acceleration, keep the pipeline as short as possible — are the result of
years of latency work.

DroidLab could instead adopt a full streaming stack (WebRTC, RTP/RTSP, a
GStreamer pipeline) or build on scrcpy's code directly.

## Decision

Implement the video path as a **native DLWP/1 stream of H.264 access units**,
following the same architectural shape as scrcpy: `MediaProjection` → encoder
surface → `MediaCodec` (H.264 baseline/main, low-latency flags) → access-unit
framing → DLWP/1 `VIDEO_FRAME` → Windows hardware decode → WPF composition. The
codec configuration (SPS/PPS) travels once in `VIDEO_CONFIG`; the controller
feeds it to the decoder before the first frame. No RTP, no WebRTC, no media
server.

Additionally, the Windows controller MAY use a locally installed `scrcpy`
binary as an **alternative, out-of-band mirror path** when the user prefers it
or when the in-protocol path is unavailable, but that path is never required for
the protocol to be conformant and is not part of DLWP/1.

## Alternatives considered

| Option | Why not |
| ------ | ------- |
| WebRTC | Brings ICE, STUN, DTLS-SRTP, congestion control and a large dependency tree on both platforms. For a single 1:1 LAN stream with a known peer, that is a lot of machinery for congestion control the LAN does not need. It also duplicates the security layer DLWP/1 already defines, and would need a second pairing/identity story. |
| RTP/RTSP over the existing session | RTP's jitter buffer and its own timestamp/session model overlap with DLWP/1 framing; the extra protocol buys nothing at LAN latencies and adds a second place for sequence-number bugs. |
| GStreamer pipeline on both sides | Heavy on Android (app size, plugin ABI issues) and duplicates `MediaCodec`/`MediaFoundation`. |
| Ship a raw bitmap stream | Trivial to implement, but at 1080p that is ~8 MB per frame; unusable over Wi-Fi. |
| Reimplement scrcpy's client/server protocols | Two incompatible protocols to maintain, and the server is pushed over a socket to a temporary path — a workflow DroidLab explicitly wants to avoid because it requires shell access. |
| Make an installed `scrcpy` binary the only mirror path | Removes control over latency, codec parameters and security (the stream would not be inside the DLWP/1 session and would not be covered by the pairing), and forces a third-party runtime dependency on every user. |

## Consequences

### Positive

* Lowest practical latency: one hardware encoder on the device, one hardware
  decoder on the host, no intermediate buffering stage.
* The video stream is protected by the same session keys as everything else;
  there is no second security model to get right.
* Codec negotiation (`avc`/`hevc`), resolution caps and bitrate are protocol
  fields, so a weak device can be told to send 720p30 while a flagship sends
  1080p60.
* The optional external `scrcpy` path means a user who already has it installed
  can use it, without the project depending on it.

### Negative

* The project owns the jitter/latency behaviour: frame pacing, dropped-frame
  policy and decode-queue depth are DroidLab's problem. RFC-0001 §5 and §8.1
  specify the drop policy and the statistics frame that makes tuning observable.
* Two implementations of the access-unit framing (Kotlin and C#) must agree
  exactly, including handling of the codec-configuration prefix. Covered by
  `protocol/vectors/video-framing.json`.
* Hardware decoder quirks on Windows (driver-specific handling of mid-stream
  parameter sets) require a fallback: on decode failure the controller requests a
  new `VIDEO_CONFIG` and a keyframe rather than silently degrading.

### Neutral

* Audio is out of scope for version 1.0; the protocol reserves no audio frame
  types, and adding them is an additive change under RFC-0001 §10.

## Compliance

* Every access unit carries `pts_us` and the `KEYFRAME` flag; a stream that omits
  either is non-conformant.
* A controller that cannot decode a frame emits `VIDEO_STOP { reason:
  "decode_error" }` followed by a fresh `VIDEO_START`, and never renders a
  corrupted frame.
* Vendor or copy a scrcpy component into the product only after an ADR that
  records the licence (scrcpy is Apache-2.0) and the maintenance obligation.
