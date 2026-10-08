# RFC-0001 — DroidLab Wire Protocol (DLWP/1)

| Field | Value |
| ----- | ----- |
| **RFC number** | 0001 |
| **Title** | DroidLab Wire Protocol |
| **Status** | Accepted |
| **Protocol version** | `1.0` |
| **Wire identifier** | `"DLWP/1"` |
| **Authors** | DroidLab maintainers |
| **Created** | 2025-01-01 |
| **Supersedes** | — |
| **Superseded by** | — |
| **Applies to** | `android/core-protocol`, `windows/DroidLab.Protocol` |

---

## Abstract

DLWP/1 is a length-prefixed, multiplexed, authenticated binary protocol that
carries a DroidLab session between an Android *agent* and a Windows
*controller* over a trustworthy local network. It defines the transport, the
frame layout, the handshake, version negotiation, the command set, the event
set, the error model and the capability-discovery mechanism. The protocol is
designed so that either endpoint may be reimplemented from this document plus
the conformance vectors in [`protocol/vectors/`](../../protocol/vectors/)
without access to the reference implementation.

## Status of this document

This document is normative. The key words **MUST**, **MUST NOT**, **REQUIRED**,
**SHALL**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL**
are to be interpreted as described in [RFC 2119][rfc2119].

[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119

## 1. Terminology

| Term | Definition |
| ---- | ---------- |
| **Agent** | The Android application. It listens for connections and *serves* device capabilities. |
| **Controller** | The Windows application. It initiates connections and *commands* the agent. |
| **Session** | One authenticated TCP connection between exactly one agent and one controller. |
| **Channel** | A logical, independently flow-controlled stream inside a session, identified by a 32-bit id. |
| **Frame** | The atomic unit of DLWP/1: a header plus an optional body. |
| **Capability** | A named, versioned feature set the agent advertises to the controller. |
| **Pairing** | The one-time out-of-band exchange that establishes a long-lived trust relationship (see RFC-0002). |
| **Access unit (AU)** | One complete video frame as produced by an encoder, including its codec configuration. |

## 2. Transport

| Property | Requirement |
| -------- | ----------- |
| Transport | TCP |
| Default port | `45917` (assigned to DroidLab; configurable in the agent's advanced settings) |
| Address family | Dual-stack. The agent SHOULD listen on `::` with `IPV6_V6ONLY=0` so that IPv4 clients connect without NAT64 issues. |
| Encryption | All frames after `HELLO_ACK` MUST be encrypted (RFC-0002 §5). `HELLO` and `HELLO_ACK` are sent in the clear but are integrity-bound by the transcript hash. |
| Keep-alive | `PING` every 5 s when the session has been idle for 5 s; `PONG` MUST be answered within 5 s. Three consecutive missed `PONG`s terminate the session. |
| Idle timeout | 30 s with no frames of any kind |
| Maximum frame size | 16 MiB (`MAX_FRAME_BYTES`). A peer MUST close the connection with `ERR_FRAME_TOO_LARGE` if a larger frame is declared. |
| Byte order | Big-endian (network order) for all multi-byte integers |
| String encoding | UTF-8, length-prefixed by a `u16` byte count |

### 2.1 Discovery (informative)

Discovery is defined in RFC-0003. A controller MAY bypass discovery and connect
to a user-supplied `host:port`. Implementations MUST NOT require discovery to
establish a session.

## 3. Frame layout

Every frame is:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Magic 0x44 0x4C 0x57 0x50             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Version (u8)          |         Flags (u8)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          HeaderLength (u8)    |      MessageType (u8)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         ChannelId (u32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        SequenceNumber (u32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Acknowledgment (u32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        BodyLength (u32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Reserved / Header extensions                |
|                    (HeaderLength - 24 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Body (BodyLength bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Width | Description |
| ----- | ----- | ----------- |
| `Magic` | 4 B | ASCII `DLWP` (`0x44 0x4C 0x57 0x50`). A mismatch MUST close the connection. |
| `Version` | 1 B | Protocol major version. `1` for DLWP/1. |
| `Flags` | 1 B | Bit field, see §3.1. Reserved bits MUST be `0` on send and MUST be ignored on receive. |
| `HeaderLength` | 1 B | Total header length in bytes, including the fixed 24-byte prefix. Minimum is `24`. |
| `MessageType` | 1 B | Frame type, see §4. |
| `ChannelId` | 4 B | Channel this frame belongs to. `0` is the control channel and is always valid. |
| `SequenceNumber` | 4 B | Per-session, monotonically increasing, wraps at `2^32`. Starts at `1`. Must never repeat within a session. |
| `Acknowledgment` | 4 B | Highest received `SequenceNumber` observed on this channel, or `0` if not applicable. |
| `BodyLength` | 4 B | Length of the body in bytes, excluding the header. |
| *Header extensions* | *var* | `HeaderLength - 24` bytes. This version defines none; senders MUST set `HeaderLength = 24` and receivers MUST reject `HeaderLength > 24` with `ERR_UNSUPPORTED_HEADER`. |
| `Body` | var | Type-dependent payload. |

The total on-wire size of a frame is `HeaderLength + BodyLength`.

### 3.1 Flag bits

| Bit | Mask | Name | Meaning |
| --- | ---- | ---- | ------- |
| 0 | `0x01` | `ENCRYPTED` | Body is AEAD-encrypted per RFC-0002 §5. Set on every frame after `HELLO_ACK`. |
| 1 | `0x02` | `URGENT` | Receiver should process ahead of normal traffic. Only `PING`, `PONG`, `ERROR` and `SESSION_END` may set this. |
| 2 | `0x04` | `END_OF_STREAM` | Last frame on this channel. |
| 3 | `0x08` | `COMPRESSED` | Body was DEFLATE-compressed *before* encryption. Absent or set on both sides is legal only if both peers advertised `CAP_COMPRESSION_DEFLATE`. |
| 4–7 | `0xF0` | *reserved* | MUST be `0`; receivers MUST ignore. |

### 3.2 Body encoding

Every body is a cbOR map ([RFC 8949][rfc8949]) with **text string** keys. An
empty body is encoded as the zero-length byte string (`0x00` bytes) for message
types that define no parameters, and as the 1-byte cbOR map `0xA0` where the
schema requires an object. Receivers MUST accept `0xA0` anywhere a map is
expected and MUST treat it as an empty map.

[rfc8949]: https://www.rfc-editor.org/rfc/rfc8949

Unknown keys in any map MUST be ignored rather than rejected, so that a newer
peer can add fields without breaking an older one. Missing keys take the
default declared in the schema.

Binary values (nonces, hashes, keys, media payloads) are cbOR byte strings.
Integers are cbOR unsigned or negative integers; the protocol defines no
floating-point fields.

## 4. Message types

| Code | Name | Dir | Channel | Encrypted | Purpose |
| ---- | ---- | --- | ------- | --------- | ------- |
| `0x01` | `HELLO` | C → A | 0 | No | Open a session, offer version and client public key. |
| `0x02` | `HELLO_ACK` | A → C | 0 | No | Accept a session, return agent public key and capabilities. |
| `0x03` | `AUTH` | C → A | 0 | Yes | Prove possession of the pairing secret. |
| `0x04` | `AUTH_OK` | A → C | 0 | Yes | Authentication succeeded; session is established. |
| `0x05` | `PING` | both | 0 | Yes | Liveness probe. |
| `0x06` | `PONG` | both | 0 | Yes | Liveness reply, echoes the probe's `SequenceNumber` in `Acknowledgment`. |
| `0x10` | `GET_CAPABILITIES` | C → A | 0 | Yes | Ask for a fresh capability list. |
| `0x11` | `CAPABILITIES` | A → C | 0 | Yes | Capability list with limits. |
| `0x20` | `CHANNEL_OPEN` | both | 0 | Yes | Create a logical channel. |
| `0x21` | `CHANNEL_OPENED` | both | 0 | Yes | Confirm channel creation. |
| `0x22` | `CHANNEL_CLOSE` | both | any | Yes | Close a channel; `END_OF_STREAM` flag set on the last frame. |
| `0x30` | `VIDEO_START` | C → A | any | Yes | Request a video stream with parameters. |
| `0x31` | `VIDEO_CONFIG` | A → C | any | Yes | Codec configuration data (SPS/PPS). |
| `0x32` | `VIDEO_FRAME` | A → C | any | Yes | One encoded access unit. |
| `0x33` | `VIDEO_STOP` | C → A | any | Yes | Stop the stream. |
| `0x34` | `VIDEO_STATS` | A → C | any | Yes | Periodic stream statistics. |
| `0x40` | `INPUT_TOUCH` | C → A | any | Yes | Touch down/move/up with one or more pointers. |
| `0x41` | `INPUT_KEY` | C → A | any | Yes | Key down/up with an Android keycode. |
| `0x42` | `INPUT_TEXT` | C → A | any | Yes | Commit a UTF-8 string. |
| `0x43` | `INPUT_SCROLL` | C → A | any | Yes | Scroll delta. |
| `0x44` | `INPUT_GESTURE` | C → A | any | Yes | Multi-step recorded gesture (macro). |
| `0x50` | `SHELL_EXEC` | C → A | any | Yes | Run a command in the agent's allow-listed shell. |
| `0x51` | `SHELL_STDOUT` | A → C | any | Yes | stdout/stderr chunk. |
| `0x52` | `SHELL_EXIT` | A → C | any | Yes | Exit status. |
| `0x60` | `FILE_LIST` | C → A | any | Yes | List a directory. |
| `0x61` | `FILE_LIST_RESULT` | A → C | any | Yes | Directory listing. |
| `0x62` | `FILE_PULL` | C → A | any | Yes | Request a file. |
| `0x63` | `FILE_CHUNK` | A → C | any | Yes | File content chunk. |
| `0x64` | `FILE_PUSH` | C → A | any | Yes | Send a file. |
| `0x65` | `FILE_RESULT` | A → C | any | Yes | Result of a file operation. |
| `0x70` | `CLIPBOARD_GET` | C → A | 0 | Yes | Read the device clipboard. |
| `0x71` | `CLIPBOARD_SET` | C → A | 0 | Yes | Write the device clipboard. |
| `0x72` | `CLIPBOARD_DATA` | A → C | 0 | Yes | Clipboard contents. |
| `0x80` | `DEVICE_INFO` | C → A | 0 | Yes | Request device metadata. |
| `0x81` | `DEVICE_INFO_RESULT` | A → C | 0 | Yes | Device metadata. |
| `0x82` | `LOG_SUBSCRIBE` | C → A | any | Yes | Subscribe to logcat. |
| `0x83` | `LOG_ENTRY` | A → C | any | Yes | One log line. |
| `0x90` | `APP_INSTALL` | C → A | any | Yes | Install an APK from a pushed file. |
| `0x91` | `APP_LAUNCH` | C → A | 0 | Yes | Launch an activity or package. |
| `0x92` | `APP_RESULT` | A → C | any | Yes | Result of an app operation. |
| `0xF0` | `ERROR` | both | any | Yes | Error report, see §6. |
| `0xF1` | `SESSION_END` | both | 0 | Yes | Graceful teardown with a reason. |

Direction: **C** = controller (Windows), **A** = agent (Android).

Any message type not listed, or listed but not enabled by a negotiated
capability, MUST be answered with `ERR_UNSUPPORTED_MESSAGE` and MUST NOT
terminate the session.

## 5. Handshake

### 5.1 Sequence

```
Controller                                          Agent
    │                                                 │
    │── HELLO ───────────────────────────────────────►│
    │   { proto:"1.0", client_id, client_nonce,       │
    │     client_pub, pairing_id,                       │
    │     versions_supported:["1.0"],                  │
    │     capabilities_offered:[…] }                   │
    │                                                 │
    │◄─ HELLO_ACK ───────────────────────────────────│
    │   { proto:"1.0", agent_id, agent_nonce,          │
    │     agent_pub, session_id, transcript_hash,      │
    │     capabilities:[…], server_time_ms }           │
    │                                                 │
    │   ── both derive keys (RFC-0002 §4) ──           │
    │                                                 │
    │── AUTH ────────────────────────────────────────►│
    │   { pairing_id, proof, client_fingerprint }      │
    │                                                 │
    │◄─ AUTH_OK ─────────────────────────────────────│
    │   { session_id, agent_fingerprint,               │
    │     negotiated:{ proto, capabilities:[…] } }     │
    │                                                 │
    │   ── session established ──                      │
```

### 5.2 `HELLO` (0x01)

| Key | Type | Required | Default | Description |
| --- | ---- | -------- | ------- | ----------- |
| `proto` | string | yes | — | Highest protocol version the controller supports, e.g. `"1.0"`. |
| `versions_supported` | array<string> | yes | — | Every version the controller can speak, most preferred first. |
| `client_id` | string | yes | — | Stable controller identity, a UUIDv4 in canonical text form. |
| `client_name` | string | no | `"DroidLab Controller"` | Human-readable host name. |
| `client_nonce` | bytes(32) | yes | — | Fresh CSPRNG nonce, MUST NOT be reused across sessions. |
| `client_pub` | bytes(32) | yes | — | Ephemeral X25519 public key. |
| `pairing_id` | bytes(16) | no | — | Id of a previously established pairing, if any. Omitted for first contact. |
| `capabilities_offered` | array<string> | no | `[]` | Capability names the controller can drive. |
| `platform` | string | no | `"windows"` | `windows`, `linux` or `macos`. |

`HELLO` MUST be the first frame of a session. Any other first frame MUST be
answered with `ERR_UNEXPECTED_MESSAGE` followed by `SESSION_END`.

### 5.3 `HELLO_ACK` (0x02)

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `proto` | string | yes | The version the agent selected. MUST be the controller's `proto` if supported, otherwise the highest of `versions_supported` the agent also supports. |
| `agent_id` | string | yes | Stable agent identity (UUIDv4 text). |
| `agent_name` | string | yes | Device model or user-configured name. |
| `agent_nonce` | bytes(32) | yes | Fresh CSPRNG nonce. |
| `agent_pub` | bytes(32) | yes | Ephemeral X25519 public key. |
| `session_id` | bytes(16) | yes | Unique id for this session. |
| `transcript_hash` | bytes(32) | yes | SHA-256 over the canonical transcript, see §5.4. |
| `capabilities` | array<string> | yes | Capabilities the agent enables for this device. |
| `limits` | map | no | Advertised limits, see §7.3. |
| `server_time_ms` | int | no | Agent wall-clock in ms since the Unix epoch, for skew estimation. |
| `max_frame_bytes` | int | no | Agent-side maximum; MUST be ≤ `MAX_FRAME_BYTES`. |

If the agent cannot support any offered version it MUST respond with
`ERROR { code: "ERR_VERSION_MISMATCH" }` and close.

### 5.4 Transcript hash

`transcript_hash` binds the cleartext handshake to the encrypted session:

```
transcript =
    "DLWP/1-handshake"            ‖ 0x00
    ‖ client_id (>utf8)           ‖ 0x00
    ‖ agent_id (>utf8)            ‖ 0x00
    ‖ client_nonce (32 bytes)
    ‖ agent_nonce  (32 bytes)
    ‖ client_pub   (32 bytes)
    ‖ agent_pub    (32 bytes)

transcript_hash = SHA-256(transcript)
```

`>utf8` denotes a length-prefixed UTF-8 string with a `u16` big-endian byte
count. Both peers MUST compute the transcript independently and MUST abort with
`ERR_HANDSHAKE_MISMATCH` on disagreement. Test vectors:
`protocol/vectors/handshake-transcript.json`.

### 5.5 `AUTH` (0x03) and `AUTH_OK` (0x04)

`AUTH` carries the proof defined in RFC-0002 §4.4:

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `pairing_id` | bytes(16) | yes | Pairing being used. |
| `proof` | bytes(32) | yes | `HMAC-SHA256(pairing_secret, "DLWP/1-client" ‖ transcript_hash)`. |
| `client_fingerprint` | string | yes | Human-checkable fingerprint of the controller identity key, e.g. `DE34-A1B0-77C9-9021`. |

`AUTH_OK`:

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `session_id` | bytes(16) | yes | Echo of the id from `HELLO_ACK`. |
| `agent_fingerprint` | string | yes | Fingerprint of the agent identity key. |
| `negotiated` | map | yes | `{ "proto": "1.0", "capabilities": [ … ] }`. |
| `session_timeout_s` | int | no | Inactivity timeout, default `30`. |

`AUTH` MUST be sent with the `ENCRYPTED` flag set and MUST be the first
encrypted frame in each direction. A second `AUTH` on an established session
MUST be rejected with `ERR_UNEXPECTED_MESSAGE`.

## 6. Error model

### 6.1 `ERROR` frame (0xF0)

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `code` | string | yes | Symbolic code, see §6.2. |
| `message` | string | yes | Human-readable, English, no stack traces, no secrets. |
| `severity` | string | yes | `warning`, `recoverable` or `fatal`. |
| `request_type` | int | no | `MessageType` of the frame that failed. |
| `request_seq` | int | no | `SequenceNumber` of the frame that failed. |
| `details` | map | no | Structured, capability-specific detail. |

A `warning` is informational and the session continues. A `recoverable` error
aborts only the affected operation or channel. A `fatal` error MUST be followed
by `SESSION_END` and the connection MUST be closed by the sender.

### 6.2 Error codes

| Code | Severity | Meaning |
| ---- | -------- | ------- |
| `ERR_UNSUPPORTED_MESSAGE` | recoverable | Unknown or disabled message type. |
| `ERR_UNSUPPORTED_FEATURE` | recoverable | Known type, capability not negotiated. |
| `ERR_UNSUPPORTED_HEADER` | fatal | `HeaderLength` other than 24. |
| `ERR_FRAME_TOO_LARGE` | fatal | Declared body exceeds `max_frame_bytes`. |
| `ERR_MALFORMED` | fatal | Body is not valid cbOR or violates the schema. |
| `ERR_VERSION_MISMATCH` | fatal | No protocol version in common. |
| `ERR_HANDSHAKE_MISMATCH` | fatal | `transcript_hash` disagreement. |
| `ERR_UNAUTHORIZED` | fatal | Missing, wrong or expired proof. |
| `ERR_PAIRING_REQUIRED` | fatal | Unknown `pairing_id`; the controller must pair first. |
| `ERR_PAIRING_REVOKED` | fatal | The pairing was revoked on the device. |
| `ERR_REPLAY_DETECTED` | fatal | Reused `SequenceNumber` or nonce. |
| `ERR_BAD_STATE` | recoverable | Message is legal but out of order. |
| `ERR_UNEXPECTED_MESSAGE` | fatal | Message may not appear at this point. |
| `ERR_CHANNEL_UNKNOWN` | recoverable | Operation on an unopened channel. |
| `ERR_CHANNEL_LIMIT` | recoverable | Too many open channels (§7.4). |
| `ERR_PERMISSION_DENIED` | recoverable | Operator has not granted the required permission. |
| `ERR_NOT_ALLOWED` | recoverable | Shell allow-list rejected the command. |
| `ERR_TIMEOUT` | recoverable | Operation exceeded its deadline. |
| `ERR_BUSY` | recoverable | Resource in use, e.g. an active capture. |
| `ERR_RESOURCE_EXHAUSTED` | recoverable | Out of memory, file descriptors or disk. |
| `ERR_IO` | recoverable | Platform I/O failure. |
| `ERR_INTERNAL` | fatal | Unclassified defect. |

### 6.3 Relationship between `ERROR` and `SESSION_END`

`SESSION_END { reason, code }` carries a short machine-readable `reason` such as
`client_shutdown`, `agent_shutdown`, `idle_timeout`, `auth_failed`,
`protocol_error` or `capture_revoked`. Sending `SESSION_END` is graceful; the
peer SHOULD NOT treat it as a failure. Closing without `SESSION_END` is an
abnormal termination and the peer SHOULD record it in the session log.

## 7. Capabilities and limits

### 7.1 Capability names

| Name | Meaning |
| ---- | ------- |
| `screen.mirror` | Video capture and streaming. |
| `screen.record` | On-device recording to a file. |
| `input.touch` | Touch injection. |
| `input.key` | Keycode injection. |
| `input.text` | Text commit injection. |
| `input.gesture` | Multi-step gesture playback. |
| `clipboard.read` | Read device clipboard. |
| `clipboard.write` | Write device clipboard. |
| `shell.exec` | Run allow-listed shell commands. |
| `file.read` | Read files from a scoped directory set. |
| `file.write` | Write files into a scoped directory set. |
| `log.stream` | logcat streaming. |
| `app.install` | APK installation. |
| `app.launch` | Activity/package launch. |
| `device.info` | Device metadata. |
| `adb.wireless` | Agent can keep `adbd` in TCP mode for the controller. |
| `compression.deflate` | DEFLATE compression of large bodies. |
| `telemetry.stats` | Periodic statistics frames. |

### 7.2 Negotiation

`negotiated.capabilities` is the intersection of the agent's `capabilities` and
the controller's `capabilities_offered`. A feature whose name is absent from the
intersection MUST NOT be used. The controller MUST also treat a capability that
the operator disabled on the device as absent.

### 7.3 `limits`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `max_frame_bytes` | int | `16777216` | Maximum body size the peer will accept. |
| `max_channels` | int | `8` | Concurrent open channels. |
| `max_video_width` | int | `1920` | Widest frame the agent will encode. |
| `max_video_height` | int | `1080` | Tallest frame. |
| `max_video_fps` | int | `60` | Frame-rate ceiling. |
| `max_video_bitrate` | int | `16000000` | Bit/s ceiling. |
| `max_file_chunk` | int | `262144` | Largest `FILE_CHUNK` body. |
| `shell_timeout_ms` | int | `30000` | Default shell deadline. |
| `max_gesture_steps` | int | `256` | Steps in a single `INPUT_GESTURE`, see §8.2. |

### 7.4 Channels

Channel `0` is reserved for session control and is always open. The controller
allocates odd channel ids; the agent allocates even ids. Both start at `1`
respectively `2` and increase monotonically. Reusing a channel id within a
session without an intervening `CHANNEL_CLOSE` MUST produce
`ERR_CHANNEL_UNKNOWN` or `ERR_BAD_STATE`.

`CHANNEL_OPEN` carries `{ purpose, params }`. Purposes are `video`, `input`,
`shell`, `file`, `log` and `app`. `CHANNEL_OPENED` echoes `purpose` and may
return narrowed `params`.

---

## 8. Message reference

### 8.1 Video

`VIDEO_START` (0x30) — controller → agent, on a channel with purpose `video`:

| Key | Type | Required | Default | Notes |
| --- | ---- | -------- | ------- | ----- |
| `codec` | string | no | `"avc"` | `avc` (H.264) or `hevc` (H.265). |
| `max_width` | int | no | `1280` | Requested ceiling, clamped to the device screen and `max_video_width`. |
| `max_height` | int | no | `720` | Requested ceiling. |
| `fps` | int | no | `30` | 1–`max_video_fps`. |
| `bitrate` | int | no | `4000000` | Bit/s. |
| `keyframe_interval_s` | int | no | `2` | Maximum I-frame interval. |
| `include_frames` | bool | no | `true` | `false` requests configuration only. |
| `orientation` | string | no | `"auto"` | `auto`, `portrait`, `landscape`. |

`VIDEO_CONFIG` (0x31):

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `codec` | string | yes | Codec actually in use. |
| `width` | int | yes | Encoded width in pixels. |
| `height` | int | yes | Encoded height. |
| `csd` | bytes | yes | Codec-specific configuration (H.264: annex-B SPS then PPS). |
| `screen_width` | int | no | Physical screen width, for coordinate mapping. |
| `screen_height` | int | no | Physical screen height. |
| `rotation` | int | no | Current rotation in degrees: `0`, `90`, `180`, `270`. |

`VIDEO_FRAME` (0x32):

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `pts_us` | int | yes | Presentation timestamp in microseconds. |
| `flags` | int | yes | Bit field, see below. |
| `data` | bytes | yes | One access unit, no length prefix of its own. |
| `sequence` | int | no | Monotonic frame counter. |

`flags` bits: bit 0 `KEYFRAME`, bit 1 `CONFIG`, bit 2 `END_OF_STREAM`.

`VIDEO_STOP` (0x33) takes `{ reason, sequence }`. When the agent receives it, it
MUST release the encoder and answer with `VIDEO_STATS` carrying
`{"final": true}`.

`VIDEO_STATS` (0x34): `{ pts_us, frames_sent, frames_dropped, bytes_sent,
encoder_ms_avg, queue_depth, bitrate_actual, final }`.

### 8.2 Input

`INPUT_TOUCH` (0x40):

| Key | Type | Required | Description |
| --- | ---- | -------- | ----------- |
| `action` | string | yes | `down`, `move`, `up` or `cancel`. |
| `pointers` | array<map> | yes | One entry per active pointer. |
| `gesture_id` | int | no | Correlates `down`…`up` for one gesture. |
| `screen_width` | int | no | Denominator for normalised coordinates. |
| `screen_height` | int | no | Denominator for normalised coordinates. |
| `pressure` | float | no | `0.0`–`1.0`; encoded as cbOR tag 0 or an integer permille if the peer lacks float support. |

Each element of `pointers` is `{ id, x, y }` where `x` and `y` are integers in
device pixels when `screen_width`/`screen_height` are absent, and integers in
`0..10000` (ten-thousandths) when they are present. Using the normalised form is
RECOMMENDED because it survives rotation and resolution changes.

`INPUT_KEY` (0x41): `{ action, keycode, meta_state, unicode }` where `action` is
`down`/`up`, `keycode` is an Android `KeyEvent` keycode, `meta_state` is the
Android meta bitmask and `unicode` is an optional code point for an alternative
character.

`INPUT_TEXT` (0x42): `{ text, replace }`. `replace: true` clears the focused
field first.

`INPUT_SCROLL` (0x43): `{ x, y, dx, dy, screen_width, screen_height, unit }`
where `unit` is `pixel` or `line`.

`INPUT_GESTURE` (0x44): `{ steps: [ { delay_ms, action, pointers } ], repeat }`.
Steps are replayed in order; `repeat` defaults to `1`. The agent MUST reject a
gesture longer than `limits.max_gesture_steps` with `ERR_RESOURCE_EXHAUSTED`.

### 8.3 Shell

`SHELL_EXEC` (0x50): `{ command, args?, cwd?, env?, timeout_ms?,
interactive:false, pty:false }`.

`command` is matched against the agent's allow-list (default policy in RFC-0004).
The agent MUST NOT invoke a shell interpreter to expand the command string;
`command` names an executable and `args` is a list. On rejection the agent
returns `ERR_NOT_ALLOWED` with `details.reason` set to `deny_listed`,
`not_in_allow_list` or `denied_by_operator`.

`SHELL_STDOUT` (0x51): `{ stream: "stdout"|"stderr", data, seq }`.

`SHELL_EXIT` (0x52): `{ exit_code, signal?, duration_ms, truncated }`.

### 8.4 File transfer

`FILE_LIST` (0x60): `{ path, recursive?, max_entries? }` — `path` MUST be inside
the scoped root set.
`FILE_LIST_RESULT` (0x61): `{ path, entries: [ { name, type, size, mtime_ms,
mode_digits, is_link } ], truncated }`.
`FILE_PULL` (0x62): `{ path, offset?, length? }` — streaming starts at `offset`.
`FILE_CHUNK` (0x63): `{ offset, data, eof }` — `data` MUST NOT exceed
`limits.max_file_chunk`.
`FILE_PUSH` (0x64): `{ path, offset, data, eof, mode?, mtime_ms? }`.
`FILE_RESULT` (0x65): `{ operation, path, ok, bytes, sha256?, error? }`.

Every completed transfer MUST report `sha256` of the whole file so the controller
can verify integrity.

### 8.5 Clipboard, device info, logs, apps

* `CLIPBOARD_GET` (0x70) `{}` → `CLIPBOARD_DATA` (0x72) `{ text, mime, ts_ms }`.
* `CLIPBOARD_SET` (0x71) `{ text, mime? }` → `CLIPBOARD_DATA` echo on success.
* `DEVICE_INFO` (0x80) `{}` → `DEVICE_INFO_RESULT` (0x81):
  `{ manufacturer, model, product, device, board, hardware, serial_redacted,
  android_release, android_sdk, build_id, build_fingerprint, abi_list,
  locale, timezone, screen_width, screen_height, density_dpi, battery_level,
  battery_charging, ram_total_kb, storage_free_kb, is_rooted, uptime_ms }`.
  `serial_redacted` MUST be a stable per-install pseudonym, never the hardware
  serial.
* `LOG_SUBSCRIBE` (0x82) `{ buffers, filter_spec, min_level, max_lines_per_s }`
  → a stream of `LOG_ENTRY` (0x83) `{ ts_ms, pid, tid, level, tag, message }`.
* `APP_INSTALL` (0x90) `{ path, replace?, grant_permissions?, downgrade?,
  user_id? }` → `APP_RESULT` (0x92) `{ operation, ok, package_name,
  version_name, error? }`.
* `APP_LAUNCH` (0x91) `{ package, activity?, action?, data?, extras?,
  force_stop_first? }` → `APP_RESULT`.

### 8.6 Session control

* `GET_CAPABILITIES` (0x10) `{}` → `CAPABILITIES` (0x11)
  `{ proto, capabilities, limits, disabled: [ … ] }`.
* `CHANNEL_OPEN` (0x20) `{ purpose, params }` → `CHANNEL_OPENED` (0x21)
  `{ purpose, params, channel_id }`.
* `CHANNEL_CLOSE` (0x22) `{ reason }` with the `END_OF_STREAM` flag.
* `SESSION_END` (0xF1) `{ reason, code?, message? }`.

---

## 9. Conformance

An implementation claims DLWP/1 conformance when it:

1. Parses and produces every frame in `protocol/vectors/framing-*.json`
   byte-for-byte.
2. Reproduces every digest, key and proof in
   `protocol/vectors/handshake-transcript.json` and
   `protocol/vectors/crypto-*.json`.
3. Rejects every malformed frame in `protocol/vectors/malformed.json` with the
   exact error code and severity listed.
4. Completes the scripted session in `protocol/vectors/session-basic.json`
   against a reference peer.

The `protocol/tools/` directory contains the runner used by CI. Passing the
vectors is the *only* accepted evidence of interoperability; screenshots and
manual demos are not evidence.

## 10. Versioning policy

* The `Version` field is a **major** number. A change that adds frames, flags,
  capability names or optional map keys does **not** bump it.
* A change that alters existing frame semantics, removes a field, or changes a
  default in a way that breaks an old peer **does** bump it and requires an RFC.
* The controller MUST implement the strategy "highest common version, no
  downgrade guessing". Silent fallback to an older version is forbidden.

## 11. IANA-style registries

This document maintains three registries: *Message Types* (§4), *Error Codes*
(§6.2) and *Capability Names* (§7.1). New entries require an RFC or an accepted
pull request that edits the tables, the JSON schemas and the vectors in the same
commit.

## 12. References

* [RFC 2119][rfc2119] — Key words for requirement levels
* [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) — cbOR
* [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3 (informative; the
  DLWP/1 handshake borrows its transcript-binding idea)
* [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) / [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) — mDNS and DNS-SD
* [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — X25519
* [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
* [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) — AES-GCM
* [RFC-0002](RFC-0002-pairing-and-session-security.md) — Pairing and session security
* [RFC-0003](RFC-0003-discovery.md) — Discovery
* [RFC-0004](RFC-0004-shell-safety.md) — Shell safety policy
