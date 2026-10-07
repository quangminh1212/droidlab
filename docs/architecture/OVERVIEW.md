# DroidLab Architecture Overview

> Status: **Draft** · Applies to protocol version `1.0` · See [RFC-0001](../rfc/RFC-0001-wire-protocol.md)

## 1. Problem statement

Android testing still usually requires a USB cable: `adb` talks to a phone over
USB, screen mirroring needs `scrcpy` on the same bus, and any automation harness
has to own that cable. Wireless ADB (`adb pair` / `adb connect`) removes the
cable but does not remove the setup friction — a developer still has to read a
pairing code off the device screen, type it into a terminal, keep track of
changing device IPs, and separately start a mirroring tool.

DroidLab turns that ad-hoc workflow into a product: a phone-side agent and a
desktop controller that discover each other, authenticate with a scanned QR
code, and then expose the phone as a first-class **test environment** —
mirroring, input, shell, file transfer and instrumentation — over the local
network only.

## 2. System context

```
                    ┌──────────────────────────────────────────────┐
                    │              Local network (Wi-Fi)           │
                    │                                              │
  ┌─────────────────┴────────────┐            ┌────────────────────┴──────────────┐
  │  Android device              │            │  Windows workstation              │
  │                              │            │                                   │
  │  ┌────────────────────────┐  │   DLWP/1   │  ┌─────────────────────────────┐  │
  │  │ DroidLab Agent (APK)   │◄─┼───────────►│  │ DroidLab Controller (.exe)  │  │
  │  │                        │  │  TLS-like  │  │                             │  │
  │  │  • Discovery (mDNS)    │  │  AES-GCM   │  │  • Discovery (mDNS)         │  │
  │  │  • Pairing / auth      │  │  over TCP  │  │  • Pairing (QR scanner)     │  │
  │  │  • Session state       │  │  :45917    │  │  • Session manager          │  │
  │  │  • Capture (H.264)     │  │            │  │  • Mirror renderer          │  │
  │  │  • Control injection   │  │            │  │  • ADB client               │  │
  │  │  • Shell (scoped)      │  │            │  │  • Automation API           │  │
  │  └────────────────────────┘  │            │  └─────────────────────────────┘  │
  │                              │            │                                   │
  │  Android platform            │            │  Windows platform                 │
  │  MediaProjection,            │            │  Winsock, WPF, Win32,             │
  │  Accessibility, adbd         │            │  adb.exe / adb server             │
  └──────────────────────────────┘            └───────────────────────────────────┘
```

There is exactly **one** network contract: DLWP/1. Neither app links against the
other, neither app knows the other's internals, and either side may be
reimplemented from the specification alone.

## 3. Component inventory

### 3.1 Android agent

| Component | Module | Responsibility |
| --------- | ------ | -------------- |
| Discovery advertiser | `core-protocol` | Publishes `_droidlab._tcp` via `NsdManager` with TXT records carrying device metadata. |
| Pairing service | `core-protocol` | Shows a QR code containing an ephemeral X25519 public key and a one-time token; performs the handshake described in RFC-0002. |
| Session server | `core-protocol` | Owns the TCP listener, performs version negotiation, multiplexes logical channels. |
| Capture pipeline | `core-capture` | `MediaProjection` → `Surface` → `MediaCodec` (AVC) → access-unit framing. |
| Control surface | `core-control` | Injects touch/key/text via `AccessibilityService` or `Instrumentation`; reads clipboard; streams files. |
| Foreground service | `app` | Keeps the session alive, shows a persistent notification with a disconnect action. |
| Operator UI | `app` | Pairing screen, connected-device screen, capability toggles, audit log. |

### 3.2 Windows controller

| Component | Module | Responsibility |
| --------- | ------ | -------------- |
| Discovery browser | `DroidLab.Discovery` | Browses `_droidlab._tcp`, maintains a live device list with presence expiry. |
| Pairing dialog | `DroidLab.App` | Camera or image-based QR capture, confirmation of the device fingerprint. |
| Session manager | `DroidLab.Core` | Connection lifecycle, reconnection with backoff, channel arbitration, telemetry. |
| Protocol codec | `DroidLab.Protocol` | DLWP/1 framing, negotiation, encryption, error mapping. |
| Mirror view | `DroidLab.Mirror` | Depacketise, decode, render, scale, record. |
| Input mapper | `DroidLab.App` | Maps mouse/keyboard/touch-pad gestures onto `input.touch`/`input.key` commands. |
| ADB bridge | `DroidLab.Adb` | Talks to the local `adb` server: `connect`, `shell`, `push`, `pull`, `install`, `logcat`. |
| Automation API | `DroidLab.Core` | Local gRPC/HTTP surface so CI runners drive a device without a GUI. |

## 4. Control flow — from pairing to mirroring

```
 Controller                                          Agent
     │                                                 │
     │ 1. mDNS browse  _droidlab._tcp                   │
     │◄─────────────── TXT: id, name, ver, caps ────────│
     │                                                 │
     │ 2. user scans QR code shown on the device        │
     │    (device_id ‖ ephemeral_pub ‖ one-time token)  │
     │                                                 │
     │ 3. HELLO  { proto=1.0, client_pub }              │
     │─────────────────────────────────────────────────►│
     │ 4. HELLO_ACK { proto=1.0, agent_pub, caps }      │
     │◄─────────────────────────────────────────────────│
     │ 5. both sides: X25519 → HKDF-SHA256 → keys       │
     │ 6. AUTH   AEAD(token, transcript_hash)           │
     │─────────────────────────────────────────────────►│
     │ 7. AUTH_OK / AUTH_FAIL                           │
     │◄─────────────────────────────────────────────────│
     │ 8. GET_CAPABILITIES → CAPABILITIES               │
     │                                                 │
     │ 9. video.start { codec=avc, max_w, max_h, fps }  │
     │─────────────────────────────────────────────────►│
     │10. video.frame × N  (access units, encrypted)    │
     │◄─────────────────────────────────────────────────│
     │11. input.touch / input.key / shell.exec  …       │
     │─────────────────────────────────────────────────►│
```

Steps 1–8 happen once per device and are persisted, so later sessions are a
single `HELLO` round trip. Keys live in the platform keystore on both sides:
Android Keystore and Windows DPAPI (`ProtectedData`, machine scope).

## 5. Threading and back-pressure

| Side | Rule |
| ---- | ---- |
| Agent | One acceptor coroutine; one reader coroutine per connection; capture runs on a dedicated `HandlerThread`; encoders never block the socket writer — a bounded queue drops the oldest frame when full and reports `video.stats { dropped }`. |
| Controller | Socket I/O on the thread pool; decode on a fixed-size decoder pool sized to `min(4, cores/2)`; UI updates coalesced to the compositor frame rate. |
| Both | Any queue that can grow without bound must expose a high-water mark, a drop policy and a counter. Unbounded queues are a review blocker. |

## 6. Failure model

| Failure | Detection | Response |
| ------- | --------- | -------- |
| Network drop | TCP FIN/RST or 5 s heartbeat timeout | Session → `RECONNECTING`, exponential backoff 300 ms → 30 s, jittered, max 10 attempts, then `DISCONNECTED`. |
| Agent process death | Heartbeat timeout | Controller surfaces "device agent unavailable" and offers an ADB-based restart. |
| Protocol mismatch | `HELLO` version check | Fail fast with `ERR_VERSION_MISMATCH`; never attempt best-effort parsing. |
| Auth failure | AEAD tag mismatch | Close immediately, increment a per-device strike counter, require re-pairing after 5 strikes. |
| Capture permission revoked | `MediaProjection.Callback.onStop` | Push `event { name: "screen.capture_revoked" }`, stop the stream, keep the session for control-only mode. |
| Encoder starvation | Queue high-water mark | Drop oldest frames, keep the stream alive, report in `video.stats`. |

## 7. Security posture

* **Local-network only.** The agent binds to the current Wi-Fi interface and
  refuses connections whose source is not on the same subnet unless the
  operator has explicitly enabled "allow routed clients".
* **Mutual authentication.** Both peers prove possession of the pairing secret;
  the controller additionally pins the agent's long-term identity key.
* **Forward secrecy per session.** Session keys come from an ephemeral X25519
  exchange and are discarded on disconnect.
* **Least privilege on the device.** Control features are individually
  switchable; shell allow-listing is default-deny with an explicit, auditable
  operator override.
* **No cloud, no telemetry.** Nothing leaves the LAN. There is no analytics
  endpoint, and the code contains no network egress other than the session and
  (optionally) ADB to the connected device.

See [RFC-0002](../rfc/RFC-0002-pairing-and-session-security.md) for the full
threat model and [SECURITY.md](../../SECURITY.md) for the disclosure policy.

## 8. Extension points

| Extension | Mechanism |
| --------- | --------- |
| New capability | Add a flag to RFC-0001 §7 and a handler on the agent; unknown flags are ignored by old controllers, unknown commands answer `ERR_UNSUPPORTED`. |
| New codec | `video.start { codec }` negotiation; the capability list advertises the supported set. |
| Automation client | The controller exposes a local API so CI runners can drive devices headlessly. |
| Alternative controller | Any implementation that passes the conformance vectors in `protocol/vectors/` is a valid controller. |

## 9. Related documents

* [RFC-0001 — DroidLab Wire Protocol](../rfc/RFC-0001-wire-protocol.md)
* [RFC-0002 — Pairing and Session Security](../rfc/RFC-0002-pairing-and-session-security.md)
* [REPOSITORY.md](REPOSITORY.md) — layout and dependency rules
* [docs/adr/](../adr/) — decision records
