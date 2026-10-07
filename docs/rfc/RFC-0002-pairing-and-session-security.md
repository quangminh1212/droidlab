# RFC-0002 — Pairing, Mutual Authentication and Session Security

| Field | Value |
| ----- | ----- |
| **RFC number** | 0002 |
| **Title** | Pairing, Mutual Authentication and Session Security |
| **Status** | Accepted |
| **Protocol version** | `1.0` |
| **Authors** | DroidLab maintainers |
| **Created** | 2025-01-01 |
| **Depends on** | [RFC-0001](RFC-0001-wire-protocol.md) |

---

## Abstract

This document defines how a DroidLab controller and agent establish trust. It
specifies the pairing ceremony, the long-term identity keys, the ephemeral key
exchange, the session-key derivation, the record protection of DLWP/1 frames,
the replay defences and the revocation model. It also states the threat model
and the security properties the design does and does not provide.

## 1. Goals and non-goals

### 1.1 Goals

| Goal | Property |
| ---- | -------- |
| G1 | **Mutual authentication.** Both peers learn the other's long-term identity and prove possession of the pairing secret. |
| G2 | **Confidentiality.** An on-path observer of the Wi-Fi traffic cannot read commands, video or files. |
| G3 | **Integrity.** Any modification of a record is detected and the session aborts. |
| G4 | **Forward secrecy.** Compromise of a long-term key after the fact does not reveal past session traffic. |
| G5 | **Replay resistance.** A recorded handshake cannot be replayed into a new session, and records cannot be reordered or duplicated. |
| G6 | **Usability.** Pairing takes one scan of a QR code and no typing of IP addresses or codes. |
| G7 | **Revocability.** Either side can forget a pairing and immediately deny future sessions. |

### 1.2 Non-goals

* Defending against a **compromised endpoint**. If the phone's OS is rooted and
  hostile, the agent's secrets are readable and the design offers nothing.
* Hiding **traffic metadata** (packet sizes, timing, presence of a session) from
  a local observer.
* Protecting against a **hostile local network operator** who can also observe
  the QR code — the QR code is the trust anchor and must be seen only by the
  intended controller.
* Authentication **on first use across the internet**. DLWP/1 is a LAN protocol.

## 2. Threat model

| Adversary | Capability | Mitigation |
| --------- | ---------- | ---------- |
| **Passive eavesdropper** | Reads every packet on the WLAN | Handshake is ECDH-protected; all records after `HELLO_ACK` are AES-256-GCM sealed. |
| **Active on-path attacker** | Injects, drops, reorders, replays | Transcript hash binds both nonces and both public keys; per-record nonces are derived and strictly increasing; AEAD tags authenticate every byte. |
| **Impersonating agent** | Runs a rogue listener on the LAN advertising `_droidlab._tcp` | The controller will only complete a handshake with an agent whose `agent_id` and identity public key match the pairing record created from the scanned QR code. |
| **Impersonating controller** | Tries to connect without pairing | `AUTH` requires an HMAC over the transcript keyed by the pairing secret; without the secret the agent answers `ERR_UNAUTHORIZED`. |
| **Replay of a captured QR code** | Reuses an old QR image | QR payloads carry a one-time `pairing_token` with a 120-second lifetime and a server-side single-use flag. |
| **Brute force on the pairing token** | Guesses tokens | 128-bit random tokens; the agent rate-limits pairing attempts to 5 per minute and locks pairing for 5 minutes after 5 failures. |
| **Denial of service** | Floods the listening port | The acceptor caps concurrent pending handshakes at `max_pending_handshakes` (default 4) and drops the oldest; established sessions are unaffected. |

The design deliberately does **not** rely on the Wi-Fi password, on the router,
or on the device's screen lock being the only gate. The pairing secret is the
root of trust.

## 3. Long-term material

### 3.1 Identity key pairs

Each side generates a long-lived **X25519** key pair on first run.

| Side | Storage | Protection |
| ---- | ------- | ---------- |
| Agent (Android) | `AndroidKeyStore`, alias `droidlab.identity.v1` | Hardware-backed when the device has a TEE/StrongBox; otherwise software, marked non-exportable. |
| Controller (Windows) | DPAPI `ProtectedData` with `DataProtectionScope.CurrentUser`, file under `%LOCALAPPDATA%\DroidLab\identity.dat` | Bound to the Windows user profile. |

`identity_pub` is the raw 32-byte X25519 public key. Its textual form is 43
characters of unpadded RFC 4648 base64url.

### 3.2 Fingerprints

A **fingerprint** is a human-checkable rendering of a public key:

```
digest    = SHA-256(  "DLWP/1-fingerprint" ‖ 0x00 ‖ identity_pub )
groups    = hex(digest[0..7])            # 8 bytes = 16 hex chars
fingerprint = groups[0:4] "-" groups[4:8] "-" groups[8:12] "-" groups[12:16]
```

Example: `9F3C-1A08-B7E2-44D1`. Both sides display the peer's fingerprint after
pairing; a mismatch is the user-visible signal of an impersonation attempt.

### 3.3 Pairing record

A completed pairing produces a record kept by both sides:

| Field | Type | Notes |
| ----- | ---- | ----- |
| `pairing_id` | bytes(16) | Random; names the pairing in the protocol. |
| `pairing_secret` | bytes(32) | The shared secret from the ceremony (§4). Never transmitted after pairing. |
| `peer_identity_pub` | bytes(32) | The other side's long-term public key. |
| `peer_fingerprint` | string | Cached rendering of the above. |
| `peer_device_id` | string | Agent id or controller id. |
| `created_at_ms` | int | Unix epoch ms. |
| `last_used_at_ms` | int | Updated on each successful `AUTH`. |
| `label` | string | Operator-supplied name, e.g. "Pixel 7 – lab bench". |

The agent stores at most 16 pairing records; the controller stores one record
per agent. Records never leave the device: there is no sync, no export, no
cloud backup (the agent excludes its database from Android auto-backup).

## 4. Pairing ceremony

### 4.1 Protocol flow

```
 Agent (phone)                                    Controller (Windows)
      │                                                   │
      │ 1. user taps "Pair a new PC"                       │
      │    agent generates:                                │
      │      pairing_id      = random(16)                  │
      │      ephemeral_sk/pk = X25519 key pair             │
      │      pairing_token   = random(16)  (one-time)      │
      │    renders QR:                                     │
      │      droidlab://pair?v=1&…&sig=…                   │
      │                                                   │
      │ 2. user scans the QR with the controller            │
      │    controller validates the embedded signature      │
      │                                                   │
      │ 3. controller connects to host:port from the QR     │
      │    and sends PAIR_REQUEST                           │
      │◄──────────────────────────────────────────────────│
      │    { pairing_id, v, ctrl_identity_pub,              │
      │      ctrl_ephemeral_pub, ctrl_nonce, ctrl_name }    │
      │                                                   │
      │ 4. agent computes the shared secret (§4.3)          │
      │    agent shows a 6-digit code derived from it       │
      │    controller shows the same code                   │
      │                                                   │
      │ 5. agent sends PAIR_RESPONSE                        │
      │───────────────────────────────────────────────────►│
      │    { pairing_id, agent_identity_pub,                │
      │      agent_ephemeral_pub, agent_nonce,              │
      │      agent_name, proof, device_info_summary }       │
      │                                                   │
      │ 6. user compares the 6-digit code on both screens   │
      │    and confirms on the device                       │
      │                                                   │
      │ 7. agent sends PAIR_CONFIRM                         │
      │───────────────────────────────────────────────────►│
      │    { pairing_id, confirmation }                     │
      │                                                   │
      │ 8. both persist the pairing record; the agent       │
      │    burns pairing_token and closes the QR screen     │
```

### 4.2 QR payload

The QR code encodes a URI:

```
droidlab://pair
  ?v=1
  &pid=<base64url(pairing_id)>
  &tok=<base64url(pairing_token)>
  &host=<ipv4 or ipv6 literal>
  &port=<tcp port>
  &apk=<base64url(agent_identity_pub)>
  &aep=<base64url(agent_ephemeral_pub)>
  &name=<urlencoded agent name>
  &exp=<unix seconds>
  &sig=<base64url(signature)>
```

Where `signature = Ed25519_sign(agent_signing_key, canonical_uri_without_sig)`.

The agent holds a second long-term key pair for signing, an **Ed25519** key
(`agent_signing_key`), whose public half travels with the pairing record so that
the controller can later verify signed announcements. Signing the QR payload
lets the controller detect a tampered QR image before it connects anywhere.

Rules:

* `exp` MUST be at most 120 seconds in the future. The controller MUST refuse an
  expired QR and MUST show "QR expired, refresh it on the phone".
* The QR MUST contain a routable address for the phone on the current Wi-Fi
  network. If the phone is on a network the controller cannot reach, the agent
  MUST warn the user before showing the code.
* The QR MUST be rendered with at least 4 modules of quiet zone and MUST be
  regenerated every time the pairing screen is opened.

### 4.3 Secret derivation

```
# both sides hold these after step 5
shared   = X25519(my_ephemeral_sk, peer_ephemeral_pub)          # 32 bytes
dh_static= X25519(my_identity_sk,  peer_identity_pub)           # 32 bytes

salt     = "DLWP/1-pairing" ‖ 0x00 ‖ pairing_id
ikm      = shared ‖ dh_static ‖ pairing_token                   # 80 bytes

prk      = HKDF-Extract(salt, ikm)                              # SHA-256
pairing_secret = HKDF-Expand(prk, "DLWP/1-pairing-secret", 32)
```

Both the ephemeral and the static Diffie-Hellman results are combined, so an
attacker who later steals one long-term key still cannot recompute the pairing
secret without the ephemeral private key, and an attacker who compromises an
ephemeral key still needs a long-term key.

### 4.4 Confirmation code

```
digest = SHA-256( "DLWP/1-pairing-code" ‖ 0x00 ‖ pairing_secret
                  ‖ ctrl_nonce ‖ agent_nonce )
code   = decimal( uint32_be(digest[0..4]) mod 1000000 )   # 6 digits, zero-padded
```

Both screens show the same code. This is the classic short-authentication-string
step: it detects a man-in-the-middle that substituted its own ephemeral keys,
because such an attacker cannot produce the same `pairing_secret` on both sides.

### 4.5 Proofs

`PAIR_RESPONSE.proof` and `PAIR_CONFIRM.confirmation`:

```
ctrl_proof = HMAC-SHA256(pairing_secret, "DLWP/1-pairing-controller" ‖ ctrl_nonce  ‖ agent_nonce)
agent_proof= HMAC-SHA256(pairing_secret, "DLWP/1-pairing-agent"      ‖ agent_nonce ‖ ctrl_nonce )
confirm    = HMAC-SHA256(pairing_secret, "DLWP/1-pairing-confirm"    ‖ agent_proof ‖ ctrl_proof)
```

The controller MUST verify `agent_proof` before showing the confirmation code as
trusted. The agent MUST verify that `confirm` matches before persisting the
record.

### 4.6 Pairing message types

| Code | Name | Direction |
| ---- | ---- | --------- |
| `0x0A` | `PAIR_REQUEST` | C → A |
| `0x0B` | `PAIR_RESPONSE` | A → C |
| `0x0C` | `PAIR_CONFIRM` | A → C |
| `0x0D` | `PAIR_REJECT` | A → C |
| `0x0E` | `PAIR_STATUS` | A → C |

Pairing frames are exchanged on channel `0` in the clear (they precede session
key derivation) but every field that could be forged is protected by the proofs
above. Pairing is a **separate TCP connection** from the session connection; the
pairing connection MUST be closed once the record is persisted.

`PAIR_REJECT` carries `{ pairing_id, reason }` with `reason` one of `denied`,
`code_mismatch`, `expired`, `rate_limited`, `already_paired`, `internal`.

`PAIR_STATUS` carries `{ pairing_id, state, retry_after_ms? }` with `state` one
of `awaiting_user`, `awaiting_controller`, `confirmed`, `rejected`.

## 5. Session security

### 5.1 Transcript and key schedule

Session keys are derived per connection, immediately after `HELLO_ACK`:

```
# inputs
client_nonce, agent_nonce            # 32 bytes each
client_pub,  agent_pub               # ephemeral X25519 public keys, 32 bytes each
shared       = X25519(my_ephemeral_sk, peer_ephemeral_pub)

transcript_hash = SHA-256(canonical transcript, RFC-0001 §5.4)

salt = "DLWP/1-session" ‖ 0x00 ‖ session_id
ikm  = shared ‖ pairing_secret

prk  = HKDF-Extract(salt, ikm)

c2a_key = HKDF-Expand(prk, "DLWP/1-c2a-key", 32)   # controller → agent
a2c_key = HKDF-Expand(prk, "DLWP/1-a2c-key", 32)   # agent → controller
c2a_iv  = HKDF-Expand(prk, "DLWP/1-c2a-iv",  4)    # nonce prefix
a2c_iv  = HKDF-Expand(prk, "DLWP/1-a2c-iv",  4)

exporter = HKDF-Expand(prk, "DLWP/1-exporter" ‖ transcript_hash, 32)

# authentication proofs (exchanged in AUTH / AUTH_OK)
auth_proof_client = HMAC-SHA256(pairing_secret, "DLWP/1-client" ‖ transcript_hash)
auth_proof_agent  = HMAC-SHA256(pairing_secret, "DLWP/1-agent"  ‖ transcript_hash)
```

Direction keys are **separate**, so a frame reflected back to its sender cannot
be accepted. Session keys are zeroed on disconnect and never persisted.

### 5.2 Record protection

Every frame with the `ENCRYPTED` flag carries:

| Field | Where | Value |
| ----- | ----- | ----- |
| `nonce` | first 12 bytes of the body | `iv_prefix (4 bytes) ‖ sequence (8 bytes, big-endian)` |
| `ciphertext` | remaining body bytes | `AES-256-GCM(key, nonce, plaintext, aad)` output, tag appended |
| `aad` | not transmitted | The 24-byte frame header (with `BodyLength` replaced by the plaintext length) |

`sequence` in the nonce is the frame's `SequenceNumber` on that channel, which
MUST be strictly increasing. A receiver MUST reject a `SequenceNumber` it has
already seen on that channel with `ERR_REPLAY_DETECTED` and MUST abort the
session. Because the nonce incorporates the sequence number and the direction
key differs per direction, nonce reuse under a given key is impossible.

Plaintext length `L` yields a body of `12 + L + 16` bytes; the frame's
`BodyLength` MUST therefore equal `12 + L + 16`. The receiver recovers `L` from
the GCM tag verification and MUST fail the session on mismatch.

### 5.3 `HELLO` / `HELLO_ACK` integrity

The first two frames are unencrypted, so an active attacker could try to swap
them. This is exactly what the transcript hash prevents: both sides derive
`transcript_hash` from the *received* values and the pairing-proof HMACs cover
it, so a substituted `HELLO` yields a different hash and the `AUTH` proof fails.

### 5.4 Sequence and replay rules

| Rule | Statement |
| ---- | --------- |
| S1 | `SequenceNumber` starts at `1` and increases by exactly `1` per frame sent in the session; it is **session-global**, not per channel. |
| S2 | A receiver MUST track the highest accepted sequence per session and reject any frame whose sequence is not strictly greater, except for a bounded reordering window. |
| S3 | The reordering window is 32 frames. Out-of-window frames MUST be rejected with `ERR_REPLAY_DETECTED` and MUST terminate the session. |
| S4 | Nonces (`client_nonce`, `agent_nonce`, `pairing_token`, `pairing_id`, `session_id`) MUST come from a CSPRNG and MUST NOT repeat across sessions. |
| S5 | A peer that observes a nonce it has used before in a previous session with the same peer MUST abort with `ERR_REPLAY_DETECTED`. |

### 5.5 Rate limits, strikes and revocation

| Event | Behaviour |
| ----- | --------- |
| Failed `AUTH` | Increment the per-`pairing_id` strike counter. At 5 strikes the agent marks the record `quarantined` and requires manual re-pairing. |
| Failed pairing attempt | Rate limit: 5 per minute, exponential lockout up to 5 minutes. |
| `SESSION_END { reason: "revoked" }` | The peer removes the record immediately. |
| Controller "Forget device" | Deletes the local record and, if reachable, sends `SESSION_END { reason: "revoked" }`. |
| Agent "Unpair this PC" | Deletes the record and closes any live session with that controller. |
| Factory reset of either side | Regenerates the identity key pair; all previous pairings become unusable by construction. |

## 6. Secure storage requirements

| Platform | Requirement |
| -------- | ----------- |
| Android | Identity keys generated with `KeyGenParameterSpec` and kept in `AndroidKeyStore`. Pairing records in an encrypted Room/SQLCipher database whose key is wrapped by a Keystore-held AES key. The database MUST be excluded from cloud backup (`android:allowBackup="false"` on the data store, or a documented `dataExtractionRules` exclusion). |
| Windows | Identity key and pairing records protected with DPAPI `CurrentUser`. Credentials MUST NOT be written to the registry, to a plain file, or to the Windows credential prompt. Logs MUST NOT contain `pairing_secret`, session keys, tokens or nonces. |

## 7. Cryptographic primitives

| Purpose | Algorithm | Parameters |
| ------- | --------- | ---------- |
| Key agreement | X25519 | RFC 7748 |
| Digital signature (QR, announcements) | Ed25519 | RFC 8032 |
| Key derivation | HKDF | RFC 5869, SHA-256 |
| Record encryption | AES-256-GCM | 96-bit nonce, 128-bit tag |
| Integrity/proofs | HMAC-SHA256 | RFC 2104 |
| Transcript / fingerprints | SHA-256 | FIPS 180-4 |
| Randomness | Platform CSPRNG | `SecureRandom` / `RandomNumberGenerator.Fill` |

Implementations MUST NOT invent their own primitives, MUST use constant-time
comparison for all secret-dependent comparisons, and MUST reject all
all-zero X25519 outputs (the contributory-behaviour check).

## 8. Key rotation

* Ephemeral session keys rotate every connection automatically.
* Long-term identity keys MAY be rotated by the operator ("Reset identity").
  Rotation invalidates every existing pairing.
* `pairing_secret` MAY be refreshed in place by re-running the pairing ceremony
  without unlinking; the agent then replaces the record and increments an
  internal `pairing_epoch`.
* The protocol carries no automatic long-term rotation timer: silent rotation
  would strand a controller that is offline for a long period, so rotation is
  always operator-initiated and always announced in the UI.

## 9. Protocol-relevant checklist for implementers

1. Generate identity keys on first launch, before any network listener is
   started.
2. Verify the QR signature and `exp` before making any connection.
3. Never log secrets; add a redaction test.
4. Implement the contributory check on X25519 results.
5. Compute the transcript hash from received bytes, never from local intent.
6. Reject non-increasing sequence numbers and abort the session.
7. Wipe session keys and nonces on disconnect.
8. Expose the peer fingerprint in the UI so a user *can* notice impersonation.
9. Make revocation immediate: a revoked pairing must fail the next `AUTH` even
   if the peer still holds the secret.
10. Keep the pairing database out of any backup or sync mechanism.

## 10. References

* [RFC-0001](RFC-0001-wire-protocol.md) — Wire protocol
* [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — X25519 and X448
* [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) — Ed25519
* [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
* [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) — GCM
* [RFC 6120](https://www.rfc-editor.org/rfc/rfc6120) §5 — SASL-style short
  authentication strings (informative)
