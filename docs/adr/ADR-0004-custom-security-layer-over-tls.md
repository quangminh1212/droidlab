# ADR-0004 — A purpose-built security layer instead of TLS

| Field | Value |
| ----- | ----- |
| Status | Accepted |
| Date | 2025-01-01 |
| Deciders | DroidLab maintainers |

## Context

DLWP/1 carries screen contents, injected input, files and shell output over Wi-Fi.
It plainly needs confidentiality and integrity. The default answer is TLS 1.3:
mature, audited, and available on both platforms (`SSLEngine` on Android, `SslStream`
on .NET). The question is whether DroidLab should use it or define its own
record layer on top of a raw TCP socket.

Forces at play:

* **Certificate UX.** TLS needs a trust decision. A self-signed phone certificate
  means the Windows side must accept an untrusted certificate, and the usual
  workaround — "just click yes" — trains users to bypass exactly the check that
  matters. A private CA shipped in the app is a long-term key distribution
  problem of its own.
* **Mutual authentication is not free.** TLS client certificates would be the
  natural mechanism, but generating and storing a client certificate pair on
  Windows and Android adds significant plumbing for a LAN tool.
* **Identity model.** DroidLab already defines a device identity model with
  fingerprints and a pairing ceremony (RFC-0002). TLS would sit beside that model
  rather than express it.
* **Multiplexing.** DLWP/1 is already a multiplexed framed protocol. TLS records
  would add a second framing layer, and a second set of fragmentation rules to
  get wrong.
* **Scope.** The protocol is LAN-only, short-lived, and pairs two devices that
  have performed an out-of-band ceremony with a human comparing a 6-digit code.

## Decision

Define DLWP/1's own record protection using standard primitives — X25519,
HKDF-SHA256, AES-256-GCM — bound to the existing pairing and identity model, as
specified in RFC-0002. Do not use TLS, and do not define new cryptographic
primitives: every algorithm and construction is a published standard, and the
framing is the only thing DroidLab invents.

## Alternatives considered

| Option | Why not |
| ------ | ------- |
| TLS 1.3 with a self-signed certificate, trust-on-first-use | Reintroduces the "accept this certificate?" prompt that users are trained to dismiss, and gives a fingerprint check that is easy to skip. |
| TLS 1.3 with a pinned certificate from the QR code | Workable, but the pin becomes the identity and the identity model in RFC-0002 has to be expressed anyway; the remaining benefit is the record layer, which must then be reconciled with DLWP/1 framing. |
| TLS 1.3 with client certificates (mTLS) | Correct on paper; heavy in practice on Android, where per-app client-key provisioning and per-OEM keychain behaviour add failure modes that a LAN test tool cannot afford. |
| Noise Protocol Framework (XX or IK) | A very good fit conceptually and closer to the spirit of this decision. Rejected only because it adds a framework, a handshake-pattern vocabulary and its own crypto dependency to both codecs, while RFC-0002's transcript binding already delivers the same properties for this narrow use. Reconsider if the protocol grows a transport-agnostic requirement. |
| Plain TCP inside a VPN | Pushes the problem to the user; a lab phone cannot be assumed to join a VPN. |
| Plain TCP with a pre-shared key and no forward secrecy | Loses G4 (forward secrecy) for no implementation saving. |

## Consequences

### Positive

* The pairing ceremony *is* the trust decision: scanning one QR code and comparing
  six digits replaces a certificate prompt with a check a user can actually make.
* No certificate lifecycle: no expiry, no renewal, no CRL, no CA bundle.
* One framing layer. The AEAD tag and the DLWP/1 header are designed together,
  so a frame is sealed with its own header as associated data — a stronger and
  simpler binding than layering TLS records under protocol frames.
* Forward secrecy per session comes from ephemeral X25519 keys, which is stronger
  than a long-lived TLS session cache would give.

### Negative

* **No third-party audit.** This is the real cost. The design uses only standard
  primitives, but the *composition* is DroidLab's, so the project carries an
  obligation: published test vectors, a documented threat model, constant-time
  comparison, contributory checks, and an explicit invitation for cryptographic
  review. RFC-0002 §9 exists for this reason.
* No interoperability with generic TLS tooling: `openssl s_client` cannot inspect
  a session. Debug tooling must be built.
* Getting the record layer wrong is easy: nonce reuse, sequence-number handling
  and AAD construction are all places where a subtle bug is a real vulnerability.
  Mitigated by the mandatory `ERR_REPLAY_DETECTED` path, the nonce construction
  (sequence number inside the nonce, per-direction keys), and test vectors that
  pin the exact bytes.

### Neutral

* If DroidLab ever needs to traverse an untrusted network (a public WLAN between
  two sites), this decision must be revisited: RFC-0002 provides no protection
  against a hostile network operator who also observes the QR code, and no
  protection against traffic analysis.

## Compliance

A pull request that invents an algorithm, uses a non-constant-time comparison on
secret data, omits the all-zero X25519 check, or reuses a nonce is rejected. Any
change to RFC-0002 requires test-vector updates and, for a semantic change, a new
RFC that supersedes this ADR.
