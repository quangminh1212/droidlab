# RFC-0003 — Device Discovery

| Field | Value |
| ----- | ----- |
| **RFC number** | 0003 |
| **Title** | Device Discovery |
| **Status** | Accepted |
| **Protocol version** | `1.0` |
| **Depends on** | [RFC-0001](RFC-0001-wire-protocol.md), [RFC-0002](RFC-0002-pairing-and-session-security.md) |

---

## Abstract

DroidLab controllers find agents on the local network without either side
knowing an IP address in advance. This document specifies the DNS-SD service
type, the TXT record contents, the presence/expiry rules, the direct-connect
fallback and the manual-address escape hatch. Discovery is an optimisation, not
a security boundary: no trust decision may be based on discovery data alone.

## 1. Service type

```
_droidlab._tcp.local
```

| Property | Value |
| -------- | ----- |
| Service type | `_droidlab._tcp` |
| Domain | `local` |
| Instance name | `<agent_name>._droidlab._tcp.local` |
| Port | The agent's DLWP/1 TCP listening port (default `45917`). |
| TTL | 120 seconds |

The agent advertises only while the "Allow discovery" switch is on. Turning the
switch off MUST send the DNS-SD "goodbye" packet (TTL 0) so controllers drop the
device promptly rather than waiting for the TTL.

## 2. TXT record keys

TXT records are DNS-SD `key=value` strings, each at most 255 bytes; the whole
record set MUST stay under 1300 bytes so it fits a single mDNS response.

| Key | Required | Example | Description |
| --- | -------- | ------- | ----------- |
| `v` | yes | `1.0` | Protocol version spoken by the agent. |
| `id` | yes | `5b1f…-…` | `agent_id`, the stable UUIDv4 text identity. |
| `name` | yes | `Pixel 7 – bench 3` | Human-readable device name. |
| `model` | no | `Pixel 7` | Hardware model. |
| `android` | no | `14` | Android release. |
| `sdk` | no | `34` | Android API level. |
| `caps` | no | `screen.mirror,input.touch,shell.exec` | Comma-separated capability names, RFC-0001 §7.1. Truncated to fit; controllers MUST treat it as advisory and MUST call `GET_CAPABILITIES` after connecting. |
| `fp` | yes | `9F3C-1A08-B7E2-44D1` | Identity fingerprint (RFC-0002 §3.2). Lets a controller show a trusted name for an already-paired device before connecting. |
| `sig` | yes | *base64url* | `Ed25519_sign(agent_signing_key, canonical_txt_payload)`, 64 bytes. |
| `tls` | no | `0` | Reserved. `0` means native DLWP/1 security. |
| `busy` | no | `0` | `1` if the agent is at its session limit. |
| `loc` | no | `lan` | `lan` for same-subnet, `routed` if the operator enabled off-subnet access. |

### 2.1 Canonical TXT payload for signing

To make the advertisement tamper-evident:

```
canonical = "DLWP/1-txt" ‖ 0x00
          ‖ "v="  ‖ v      ‖ 0x0A
          ‖ "id=" ‖ id     ‖ 0x0A
          ‖ "fp=" ‖ fp     ‖ 0x0A
          ‖ "caps=" ‖ caps ‖ 0x0A
          ‖ "port=" ‖ port
```

Keys appear in exactly this order and the payload is signed with the agent's
long-term Ed25519 key. A controller that holds a pairing record for `id` MUST
verify `sig` and MUST ignore (not connect to) an advertisement whose signature
fails. A controller that has never paired with `id` cannot verify the signature
and MUST mark the device as unverified in the UI, which is expected for
first-time pairing.

## 3. Discovery procedure

### 3.1 Controller (browse)

1. Open a browse for `_droidlab._tcp.local`.
2. On `ServiceFound`, resolve the host and port.
3. Parse TXT, verify `sig` when a matching pairing record exists.
4. Present the device list row: name, model, Android version, fingerprint, and a
   status pill (`Paired`, `New`, `Busy`, `Unverified`, `Reachable via IP only`).
5. On `ServiceLost` or TTL expiry (120 s), mark the row `Offline` but keep it in
   the saved-device list. Presence is not the same as pairing.

### 3.2 Fallback order

When the user asks to connect, the controller tries, in order:

1. **Live mDNS presence** — connect to the resolved address.
2. **Last-known endpoint** — the address and port stored with the pairing
   record, if it is younger than 7 days.
3. **Subnet sweep** — only if the user enabled "Scan my network". A TCP connect
   to port `45917` across the local `/24`, at most 8 concurrent attempts, 300 ms
   timeout each, aborted as soon as one succeeds. Results are used only to
   refresh the last-known endpoint.
4. **Manual address** — the user types `host` or `host:port`.

The controller MUST NOT connect to a discovered agent whose `id` matches a
pairing record whose `fp` differs. That case MUST raise a visible
"device identity changed — possible impersonation" warning and refuse to
authenticate automatically.

### 3.3 Agent (advertise)

1. Register the service with `NsdManager` on the active Wi-Fi interface.
2. Re-register when the interface address changes (DHCP lease renewal, Wi-Fi
   roaming, hotspot toggling).
3. Include every routable address the device has; a phone commonly has several
   (Wi-Fi, hotspot, VPN). The agent SHOULD prefer the Wi-Fi address.
4. Stop advertising when the session limit is reached and `busy=1`, and stop
   advertising entirely when the operator disables discovery.

## 4. mDNS implementation notes

| Concern | Guidance |
| ------- | -------- |
| Android | `NsdManager` on API 34+. Some OEM builds throttle mDNS; the agent SHOULD additionally open a lightweight UDP beacon (see §4.1) so discovery does not depend on OEM mDNS quality. |
| Windows | Use the built-in DNS-SD APIs or a managed mDNS implementation; a pure-managed implementation is RECOMMENDED because the Windows service can be disabled by policy. |
| Multicast | `224.0.0.251:5353` (IPv4) and `ff02::fb:5353` (IPv6). |
| TTL | 120 s for records, 255 for the PTR that points to the instance. |
| Conflict handling | If the instance name collides, append ` (2)`, ` (3)`, … and re-announce. |

### 4.1 Optional UDP beacon (informative)

When mDNS is unreliable the agent MAY broadcast a small announcement to
`255.255.255.255:45918` every 10 seconds:

```json
{
  "magic": "DLWP-BEACON/1",
  "id": "…",
  "name": "…",
  "v": "1.0",
  "port": 45917,
  "fp": "…",
  "busy": 0,
  "sig": "…"
}
```

The signature covers the canonical serialisation of all fields except `sig`,
in ascending key order, with no whitespace. Controllers listen on `45918` and
merge beacons into the same device list. The beacon carries no secrets and MUST
be ignored when discovery is disabled.

## 5. Security considerations

* Discovery data is **unauthenticated by default**. Anything on the LAN can
  advertise `_droidlab._tcp`. The controller must therefore never trust a
  discovered name, capability list or address beyond using it as a hint.
* The `sig` field upgrades the advertisement to tamper-evident **only** for
  controllers that already hold the agent's identity public key.
* Discovery MUST be disabled by default on first launch in the agent, so a
  freshly installed app does not broadcast the presence of a test device on a
  corporate network without the operator's awareness. The pairing screen offers
  a single toggle to enable it; the explanation shown to the user must state
  what is broadcast.
* The agent MUST NOT include any serial number, account name, IMEI, phone number
  or file path in discovery data.
* The beacon in §4.1 MUST be limited to the broadcast domain and MUST NOT be
  sent to a unicast address the agent has not itself been contacted from.

## 6. Testability

Discovery conformance is checked with the shared vector set
`protocol/vectors/discovery.json`, which contains:

* canonical TXT payloads and their expected Ed25519 signatures (fixed test keys),
* a set of malformed advertisements with the expected rejection verdict,
* beacon canonicalisations, including the "keys in ascending order" rule.

The runner used by CI is `protocol/tools/test-vectors/verify.mjs`.
