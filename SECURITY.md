# Security Policy

## Supported versions

| Version | Supported | Notes |
| ------- | --------- | ----- |
| 1.0.x | Yes | Current stable line. |
| < 1.0 | No | Pre-release development builds; upgrade before reporting. |

Security fixes are issued for the latest patch release of each supported minor
line. Because the agent and the controller implement the same protocol, a
security fix may require an update on **both** sides; the release notes state
explicitly whether the agent, the controller, or both must be upgraded.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on the repository
(*Security → Report a vulnerability*), or email the maintainers at the address
listed in `.github/SECURITY-CONTACT` if that file is present. If you have no
private channel available, open a public issue containing only the words
"security report — please contact me" and no technical detail, and a maintainer
will reach out.

Please include:

* the affected component and version (`agent` or `controller`, and the build
  number shown in the app's About screen),
* the protocol version in use,
* a minimal description of the issue and its impact,
* reproduction steps or a proof of concept, if you have one,
* whether you intend to publish, and any disclosure deadline you are working to.

## Our commitments

| Stage | Target |
| ----- | ------ |
| Acknowledge receipt | 3 business days |
| Initial assessment and severity, with a CVSS v3.1 vector | 7 business days |
| Fix or documented mitigation for Critical/High | 30 days |
| Fix for Medium | 90 days |
| Fix for Low | next minor release |
| Public advisory, with credit unless you prefer to stay anonymous | on release of the fix |

If a fix cannot be produced within the target, we will tell you why, what the
interim mitigation is, and what the revised date is. We will not silently let a
deadline pass.

## Scope

### In scope

* The Android agent (APK) and the Windows controller (EXE).
* The DLWP/1 protocol as specified in `docs/rfc/`.
* The pairing, authentication and session-security model (RFC-0002).
* Release artefacts and the build pipeline that produces them.
* The conformance vectors, where a wrong vector could make an insecure behaviour
  look conformant.

### Out of scope

* A device whose operating system or bootloader is compromised (rooted, unlocked
  with a hostile ROM, or with a malicious accessibility service already
  installed). See RFC-0002 §1.2.
* An attacker who has already read the QR code shown on the device screen, or who
  has physical access to an unlocked device.
* Denial of service by exhausting Wi-Fi bandwidth.
* Vulnerabilities in `adb`, in the Android platform, in Windows, or in any
  third-party dependency — report those upstream. If DroidLab's usage turns an
  upstream flaw into a DroidLab-specific impact, that *combination* is in scope.
* The optional external `scrcpy` binary that a user may install; report scrcpy
  issues to the scrcpy project.
* Social engineering of the operator into enabling a capability. DroidLab's job
  is to make the consent visible and reversible, which it does.

## Threat model summary

DroidLab assumes a **local network that may be hostile to observe but that cannot
modify the device**. Specifically:

* A passive eavesdropper on the WLAN learns nothing about session contents.
* An active on-path attacker cannot forge a session, cannot replay a captured
  handshake, and cannot substitute its own key material without the operator
  seeing a mismatched confirmation code.
* An attacker on the LAN can discover that a device is advertising the service
  (unless the operator disabled discovery) and can attempt connections, which
  will fail authentication and are rate-limited.
* The pairing QR code is the trust anchor. It must be visible only to the
  intended controller.

Full detail, including the security goals G1–G7 and the non-goals, is in
[RFC-0002](docs/rfc/RFC-0002-pairing-and-session-security.md).

## Secure configuration guidance for operators

1. Leave **discovery off** on untrusted networks; use the manual address field.
2. Leave **shell access off** unless the test run needs it, and prefer the
   read-only rule set (RFC-0004 §4.4).
3. Check the **peer fingerprint** shown after pairing against the device's own
   screen the first time you pair, and again if the device is factory reset.
4. Turn **wireless debugging off** on the device when a test session ends; the
   debugging channel is more powerful than a DroidLab session.
5. Do not reuse a pairing across a device that has changed hands; use "Unpair"
   and pair again.
6. Keep both applications updated; a protocol fix usually needs both sides.

## Cryptographic review

The security layer composes standard primitives (X25519, HKDF-SHA256,
AES-256-GCM, Ed25519, HMAC-SHA256) but the composition is DroidLab's own design
(ADR-0004). We explicitly invite cryptographic review and will credit reviewers
in the advisory. Concrete areas where review is most valuable:

* the transcript construction and its binding to `AUTH` (RFC-0001 §5.4,
  RFC-0002 §5.1),
* the nonce construction and the per-direction key split (RFC-0002 §5.2),
* the pairing secret derivation and the short-authentication-string step
  (RFC-0002 §4.3–§4.4),
* the replay window and sequence-number handling (RFC-0002 §5.4).

## Disclosure and credit

We follow coordinated disclosure. Once a fix is released we publish a GitHub
Security Advisory containing the impact, the affected versions, the fix version
and any mitigation, and we credit the reporter by name or handle unless asked
not to. We do not operate a bug bounty.
