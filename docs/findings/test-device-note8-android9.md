# Test device: Samsung Galaxy Note 8 (SM-N950F), Android 9

**Status:** available on the LAN, used for quick manual checks. **Not** the target platform.

Recorded because the test device and the supported platform are not the same thing, and mixing
them up is how a project ends up claiming support it has never exercised.

## What the device is

| Property | Value |
| -------- | ----- |
| Model | `SM-N950F` — Samsung Galaxy Note 8 |
| Device / product | `greatlte` / `greatltexx` |
| Android | **9** (`PPR1.180610.011`, build `N950FXXUGDZEA`) |
| API level | **28** |
| ABI | `arm64-v8a` |
| Screen | 1440×2960 physical, overridden to 1080×2220; density 420 |
| Locale / timezone | `vi-VN` / `Asia/Ho_Chi_Minh` |
| Address | `192.168.1.177:5555` (DHCP; will change) |
| Root | **No** — `su` absent, `ro.build.type=user`, `ro.secure=1` |
| Battery | 79 %, on AC |

Reached with `adb connect 192.168.1.177:5555`. Found by scanning the LAN for an open port 5555
after `adb mdns services` returned nothing — the device is on a legacy `adbd` TCP listener
(`persist.adb.tcp.port=5555`) and is **not** advertising through ADB's mDNS, because Android 9
predates ADB's mDNS discovery and wireless-debugging pairing.

## Why this matters: the device does not meet the project's own requirement

DroidLab's README states **Android 11+ (API 30+)**. This device is API 28. The gap is not
cosmetic:

| Capability | API 30 (supported) | API 28 (this device) |
| ---------- | ------------------ | -------------------- |
| Foreground service types | `FOREGROUND_SERVICE_MEDIA_PROJECTION` exists (API 29+) | Absent |
| MediaProjection consent reuse | One `getMediaProjection()` per token | Looser, so code that works here can fail on API 34 |
| ADB wireless debugging + `adb pair` | Present (API 30+) | **Absent** — no pairing service, no `_adb-tls-pairing._tcp` |
| `adb mdns` discovery | Present | **Absent** |
| mDNS / NSD TXT records for discovery | Fully supported | Supported, but behaviour differs |
| Notification permission | Runtime `POST_NOTIFICATIONS` (API 33) | Granted at install |

So a feature that works on this device can fail on the platforms the README promises, and the
reverse. Two concrete examples that will bite M3 and M5:

* **M3 (mirror).** MediaProjection on API 28 does not need a foreground-service type and its
  consent token is reusable; on API 34 the token is single-use and the service type is mandatory.
  Developing on API 28 would let code ship that fails on every modern device.
* **M5 (ADB over Wi-Fi).** This device has **no ADB pairing at all**, so the entire
  `adb pair` flow — one of M5's two halves — cannot be exercised here. Only the legacy
  `adb tcpip` path exists, reached through `persist.adb.tcp.port=5555`.

Additionally the device is **not rooted**, so `/dev/uinput` exists but is owned
`system:bluetooth` mode `0660`, which an ordinary app cannot open. That rules out the uinput
input-injection strategy on this device and is worth confirming on the target devices rather
than assuming either way.

## Decision

**The emulator is the reference test platform; this device is for quick manual checks.**

* `litmatch_play` (AVD, system image `android-30/google_apis_playstore/x86_64`) is API **30** — the
  minimum the project supports — so it is the device automated tests run against. Verified
  bootable on this machine: 1280×1920 @ 320 dpi, x86_64, `sys.boot_completed=1`, and it advertises
  the full multitouch feature set (`touchscreen.multitouch.distinct`, `.jazzhand`), which the input
  injection work in M3 needs.
* A physical device running **Android 13 or 14** is still wanted, because that is where the
  MediaProjection and foreground-service rules that actually shape M3's design apply, and
  because H.264 hardware encode and real input injection are not faithfully reproduced by x86
  emulation. Note also that ADB's own wireless debugging reports `adb_wifi_enabled=0` on this
  emulator, so M5's pairing half cannot be exercised there either without enabling it.
* This Note 8 is genuinely useful for: `adb` transport plumbing, file transfer, logcat,
  shell-policy behaviour against real binaries, and a first end-to-end run of the transport.
  It is not useful as evidence that a feature will work on a supported platform, and no claim
  may rest on it alone.

### Devices available as of this record

| Device | API | Role | Notes |
| ------ | --- | ---- | ----- |
| `emulator-5554` (`litmatch_play` AVD) | 30 | **Reference.** Automated tests run here. | x86_64, 1280×1920 @ 320 dpi |
| `192.168.1.177:5555` (SM-N950F) | 28 | Quick manual checks only. | arm64-v8a, unrooted, no ADB pairing |
| *wanted* — physical Android 13/14 | 33–34 | Confirm M3's MediaProjection design. | Needed before M3 can be called done |

## The transport finding, which applies regardless

The device is reachable over plain TCP on 5555 with **no pairing and no encryption**, and it
appeared in a LAN scan immediately. That is the legacy `adb tcpip` model, and it is exactly the
situation RFC-0002 and ADR-0006 exist to improve on: a listener that anyone on the same network
can connect to and control.

It is worth recording as a live demonstration of why DLWP/1 does not adopt that model, and why
the agent's first-run experience must not expose an unauthenticated listener even for
convenience during development.
