# ADR-0002 — Native apps instead of a cross-platform stack

| Field | Value |
| ----- | ----- |
| Status | Accepted |
| Date | 2025-01-01 |
| Deciders | DroidLab maintainers |

## Context

DroidLab needs an Android APK and a Windows EXE that speak one protocol. The
tempting simplification is to write the UI once with a cross-platform toolkit
(Flutter, .NET MAUI, React Native, Electron) and share the whole presentation
layer. The product, however, is not a CRUD app:

* The Android side must run a long-lived foreground service, hold a
  `MediaProjection` token, drive a `MediaCodec` H.264 encoder at 60 fps, inject
  input through accessibility, and keep the camera-free QR flow reliable.
* The Windows side must decode a 1080p60 H.264 stream with hardware acceleration,
  render it under WPF composition, and shell out to `adb`.

Both sides are close to their platform: every millisecond of buffering and every
OEM-specific quirk matters.

## Decision

Write the Android agent in **Kotlin** against the Android SDK, and the Windows
controller in **C# / .NET 9 with WPF**. Share no UI code and no runtime code
between them. Share only the **specification and its conformance vectors**,
which both implementations consume.

## Alternatives considered

| Option | Why not |
| ------ | ------- |
| Flutter for both | Requires a second toolchain, and video decode/encode on the Android side would still drop to platform channels for `MediaProjection` and accessibility. Flutter desktop on Windows works, but the `adb` integration and WPF-class window management would be reimplemented anyway. |
| .NET MAUI for both | MAUI's Android video and background-service story is thinner than the native SDK; the agent would fight the framework in exactly the areas that matter. |
| React Native / Electron | Adds a JavaScript runtime to a latency-sensitive video path and to a long-lived background service; also inflates the Android APK for no product benefit. |
| Kotlin Multiplatform | Attractive for sharing the protocol codec, but the two UI layers and virtually all features are platform-bound, so the shared surface would be ~10% of the code while adding a build system, a Gradle→NuGet bridge and a second failure mode. |
| A C++ core with two shells | Maximum control, but the toolchain cost (NDK, JNI, MSVC, cross-compilation in CI) is not justified by the codec work, which is already delegated to platform encoders. |

## Consequences

### Positive

* Each app uses the platform's own primitives: `MediaCodec` + `Surface` on
  Android, `MediaFoundation`/`FFmpeg`-class decode on Windows.
* Best possible startup and runtime performance, smallest distributable size.
* Platform security features are usable directly: Android Keystore with
  hardware backing, Windows DPAPI.
* No framework upgrade treadmill between the two app stores.

### Negative

* Two codebases, two build systems, two CI jobs.
* Protocol changes must be implemented twice. Mitigated by the RFC process and
  by shared conformance vectors: neither implementation may merge a wire-format
  change without the vectors passing on both sides.
* UI look-and-feel must be maintained separately, and the two apps will not be
  pixel-identical.

### Neutral

* Contributors specialise: some work on Kotlin, some on C#. The RFCs are the
  common language.

## Compliance

A pull request that introduces a shared runtime library between the Android and
Windows apps is rejected. A pull request that changes a wire format must, in the
same pull request, update `docs/rfc/`, `protocol/schema/`, `protocol/vectors/`
and both codecs.
