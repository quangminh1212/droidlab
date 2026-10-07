# Dependencies

The following third-party dependencies are used. Each entry records why it is
needed and what it replaces, so a reviewer can judge the maintenance cost. Rule
R6 of [docs/architecture/REPOSITORY.md](docs/architecture/REPOSITORY.md) requires
an ADR before adding a dependency to a protocol or session layer; ADR links are
given where applicable.

## Android agent

| Dependency | Layer | Licence | Purpose | Alternative considered |
| ---------- | ----- | ------- | ------- | ---------------------- |
| AndroidX Core KTX, AppCompat, Activity | UI/platform | Apache-2.0 | Standard Android support libraries for lifecycle and compatibility. | Platform APIs alone are unusably verbose on API 26+. |
| AndroidX Lifecycle (ViewModel, Service) | UI/platform | Apache-2.0 | Lifecycle-aware components for the foreground service and screens. | Hand-rolled lifecycle observers, which are a common source of leaks. |
| AndroidX CameraX (`camera-mlkit-vision` optional) | UI | Apache-2.0 | QR scanning for the controller side is not needed here; the agent *renders* the QR with ZXing instead. | — |
| ZXing core (`com.google.zxing:core`) | UI | Apache-2.0 | Generate the pairing QR bitmap from the payload. | Hand-writing a QR encoder is out of the question; the library is small and stable. |
| Kotlin coroutines | protocol, core | Apache-2.0 | Structured concurrency for the listener, session and encoding pipelines. | Threads plus callback plumbing; coroutines give cancellation and back-pressure with far less code. |
| Okio or plain `java.nio` | protocol | Apache-2.0 / — | Buffered socket I/O. `java.nio` is sufficient; Okio is only used if the team adopts it. | — |
| Room + SQLCipher | core | Apache-2.0 | Pairing records and the audit log, encrypted at rest with a Keystore-wrapped key (RFC-0002 §6). | Plain files, which cannot express queries or migrations safely. |

The protocol layer deliberately has **no** dependency on a JSON or cbOR library
beyond a small in-repo cbOR codec (ADR-0003). Adding one requires an ADR.

## Windows controller

| Dependency | Layer | Licence | Purpose | Alternative considered |
| ---------- | ----- | ------- | ------- | ---------------------- |
| .NET 9 (`net9.0-windows`) | platform | MIT | Runtime and WPF. | .NET 8 LTS is also acceptable; the project targets the current SDK available in CI. |
| WPF (`PresentationFramework`) | UI | MIT | Desktop shell and composition. Text, DPI and window management are mature here. | WinUI 3 has a newer rendering stack but a heavier deployment model and less mature text rendering for this use. |
| CommunityToolkit.Mvvm | UI | MIT | `ObservableObject`, `RelayCommand`, source-generated properties. | Hand-written `INotifyPropertyChanged`, which is noise across a dozen view models. |
| Microsoft.Extensions.Hosting / DependencyInjection / Logging | app | MIT | Host, configuration, DI container, structured logging. | Manual composition, which does not scale past a handful of services. |
| Microsoft.Extensions.Http | app | MIT | Update checks only (opt-in, and the only egress the product has besides the session and `adb`). | Raw `HttpClient` usage without resilience; acceptable but more code. |
| System.Text.Json | app | MIT | Local settings and the diagnostic frame dump. **Not** the wire format (ADR-0003). | — |
| FFmpeg.AutoGen or a Media Foundation wrapper | mirror | LGPL-2.1 (FFmpeg) / MIT (wrapper) | H.264 decoding for the mirror view. Media Foundation is preferred when the driver's decoder supports the stream, to avoid shipping native binaries. | A managed decoder is not realistic for 1080p60. Shipping FFmpeg native binaries requires a licence and distribution review and MUST NOT happen without an ADR. |
| QRCoder | UI | MIT | Decode the pairing QR from a screenshot or a camera frame on the controller side. | Hand-writing a QR decoder, which is worse. |

## Shared / tooling

| Dependency | Layer | Licence | Purpose |
| ---------- | ----- | ------- | ------- |
| Node.js + `markdownlint-cli2` | tooling | MIT | Markdown lint in CI and locally. |
| commitizen + `cz-conventional-changelog` | tooling | MIT | Interactive conventional-commit helper (optional). |
| ktlint (Gradle plugin) | tooling | MIT | Kotlin formatting. |
| `dotnet format` | tooling | MIT | C# formatting. |
| xUnit | tests | Apache-2.0 | C# unit tests. |
| JUnit 5 + kotlinx-coroutines-test | tests | EPL-2.0 / Apache-2.0 | Kotlin unit tests. |

## Rejected dependencies

| Candidate | Why rejected |
| --------- | ------------ |
| WebRTC (libwebrtc) | Pulls a very large native build into both apps for a 1:1 LAN stream; duplicates the DLWP/1 security layer (ADR-0005). |
| A protobuf/gRPC stack for the wire format | Requires code generation in both builds and complicates forward compatibility (ADR-0003). |
| Electron or a browser engine in the controller | Adds a second renderer and a large attack surface for a native-quality video view (ADR-0002). |
| Any GPL/AGPL/SSPL library | Licence-incompatible with Apache-2.0 distribution (rule R7). |
| A cloud relay service | Contradicts the local-only design and the no-telemetry commitment (RFC-0002 §1.2, ADR-0004). |

## Reviewing a dependency

When reviewing a pull request that adds a dependency, check:

1. Licence is on the allow-list (Apache-2.0-compatible; see rule R7).
2. It is actively maintained — a release in the last 18 months, or a documented
   reason why inactivity is acceptable.
3. Its transitive tree is small; print it (`./gradlew dependencies` or
   `dotnet list package --include-transitive`) and paste the summary in the pull
   request.
4. The alternative of writing the 200 lines yourself was genuinely considered.
5. If the layer is protocol or session, an ADR exists.
6. It is recorded in this file in the same pull request.
