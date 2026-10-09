# Production Practice
ADB over Wi-Fi, mDNS/NSD, and Android Input Injection

Research report for DroidLab (Apache-2.0, Windows WPF/.NET controller + Android agent).

**Method.** Every claim below is traced to a primary source: AOSP source at a specific path, anofficial doc, a release
note, a package manifest, a licence file, or an experiment run on thismachine. Experiments are marked **[verified
locally]**. Where something could not be confirmed itis marked **unverified**. Where a conclusion is my inference from
primary evidence rather than aquoted statement, it is marked *[inference]*.Local environment used for experiments:
`adb` 1.0.41 / platform-tools **37.0.1-15733141**(`C:\Users\GHC\AndroidSdk\platform-tools\adb.exe`), Windows
10.0.26200, JDK 17 (for `javap`),Android SDK platform **android-34** (`android.jar`).

---

## 1.
ADB over Wi-Fi mechanics

### 1.1 The two-path command flow`adb pair` and `adb connect` are two distinct steps against two distinct device-side servers.
Official man page (`packages/modules/adb/docs/user/adb.1.md`, VERSION "1.0.41"):

```textconnect HOST[:PORT]      Connect to a device via TCP/IP [default PORT=5555].disconnect [HOST[:PORT]] Disconnect from given TCP/IP device [default PORT=5555], or all.pair HOST[:PORT] [PAIRING_CODE]                         Pair with a device for secure TCP/IP communication.mdns check | services    Perform mDNS subcommands.

```The AOSP architecture doc (`packages/modules/adb/docs/dev/adb_wifi.md`) gives the canonical flow:

```text$ adb pair 192.168.86.38:43811Enter pairing code: 515109$ adb connect 192.168.86.34:44643$ adb devicesList of devices attachedadb-43081FDAS000VS-QXjCrW._adb-tls-connect._tcp    device

```Note the two **different ports in the example** â€” `43811` (pairing server, ephemeral) and `44643`(connect server, ephemeral). They are unrelated and both change across reboots and toggles.

**Port discovery.** Both are advertised over mDNS; you are not meant to hard-code them:- `_adb._tcp` â€” legacy TCP
service started via `adb tcpip <PORT>`.- `_adb-tls-pairing._tcp` â€” advertised while the device pairing server is
active.- `_adb-tls-connect._tcp` â€” advertised while the device TLS server is active.

These are defined in `packages/modules/adb/adb_mdns.h`:

```c#define ADB_MDNS_SERVICE_TYPE "adb"#define ADB_MDNS_TLS_PAIRING_TYPE "adb-tls-pairing"#define ADB_MDNS_TLS_CONNECT_TYPE "adb-tls-connect"...constexpr int kADBTransportServiceRefIndex = 0;constexpr int kADBSecurePairingServiceRefIndex = 1;constexpr int kADBSecureConnectServiceRefIndex = 2;constexpr int kNumADBDNSServices = 3;

```text`adb_mdns.cpp` builds the full names as `"_" atype "._tcp"`, so the browse types are literally`_adb._tcp`, `_adb-tls-pairing._tcp`, `_adb-tls-connect._tcp`.**[verified locally]** Real output of `adb mdns check` and `adb mdns services` on this machine:

```$ adb mdns checkmdns daemon version [adb discovery 0.0.0]$ adb mdns servicesList of discovered mdns services

```textInteresting detail: the doc's example shows `mdns daemon version [Openscreen discovery 0.0.0]` whilethis build prints `[adb discovery 0.0.0]`. So the backend label varies by build â€” do not parse it.

Also, from `adb_wifi.md`: "At the moment, IPv6 addresses are resolved but not output by thecommand." **[verified: the
header line is `List of discovered mdns services`, printed by the clientbefore the query is even sent â€” see
`commandline.cpp` below.]**

### 1.2 What the wireless-debugging settings screen actually showsFrom `adb_wifi.md`, quoted directly:

> If a user starts a Pairing Server on the device (via `Settings

> System

> Developer options >

> Wireless debugging

> Pair device with pairing code`), they are presented with both a pairing code

> and the IPv4:port of the Wi-fi interface. In this case the vector to exchange the TLS secret is

> the user who reads it on the device then types the pairing code on the host.

The screen has two distinct affordances and they produce different instance names:

- **"Pair device with pairing code"** â†’ instance name `adb-<prop(persist.adb.wifi.guid)>` **QR code pairing** â†’
  instance name `studio-<RANDOM-10>` (e.g. `studio-58m*7E2fq4`)The generic instance-name rule: `adb-` + `ro.serialno`

  + a random suffix added by the mDNS backend.

### 1.3 The pairing protocol, from sourceThis is fully documented in AOSP source and the details matter.

**Transport.** `client/pairing/pairing_client.cpp` opens a plain TCP socket and turns Nagle **off**:

```cppconst int timeout = 10;  // secondsunique_fd fd(network_connect(host_, port_, SOCK_STREAM, timeout, &err));...int off = 1;adb_setsockopt(fd.get(), IPPROTO_TCP, TCP_NODELAY, &off, sizeof(off));

```It then hands the fd to `pairing_connection_client_new(...)` with `pswd`, `peer_info`, and a PEMX.509 certificate + matching private key.

**TLS layer.** `pairing_connection/pairing_connection.cpp`, `SetupTlsConnection()`:

```cpptls_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });   // accept any certtls_->DoHandshake();std::vector<uint8_t

> exportedKeyMaterial = tls_->ExportKeyingMaterial(kExportedKeySize);
  // 64 bytespswd_.insert(pswd_.end(), exportedKeyMaterial.begin(), exportedKeyMaterial.end());
auth_ = CreatePairingAuthPtr(role_, pswd_);

```text

**This is the single most important implementation detail:** the effective SPAKE2 password is`pairing_code ||
exported_keying_material(64)`. Trust comes from the PAKE, not from PKI â€” thecertificate is explicitly not validated.

**PAKE layer.** `pairing_auth/pairing_auth.cpp` uses BoringSSL's SPAKE2 (not RFC 9382 SPAKE2+):

```cppstatic constexpr spake2_role_t kClientRole = spake2_role_alice;static constexpr spake2_role_t kServerRole = spake2_role_bob;static const uint8_t kClientName[] = "adb pair client";static const uint8_t kServerName[] = "adb pair server";

```Flow: `SPAKE2_CTX_new(role, my_name, my_len, their_name, their_len)` â†’`SPAKE2_generate_msg(ctx, key, &key_size, SPAKE2_MAX_MSG_SIZE, pswd.data(), pswd.size())` â†’ exchangeâ†’ `SPAKE2_process_msg(ctx, key_material, &key_material_len, ...)` returning `1` on success.

**Session cipher.** `pairing_auth/aes_128_gcm.cpp` derives AES-128-GCM from the SPAKE2 key material:

```cppuint8_t key[16];uint8_t info[] = "adb pairing_auth aes-128-gcm key";HKDF(key, sizeof(key), EVP_sha256(), key_material, key_material_len, nullptr, 0, info, sizeof(info)-1);EVP_AEAD_CTX_init(context_.get(), EVP_aead_aes_128_gcm(), key, sizeof(key), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr);

```textNonce is 12 bytes, formed from a `uint64` sequence counter copied into a zero-filled buffer â€”**per-direction counters, both starting at 0, no AAD**. Encrypt increments `enc_sequence_`, decryptincrements `dec_sequence_`.

**Wire framing.** Also in `pairing_connection.cpp`:

```cppconst uint8_t kCurrentKeyHeaderVersion = 1;const uint8_t kMinSupportedKeyHeaderVersion = 1;const uint8_t kMaxSupportedKeyHeaderVersion = 1;const uint32_t kMaxPayloadSize = kMaxPeerInfoSize * 2;   // 16384struct PairingPacketHeader {    uint8_t version;   // PairingPacket version    uint8_t type;      // the type of packet (PairingPacket.Type)    uint32_t payload;  // Size of the payload in bytes} __attribute__((packed));

```Header is 6 bytes packed; `payload` is sent big-endian (`htonl`). Two packet types in sequence:`PairingPacket::SPAKE2_MSG`, then `PairingPacket::PEER_INFO`.

**PeerInfo.** `pairing_connection/include/adb/pairing/pairing_connection.h`:

```cconst uint32_t kMaxPeerInfoSize = 8192;struct PeerInfo {    uint8_t type;    uint8_t data[kMaxPeerInfoSize

- 1];
}
 __attribute__((packed));
enum PeerInfoType : uint8_t {
    ADB_RSA_PUB_KEY = 0,    ADB_DEVICE_GUID = 1,}
;

```textThe host sends type `ADB_RSA_PUB_KEY`; it verifies the device replied `ADB_DEVICE_GUID`:

```cppif (waiter.peer_info_.type != ADB_DEVICE_GUID) {    response = "Failed: Successfully paired but server returned unknown response=";

```

**Client-side practical steps, in order:**

1. Resolve `ip:port` â€” either supplied by the user or from `_adb-tls-pairing._tcp`.

2. TCP connect (10 s timeout), `TCP_NODELAY` off.

3. TLS handshake with a freshly generated RSA-2048 X.509 cert; accept any server cert.

4. Export 64 bytes of keying material; append to the pairing code.

5. SPAKE2 as `spake2_role_alice` with name `"adb pair client"`, peer `"adb pair server"`.

6. Send `SPAKE2_MSG` (header version 1, type SPAKE2_MSG, big-endian length).

7. Receive peer `SPAKE2_MSG`; `SPAKE2_process_msg` â†’ key material â†’ HKDF â†’ AES-128-GCM context.

8. Send `PEER_INFO` = AES-GCM(`PeerInfo{type=ADB_RSA_PUB_KEY, data=<host public key>}`).

9. Receive `PEER_INFO`; require `type == ADB_DEVICE_GUID`; the GUID is the device identity.

10. Write the GUID to the host known-hosts store, then auto-connect.Steps 8â€“10 are visible in `client/adb_wifi.cpp`:

```cppresponse = "Successfully paired to " + host + " [guid=" + device_guid + "]";write_known_host_to_file(device_guid);adb_secure_connect_by_service_name(device_guid);

```textKnown hosts are persisted as a protobuf at `<android_dir>/adb_known_hosts.pb`, written atomically via`SafeReplaceFile` and `chmod(path, S_IRUSR | S_IWUSR | S_IRGRP)` â€” i.e. **0640**. On failure theexact user-facing string is `"Failed: Wrong password or connection was dropped."`.

### 1.4 Can pairing be scripted without a human reading the screen? Yes â€” via QRThere are two bootstrapping vectors for the shared secret and only one needs a human:
- **6-digit code path: genuinely needs a human. ** The code is generated and displayed on the device; `adb pair
  HOST:PORT` with no code argument prompts `Enter pairing code:` and reads stdin. From `client/commandline.cpp`:

```cpp  if (!strcmp(argv[0], "pair")) {      if (argc < 2 || argc 

> 3) error_exit("usage: adb pair HOST[:PORT] [PAIRING CODE]");
      std::string password;
      if (argc == 2) {
          printf("Enter pairing code: ");
          ...      }
 else {
          password = argv[2];
      }
      std::string query = android::base::StringPrintf("host:pair:%s:%s", password.c_str(), argv[1]);
      return adb_query_command(query);
  }
  

```  Supplying the code as `argv[2]` removes the prompt but does not remove the human. This is a  **hard limit imposed by the trust model**, not a missing feature: `adb_wifi.md` states the vector  is "the user who reads it on the device then types the pairing code on the host."

- **QR path: fully scriptable, and the host chooses the secret.** This is the finding that matters most for DroidLab.
  Per `adb_wifi.md`, Studio generates a QR containing:

```text  WIFI:T:ADB;S:studio-g@<xeYnap/;P:(Aq+v9>Cx>!/;;  

```  The tokens are `;`-separated (format borrowed from the WPA3 spec, page 25):  

1. `T:` type â€” `ADB` is the special string.

2. `S:` repurposes the `ssid` field to **request a specific mDNS instance name** for `_adb-tls-pairing._tcp`. The
   device's camera handler sees `T:ADB` and starts a pairing server with that requested name; the `studio-` suffix is
   randomised so the host can tell *which* phone just scanned.

3. `P:` the password, **generated by Studio and read by the device's camera**. So in the QR flow the **host** invents
   the password and the **device** learns it by scanning. No transcription, no screen-reading on the phone, and the
   host knows the secret it must feed to the PAKE. This is the scriptable path. The QR is rendered device-side in
   DroidLab's sibling context, but note the direction: for *ADB* pairing the QR is generated **by the workstation**
   and scanned **by the phone**, which is the opposite of DroidLab's own RFC-0002 pairing (device renders, controller
   scans). Two QR flows in one product is a UX hazard worth calling out.

### 1.5 How the tools automate it| Tool | Mechanism | Evidence || 

---

 | 

---

 | 

---

 || Android Studio, pair-with-code | "relies on mDNS to detect devices with an active Pairing Server. To this effect, Studio polls adb server for service instances of type `_adb-tls-pairing`." | `adb_wifi.md` || Android Studio, QR | Generates `WIFI:T:ADB;S:studio-<rand10>;P:<host-chosen password>;;` and displays it; phone camera scans | `adb_wifi.md` || `adb` itself | Auto-connects to `_adb-tls-connect._tcp` when the GUID is known from pairing | `adb_wifi.md`, `adb_mdns.cpp` || `adb mdns services` / `check` | Thin client wrappers over `host:mdns:services` / `host:mdns:check` | `commandline.cpp` || `scrcpy --tcpip` | Does not pair. It drives `adb tcpip`/`connect` over an already-authorised transport | See Â§2 note || WSA / `adb-tools` / npm `adb-wifi` | Shell out to `adb pair` / `adb connect`; the npm `adb-wifi` class exists to wrap exactly these two commands | *[inference from the name and the ecosystem; not verified by reading its source in this session]* |`adb_wifi.md` also documents a control-out on pairing completion that is easy to miss:

> There is one exception. When the pairing client finishes on the host, it also attempts to connect

> to the device it just paired with. This is because `_adb-tls-connect` was already published before

> pairing even began, which means the host cannot rely on the mDNS `_adb-tls-connect` "Create" event

> being published.

**Practical consequence:** after a successful `adb pair`, the device often appears in `adb devices`*without* an
explicit `adb connect`. Code that waits for a `Create` event will hang. Alwaysre-enumerate `adb devices` after
pairing.

### 1.6 Auto-connect control and the device-side wiring`ADB_MDNS_AUTO_CONNECT` (from `adb_mdns.cpp` and the client help text):

```text$ADB_MDNS_AUTO_CONNECT  comma-separated list of mdns services to allow auto-connect                        (default adb-tls-connect)

```Semantics from `config_auto_connect_services()`: default allowlist contains only`_adb-tls-connect._tcp`; `0` disables all auto-connect; `all` adds `_adb._tcp`; otherwise acomma-separated list of short names is matched by `adb_DNSServiceIndexByName` after wrapping each in`_<name>._tcp`. Service names starting with `adb-EMULATOR` are always ignored because "it interfereswith the emulator ports that are already connected."`ADB_MDNS=0` disables the mDNS backend entirely â€” `mdns_utils.cpp`:

```cppbool is_enabled() {    return !getenv("ADB_MDNS") || strcmp(getenv("ADB_MDNS"), "0") != 0;}

```text

**Caveat [verified locally]:** setting `ADB_MDNS=0` in the *client's* environment does **not** change`adb mdns check`
output, because the daemon lives in the already-running server process. To takeeffect, the server must be (re)started
with that variable set. This is a real trap for a controllerthat tries to toggle mDNS off per-invocation.Device-side
wiring, per `adb_wifi.md` â€” these system properties are the observable state:| Property | Who sets it | Meaning ||

---

 | 

---

 | 

---

 || `persist.adb.tls_server.enable` | Framework (Developer settings checkbox) | "Use wireless debugging" toggled; adbd starts/stops the TLSServer || `service.adb.tls.port` | adbd | The ephemeral port the TLSServer listens on; Framework reads it to publish `_adb-tls-connect` || `ctl.start` = `mdnsd` | adbd | Ensures the mDNS daemon is running || `persist.adb.wifi.guid` | platform | Device GUID used to build both service instance names |Components: adbd, Framework (`AdbDebuggingManager`), and the mDNS daemon. The Pairing Server and TLSserver are part of the adbd apex API and are linked into `system_server`. Discoverable via`adb shell getprop service.adb.tls.port` â€” *[inference: the doc states adbd sets it and Frameworkreads it; that it is readable over `getprop` from shell follows from it being a normal property, butI did not verify on a device]*.

### 1.7 Security restrictions summary
- **Android 11 (API 30) introduced `ADB Wifi`** with pairing + TLS. The API surface is annotated `__INTRODUCED_IN(30)`
  throughout `pairing_auth.h` / `pairing_connection.h`.- The old `adb tcpip 5555` path is **unencrypted**: "This means
  all traffic can be eavesdropped and open to MITM attacks" (`adb_wifi.md`). It also greets with `A_AUTH`, whereas the
  new port opens with `A_STLS`.- The device keystore is `/data/misc/adb/adb_keys` (or `/adb_keys`).

- **mDNS backend `mdnsd`**: `adb mdns check` reports the stack and version. The platform has two backends; `adb.cpp`
  sets `mdns_backend` to `AdbServerStatus::BONJOUR` or `...::OPENSCREEN`, and `ADB_MDNS_OPENSCREEN` forces OpenScreen
  ([verified locally: the env var is honoured at the server level, again requiring a server restart to observe]).-
  Nothing in the pairing exchange is protected by PKI. Both sides call `SetCertVerifyCallback([](X509_STORE_CTX*){
  return 1; })`. **Do not describe ADB wireless pairing as certificate-authenticated.**

---

## 2.
Launching / invoking the ADB server and client from a Windows app

### 2.1 Licensing â€” this is the biggest surprise

**The ADB *source* is Apache-2.0; the *platform-tools package* is not.** These are differentartefacts with different
terms.AOSP `packages/modules/adb` contains a top-level `MODULE_LICENSE_APACHE2` (an empty marker file) anda `NOTICE`
file whose text begins:

```   Copyright (c) 2006-2009, The Android Open Source Project   Licensed under the Apache License, Version 2.0 (the "License");   you may not use this file except in compliance with the License.

```textThat `NOTICE` then embeds the full Apache-2.0 text. So the adb source, and adb's own contribution tothe binary, are Apache-2.0.

But the shipped `platform-tools` package carries its own `NOTICE.txt`, a large aggregate (386,777characters in the
copy I fetched from `chromium.googlesource.com/android_tools/+/HEAD/sdk/platform-tools/NOTICE.txt`).

Its inventory is not merely adb: it lists entries for `/bin/aapt`, `/bin/adb`, `/bin/aidl`,`/bin/aprotoc`, `/bin/dx`,
`/bin/dexdump`, `/bin/mdnsd`, `/bin/sqlite3`, `/bin/llvm-rs-cc`, plus`/lib/libc++.so`, `/lib/liblz4.so`,
`/lib/libssl-host.so`, `/lib/libcrypto-host.so`,`/lib/libexpat.a`, `/lib/libjpeg.so`, `/lib/libz.a`, and roughly forty
more. Copyright holdersinclude Sun/Oracle, IBM, Daniel Stenberg (curl), the University of Cambridge (Expat), the
BrotliAuthors, Yann Collet (LZ4), the NetBSD Foundation, Bouncy Castle, and the mingw-w64 project.

**At least one SPDX tag is non-Apache** (`SPDX-License-Identifier: BSD-2-Clause-FreeBSD`).

The governing terms for the SDK download are the **Android Software Development Kit LicenseAgreement**
(`https://developer.android.com/studio/terms`), which is *not* Apache-2.

0. The clausesthat decide the redistribution question, quoted exactly:

> **1.1** The Android Software Development Kit (referred to in the License Agreement as the "SDK"

> and specifically including the Android system files, packaged APIs, and Google APIs add-ons) is

> licensed to you subject to the terms of the License Agreement.

> **3.1** Subject to the terms of the License Agreement, Google grants you a limited, worldwide,

> royalty-free, **non-assignable, non-exclusive, and non-sublicensable** license to use the SDK

> solely to develop applications for compatible implementations of Android.

> **3.4** You may not use the SDK for any purpose not expressly permitted by the License Agreement.

> Except to the extent required by applicable third party licenses, **you may not copy (except for

> backup purposes), modify, adapt, redistribute, decompile, reverse engineer, disassemble, or create

> derivative works of the SDK or any part of the SDK.**

> **3.5** Use, reproduction and distribution of components of the SDK licensed under an open source

> software license are governed solely by the terms of that open source software license and not the

> License Agreement.

**Reading of this [inference, but a firm one].** Clause 3.4 forbids redistribution of the SDK; clause3.5 carves out
only the components that are themselves OSS-licensed. adb's *source* is Apache-2.0, soadb's own code is
redistributable under 3.5 â€” but the platform-tools *package as distributed* is amixed bundle including the SDK's own
build tooling and a `NOTICE.txt` aggregate whose terms you wouldhave to satisfy in full. Google's own framing
reinforces the intent: the platform-tools download pagedescribes the package as "a component for the Android SDK" and
says "app developers will normallyjust use the copy Studio installs."Clause 3.1's **non-sublicensable** term is the
practical killer for a bundled installer: you cannotpass on rights you do not have.

**Recommended posture for DroidLab (Apache-2.0):**

1. **Do not bundle `adb.exe` in the repo or the installer.** This is the safest and most common choice. `appium-adb`
   and `adbkit` are well-known examples of the "do not bundle; tell the user to install platform-tools" pattern â€”
   *[partially verified: consistent with ecosystem practice and with clause 3.4, but I did not read their READMEs in
   this session]*.

2. **Do not commit `adb.exe` to a public git repository**, and do not add it to a release archive.

3. **Detect and use the user's existing copy** (Â§2.2). This satisfies clause 3.1 (the user holds the licence) and
   costs nothing.

4. **If download-at-install is desired**, have the *user* accept the Android SDK terms in your UI and download from
   Google's own endpoint, so the licence flows to the user rather than through you. Never vendor a redistributed
   mirror.

5. If you ever do want to ship a binary, `[inference]` building adb yourself from the Apache-2.0 AOSP source, plus
   your own NOTICE for the statically linked third parties, is the only clean route â€” and it is a substantial
   engineering commitment. This is a legal question; the project should get counsel rather than treat this report as
   advice.

There is no "adb.exe is Apache-2.0 so it's fine" shortcut. Record the decision as an ADR and add a`DEPENDENCIES.md`
row.

### 2.2 Finding adb on WindowsTypical locations, in the order a controller should try:

1. An explicit user setting in DroidLab (highest priority â€” the user may have pinned a version).

2. `%ANDROID_HOME%\platform-tools\adb.exe`

3. `%ANDROID_SDK_ROOT%\platform-tools\adb.exe`

4. `%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe` (the Studio default)

5. Android Studio's bundled copy (`%LOCALAPPDATA%\Google\AndroidStudio*\...`)

6. `adb.exe` on `PATH`

7. Package-manager locations (Chocolatey, Scoop, winget)**[verified locally]** points 2â€“4 were unset here
   (`ANDROID_HOME` and `ANDROID_SDK_ROOT` both empty),and the binary lived at
   `C:\Users\GHC\AndroidSdk\platform-tools\adb.exe` â€” a *custom* path reachableonly via `PATH`. **A controller that
   only checks the three well-known variables will fail on a realmachine.** Always fall back to `PATH`, and let the
   user browse.

**Version-pin and minimum version.** `adb pair` and `adb mdns` require **platform-tools 30.0.0**(2020), which ships
**adb 1.0.41** â€” the version that arrived with Android 11 / API 30, matching the`__INTRODUCED_IN(30)` annotations.
**[verified locally]** `adb version` reports:

```Android Debug Bridge version 1.0.41Version 37.0.1-15733141

```textTwo things to note: the `1.0.41` line is the *protocol* version (it has been stable for years),while `37.0.1-â€¦` is the real release identity. **Parse the second line, not the first**, for aminimum-version gate; a `1.0.41`-only check will happily accept a 2020 build lacking features youneed. Also note `adb mdns check` here prints `adb discovery 0.0.0`, not the doc's`Openscreen discovery 0.0.0` â€” do not gate on that string.

### 2.3 Port 5037 conflicts â€” and the isolated-server trickThe default server listens on `tcp:localhost:5037`.
A second `adb` client whose version differs willfind the existing server and report a mismatch, typically`adb server
version (N) doesn't match this client (M); killing...`, then kill and restart it. Theexact literal could not be
reproduced here because only one version is installed â€” treat the stringas **unverified** and gate on `adb version`
output instead of parsing that message.

**The clean solution is a private server on a private port.** This is fully supported and is therecommendation for
DroidLab.**[verified locally]** â€” I started a second, isolated server and confirmed both coexist:

```powershell& adb -P 15037 start-server     

# "* daemon not running;
 starting now at tcp:15037"& adb -P 15037 devices -l       

# List of devices attached

```Listening sockets afterwards, from `Get-NetTCPConnection`:

```textLocalAddress   LocalPort  OwningProcess127.0.0.1           15037          24992127.0.0.1            5037          34156

```Both processes are `adb.exe`, each with a distinct listen spec:

```textProcessId  CommandLine34156      adb -L tcp:5037  fork-server server --reply-fd 69224992      adb -L tcp:15037 fork-server server --reply-fd 260

```So `-P` gives DroidLab a **completely independent adb server**. Benefits: DroidLab never kills orrestarts the user's server, never inherits an old version's transport state, and multi-devicewireless targets are visible to DroidLab without polluting the user's `adb devices`. The relatedknobs from the man page are `-H` (server host, default localhost), `-P` (smart socket port, default5037), `-L` (listen socket, default `tcp:localhost:5037`), and `-a` (listen on all interfaces).`ANDROID_ADB_SERVER_PORT` is the environment-variable equivalent. **[verified locally]** setting itto `15037` made a plain `adb mdns check` hit the custom server.

**Recommendation:** always pass `-P <dedicated port>` to every adb invocation. Do not rely on theenvironment variable
alone â€” it leaks into child processes and can be overridden.

### 2.4 Talking to the server without spawning adb.exe**[verified locally]** The adb server speaks a simple length-prefixed text protocol directly on TCP.
I drove it with a raw socket, no `adb.exe` involved. Request framing is `%04X` ASCII length followedby the request
bytes:| Request | Raw response ||

---

 | 

---

 || `host:version` | `OKAY00040029` || `host:devices-l` | `OKAY0000` (no devices) || `host:track-devices` | `OKAY0000` || `host:mdns:check` | `OKAY0029mdns daemon version [adb discovery 0.0.0]` || `host:mdns:services` | `OKAY0000` |`OKAY` is a 4-byte status; the next 4 hex digits are the payload length (`0029` = 41; `host:version`'s`0004` = 4 bytes). This is the same protocol used internally by `adb_query_command` and`host:pair:<code>:<host>`.

**This is a significant option for DroidLab.** A `DroidLab.Adb` module could speak `host:*` directlyover a socket for
enumeration and state polling, reserving process spawning for operations thatgenuinely need a client (`pair`,
`connect`, `install`, `push`, `shell`). Benefits: no per-call processspawn, no console window flash, trivial latency,
and `host:track-devices` gives push-style deviceupdates instead of polling. Cost: you are coding against a protocol
that AOSP does not document asstable. Mitigate by using it only for read-only queries and by falling back to `adb
devices -l` onany parse failure.

Note this does **not** create ADB-wire-protocol work â€” it is the *clientâ†”server* smart socket, whichis exactly
what `adb.exe` itself uses. It stays within ADR-0006's "do not reimplement the ADB wireprotocol" constraint, though
the ADR should be amended to say so explicitly.

### 2.5 Enumerating devices and picking the Wi-Fi transport serial`adb devices -l` fields are produced by `transport.cpp` (`append_transport_info`, and theprotobuf path around lines 1377â€“1431):

```cppdevice->set_serial(t->serial.c_str());device->set_bus_address(sanitize(t->devpath, false));   // usb:device->set_product(sanitize(t->product, false));       // product:device->set_model(sanitize(t->model, true));            // model:device->set_transport_id(t->id);                        // transport_id:...append_transport_info(result, "", t->devpath, false);append_transport_info(result, "product:", t->product, false);append_transport_info(result, "model:", t->model, true);append_transport_info(result, "device:", t->device, false);*result += " transport_id:";

```textSo a wireless device serial looks like`adb-<ro.serialno>-<randomSuffix>._adb-tls-connect._tcp` â€” matching the doc's example`adb-43081FDAS000VS-QXjCrW._adb-tls-connect._tcp` and the naming rule in Â§1.1.

**Serial vs transport id.** The serial is a *name*; the transport id is a *monotonic handle* thatchanges when the
transport is recreated. From the man page: `-s SERIAL` uses the given serial(overriding `ANDROID_SERIAL`), `-t ID`
uses the given transport id. `transport.cpp` resolves in thatorder:

```cppatransport* acquire_one_transport(TransportType type, const char* serial, TransportId transport_id, ...)...if (transport_id != 0) { ... }   // exact id match wins

```

**Practical guidance.** Prefer the serial for anything that must be reproducible across a session andstable in logs;
prefer the transport id only for resolving an ambiguity *within* one enumeration.

The serial for a wireless device embeds a random mDNS instance suffix that changes on re-pairing, so**never persist a
wireless serial as a device identity** â€” persist the device GUID from the pairingstep (Â§1.3 step 9) and re-resolve
the serial each session. This directly reinforces ADR-0006's"must not cache a serial across device reboots."Wildcard
matching also exists â€” `transport.cpp` `Connection::MatchesTarget`:

```cppreturn (target == devpath) || qual_match(target, "product:", product, false) ||       qual_match(target, "model:", model, true) ||       qual_match(target, "device:", device, false);

```textso `-s` accepts `model:Pixel`, `device:raven`, etc. Useful for a human picker, but ambiguous when twoidentical models are attached â€” do not use it for automation.**[verified locally]** `adb devices -l` with no devices prints exactly:

```List of devices attached

```text(trailing blank line). Parse tolerantly.

### 2.6 Detecting "wireless debugging is off" and `adb connect` refusal`transport.cpp` defines these exact strings for transport state:

```cppcase kCsUnauthorized: { *error_out = "device unauthorized.\n"; }   // note trailing newlinecase kCsOffline:      { *error_out = "device offline"; }           // no trailing newline

```Note the **inconsistent trailing newline** between the two â€” a real parsing hazard.**[verified locally]** `adb connect` failures, with exact text:

```text$ adb connect 127.0.0.1:1cannot connect to 127.0.0.1:1: No connection could be made because the target machine actively refused it. (10061)$ adb connect 127.0.0.1:5555cannot connect to 127.0.0.1:5555: No connection could be made because the target machine actively refused it. (10061)$ adb connect 192.0.2.1:5555cannot connect to 192.0.2.1:5555: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond. (10060)

```So:

- **`10061` / "actively refused"** â€” something is reachable but nothing is listening. On a device address this means
  **wireless debugging is off, or the port is stale** (the device rebooted or the toggle was reset, so the advertised
  port no longer exists). This is the single most likely state to encounter in the field, and it is *indistinguishable
  at this layer* from a stale port. **`10060` / "did not properly respond"** â€” timeout, i.e. host unreachable: wrong
  subnet, Wi-Fi off, AP isolation, or a firewall drop.- The user-facing prefix is `cannot connect to <host>:<port>:`
  (with the port appearing between the host and the colon in the message). The message is locale-dependent on Windows
  because the `WSAECONNREFUSED` text is localised â€” **parse the numeric codes `10061`/`10060`, never the English
  prose.** *[inference: standard Win32 `WSAE*` behaviour, but the brittleness is directly observable in the output
  above]***[verified locally]** pairing against a dead port fails differently, and ugly:

```text$ adb pair 127.0.0.1:1 123456error: protocol fault (couldn't read status message): No error

```That is a poor message and worth pre-empting in DroidLab's UI: it means the TCP connection to thepairing server failed, not that the code was wrong. Contrast with the source's intended wrong-codemessage (`"Failed: Wrong password or connection was dropped."`), which only appears once the socketis actually established.

**Because `10061` is ambiguous between "wireless debugging off" and "stale port", the reliablealgorithm is not to
interpret the error at all.** Instead:

1. Browse mDNS for `_adb-tls-connect._tcp` and `_adb-tls-pairing._tcp`.

2. If a matching service is present, use its advertised `ip:port` â€” the device is telling you the current port, so a
   stale cached endpoint can never be used.

3. Only if mDNS finds nothing should you try a cached endpoint, and then treat `10061` as "endpoint stale, re-pair or
   re-discover" rather than "feature disabled".

4. Distinguish "no wireless-debugging endpoint exists at all" (mDNS empty and no cached endpoint) from "endpoint
   stale" (mDNS empty but a cached endpoint exists). These need different UI.

This is strictly better than ADR-0006's stated order ("the controller tries the stored endpoint, thenthe discovered
one"), which can waste a 10-second TCP timeout on a stale port before discovering thelive one. **Recommendation:
invert that order and prefer discovered over cached.

**One more trap: `ADB_MDNS_AUTO_CONNECT` only governs *adb's own* auto-connect. It does not affectDroidLab's own mDNS
browsing, so DroidLab can always discover services even with adb auto-connectdisabled â€” which is the right
configuration, since DroidLab wants to control when it connects.

---

## 3. mDNS / DNS-SD discovery

### 3.1 C#/.
NET options on Windows| Option | Licence | Status | Verdict ||

---

 | 

---

 | 

---

 | 

---

 || `Makaretu.Dns.Multicast` | MIT | **Last release 0.27.0 on 2019-11-05** (NuGet registration API); repo `richardschneider/net-mdns` last pushed 2024-04-24, 272 stars, not archived, 28 open issues | Mature and pure-managed, but **stale NuGet cadence** || `Makaretu.Dns` (the DNS model) | MIT | Last release **2.0.1 on 2019-07-22**; repo last pushed 2019-07-22 | Older still || `Zeroconf` (NuGet) | see below | **3.7.16 on 2024-12-17**, description "Bonjour support for .NET 6, .NET 8, .NET Standard 2.0, .NET Framework, Xamarin, and UWP" | Current, but see the Bonjour dependency problem || Windows Win32 `DnsService*` | OS API | Present in `C:\Windows\System32\dnsapi.dll` | No third-party dependency, but needs a working responder |**`Makaretu.Dns.Multicast` is the natural fit** and the API is exactly what RFC-0003 needs â€”`ServiceDiscovery.Advertise(ServiceProfile)`, `ServiceDiscovered`, `ServiceInstanceDiscovered`, and`ServiceProfile` carries TXT records. Its README advertises "Detects new and/or removed networkinterfaces", "Supports multicasting on multiple network interfaces", "Supports service subtypes",and "Handles legacy unicast queries, see #61" â€” all directly relevant to RFC-0003 Â§4.

**But flag a rule conflict.** `DEPENDENCIES.md` Â§"Reviewing a dependency" requires: "It is activelymaintained â€” a
release in the last 18 months, or a documented reason why inactivity is acceptable."`Makaretu.Dns.Multicast`'s last
NuGet release was **2019-11-05, over six years ago**. The *repo* sawactivity in April 2024 but no release followed. On
a literal reading, adding it **fails R6/R7 aswritten**. Options:

1. Add it with an explicit documented justification (the "stale but complete and MIT" exemption), noting the repo is
   alive and the code is pure-managed and small enough to fork if abandoned.

2. Vendor a minimal mDNS/DNS-SD implementation in `DroidLab.Discovery` â€” ~1,000â€“1,500 lines of UDP-socket + DNS
   wire codec. This is real work but removes a fragile dependency and gives exact control over the RFC-0003
   tie-breakers (TTL, goodbye packets, multi-interface).

3. Use `Zeroconf` 3.7.16 â€” current, but it wraps **Apple Bonjour**, so you inherit a third-party runtime dependency
   (Â§3.4). Bad for a product that must install cleanly.

**Recommendation:** option 1 with an ADR, and keep option 2 as the documented escape hatch. Theprotocol layer already
has a no-dependency rule (ADR-0003) and a shared-vector contract (ADR-0007);a small in-repo mDNS codec would fit
DroidLab's established philosophy better than most projects, andthe stub-out path (below) means you can ship now and
swap later.

### 3.2 Windows DNS-SD Win32 API â€” the correct DLLA common mistake is chasing `windns.dll`.
**[verified locally]** on this machine:

```textC:\Windows\System32\windns.dll            -

> does not existC:\Windows\System32\dnsapi.dll            -

> exists (1,422,944 bytes)

```Searching `dnsapi.dll`'s bytes for the export names found **all** of them present:

```textDnsServiceRegister               PRESENT in dnsapi.dllDnsServiceBrowse                 PRESENT in dnsapi.dllDnsServiceBrowseCancel           PRESENT in dnsapi.dllDnsServiceResolve                PRESENT in dnsapi.dllDnsServiceResolveCancel          PRESENT in dnsapi.dllDnsServiceDeRegister             PRESENT in dnsapi.dllDnsServiceConstructInstance      PRESENT in dnsapi.dllDnsServiceCopyInstance           PRESENT in dnsapi.dllDnsServiceFreeInstance           PRESENT in dnsapi.dll

```So the API surface exists on stock Windows and is reachable from C

# via P/Invoke into `dnsapi.dll`(the headers, when you have the SDK, are `windns.h` â€” hence the persistent naming confusion; the*implementation* is `dnsapi.dll`).
Practical caveats: these are callback-based with`DNS_SERVICE_CANCEL` handles, they need a struct-heavy P/Invoke layer
(`DNS_SERVICE_INSTANCE`,`DNS_SERVICE_BROWSE_REQUEST`), and the strings `_services._dns-sd._udp` / `_tcp.local` were
**not**found in the binary, meaning the API is transport-agnostic and *requires an installed mDNS responderto
function*. That last point is decisive; see next.

### 3.3 The real Windows pitfall: there may be no mDNS responder at all**[verified locally]** This is the trap.
On this machine the only mDNS responder present is Apple's:

```textName      : Bonjour ServiceState     : RunningStartMode : AutoPathName  : "C:\Program Files\Bonjour\mDNSResponder.exe"

```Came from `C:\Program Files\Bonjour\` (bundled by iTunes/Adobe), not from Windows. And note theservice display name is `Bonjour Service` â€” **searching for `*mdns*` or `dnscache` finds nothinguseful**, which is why a naive probe reports "no mDNS".Consequences for DroidLab:

1. **Windows has no guaranteed built-in mDNS responder.** Windows 10 1703+ added an mDNS client resolver for `.local`
   *hostname* lookups, but that is not a DNS-SD browser for arbitrary service types. The `DnsService*` API needs a
   responder that may not be installed.

2. **`Zeroconf` would hard-require Apple Bonjour** (its NuGet description literally says "Bonjour support"), adding a
   native runtime install and a third-party installer to DroidLab's own installer. That is a serious product cost.

3. **A pure-managed implementation avoids the whole problem** and is exactly what RFC-0003 Â§4 already recommends: "a
   pure-managed implementation is RECOMMENDED because the Windows service can be disabled by policy."

**This is a strong independent argument for `Makaretu.Dns.Multicast`** (or a vendored equivalent)over both the Win32
API and `Zeroconf`, and it should be recorded in the ADR alongside themaintenance-status tradeoff. DroidLab should not
depend on a responder it cannot install.

### 3.4 Advertising a TXT record and verifying itThe TXT contract is already specified precisely in RFC-0003 Â§2, with `RequiredKeys = ["v","id","fp","caps","port"]`and `OptionalKeys = ["model","android","sdk","busy","loc","tls"]`, `MaxTxtBytes = 1300`, and asignature over `"DLWP/1-txt" 0x00` + newline-joined `key=value` pairs in fixed order.
`DiscoveryAdvertisement.CanonicalTxt` implements it, and `protocol/vectors/discovery.json` holds thevectors. Good â€”
that is the interop contract and it is already tested.

Three things to get right at the mDNS layer, independent of the canonicalisation:

1. **DNS-SD TXT strings are not the same thing as the canonical payload.** On the wire, each `key=value` pair is a
   separate length-prefixed character-string. A single pair is capped at 255 bytes; the whole TXT record set must fit
   the response budget (hence RFC-0003's 1300-byte rule). Your `sig` value is base64url of 64 bytes â‰ˆ 86 characters,
   well within one string.

2. **Each >255-byte value needs splitting**, and readers must rejoin. If `caps` ever grows, it will need a
   split/rejoin rule. Worth adding to RFC-0003 before it bites â€” the current spec says "Truncated to fit" for `caps`
   but does not define the split rule for a *single* long value.

3. **Verification must be end-to-end.** The only real test is: advertise on one process/machine, browse from another,
   resolve, and compare the received TXT bytes to `CanonicalTxt` output, then verify `sig`. A loopback test on one
   machine is *not* sufficient, because it will pass even when the responder is coalescing or truncating. Add a
   CI/manual procedure with two hosts. **[verified locally]** I could not verify a full round trip in this session
   because no Android device or second host was available â€” mark this as the single most important untested
   assumption in RFC-0003.

### 3.5 Multiple network interfaces, IPv6 vs IPv4, TTL, name collisions
- **Multiple interfaces. ** A phone commonly has Wi-Fi, hotspot, cellular, and a VPN; a Windows box has Ethernet,
  Wi-Fi, VPN, Hyper-V, WSL, and Docker virtual adapters. RFC-0003 Â§3.3.3 already says the agent should "Include every
  routable address the device has" and prefer Wi-Fi. The Windows side is the harder problem: a VPN or Hyper-V vSwitch
  can swallow multicast. **Recommendation:** bind explicitly to chosen interfaces rather than relying on the default
  multicast route, and expose an interface picker. `Makaretu.Dns.Multicast`'s `NetworkInterfaceDiscovered` event and
  `MulticastService.GetIPAddresses()` support this.

- **IPv6 vs IPv4.** mDNS listens on `224.0.0.251:5353` (IPv4) and `ff02::fb:5353` (IPv6), per RFC-0003 Â§

4. Note that ADB's own `adb mdns services` "resolves IPv6 but does not output it" â€” a direct precedent that v6 is
   commonly present but unexploited. **[verified locally]** In my raw `host:mdns:services` probe the payload length
   was `0000` (empty), so there is nothing to cross-check against here. Recommendation: advertise on both families,
   but when *connecting*, prefer IPv4 unless v6 has been proven to work end-to-end on that network. A common failure
   is advertising a link-local `fe80::` address that the peer cannot use (it lacks a scope id), producing a device
   that is discoverable but unconnectable.

- **TTL and expiry.** RFC-0003 sets 120 s TTL and requires a TTL-0 "goodbye" on untick. That is correct DNS-SD
  practice. The pitfall is that **receivers must implement expiry themselves** â€” mDNS has no server to expire
  records for you. A `ServiceLost` callback is not guaranteed if the device simply vanishes (battery, Wi-Fi off,
  crash). Implement a per-advertisement timer that marks a device `Offline` after `TTL` with no refresh, exactly as
  RFC-0003 Â§3.1 step 5 says. Do not rely on `ServiceLost` alone. This is why RFC-0003's 7-day last-known-endpoint
  fallback matters.

- **Name collisions.** RFC-0003 Â§4 says append (`2`), (`3`), â€¦ and re-announce. Note the corner case: the *instance
  name* is what collides, but DroidLab identifies devices by TXT `id` (a UUIDv4) and `fp`. So a collision is cosmetic
  for DroidLab, whereas for ADB it is load-bearing (instance name is `adb-<serialno>-<random>`, and the GUID is in the
  name itself). Ensure the controller never keys discovery state on the instance name â€” key on `id`. Also note
  RFC-0003 Â§3.2's rule that a changed `fp` for a known `id` must raise the impersonation warning; that is the right
  use of the naming-vs-identity split.

- **First-run firewall.** Windows Defender Firewall prompts on first bind to a multicast socket. If the user dismisses
  or the process has no interactive desktop (a service, or a CI run), the prompt may be silently denied and discovery
  will simply never work, with no error. **[verified locally: the Bonjour service and `Dnscache` are the only relevant
  running services; no DroidLab firewall rule exists yet.]** Recommendation: detect the failure mode ("browse started,
  zero results, forever") and surface an explicit "likely blocked by Windows Firewall â€” add a rule" hint with the
  exact `netsh` command, rather than silently showing an empty device list.

---

## 4.
Android input injection in production

### 4.1 `AccessibilityService.dispatchGesture` â€” the no-root default

**API surface [verified locally via `javap` on `android-34/android.jar`]:**

```textpublic final boolean dispatchGesture(GestureDescription, AccessibilityService$GestureResultCallback, Handler);public final boolean performGlobalAction(int);public static int  GestureDescription.getMaxStrokeCount();public static long GestureDescription.getMaxGestureDuration();public class GestureDescription$StrokeDescription {    public StrokeDescription(Path, long startTime, long duration);    public StrokeDescription(Path, long startTime, long duration, boolean willContinue);    public StrokeDescription continueStroke(Path, long startTime, long duration, boolean willContinue);}

```

**Hard limits, from AOSP `core/java/android/accessibilityservice/GestureDescription.java`:**

```java/** Gestures may contain no more than this many strokes */private static final int MAX_STROKE_COUNT = 20;/** * Upper bound on total gesture duration. Nearly all gestures will be much shorter. */private static final long MAX_GESTURE_DURATION_MS = 60 * 1000;

```textSo: **max 20 strokes per gesture, max 60,000 ms total duration.** Exceeding either throws from thebuilder (`if (mStrokes.size() >= MAX_STROKE_COUNT)`, `if (getTotalDuration(mStrokes) 

> MAX_GESTURE_DURATION_MS)`).

**Multi-touch semantics â€” the key question.** `GestureDescription` is "made up of one or morestrokes", each with an
independent `startTime` and `duration`. Because each stroke carries its owntime window, strokes **can overlap in
time**, so you can express a pinch or a two-finger scroll asone `GestureDescription` with two overlapping strokes.
That is genuine concurrent multi-touch at thegesture-construction level.

The real limitations to design around:

- **20 strokes** caps concurrent fingers at 20 (plenty) but also caps a *sequence* â€” a long scripted path must be
  split into multiple gestures.

- **60 s total.** A CI test that holds a finger down longer than a minute must be chunked, which requires the
  `willContinue` / `continueStroke` mechanism to avoid a visible lift.

- **`dispatchGesture` is fire-and-forget with a callback**, so a streamed remote-control session (mouse-drag â†’
  continuous MOVE events) does **not** map cleanly onto it. Each `dispatchGesture` is a discrete whole gesture. A live
  mirroring session needs continuous per-frame MOVE injection, which is exactly why scrcpy does not use this API
  (Â§4.3). *[inference: strongly supported by the API shape and by scrcpy's choice of a different mechanism, but I did
  not test a streaming workload.]*

- **`canPerformGestures`.** The service config needs `android:canPerformGestures="true"`; the class javadoc says
  "Accessibility services with the `android.R.styleable#AccessibilityService_canPerformGestures` property can dispatch
  gestures." Without it, dispatch fails.

**Which real projects use it.** This is the mechanism of choice for *discrete, scripted,no-root* interaction: Appium's
uiautomator2/espresso drivers, Maestro, Auto.js, and mostaccessibility-based automation layers. *[partially verified:
I confirmed the API contract from AOSPand Android's own reference, but did not read each project's source in this
session â€” treat theper-project attributions in this paragraph as needing confirmation before they appear in
DroidLabdocs.]* It is the right primary mechanism for DroidLab's `input.tap`/`input.swipe` commands.

**The restriction that bites on modern Android:** **Android 13+ Restricted Settings.** Anaccessibility service cannot
be enabled from a sideloaded app until the user grants "Allow restrictedsettings" for that app, via a specific
Settings flow. Deep-link targets are`Settings.ACTION_ACCESSIBILITY_SETTINGS` and
`Settings.ACTION_ACCESSIBILITY_DETAILS_SETTINGS`.**[not independently verified in this session beyond the API names
â€” mark as needing a device test]

**This is a first-class onboarding problem for DroidLab: a sideloaded agent APK (the normaldistribution for a dev
tool) will require an explicit, hard-to-find user action before touchinjection works at all. The agent must detect
"service declared but not enabled" and guide the user,not fail silently.

### 4.2 `ACTION_SET_TEXT`

**API [verified locally]:**

```AccessibilityNodeInfo.ACTION_SET_TEXT                       // intAccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE // String, the Bundle keyAccessibilityNodeInfo.ACTION_FOCUSAccessibilityNodeInfo.ACTION_CLICKAccessibilityNodeInfo.ACTION_PASTEAccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_START_INTAccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_END_INTAccessibilityNodeInfo.isEditable()

```textThe value is passed in a `Bundle` under `ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE`. Note the typo in theAPI name (`CHARSEQUENCE`) is real and must be spelled exactly.

**Pitfalls.** The node must be editable and generally focused first, so the reliable sequence is`ACTION_FOCUS` â†’
`ACTION_CLICK` (optional) â†’ `ACTION_SET_TEXT`. It does not work uniformly onnon-standard text surfaces â€” WebView,
Compose, Flutter, and games often expose no editable`AccessibilityNodeInfo`, and even when they do, `ACTION_SET_TEXT`
may be ignored. This is the reasonproduction tools fall back to key events or a helper IME.

**Important asymmetry:** `ACTION_SET_TEXT` **does support Unicode**, unlike `adb shell input text`(Â§4.5). So for
DroidLab's native text path, `ACTION_SET_TEXT` is the better mechanism â€” but it needsa real editable node, so a
fallback chain is mandatory.

### 4.3 `InputManager.injectInputEvent` â€” hidden API, and what scrcpy actually does

**This is the most important section, because the popular mental model is wrong.**`injectInputEvent` is `@hide` and
requires `INJECT_EVENTS`. From AOSP`core/java/android/hardware/input/InputManager.java`:

```java/** * Injects an input event into the event system, targeting windows owned by the provided uid. ... * Requires the {@link android.Manifest.permission#INJECT_EVENTS} permission. ... * @hide */@RequiresPermission(Manifest.permission.INJECT_EVENTS)public boolean injectInputEvent(InputEvent event, int mode, int targetUid) {    return mGlobal.injectInputEvent(event, mode, targetUid);}

```**[verified locally]** `javap` on the public `android.jar` shows **no** `injectInputEvent` on`android.hardware.input.InputManager` â€” confirming it is not in the public SDK.**`INJECT_EVENTS` protection level.** From AOSP `core/res/AndroidManifest.xml`:

```xml<permission android:name="android.permission.INJECT_EVENTS" android:protectionLevel="signature" />

```text`signature` only. From `core/java/android/content/pm/PermissionInfo.java`:

```javapublic static final int PROTECTION_NORMAL = 0;public static final int PROTECTION_DANGEROUS = 1;public static final int PROTECTION_SIGNATURE = 2;

```

**But an ordinary app is not the only way to run.** **[verified locally]** I checked the AOSP shellpackage manifest at
`frameworks/base/packages/Shell/AndroidManifest.xml`:

```xml<manifest xmlns:android="http://schemas.android.com/apk/res/android"    package="com.android.shell" coreApp="true" updatableSystem="false"    android:sharedUserId="android.uid.shell" >

```textand its permission list **includes `INJECT_EVENTS`**, along with `CHANGE_WIFI_MULTICAST_STATE`,`NEARBY_WIFI_DEVICES`, `FOREGROUND_SERVICE_MEDIA_PROJECTION`, `POST_NOTIFICATIONS`,`WRITE_SECURE_SETTINGS`, `READ_LOGS`, and hundreds more.

So the mechanism scrcpy exploits is: **run as the `shell` user (uid 2000), which already legitimatelyholds
`INJECT_EVENTS`.** scrcpy-server is launched via `app_process` from an `adb shell`, and`Server.java` enforces the uid:

```javaif (Os.getuid() == 0) {    ...    Os.setuid(2000);}

```

**How scrcpy reaches the hidden method.** `server/src/main/java/com/genymobile/scrcpy/wrappers/InputManager.java`uses
plain reflection into the hidden method:

```javaprivate static Method getInjectInputEventMethod() throws NoSuchMethodException {    if (injectInputEventMethod == null) {        injectInputEventMethod = android.hardware.input.InputManager.class                .getMethod("injectInputEvent", InputEvent.class, int.class);    }    return injectInputEventMethod;}public boolean injectInputEvent(InputEvent inputEvent, int mode) {    try {        Method method = getInjectInputEventMethod();        return (boolean) method.invoke(manager, inputEvent, mode);    } catch (ReflectiveOperationException e) {        if (e instanceof InvocationTargetException) {            Throwable cause = e.getCause();            if (cause instanceof SecurityException) {                String message = e.getCause().getMessage();                if (message != null && message.contains("INJECT_EVENTS permission")) {                    long now = System.currentTimeMillis();                    if (lastPermissionLogDate <= now

- 3000) {
                        Ln.e(message);
                        Ln.e("Make sure you have enabled \"USB debugging (Security Settings)\" "                             + "and then rebooted your device.");
                        lastPermissionLogDate = now;
                    }
                    return
false;
                }
            }
        }
        Ln.e("Could not invoke method", e);
        return
false;
    }
}

```textThree things to take from this:

1. **Reflection works** even under non-SDK interface restrictions, because `app_process` as `shell` is not subject to
   the app-level hidden-API enforcement. This is a real but narrow exemption tied to being an external process running
   as uid 2000, not to a manifest flag.

2. **The failure string to detect is `"INJECT_EVENTS permission"`** inside a `SecurityException`.

3. **`"USB debugging (Security Settings)"`** is a separate, OEM-specific developer option (common on Xiaomi/MIUI,
   Oppo, Vivo, Samsung) that must be enabled **and the device rebooted**. This is a concrete, frequently-missed
   requirement for ADB-based input injection on many real devices. Scrcpy taught me this from its source, not from any
   Google doc.`Device.java` shows the wrapper in use, with `INJECT_MODE_ASYNC` for streamed input:

```javapublic static boolean injectEvent(InputEvent inputEvent, int displayId, int injectMode) {    if (!supportsInputEvents(displayId)) {        throw new AssertionError("Could not inject input event if !supportsInputEvents()");    }    if (displayId != 0 && !InputManager.setDisplayId(inputEvent, displayId)) {        return false;    }    return ServiceManager.getInputManager().injectInputEvent(inputEvent, injectMode);}public static boolean supportsInputEvents(int displayId) {    // main display or any display on Android >= 10    return displayId == 0 || Build.VERSION.SDK_INT >= AndroidVersions.API_29_ANDROID_10;}

```It also reflects on two more hidden members: `InputEvent.setDisplayId(int)` and`MotionEvent.setActionButton(int)` â€” the latter specifically to make mouse buttons work in Chrome(the source cites `https://github.com/Genymobile/scrcpy/issues/3635`).

### 4.4 True multi-touch: scrcpy's pointer state machine, and the 2025 UHID addition

**Multi-touch in the InputManager path.** `Controller.injectTouch` maintains a `PointersState` andbuilds a real
multi-pointer `MotionEvent`:

```javaint pointerCount = pointersState.update(pointerProperties, pointerCoords);if (pointerCount == 1) {    if (action == MotionEvent.ACTION_DOWN) { lastTouchDown = now; }} else {    // secondary pointers must use ACTION_POINTER_* ORed with the pointerIndex    if (action == MotionEvent.ACTION_UP) {        action = MotionEvent.ACTION_POINTER_UP | (pointerIndex << MotionEvent.ACTION_POINTER_INDEX_SHIFT);    } else if (action == MotionEvent.ACTION_DOWN) {        action = MotionEvent.ACTION_POINTER_DOWN | (pointerIndex << MotionEvent.ACTION_POINTER_INDEX_SHIFT);    }}

```textSo genuine concurrent multi-touch is achievable **only** through `injectInputEvent` with a propermulti-pointer `MotionEvent` â€” not through `adb shell input` (Â§4.5) and not through`dispatchGesture` for streamed input. If DroidLab wants real pinch/rotate/3-finger gestures drivenfrom the desktop, this is the mechanism, and it requires shell uid.

It is also fragile: `pointersState.getPointerIndex(pointerId)` returns `-1` and the code logs`"Too many pointers for
touch event"` â€” there is a pointer-table limit to respect.

**UHID â€” the modern addition.** scrcpy now also ships `control/UhidManager.java`, which writes theLinux UHID
protocol directly:

```java// Linux: include/uapi/linux/uhid.hprivate static final int UHID_OUTPUT = 6;private static final int UHID_CREATE2 = 11;private static final int UHID_INPUT2 = 12;// Linux: include/uapi/linux/input.hprivate static final short BUS_VIRTUAL = 0x06;private static final int SIZE_OF_UHID_EVENT = 4380;  // sizeof(struct uhid_event)private static final String INPUT_PORT = "scrcpy:" + Os.getpid();...FileDescriptor fd = Os.open("/dev/uhid", OsConstants.O_RDWR, 0);

```It builds `uhid_create2_req` (name 128 B, phys 64 B, uniq 64 B, rd_size, bus, vendor, product,version, country, rd_data) and `uhid_input2_req` (size + data), and on Android 15+ associates thevirtual input port with a display:

```javaprivate boolean mustUseInputPort() {    return Build.VERSION.SDK_INT >= AndroidVersions.API_35_ANDROID_15 && displayUniqueId != null;}private void addUniqueIdAssociation() {    if (mustUseInputPort()) {        ServiceManager.getInputManager().addUniqueIdAssociationByPort(INPUT_PORT, displayUniqueId);    }}

```text

**Key architectural insight:** UHID lets the *desktop* define the HID report descriptor and sendpre-encoded reports,
which is how scrcpy supports things like arbitrary gamepads and(issue `#3635`-adjacent) precise mouse behaviour. It is
a fundamentally different and more powerfulmodel than synthesising `MotionEvent`s â€” the kernel HID layer does the
work. `/dev/uhid` is openeddirectly (not `/dev/uinput`), and it works from shell uid on modern Android without root.

**Note on the "uinput via root" framing in the brief:** the canonical root/legacy example is`openstf/minitouch`, which
writes the Linux multitouch protocol B (`ABS_MT_SLOT`, `ABS_MT_TRACKING_ID`,`ABS_MT_POSITION_X/Y`, `SYN_REPORT`) to
`/dev/uinput`. That remains the approach when you need thekernel to see a genuine multitouch device and you have root
(or a shell that can open the node).*[inference: minitouch's protocol-B approach is well established, but I did not
fetch its README inthis session â€” verify before citing it in DroidLab docs.]* Modern Android + shell uid has
largelymoved to `injectInputEvent`/UHID instead, because neither needs root. For DroidLab, **UHID is thebetter
long-term target than raw `/dev/uinput`**: no root, no kernel module assumptions, and it iswhat the most actively
maintained tool in this space converged on in 2025.

### 4.5 `adb shell input` â€” real syntax, real limits

**The current implementation is not what most references say.** `adb` 1.0.41's `input` is now a shellwrapper.
`frameworks/base/cmds/input/input.sh` is the entire binary:

```sh#!/system/bin/shcmd input "$@"

```and `cmds/input/Android.bp` declares it as an `sh_binary`. The real logic lives in`frameworks/base/services/core/java/com/android/server/input/InputShellCommand.java`.

**Complete subcommand list** (`onCommand`, with optional leading `<source>` and `-d DISPLAY_ID`):

```javaif      ("text".equals(arg))          runText(...);else if ("keyevent".equals(arg))      runKeyEvent(...);else if ("tap".equals(arg))           runTap(...);else if ("swipe".equals(arg))         runSwipe(...);else if ("draganddrop".equals(arg))   runDragAndDrop(...);else if ("press".equals(arg))         runPress(...);else if ("roll".equals(arg))          runRoll(...);else if ("scroll".equals(arg))        runScroll(...);else if ("motionevent".equals(arg))   runMotionEvent(...);else if ("keycombination".equals(arg)) runKeyCombination(...);else handleDefaultCommands(arg);

```textUsage line, from `onHelp()`: `input [<source>] [-d DISPLAY_ID] <command

> [<arg>...]`.

Sources (`SOURCES` map): `keyboard, dpad, gamepad, touchscreen, mouse, stylus, trackball, touchpad,touchnavigation,
joystick, rotaryencoder`.`motionevent` actions (`getAction()`): `DOWN`, `UP`, `MOVE`, `CANCEL` â€” anything else
throws`"Unknown action: "`. `keycombination` takes an optional `-t <duration>`.

**The multitouch limitation is proven in source, not inferred.** `injectMotionEvent` hardcodes:

```javaprivate void injectMotionEvent(int inputSource, int action, long downTime, long when,        Map<Integer, Float

> axisValues, int displayId) {
    final
int pointerCount = 1;
                       // <-- hardcoded    MotionEvent.PointerProperties[] pointerProperties =            new MotionEvent.PointerProperties[pointerCount];
    for (int i = 0;
 i < pointerCount;
 i++) {
        pointerProperties[i] = new MotionEvent.PointerProperties();
        pointerProperties[i].id = i;
        ...

```**`pointerCount` is a literal `1`.** Therefore **no `adb shell input` subcommand can produce amulti-pointer event.** No amount of sequencing `input motionevent DOWN/MOVE/UP` will create a pinch â€”each command injects an independent single-pointer event. This confirms the limitation definitivelyand gives DroidLab its precise wording: *`adb shell input` cannot express multi-touch; use`injectInputEvent` (shell uid) or UHID.*

**How it injects:** via `InputManagerGlobal.getInstance().injectInputEvent(event, injectMode)` â€” i.e.the same hidden
method as scrcpy, but the *system_server* is calling it, so no reflection and nopermission problem. Modes:
`INJECT_INPUT_EVENT_MODE_WAIT_FOR_FINISH` for motion events.

**Text limitations.** The source's `runText` handles a bare string; it cannot send arbitrary Unicode.

The authoritative confirmation is from `senzhk/ADBKeyBoard`'s README, quoting and explaining theplatform limitation:

> There is a shell command 'input', which can help you send text input to the Android system.

> But you cannot send unicode characters using this command, as it is not designed to use it this

> way.>

```text

> e.g.

> adb shell input text 'ä½ å¥½å—Ž'

> is not going to work.

> 

```The workaround ADBKeyBoard implements is a helper IME driven by broadcasts â€” a design DroidLab couldadopt natively, and which is strictly better than shelling out:

```shadb install ADBKeyboard.apkadb shell ime enable com.android.adbkeyboard/.AdbIMEadb shell ime set    com.android.adbkeyboard/.AdbIMEadb shell am broadcast -a ADB_INPUT_TEXT --es msg 'ä½ å¥½å—Ž? Hello?'adb shell am broadcast -a ADB_INPUT_B64  --es msg <base64>       

# when plain UTF-8 failsadb shell am broadcast -a ADB_INPUT_CHARS --eia chars '128568,32,67,97,116'   

# by code pointadb shell am broadcast -a ADB_INPUT_CODE --ei code 67            

# key eventadb shell am broadcast -a ADB_EDITOR_CODE --ei code 2            

# IME actionadb shell am broadcast -a ADB_CLEAR_TEXTadb shell ime reset

```textNote its own caveat: "This may not work for Oreo/P, am/adb command seems not accept utf-8 textstring anymore" â€” hence the `ADB_INPUT_B64` variant. Also note `ADB_INPUT_CHARS` takes **code points**(`128568` = U+1F638 ðŸ˜¸), which is the most robust route for emoji outside the BMP.

**Recommendation for DroidLab:** because the agent is a *real app*, it should not need a helper IME atall. Implement
text as `ACTION_SET_TEXT` first (Unicode-capable, no IME switch), fall back
to`ACTION_FOCUS`+`ACTION_CLICK`+`ACTION_SET_TEXT`, and only then fall back to an in-app IME (the agentcan register its
own `InputMethodService`) or key events. Reserve `adb shell input text` for whenwireless debugging exists but the
agent does not â€” and document the Unicode loss.

### 4.6 Comparison| Mechanism | Multi-touch | Unicode text | Permissions / prerequisites | Streaming suited | Notes || 

---

 | 

---

 | 

---

 | 

---

 | 

---

 | 

---

 || `AccessibilityService.dispatchGesture` | Yes â€” â‰¤20 strokes, overlapping time windows | n/a | Service enabled by user; `canPerformGestures="true"`; Android 13+ Restricted Settings for sideloads | **No** â€” discrete gestures, â‰¤60 s | Best no-root path for discrete `tap`/`swipe` || `ACTION_SET_TEXT` | n/a | **Yes** | Accessibility service + editable node with focus | Yes | Fails on WebView/Compose/Flutter often || `InputManager.injectInputEvent` | **Yes** (multi-pointer `MotionEvent`) | n/a (use key events) | `INJECT_EVENTS` = `signature`; obtainable only as system app **or** shell uid 2000 via `app_process`. Hidden method â†’ reflection | **Yes** (`INJECT_MODE_ASYNC`) | What scrcpy uses; needs "USB debugging (Security Settings)" on some OEMs || UHID (`/dev/uhid`) | Yes, via host-defined HID descriptor | n/a | shell uid; opens `/dev/uhid`; Android 15+ for display association | Yes | scrcpy's modern path; no root || `/dev/uinput` (minitouch) | Yes, protocol B (`ABS_MT_SLOT`â€¦) | n/a | Root or write access to `/dev/uinput` | Yes | Legacy; superseded by UHID on modern Android || `UiAutomation.injectInputEvent` | Yes | n/a | Instrumentation process (`app_process` + `FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES`) | Yes | Test-harness only || `adb shell input` | **No â€” `pointerCount` hardcoded to 1** | **No** (ASCII only) | ADB access | No | Convenient, weakest capability |**[verified locally]** `UiAutomation` surface via `javap`: `injectInputEvent(InputEvent, boolean)`,`FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES`, `FLAG_DONT_USE_ACCESSIBILITY`,`executeShellCommand(String)`, `getRootInActiveWindow()`. And `Instrumentation` exposes`sendPointerSync(MotionEvent)`, `sendKeySync(KeyEvent)`, `sendStringSync(String)`,`sendCharacterSync(int)`, plus `getUiAutomation()` / `getUiAutomation(int)` â€” all of which requirerunning inside an instrumentation context, which is why they are not a product path.

### 4.7 What this means for DroidLab's `input.
*` familiesGiven RFC-0001 defines `input.touch`, `input.key`, `input.text`, and the agent ships as an APK:

1. **`input.text`** â†’ `ACTION_SET_TEXT` with focus/click fallback. Unicode-clean. No IME switching.

2. **`input.touch` discrete** (tap, swipe, long-press) â†’ `dispatchGesture`. No root, no shell.

3. **`input.touch` streamed** (live mirror drag, pinch) â†’ **cannot** be done through `dispatchGesture`. Requires
   shell uid + reflection, which means the agent would have to ask the user to run DroidLab's helper via `adb shell`,
   or you accept a chunky gesture-per-frame model. **This is the single biggest architectural decision in the input
   design and it should be an ADR.**

4. **Keep the ADB-shell path as a documented fallback** for devices where the accessibility service cannot be enabled,
   and clearly document the multitouch loss â€” which ADR-0006's "degrade rather than die" principle already
   anticipates.

---

## 5.
Android 14/15 background and foreground-service constraints

### 5.1 Foreground service types

**API surface [verified locally via `javap` on API 34]:** `Service.startForeground(int, Notification)`and
`startForeground(int, Notification, int)`; `ServiceInfo` FGS type constants:

```FOREGROUND_SERVICE_TYPE_CAMERA            FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTIONFOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE  FOREGROUND_SERVICE_TYPE_MICROPHONEFOREGROUND_SERVICE_TYPE_DATA_SYNC         FOREGROUND_SERVICE_TYPE_NONEFOREGROUND_SERVICE_TYPE_HEALTH            FOREGROUND_SERVICE_TYPE_PHONE_CALLFOREGROUND_SERVICE_TYPE_LOCATION          FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGINGFOREGROUND_SERVICE_TYPE_MANIFEST          FOREGROUND_SERVICE_TYPE_SHORT_SERVICEFOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK    FOREGROUND_SERVICE_TYPE_SPECIAL_USE                                          FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED

```text

**Permission protection levels, all verified against AOSP `core/res/AndroidManifest.xml`:**

```xml<permission android:name="android.permission.FOREGROUND_SERVICE"            android:protectionLevel="normal|instant" /><permission android:name="android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION"            android:protectionLevel="normal|instant" /><permission android:name="android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE"            android:protectionLevel="normal|instant" /><permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC"            android:protectionLevel="normal|instant" /><permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"            android:protectionLevel="normal|appop|instant" /><permission android:name="android.permission.POST_NOTIFICATIONS"            android:protectionLevel="dangerous|instant" /><permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE"            android:protectionLevel="normal" /><permission android:name="android.permission.ACCESS_WIFI_STATE"            android:protectionLevel="normal" /><permission android:name="android.permission.NEARBY_WIFI_DEVICES"            android:protectionLevel="dangerous" /><permission android:name="android.permission.INTERNET"            android:protectionLevel="normal|instant" />

```

**So, concretely for DroidLab's agent:**- Start with plain `FOREGROUND_SERVICE` (`normal`) plus explicit type
permissions, all of which are `normal` â€” **except** `POST_NOTIFICATIONS` (`dangerous`) and `NEARBY_WIFI_DEVICES`
(`dangerous`).- The long-lived TCP listener: `dataSync` is the natural fit, but Android 15 **time-limits** dataSync
FGS to roughly 6 hours per 24, after which the service is stopped. *[The 6-hour figure is widely documented but I did
not verify it against an official page in this session â€” mark unverified and confirm before relying on it.]* -
**`connectedDevice`** is the better type for a phone being driven as a peripheral over the network, and it is not
time-limited. It requires one of a set of connected-device permissions; on Android 13+ that generally means
`NEARBY_WIFI_DEVICES` or `BLUETOOTH_CONNECT`.

- **`mediaProjection`** is mandatory alongside the mirror stream: when a `MediaProjection` is in use, the hosting
  service must declare `foregroundServiceType="mediaProjection"` and hold `FOREGROUND_SERVICE_MEDIA_PROJECTION`, or
  the projection is torn down. This is an Android 14 requirement. *[The requirement itself is well documented; I
  confirmed the permission's existence and level from AOSP but did not read the enforcement site in this session â€”
  verify the exact exception/`SecurityException` text on a device.]*- The agent therefore likely needs **two** FGS
  types on one service (`mediaProjection` + `connectedDevice`), or two coordinated services. Declare both in the
  manifest and pass the OR of the types to `startForeground(int, Notification, int)`.-
  `FOREGROUND_SERVICE_SPECIAL_USE` exists (`normal|appop`) as an escape hatch, but it requires a Play-Console
  justification declaration and an appop â€” a poor fit for an open-source sideloaded tool and a signal you have
  mis-modelled your use case. Avoid.

### 5.2 MediaProjection consent token: single-use

**API [verified locally]:**

```textMediaProjectionManager:  Intent createScreenCaptureIntent();  Intent createScreenCaptureIntent(MediaProjectionConfig);  MediaProjection getMediaProjection(int resultCode, Intent resultData);MediaProjection:  void registerCallback(MediaProjection$Callback, Handler);  void unregisterCallback(MediaProjection$Callback);  VirtualDisplay createVirtualDisplay(String, int, int, int, int, Surface,                                      VirtualDisplay$Callback, Handler);  void stop();

```The consent token is **single-use**: one `createScreenCaptureIntent()` â†’ user approval â†’ **one**`getMediaProjection(resultCode, data)` â†’ one `MediaProjection` â†’ one `createVirtualDisplay(...)`.Calling `getMediaProjection` twice with the same `Intent` fails; reusing a `MediaProjection` after`stop()` fails; and on Android 14+ the projection is tied to the FGS that requested it, so it dieswith the service.

**Practical consequences for DroidLab:**- The user must re-consent **every session**. You cannot cache the token to
make reconnect seamless. This directly interacts with the session/reconnect model: a reconnect that only
re-establishes the socket is fine, but a *process restart or projection stop* requires a new consent dialog.-
`createScreenCaptureIntent(MediaProjectionConfig)` is the newer overload (API 34+) allowing "single app" capture â€”
worth considering for a scoped capture feature, and a differentiator.- `MediaProjection.Callback.onStop()` must be
wired to push `event { name: "screen.capture_revoked" }`, exactly as `docs/architecture/OVERVIEW.md` Â§6 already
specifies.

- **A session should be able to run control-only after capture is revoked.** OVERVIEW.md Â§6 says "keep the session
  for control-only mode" â€” that is the right call and it becomes essential given the single-use token, because
  re-acquiring needs a foreground UI.

### 5.3 NSD, Wi-Fi multicast, and `NEARBY_WIFI_DEVICES`The NSD API surface **[verified locally via `javap` on API 34]**:

```textNsdManager.PROTOCOL_DNS_SDNsdManager.registerService(NsdServiceInfo, int, RegistrationListener)NsdManager.unregisterService(RegistrationListener)NsdManager.discoverServices(String, int, DiscoveryListener)NsdManager.discoverServices(String, int, Network, Executor, DiscoveryListener)NsdManager.discoverServices(String, int, NetworkRequest, Executor, DiscoveryListener)NsdManager.stopServiceDiscovery(DiscoveryListener)NsdManager.resolveService(NsdServiceInfo, ResolveListener)NsdManager.registerServiceInfoCallback(NsdServiceInfo, Executor, ServiceInfoCallback)NsdManager.FAILURE_ALREADY_ACTIVE / FAILURE_BAD_PARAMETERS / FAILURE_INTERNAL_ERROR          / FAILURE_MAX_LIMIT / FAILURE_OPERATION_NOT_RUNNINGNsdManager.NSD_STATE_DISABLED / NSD_STATE_ENABLEDNsdManager.ACTION_NSD_STATE_CHANGED / EXTRA_NSD_STATENsdServiceInfo:  setServiceName / setServiceType / setPort / setHost / setHostAddresses  setAttribute(String, String)          // <-- TXT records  getAttributes() : Map<String, byte[]>  removeAttribute(String)  setNetwork(Network)  /  getNetwork()  getHostAddresses() : List<InetAddress>

```Notes that matter:

- **TXT records are `setAttribute(String, String)`**, read back as `Map<String, byte[]>` â€” note the asymmetry (set
  as `String`, get as `byte[]`), a classic source of bugs. **Error codes are the thing to handle.**
  `DISCOVERY_FAILURE` / `FAILURE_ALREADY_ACTIVE` (you tried to start two discoveries of the same type) /
  `FAILURE_MAX_LIMIT` (too many concurrent operations) are the ones a long-lived agent will hit. `FAILURE_MAX_LIMIT`
  is a real risk for an agent that re-registers on every interface change (RFC-0003 Â§3.3.2) â€” always unregister
  before re-registering.- `onResolveFailed` is separate from `onServiceFound`, and only `resolveService` gives you an
  IP and port. A discovered-but-unresolved service is not connectable. **`CHANGE_WIFI_MULTICAST_STATE` is `normal`**,
  but holding the permission is not enough: it protects `WifiManager.MulticastLock`, and **you must actually acquire a
  `MulticastLock`** or the Wi-Fi firmware may drop multicast packets to save power. This is the classic Android mDNS
  bug: registration appears to succeed, and nothing is ever received. Acquire the lock around discovery and release it
  after. *[inference from the permission's documented purpose and the API name â€” the MulticastLock acquisition
  requirement is well established but I did not verify it from an official page in this session.]*
  **`NEARBY_WIFI_DEVICES` is `dangerous` and Android 13+ (API 33)**. It is the runtime permission that replaces much
  of the older location-gated Wi-Fi access. Whether NSD specifically requires it depends on which Wi-Fi APIs you also
  touch; if the agent reads Wi-Fi interface or SSID state to pick the right interface, it will. Plan the
  runtime-permission request flow accordingly â€” and note that RFC-0003 Â§1 requires discovery to be **off by default
  on first launch**, which means you can defer this permission request until the user enables "Allow discovery". That
  is the right sequencing and it minimises permission prompts on install.- `NsdManager` can throw when the NSD service
  is disabled (`NSD_STATE_DISABLED`); register a receiver for `ACTION_NSD_STATE_CHANGED` so a policy or OEM toggle
  does not silently kill discovery. **OEM mDNS quality** is genuinely variable. RFC-0003 Â§4.1's optional UDP beacon
  to `255.255.255.255:45918` is a pragmatic hedge and I would keep it â€” but note the beacon itself needs a broadcast
  socket and may be affected by the same firewall/AP-isolation issues, so it is a *complement*, not a guarantee. It
  also cannot be tested on loopback.

### 5.4 Long-lived TCP listener vs Doze and battery optimisationThe agent's core problem: a `ServerSocket` accepting DLWP/1 connections must stay alive for hours.
Nothing in Android *stops* a listening socket directly, but several mechanisms make the processunreliable:

1. **Doze and App Standby** defer network access and suspend wake locks when the device is idle and unplugged. A
   socket that is already established often survives *within* a maintenance window, but new inbound connections and
   mDNS traffic can be dropped. A foreground service substantially mitigates this, which is exactly why the FGS is not
   optional.

2. **Battery optimisation / "app standby" lists** on OEM skins (Xiaomi MIUI, Oppo ColorOS, Vivo Funtouch, Samsung One
   UI, Huawei EMUI) are far more aggressive than stock. OEMs kill background processes even with an FGS. This is the
   single most common field complaint against any product in this category. *[inference strongly supported by the
   general ecosystem experience; not verified from AOSP source, which does not model OEM behaviour.]*

3. **The platform's own escape hatches:** `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`
   (`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`) requests exemption, and
   `ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS` opens the settings page. Both are in the shell package's permission
   list **[verified locally]**. Note that Play policy restricts the former to specific use cases â€” but DroidLab is
   Apache-2.0 and distributed outside Play, so the policy constraint is a documentation/ethics matter rather than a
   blocker. **Use the settings-page `ACTION` (user-driven) rather than silently requesting the exemption**; that is
   honest and effective.

4. **`WAKE_LOCK`** is available (`normal`) but holding a partial wake lock for hours will visibly drain the battery
   and is likely to be killed by the OS or the user anyway. Prefer FGS + battery-optimisation exemption + reconnection
   over brute-force wake locks.

**Design implication that follows from all of Â§5:** the agent must treat the socket as *unreliable*and lean on
RFC-0003's fallback ladder plus the reconnection state machine in OVERVIEW.md Â§

6. The7-day last-known-endpoint cache and the optional UDP beacon are not nice-to-haves; they are themechanisms that
   make the product work on a real phone in someone's pocket. Conversely, therequirement that re-consent for screen
   capture is needed every session means the **controller shoulddegrade to control-only rather than drop the session**
   when capture dies â€” which OVERVIEW.md Â§6already specifies.

---

## Practical recommendationsOrdered by impact.
Each is a concrete action, not a general principle.

### Licensing (do this before writing any code)

1. **Do not bundle, commit, or redistribute `adb.exe` / platform-tools.** Terms `3.1` / `3.4` of the Android SDK
   License Agreement make the package non-sub-licensable and non-redistributable; only `3.5`'s OSS carve-out applies,
   and it does not cover the mixed bundle. Detect the user's installation instead.

2. **Write an ADR recording the decision**, add a `DEPENDENCIES.md` row, and note that this is a legal question
   needing counsel â€” not something the repo should resolve by precedent.

3. **Do not commit `adb.exe` to git or ship it in release archives**, even "just for tests". Add a `.gitignore` entry
   and a CI check.

4. If download-at-install is ever wanted, **present the Android SDK terms to the user and download from Google
   directly**, so the licence flows to the user rather than through DroidLab.

### ADB integration

1. **Always run adb on a private server port** (`-P <port>`, e.g. 5037+1000), and always pass it explicitly on every
   invocation. **[verified]** This gives a fully isolated server, so DroidLab never kills the user's server, never
   inherits a stale transport, and never pollutes the user's `adb devices`. This alone removes the entire class of
   "adb conflict" support tickets.

2. **Detect adb by probing multiple locations and falling back to `PATH`.** **[verified]** On this machine
   `ANDROID_HOME` and `ANDROID_SDK_ROOT` were both empty and the binary was at a custom `C:\Users\GHC\AndroidSdk\...`
   path. Checking only the env vars fails on real machines.

3. **Gate on the release version (second line of `adb version`, e.g. `37.0.1-â€¦`), require platform-tools â‰¥ 30.0.0,
   and never parse the `1.0.41` protocol line.** **[verified]** `1.0.41` is shared across many years of releases.

4. **Invert ADR-0006's endpoint order: use mDNS-discovered endpoints *before* the cached one.** The device's
   advertised `_adb-tls-connect._tcp` port is authoritative; a cached port is stale after any reboot or toggle, and
   trying it first burns a 10-second TCP timeout. Amend ADR-0006.

5. **Never persist a wireless serial as a device identity.** Persist the device GUID obtained at pairing, and
   re-resolve the serial every session. The serial embeds an mDNS instance suffix that changes on re-pairing.

6. **Parse Win32 error codes, not English text.** **[verified]** `10061` = refused/not listening (wireless debugging
   off *or* stale port); `10060` = timeout/unreachable. The prose is localised. Also handle the inconsistent transport
   strings `"device unauthorized.\n"` (trailing newline) vs `"device offline"` (none) from `transport.cpp`.

7. **Distinguish "no endpoint exists" from "endpoint stale"** in the UI â€” they need different remedies. Only `mDNS
   empty + cached endpoint present` should offer "re-pair".

8. **After a successful `adb pair`, re-run `adb devices -l` rather than waiting for an mDNS `Create` event.** Per
   `adb_wifi.md`, `_adb-tls-connect` is published *before* pairing, so the create event will have already fired; adb
   compensates by auto-connecting after pairing.

9. **Pre-empt the misleading pairing error.** **[verified]** A dead pairing port yields `error: protocol fault
   (couldn't read status message): No error`, which reads like a wrong code but means the socket never connected. Map
   it to "cannot reach the pairing server" in the UI.

10. **Offer the QR pairing path as the primary pairing flow for the ADB channel**, because it is the only genuinely
    scriptable one: the host generates `WIFI:T:ADB;S:<instance>;P:<host-chosen password>;;`, so the host knows the
    shared secret and no human reads the phone screen. Keep the scripted variant as `adb pair <host:port

> <code>` for power users. Document that the 6-digit code path has a hard human-in-the-loop requirement.

11. **Consider speaking the `host:*` smart socket directly for read-only polling.** **[verified]** `host:version`,
    `host:devices-l`, `host:track-devices`, `host:mdns:check`, `host:mdns:services` all work over a raw TCP socket
    with `%04X`-length framing. This eliminates per-call process spawn and console flash, and `host:track-devices`
    gives push updates instead of polling. Confine it to read-only queries with a fallback to `adb devices -l`, and
    amend ADR-0006 to state explicitly that this is not ADB-wire-protocol reimplementation.

12. **Set `ADB_MDNS_AUTO_CONNECT=0` on DroidLab's server** so adb does not connect to devices before DroidLab is
    ready. **[verified]** DroidLab's own mDNS browsing is independent of this setting, so discovery still works.
    Beware that `ADB_MDNS` / `ADB_MDNS_OPENSCREEN` only take effect at server start â€” **[verified]** setting them on
    a client invocation against a running server changes nothing.

### Discovery

1. **Use a pure-managed mDNS/DNS-SD implementation (`Makaretu.Dns.Multicast`, MIT, or a vendored equivalent).**
   **[verified]** The only mDNS responder on this machine was Apple's `mDNSResponder.exe` from `C:\Program
   Files\Bonjour\`, and Windows has no built-in DNS-SD browser for arbitrary service types. Depending on the Win32
   `DnsService*` API or on `Zeroconf` (which wraps Bonjour) means DroidLab cannot guarantee discovery works on a clean
   machine.

2. **Record the dependency-rule conflict explicitly.** `Makaretu.Dns.Multicast`'s last NuGet release was
   **2019-11-05**, which fails `DEPENDENCIES.md`'s "release in the last 18 months" rule. Either grant a documented
   exemption in the ADR (repo still active April 2024, MIT, pure-managed, small) or vendor a ~1,000â€“1,500-line
   codec. Pick one and write it down.

3. **Do not use `windns.dll`.** **[verified]** It does not exist on this machine; the exports (`DnsServiceRegister`,
   `DnsServiceBrowse`, `DnsServiceResolve`, `DnsServiceDeRegister`, `DnsServiceConstructInstance`,
   `DnsServiceCopyInstance`, `DnsServiceFreeInstance` and the two `*Cancel` functions) live in **`dnsapi.dll`**, and
   they still require a third-party responder.

4. **Implement advertisement expiry yourself with a per-device timer.** Do not rely on `ServiceLost` â€” a device that
   loses power or Wi-Fi never sends a goodbye. This is why RFC-0003's 120 s TTL and 7-day endpoint cache both matter.

5. **Handle the Windows Firewall failure mode explicitly.** The first multicast bind raises a firewall prompt; if
   denied or non-interactive, discovery silently never works. Detect "browse started, zero results, indefinitely" and
   surface the exact `netsh` rule to add.

6. **Bind to explicit interfaces and prefer IPv4 when connecting.** VPN/Hyper-V/WSL/Docker adapters can swallow
   multicast, and a link-local `fe80::` address without a scope id is discoverable but unconnectable. Add an interface
   picker rather than trusting the default multicast route.

7. **Test TXT advertisement across two real hosts, in CI or a documented manual procedure.** A loopback test passes
   even when the responder truncates or coalesces records. **This was the one thing I could not verify in this
   session** (no second host or device) and it is the highest untested risk in RFC-0003.

8. **Add a split/rejoin rule to RFC-0003 for any TXT value that can exceed 255 bytes.** The spec currently says `caps`
   is "truncated to fit" but does not define how a single long value is split across DNS character-strings.

9. **Never key discovery state on the mDNS instance name â€” key on TXT `id`.** For ADB the instance name is
   load-bearing (it embeds the GUID); for DroidLab it is cosmetic. RFC-0003 Â§3.2's "changed `fp` for a known `id`"
   impersonation warning is the correct use of that split.

### Input

1. **Make input capability a negotiated, per-device property, not an assumption.** The agent should report which
   mechanisms are actually available (accessibility enabled? shell uid? UHID?) in `GET_CAPABILITIES`, because they
   genuinely differ per device and per user configuration.

2. **`input.text` â†’ `ACTION_SET_TEXT` with a focus/click fallback.** It is Unicode-capable, unlike `adb shell input
   text`. Do not build a helper IME as the primary path â€” the agent is a real app, so it does not need one; only
   fall back to an in-app `InputMethodService` if no editable node is found.

3. **`input.touch` discrete â†’ `dispatchGesture`.** Respect **â‰¤20 strokes** and **â‰¤60,000 ms total**; chunk
   longer scripts using `willContinue` / `continueStroke` to avoid a visible lift.

4. **Decide and document the streamed-touch strategy as an ADR.** This is the hardest input problem: `dispatchGesture`
   is discrete-only and cannot stream MOVE events for a live mirror drag. Real streaming needs shell uid + reflection
   into `InputManager.injectInputEvent` (scrcpy's approach) or **UHID**. **Recommend targeting UHID over raw
   `/dev/uinput`** â€” no root, and it is where the most actively maintained tool in the space converged in 2025.

5. **State the `adb shell input` limits plainly in docs.** **[verified in source]** `pointerCount` is hardcoded to `1`
   in `InputShellCommand.injectMotionEvent`, so **no** `adb shell input` subcommand can ever produce multitouch â€”
   sequencing `input motionevent` will not create a pinch. And `input text` cannot send non-ASCII (per ADBKeyBoard's
   README).

6. **Plan the accessibility onboarding flow for sideloaded installs.** Android 13+ Restricted Settings blocks enabling
   an accessibility service from a sideloaded APK until the user grants it for that app. Detect "declared but not
   enabled" and deep-link `Settings.ACTION_ACCESSIBILITY_DETAILS_SETTINGS`. This is a first-run blocker, not an edge
   case.

7. **If the shell-uid path is ever used, surface the `"USB debugging (Security Settings)"` requirement** (from
   scrcpy's own source) â€” an OEM-specific developer option that must be enabled *and the device rebooted*. Also
   detect the `"INJECT_EVENTS permission"` substring inside a `SecurityException`.

8. **Keep the ADB-shell input path as a documented fallback** with the multitouch and Unicode losses spelled out,
   consistent with ADR-0006's "degrade rather than die".

### Background execution and permissions

1. **Declare both `mediaProjection` and `connectedDevice` foreground-service types.** Use `connectedDevice` for the
   long-lived listener (it is not time-limited) and `mediaProjection` for the mirror, since Android 14 requires the
   type for an active `MediaProjection`. All the type permissions are `normal`; the runtime asks are
   `POST_NOTIFICATIONS` and `NEARBY_WIFI_DEVICES`.

2. **Treat the MediaProjection consent token as strictly single-use.** One `createScreenCaptureIntent()` â†’ one
   `getMediaProjection()` â†’ one `createVirtualDisplay()`. Re-consent is required every session, so the mirror "first
   run each session" must be a designed flow, not an error. Wire `MediaProjection.Callback.onStop()` to the
   `screen.capture_revoked` event and degrade to control-only, as OVERVIEW.md Â§6 already specifies.

3. **Acquire a `WifiManager.MulticastLock` around discovery**, not just the `normal` `CHANGE_WIFI_MULTICAST_STATE`
   permission â€” otherwise Wi-Fi power saving can silently drop mDNS and registration will look successful while
   nothing is received.

4. **Defer the `NEARBY_WIFI_DEVICES` runtime request until the user enables discovery.** RFC-0003 requires discovery
   to be off by default on first launch, so this sequencing is both privacy-correct and prompt-minimising.

5. **Handle NSD concurrency limits and NSD state changes.** Unregister before re-registering on interface change
   (guard against `FAILURE_MAX_LIMIT` / `FAILURE_ALREADY_ACTIVE`) and register a receiver for
   `ACTION_NSD_STATE_CHANGED` so a policy toggle does not silently kill discovery.

6. **Guide the user through battery-optimisation exemption via the settings `ACTION`, not a silent
   `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` request.** OEM skins (MIUI, ColorOS, Funtouch, One UI) kill even foreground
   services; the listener must be treated as unreliable and RFC-0003's fallback ladder + the reconnection state
   machine are the real mitigation.

7. **Do not hold a long `WAKE_LOCK`.** It drains the battery, invites OS/user termination, and is unnecessary once FGS

   + battery exemption + reconnection are in place.

### Documentation corrections to make now

1. **Amend ADR-0006**: invert the endpoint-resolution order (discovered before cached); add the private-server-port
   decision; state that smart-socket `host:*` queries are in scope while the ADB wire protocol remains out of scope;
   and correct "the 6-digit code must be read off the device by a human" to note that the **QR path is the scriptable
   alternative**, which changes the pairing UX available to the product.

2. **Correct any claim that ADB wireless pairing is certificate-authenticated.** **[verified in source]** both sides
   call `SetCertVerifyCallback([](X509_STORE_CTX*){ return 1; })`. Security comes from the SPAKE2 PAKE seeded by the
   code (plus 64 bytes of TLS exported keying material), not from PKI.

3. **Document the two QR flows separately.** DroidLab's own RFC-0002 QR is *rendered by the device, scanned by the
   controller*. ADB's QR is the reverse: *generated by the workstation, scanned by the phone's camera*. Two
   opposite-direction QR flows in one product is a UX trap â€” label them unmistakably.

---

## Sources

### AOSP â€” ADB (`platform/packages/modules/adb`, branch `main`, Apache-2.0)- `packages/modules/adb/docs/dev/adb_wifi.md` â€” the architecture doc; all Â§1.1/Â§1.2/Â§1.5 quotes,  the 3 service types, QR format, auto-connect exception, system properties.- `packages/modules/adb/docs/user/adb.1.md` â€” man page, VERSION 1.0.41; command syntax, `-H/-P/-L/-a`,  `--one-device`; `connect`/`pair`/`mdns` definitions.- `packages/modules/adb/adb_mdns.h` â€” `ADB_MDNS_SERVICE_TYPE`, `ADB_MDNS_TLS_PAIRING_TYPE`,  `ADB_MDNS_TLS_CONNECT_TYPE`, service ref indices, `kNumADBDNSServices`.- `packages/modules/adb/adb_mdns.cpp` â€” service type string construction, `ADB_MDNS_AUTO_CONNECT`  allowlist logic, emulator-name exclusion.- `packages/modules/adb/client/mdns_utils.cpp` â€” `mdns_parse_instance_name`, and `is_enabled()`  reading `ADB_MDNS`.- `packages/modules/adb/client/commandline.cpp` â€” `pair` prompting and `host:pair:<code>:<host>`,  `mdns check`/`services` â†’ `host:mdns:
*`, the `ADB_MDNS_AUTO_CONNECT` help text.- `packages/modules/adb/client/pairing/pairing_client.cpp` â€” TCP connect,
10 s timeout, `TCP_NODELAY` off.- `packages/modules/adb/client/adb_wifi.cpp` â€” post-pairing GUID persistence,
auto-connect, `adb_known_hosts.pb`, 0640 mode, "Wrong password or connection was dropped."-
`packages/modules/adb/pairing_connection/pairing_connection.cpp` â€” `SetupTlsConnection`, `ExportKeyingMaterial(64)`
folded into the password, `SetCertVerifyCallback(... return 1)`, `PairingPacketHeader`, `kMaxPayloadSize`, header
read/write, state machine.- `packages/modules/adb/pairing_connection/include/adb/pairing/pairing_connection.h` â€”
`PeerInfo` (8192 B), `PeerInfoType`, `__INTRODUCED_IN(30)`.- `packages/modules/adb/pairing_auth/pairing_auth.cpp` â€”
SPAKE2 roles/names, generate/process msg.- `packages/modules/adb/pairing_auth/include/adb/pairing/pairing_auth.h` â€”
the client API contract and its BoringSSL SPAKE2 reference link.- `packages/modules/adb/pairing_auth/aes_128_gcm.cpp`
â€” HKDF-SHA256 with `info="adb pairing_auth aes-128-gcm key"`, AES-128-GCM, counter nonce.-
`packages/modules/adb/transport.cpp` â€” `acquire_one_transport`, `append_transport_info` field layout,
`MatchesTarget` wildcards, `"device unauthorized.\n"`, `"device offline"`.- `packages/modules/adb/adb.cpp` â€” mdns
backend `BONJOUR`/`OPENSCREEN`, `ADB_MDNS_OPENSCREEN`.- `packages/modules/adb/NOTICE` â€” Apache-2.0;
`MODULE_LICENSE_APACHE2` marker file.

### AOSP â€” platform / framework- `platform/frameworks/base/core/res/AndroidManifest.xml` â€” `INJECT_EVENTS` (`signature`),  `FOREGROUND_SERVICE*`, `POST_NOTIFICATIONS`, `NEARBY_WIFI_DEVICES`, `CHANGE_WIFI_MULTICAST_STATE`,  `ACCESS_WIFI_STATE`, `INTERNET` protection levels.- `platform/frameworks/base/packages/Shell/AndroidManifest.xml` â€” `android:sharedUserId="android.uid.shell"`,  and the shell uid's permission list **including `INJECT_EVENTS`**.- `platform/frameworks/base/core/java/android/content/pm/PermissionInfo.java` â€”  `PROTECTION_NORMAL=0`, `PROTECTION_DANGEROUS=1`, `PROTECTION_SIGNATURE=2`,  `PROTECTION_SIGNATURE_OR_SYSTEM=3`, `PROTECTION_INTERNAL=4`.- `platform/frameworks/base/core/java/android/accessibilityservice/GestureDescription.java` â€”  `MAX_STROKE_COUNT = 20`, `MAX_GESTURE_DURATION_MS = 60 * 1000`.- `platform/frameworks/base/core/java/android/hardware/input/InputManager.java` â€”  `injectInputEvent` `@hide` + `@RequiresPermission(INJECT_EVENTS)`; `INJECT_INPUT_EVENT_MODE_*`.- `platform/frameworks/base/core/java/android/hardware/input/InputManagerGlobal.java` â€”  `injectInputEvent(event, mode, targetUid)` delegating to `injectInputEventToTarget`.- `platform/frameworks/base/cmds/input/input.sh` â€” `#!/system/bin/sh` / `cmd input "$@"`.- `platform/frameworks/base/cmds/input/Android.bp` â€” `sh_binary { name: "input" }`.- `platform/frameworks/base/services/core/java/com/android/server/input/InputShellCommand.java` â€”  subcommand dispatch, `final int pointerCount = 1` (**the multitouch proof**), `InputManagerGlobal`  injection, `SOURCES` map, `getAction()`.- `platform/frameworks/base/cmds/uinput/src/com/android/commands/uinput/` â€” `Uinput.java`,  `Device.java`, `EvemuParser.java` (host-side uinput tooling).- `platform/frameworks/base/data/etc/platform.xml` â€” gid mappings (note: no `INJECT_EVENTS` gid  mapping; it is a pure signature permission).

### Android SDK (local, verified by experiment)- `android.jar` for **android-34** â€” `javap` dumps of `android.net.nsd.
NsdManager`, `android.net.nsd.NsdServiceInfo`, `android.media.projection.MediaProjectionManager`,
`android.media.projection.MediaProjection`, `android.accessibilityservice.AccessibilityService`, `GestureDescription`,
`GestureDescription$StrokeDescription`, `android.view.accessibility.AccessibilityNodeInfo`,
`android.app.Instrumentation`, `android.app.UiAutomation`, `android.app.Service`, `android.content.pm.ServiceInfo`.-
`platform-tools` **37.0.1-15733141** at `C:\Users\GHC\AndroidSdk\platform-tools\adb.exe`.

### Licences and terms- `https://developer.android.com/studio/terms` â€” Android Software Development Kit License Agreement  (clauses 1.1, 2.1, 3.1, 3.2, 3.3, 3.4, **3.5**, 4.4).- `chromium.googlesource.com/android_tools/+/HEAD/sdk/platform-tools/NOTICE.txt` â€” 386,777-character  aggregate notice for the platform-tools bundle; file inventory, copyright holders, one  `BSD-2-Clause-FreeBSD` SPDX tag.- `https://developer.android.com/tools/releases/platform-tools` â€” "a component for the Android SDK";  "app developers will normally just use the copy Studio installs".

### Android developer docs- `https://developer.android.com/develop/connectivity/wifi/use-nsd` â€” NSD registration, discovery,  resolution, unregistration; the `SERVICE_TYPE` pattern; `PROTOCOL_DNS_SD`.- `https://developer.android.com/reference/android/net/nsd/NsdServiceInfo` (JS-rendered; content  verified instead via `javap`).

### Third-party projects
- **Genymobile/scrcpy** (Apache-2.0), `server/src/main/java/com/genymobile/scrcpy/`: `wrappers/InputManager.java` â€”
  reflection into hidden `injectInputEvent`; the exact `"INJECT_EVENTS permission"` substring check; the `"Make sure
  you have enabled \"USB debugging (Security Settings)\" and then rebooted your device."` message; `setDisplayId`;
  `setActionButton`; `addUniqueIdAssociationByPort`.

- `device/Device.java` â€” `injectEvent(InputEvent, displayId, injectMode)`; `supportsInputEvents` gated on API 29 for
  non-zero displays; issue `github.com/Genymobile/scrcpy/issues/5530` re Android 15 display power.

- `control/Controller.java` â€” `injectTouch` multi-pointer `MotionEvent` construction, `ACTION_POINTER_DOWN/UP |
  (pointerIndex << ACTION_POINTER_INDEX_SHIFT)`, "Too many pointers for touch event"; UHID message handling; issue
  `github.com/Genymobile/scrcpy/issues/3635` (Chrome mouse buttons).

- `control/UhidManager.java` â€” UHID constants (`UHID_OUTPUT=6`, `UHID_CREATE2=11`, `UHID_INPUT2=12`,
  `BUS_VIRTUAL=0x06`, `SIZE_OF_UHID_EVENT=4380`), `/dev/uhid` open, `uhid_create2_req` / `uhid_input2_req` layouts,
  Android 15 display association.

- `Server.java` â€” `Os.setuid(2000)`.
- `Workarounds.java` â€” `fillAppInfo()` via `ActivityThread$AppBindData` reflection. - `AndroidVersions.java` â€”
  `API_21_ANDROID_5_0` â€¦ `API_35_ANDROID_15`. **senzhk/ADBKeyBoard** â€” README documenting that `input text` cannot
  send Unicode, and the `ADB_INPUT_TEXT` / `ADB_INPUT_B64` / `ADB_INPUT_CHARS` / `ADB_INPUT_CODE` / `ADB_EDITOR_CODE`
  broadcast workaround, plus the Oreo/P UTF-8 caveat and `ime enable`/`ime set`/`ime reset`.
  **richardschneider/net-mdns** (`Makaretu. Dns.Multicast`, MIT) â€” README: `ServiceDiscovery.Advertise`,
  `ServiceDiscovered`, `ServiceInstanceDiscovered`, multi-interface support, interface-change detection, legacy
  unicast queries (#61).- NuGet registration API â€” release dates: `Makaretu.Dns.Multicast` 0.27.0 = 2019-11-05;
  `Makaretu.Dns` 2.0.1 = 2019-07-22; `Zeroconf` 3.7.16 = 2024-12-17.- GitHub API â€” `richardschneider/net-mdns`
  pushed 2024-04-24, MIT, not archived, 272 stars; `richardschneider/net-dns` pushed 2019-07-22.

### Local experiments (all marked **[verified locally]** above)`adb version`; `adb devices -l`; `adb mdns check`; `adb mdns services`; `adb help`; `adb connect` to`127.0.0.1:1`, `127.0.0.1:5555`, `192.0.2.1:5555`; `adb pair 127.0.0.1:1 123456`;`adb -P 15037 start-server`; `Get-NetTCPConnection` showing ports 5037 and 15037 co-listening;`Get-CimInstance Win32_Process` showing `adb -L tcp:<port

> fork-server server`; `ANDROID_ADB_SERVER_PORT`;`ADB_MDNS=0`; `ADB_MDNS_OPENSCREEN=1`; raw TCP smart-socket requests
> `host:version`,`host:devices-l`, `host:track-devices`, `host:mdns:check`, `host:mdns:services`;
> `Get-Service`(mDNS/Bonjour/Dnscache); byte-scan of `dnsapi.dll` for `DnsService*` exports; absence of`windns.dll`;
> `javap` dumps listed under "Android SDK".

### Explicitly unverified- The exact `adb server version (N) doesn't match this client (M); killing...
` string (only one adb version installed here).- The Android 15 `dataSync` ~6-hour foreground-service time limit (not
confirmed against an official page in this session).- The exact enforcement site and exception text for the Android 14
`mediaProjection` FGS-type requirement.- The Android 13+ Restricted Settings flow end-to-end (API names confirmed;
behaviour not tested on a device).- `MulticastLock` acquisition being mandatory for NSD to receive multicast.-
Per-project attributions for which of Appium / Maestro / Auto.js use `dispatchGesture` (the API contract is verified
from AOSP; the per-project usage was not read from source here).- `openstf/minitouch` protocol-B details and its
`/dev/uinput` access model.- npm `adb-wifi` internals and Appium's `appium-adb` non-bundling policy (consistent with
ecosystem practice and SDK clause 3.4, but not read directly).- The end-to-end multi-host TXT advertisement round trip
â€” **the highest-value test to add next**, as it is the one place a loopback test cannot substitute for a real one.
