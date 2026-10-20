//! The Tauri command surface, and the logging the binary installs.
//!
//! # Why commands are a module and not `main.rs`
//!
//! Every command here is a plain function with a `Result` return type, and the Tauri attribute is
//! the only thing that makes it a command. Keeping them in the library means the tests can call
//! them directly: the *logic* of a command is testable without a window, and only the IPC plumbing
//! needs the runtime.
//!
//! # What a command may and may not do
//!
//! Commands translate between the UI's JSON and the controller's Rust types. They may not contain
//! protocol arithmetic — that is in `droidlab_protocol` — and they may not own a socket directly;
//! they go through [`crate::session`] and [`crate::transport`]. The exception is the handful that
//! are genuinely about the process rather than about a device, such as the version query below.

use serde::Serialize;
use tracing_subscriber::EnvFilter;

use crate::{PROTOCOL_VERSION, SUPPORTED_VERSIONS};

/// One entry in the device list, as the UI sees it.
///
/// A view model rather than a protocol type. The discovery layer produces a
/// `droidlab_protocol::discovery::TxtFields`; this is what the UI is allowed to know, which is
/// deliberately less — an advertisement's raw TXT map is not something a view should render
/// directly, and keeping the two apart means a change to the advertisement cannot change what the
/// UI receives without someone deciding to change it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DeviceView {
    /// The device's display name, from the advertisement.
    pub name: String,
    /// The host the agent was seen at.
    pub host: String,
    /// The port the agent's listener is on.
    pub port: u16,
    /// The protocol version the advertisement claims.
    pub version: u16,
    /// Whether this controller has a stored pairing for the device.
    pub paired: bool,
}

/// What the UI shows as the controller's own identity and capabilities.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ControllerInfo {
    /// The protocol version this build speaks.
    pub protocol_version: u16,
    /// Every protocol version this build accepts.
    pub supported_versions: Vec<u16>,
    /// The controller's version, from the package manifest.
    pub controller_version: String,
}

/// Installs the tracing subscriber the whole process logs through.
///
/// Idempotent-safe by using `try_init`, which returns an error rather than panicking if a
/// subscriber is already installed. That matters because tests install one too, and a second call
/// panicking would make the first test to run poison every later one.
///
/// The default level is `info`, and `RUST_LOG` overrides it. The default is not `debug` because a
/// mirror session logs a frame per input event, and a default that floods the console is a default
/// users turn off entirely — which then hides the `warn` lines that matter.
pub fn install_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _already_installed = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

/// Returns the controller's identity and the protocol versions it speaks.
///
/// The first command the UI calls, and the one that lets the window say what it is before any
/// device is involved. It exists in M2 mainly to prove the IPC bridge works end to end with real
/// data rather than a spike's placeholder.
#[tauri::command]
#[must_use]
pub fn controller_info() -> ControllerInfo {
    ControllerInfo {
        protocol_version: PROTOCOL_VERSION,
        supported_versions: SUPPORTED_VERSIONS.to_vec(),
        controller_version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

/// Starts the controller window.
///
/// # Errors
///
/// Returns Tauri's error if the window cannot be created. In practice this means the WebView2
/// runtime is missing, which is the one deployment prerequisite this application has.
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![controller_info])
        .run(tauri::generate_context!())
}
