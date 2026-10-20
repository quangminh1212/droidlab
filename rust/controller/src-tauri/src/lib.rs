//! The DroidLab controller's Rust core.
//!
//! Layout, bottom to top:
//!
//! * [`transport`] — DLWP/1 frames on a TCP socket. Bounded reads, no panics.
//! * [`session`] — the handshake: `HELLO` → `HELLO_ACK` → `AUTH` → `AUTH_OK`.
//! * `commands` — the Tauri command surface the UI calls.
//!
//! Everything about *what the bytes mean* lives in [`droidlab_protocol`], linked as a path
//! dependency rather than reimplemented here. That is ADR-0009's rule R8, and it is the reason the
//! controller was moved to this stack: one protocol implementation in the Windows process instead
//! of two that have to agree.

#![deny(missing_docs)]
#![forbid(unsafe_code)]
// The same panic-hunting lints the protocol core denies, for the same reason and with the same
// scoping: they are here on the library target rather than in the manifest because the `[lints]`
// table would also apply to the integration tests, where a panic is how an assertion reports.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]

pub mod commands;
pub mod session;
pub mod transport;

pub use session::{Established, HandshakeError};
pub use transport::{Frame, FrameReader, FrameWriter, Transport, TransportError};

/// The protocol version this controller speaks.
///
/// A single constant rather than a literal wherever it is needed, because it appears in the
/// handshake, in the discovery beacon and in the user agent, and three copies would eventually
/// disagree.
pub const PROTOCOL_VERSION: u16 = 1;

/// The protocol versions this controller supports, newest first.
///
/// Passed to the handshake as a list rather than as a single number so that a controller which
/// learns a second version can offer both without changing the handshake's shape.
pub const SUPPORTED_VERSIONS: &[u16] = &[1];
