//! DLWP/1 — the DroidLab Wire Protocol, version 1.
//!
//! This crate is the **reference implementation** of DLWP/1. It is the only one in the repository
//! that is compiled and tested as part of an ordinary build, so when the three implementations
//! disagree, this one's behaviour is what the specification is taken to mean until the
//! specification is corrected.
//!
//! The three implementations are siblings under ADR-0007: the conformance vectors in
//! `protocol/vectors/` are the only interoperability contract between them, and none of the three
//! is authoritative over the others by construction. What makes this one useful is narrower and
//! more practical — it runs.
//!
//! # Scope
//!
//! This crate is layer L1 in the architecture: it depends on nothing but Rust's standard library
//! and audited cryptographic primitives, and it knows nothing about sockets, threads, Android or
//! Windows. Transport lives above it.
//!
//! # Design rules that the vectors enforce
//!
//! * **Decoding never panics for malformed input.** Every failure is a value. A panic in a codec
//!   reachable from the network is a denial of service, and the lint configuration denies
//!   `unwrap`, `expect` and `panic` to keep one from appearing by accident.
//! * **Decoding does not enforce policy.** Turning bytes into fields and deciding whether the
//!   result is legal are different jobs with different inputs; the second needs the registry and
//!   the negotiated limits.
//! * **Reserved bits are preserved on decode and masked on encode.** A receiver must ignore them,
//!   not reject them, so throwing them away on decode would lose information a round trip needs.
//!
//! # Example
//!
//! ```
//! use droidlab_protocol::{FrameFlag, FrameHeader};
//!
//! let header = FrameHeader {
//!     version: 1,
//!     flags: FrameFlag::Urgent as u8,
//!     header_length: 24,
//!     message_type: 5, // PING
//!     channel_id: 0,
//!     sequence_number: 1,
//!     acknowledgment: 0,
//!     body_length: 0,
//! };
//!
//! let bytes = header.encode();
//! assert_eq!(bytes.len(), 24);
//! assert_eq!(FrameHeader::decode(&bytes).unwrap(), header);
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]
// A panic in a codec reachable from the network is a denial of service, so the lints that find one
// are denied HERE, on the library target. They are not in the crate manifest's `[lints]` table
// because that table also applies to the test targets, where `expect` and `panic!` are how an
// assertion reports its failure -- suppressing them there would make every test's failure message
// worse and its success path longer, for no safety gained.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]

pub mod cbor;
pub mod error;
pub mod frame_header;
pub mod limits;
pub mod wire;

pub use cbor::{CborError, CborErrorKind, MajorType, Value, MAX_DEPTH};
pub use error::{ErrorCode, FrameError, Severity};
pub use frame_header::{
    FrameFlag, FrameHeader, DEFINED_FLAGS, FIXED_LENGTH, MAGIC, PROTOCOL_VERSION, RESERVED_FLAGS,
};
pub use limits::Limits;
pub use wire::{
    enables_compression, should_compress, wire_size, wire_size_compressed, CompressionDecision,
    FrameView, FrameViewError, HeaderTemplate, TemplateError, COMPRESSION_DENOMINATOR,
    COMPRESSION_MIN_BODY, COMPRESSION_NUMERATOR, DEFLATE_STORED_OVERHEAD,
};
