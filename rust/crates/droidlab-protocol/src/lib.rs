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

pub mod capability;
pub mod cbor;
pub mod classify;
pub mod discovery;
pub mod error;
pub mod frame_header;
pub mod keyschedule;
pub mod labels;
pub mod limits;
pub mod pairing;
pub mod registry;
pub mod schema;
pub mod seed;
pub mod transcript;
pub mod version;
pub mod wire;

pub use capability::{
    clamp_file_chunk, clamp_shell_timeout, clamp_video, even_floor, fit_inside,
    is_known_capability, may_reopen, negotiate, ungated_message_types, ChannelAllocator,
    ClampOutcome, Negotiated, VideoApplied, VideoRequest, CAPABILITIES, COMPRESSION,
};
pub use cbor::{CborError, CborErrorKind, MajorType, Value, MAX_DEPTH};
pub use classify::{
    classify, classify_in_state, classify_with_message_type, is_repeat_of_a_passed_state,
    may_be_cleartext, Classification, HandshakeState, Verdict,
};
pub use discovery::{
    advertises_when_busy, build_txt, canonical_beacon, canonical_beacon_string,
    canonical_key_order, canonical_txt, canonical_txt_string, evaluate_advertisement, goodbye_ttl,
    is_expired, is_known_txt_key, is_usable_port, may_emit_beacon, requires_reregistration,
    truncate_capabilities, AdvertisementVerdict, Presence, TxtError, TxtFields, BEACON_PORT,
    DEFAULT_PORT, DOMAIN, MAX_TXT_BYTES, OPTIONAL_KEYS, REQUIRED_KEYS, SERVICE_TYPE, TTL_SECONDS,
};
pub use error::{ErrorCode, FrameError, Severity};
pub use frame_header::{
    FrameFlag, FrameHeader, DEFINED_FLAGS, FIXED_LENGTH, MAGIC, PROTOCOL_VERSION, RESERVED_FLAGS,
};
pub use keyschedule::{
    aad_from_header, build_nonce, constant_time_eq, derive_session_keys, hmac_labeled, hmac_sha256,
    open, seal, session_ikm, session_salt, sha256, sha256_labeled, Direction, KeyScheduleError,
    RecordError, SessionKeys, EXPORTER_LENGTH, IV_PREFIX_LENGTH, KEY_LENGTH, NONCE_LENGTH,
    SEQUENCE_LENGTH, TAG_LENGTH,
};
pub use limits::Limits;
pub use pairing::{
    derive_pairing_secret, ed25519_public_key_with_seed, pairing_code, pairing_salt,
    sign_ed25519_with_seed, verify_ed25519, verify_proof, x25519_shared, AuthProofs, Fingerprint,
    FingerprintError, PairingError, PairingSecret, FINGERPRINT_BYTES, FINGERPRINT_RENDERED,
    PAIRING_CODE_DIGITS, PAIRING_CODE_MODULUS, PAIRING_SECRET_LENGTH, PROOF_LENGTH,
};
pub use registry::Direction as MessageDirection;
pub use registry::{
    all_codes, all_names, capability_for_message_type, is_registered_message_type,
    is_registered_name, may_be_unencrypted, message_type, message_type_by_name, must_be_encrypted,
    ChannelScope, MessageType, MESSAGE_TYPES,
};
pub use schema::{
    check_capability, check_channel, check_channel_limit, validate_body, validate_raw_body,
    BodySchema, FieldSpec, FieldType, SemanticCheck, ValidationError, SCHEMAS,
};
pub use seed::{
    from_base64url, from_hex, key_from_hex, key_from_seed, seed_hex, to_base64url, to_hex,
    Base64Error, HexError, SEED_PREFIX,
};
pub use transcript::{
    Transcript, TranscriptError, FIXED_WIDTH_TOTAL, LABEL_LENGTH, LENGTH_PREFIX_LENGTH,
    SEPARATOR_LENGTH,
};
pub use version::{
    check_header_against_body, classify_change, is_a_valid_answer, negotiate_versions, ChangeKind,
    HeaderBodyMismatch, Negotiation, Version, VersionError,
};
pub use wire::{
    enables_compression, should_compress, wire_size, wire_size_compressed, CompressionDecision,
    FrameView, FrameViewError, HeaderTemplate, TemplateError, COMPRESSION_DENOMINATOR,
    COMPRESSION_MIN_BODY, COMPRESSION_NUMERATOR, DEFLATE_STORED_OVERHEAD,
};
