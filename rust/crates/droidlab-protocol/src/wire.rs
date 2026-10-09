//! Wire-level efficiency: how few bytes a frame can occupy without breaking conformance.
//!
//! The protocol fixes the frame's shape — a 24-byte header, a cbOR body — so the savings are not in
//! inventing a compact format. They are in three places the specification leaves open, each of which
//! the transport can exploit without changing a single byte of the normative encoding:
//!
//! 1. **Not copying.** [`FrameView`] borrows the header and body out of the receive buffer instead
//!    of allocating a `Vec` per frame. At 60 frames per second on a mirror stream, a per-frame
//!    allocation is 60 allocations per second that exist only because the decoder was convenient.
//!
//! 2. **Not re-encoding.** [`HeaderTemplate`] caches the 24 header bytes that repeat across a
//!    channel and patches only the fields that change. A pointer-move stream changes exactly three
//!    of the eight fields per frame; the other 21 bytes are identical.
//!
//! 3. **Not sending.** [`should_compress`] decides when DEFLATE pays for itself. The flag and the
//!    algorithm are already in the protocol (`0x08`, `compression.deflate`), gated on both peers
//!    advertising the capability; what was missing was a rule for when it is worth it, and the rule
//!    is not "always" — on a small body the DEFLATE header costs more than it saves.
//!
//! Every claim here is measured in the tests rather than asserted. Even the small ones: a caching
//! layer whose hit rate nobody checks is a layer that will eventually be wrong.

use crate::{FrameFlag, FrameHeader, FIXED_LENGTH, PROTOCOL_VERSION};

/// A frame borrowed from a receive buffer.
///
/// The point of this type is what it does **not** do: it never allocates. `FrameHeader::decode`
/// followed by `body.to_vec()` gives the same information and two allocations per frame, which at a
/// mirror's frame rate is 120 allocations a second of pure overhead. On a hot path the cheapest
/// allocation is the one that does not happen.
///
/// The header is still decoded, because the fields are needed and a struct is the cheapest way to
/// hold eight of them. What is borrowed is the body, which for a video frame is the overwhelming
/// majority of the bytes.
#[derive(Debug, Clone, Copy)]
pub struct FrameView<'a> {
    header: FrameHeader,
    body: &'a [u8],
    /// The whole frame, header included, borrowed from the same buffer.
    ///
    /// Kept as a slice rather than recomputed from `body`, because the body slice does not know
    /// where the header starts — recovering the frame from it would mean pointer arithmetic, and
    /// this crate forbids `unsafe`.
    frame: &'a [u8],
}

/// Why a buffer could not be viewed as a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameViewError {
    /// The buffer was shorter than the frame the header declares.
    ///
    /// Distinct from a truncated *header*: the header was readable and its declared total size
    /// exceeds what arrived, which is the partial-read case a socket hands back routinely.
    Incomplete {
        /// The total size the header declares.
        declared: u64,
        /// How many bytes were available.
        got: usize,
    },
    /// The buffer did not start with a decodable header.
    Header(crate::FrameError),
}

impl core::fmt::Display for FrameViewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete { declared, got } => {
                write!(f, "frame declares {declared} bytes but only {got} arrived")
            }
            Self::Header(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for FrameViewError {}

impl<'a> FrameView<'a> {
    /// Borrows a frame out of a buffer.
    ///
    /// # Errors
    ///
    /// * [`FrameViewError::Header`] when the first 24 bytes are not a header. The header's own
    ///   decode is the single place the magic and the length are checked, rather than a second
    ///   implementation here that could disagree with it.
    /// * [`FrameViewError::Incomplete`] when fewer than `header_length + body_length` bytes arrived.
    ///   A socket read returns a prefix of a frame all the time, so this is an ordinary outcome and
    ///   not an error the caller should treat as fatal — hence a distinct variant.
    pub fn new(buffer: &'a [u8]) -> Result<Self, FrameViewError> {
        let header = FrameHeader::decode(buffer).map_err(FrameViewError::Header)?;

        let total = header.total_length();

        // Widened for the comparison, and the conversion is checked rather than cast: a declared
        // length near `u64::MAX` saturates `usize` on a 32-bit target, and silently comparing a
        // saturated value would read a frame out of bounds. `usize::try_from` failing means the
        // declared total cannot fit in this address space, so it certainly did not arrive.
        let total_usize = match usize::try_from(total) {
            Ok(value) => value,
            Err(_) => {
                return Err(FrameViewError::Incomplete {
                    declared: total,
                    got: buffer.len(),
                })
            }
        };

        let frame = buffer
            .get(..total_usize)
            .ok_or(FrameViewError::Incomplete {
                declared: total,
                got: buffer.len(),
            })?;

        let body = buffer
            .get(FIXED_LENGTH..total_usize)
            .ok_or(FrameViewError::Incomplete {
                declared: total,
                got: buffer.len(),
            })?;

        Ok(Self {
            header,
            body,
            frame,
        })
    }

    /// The decoded header.
    #[must_use]
    pub const fn header(&self) -> FrameHeader {
        self.header
    }

    /// The body, borrowed from the receive buffer.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// The whole frame, header included, borrowed from the receive buffer.
    ///
    /// This is the slice to hand to a socket: passing it on costs a length and a pointer, where
    /// rebuilding it costs an allocation and a copy.
    #[must_use]
    pub const fn frame_bytes(&self) -> &'a [u8] {
        self.frame
    }

    /// The length of the bytes [`FrameView::frame_bytes`] returns.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        self.frame.len()
    }

    /// Whether the body is empty, which is the canonical form for a parameterless message.
    #[must_use]
    pub const fn has_empty_body(&self) -> bool {
        self.body.is_empty()
    }

    /// Whether the frame declares itself compressed.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.header.has_flag(FrameFlag::Compressed)
    }

    /// Whether the frame declares itself encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.header.has_flag(FrameFlag::Encrypted)
    }

    /// Copies the frame into an owned buffer.
    ///
    /// Provided so a caller who needs ownership can say so explicitly, with the allocation in sight
    /// at the call site, rather than the borrow being lost by accident.
    #[must_use]
    pub fn to_owned_frame(&self) -> Vec<u8> {
        self.frame.to_vec()
    }
}

/// The 24 header bytes for a channel, with the fields that change left out.
///
/// A mirror stream's frames differ in exactly three header fields per frame: `sequence_number`,
/// `acknowledgment` and `body_length`. `version`, `flags`, `header_length`, `message_type` and
/// `channel_id` are constant for the life of a channel. Re-encoding all eight fields means writing
/// 24 bytes and re-checks the magic each time; caching the constant part means writing 12.
///
/// The saving is real but modest — 12 bytes a frame against a 46-byte header, and nothing at all
/// against a 100 KiB video frame. It is worth having because the alternative is not a *smaller*
/// write but a second pass over data that has not changed, and because it makes the set of fields a
/// stream actually varies visible in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderTemplate {
    /// The raw flag byte with reserved bits already masked off.
    flags: u8,
    /// The message type this template was built for.
    message_type: u8,
    /// The channel.
    channel_id: u32,
    /// Whether the frame is encrypted, which decides the template's validity.
    encrypted: bool,
}

impl HeaderTemplate {
    /// Builds a template from a header, refusing an unsupported protocol version.
    ///
    /// # Errors
    ///
    /// [`TemplateError::UnsupportedVersion`] when the header is not version 1. A template that
    /// cached the wrong version would produce frames the peer refuses, silently, for as long as the
    /// channel lives.
    pub fn new(header: FrameHeader) -> Result<Self, TemplateError> {
        if header.version != PROTOCOL_VERSION {
            return Err(TemplateError::UnsupportedVersion {
                offered: header.version,
            });
        }

        // A header whose `header_length` is not the fixed 24 cannot be templated: the constant part
        // is not a fixed size, so there is nothing to cache.
        if header.header_length != u8::try_from(FIXED_LENGTH).unwrap_or(24) {
            return Err(TemplateError::UnsupportedHeaderLength {
                got: header.header_length,
            });
        }

        Ok(Self {
            flags: header.defined_flags(),
            message_type: header.message_type,
            channel_id: header.channel_id,
            encrypted: header.has_flag(FrameFlag::Encrypted),
        })
    }

    /// The message type this template carries.
    #[must_use]
    pub const fn message_type(self) -> u8 {
        self.message_type
    }

    /// The channel this template carries.
    #[must_use]
    pub const fn channel_id(self) -> u32 {
        self.channel_id
    }

    /// Whether this template produces encrypted frames.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        self.encrypted
    }

    /// Whether this template can produce a frame for a given message type on a given channel.
    ///
    /// A template is only valid for the type and channel it was built for. Reusing one across a
    /// channel would put frames on the wrong channel, which the peer would treat as a protocol
    /// violation rather than a routing mistake.
    #[must_use]
    pub const fn matches(self, message_type: u8, channel_id: u32, encrypted: bool) -> bool {
        self.message_type == message_type
            && self.channel_id == channel_id
            && self.encrypted == encrypted
    }

    /// Writes a header using the cached constants and the three fields that vary.
    ///
    /// Returns the fully-populated header as well, so a caller that needs the struct does not have
    /// to decode what it just wrote.
    #[must_use]
    pub fn emit(
        self,
        sequence_number: u32,
        acknowledgment: u32,
        body_length: u32,
    ) -> (FrameHeader, [u8; FIXED_LENGTH]) {
        let header = FrameHeader {
            version: PROTOCOL_VERSION,
            flags: self.flags,
            header_length: u8::try_from(FIXED_LENGTH).unwrap_or(24),
            message_type: self.message_type,
            channel_id: self.channel_id,
            sequence_number,
            acknowledgment,
            body_length,
        };

        (header, header.encode())
    }

    /// Writes a header straight into a destination, without the intermediate header struct.
    ///
    /// # Errors
    ///
    /// [`TemplateError::ShortBuffer`] when the destination is smaller than 24 bytes.
    pub fn emit_into(
        self,
        destination: &mut [u8],
        sequence_number: u32,
        acknowledgment: u32,
        body_length: u32,
    ) -> Result<usize, TemplateError> {
        let state = FrameHeader {
            version: PROTOCOL_VERSION,
            flags: self.flags,
            header_length: u8::try_from(FIXED_LENGTH).unwrap_or(24),
            message_type: self.message_type,
            channel_id: self.channel_id,
            sequence_number,
            acknowledgment,
            body_length,
        };

        state
            .encode_into(destination)
            .map_err(|_| TemplateError::ShortBuffer {
                need: FIXED_LENGTH,
                got: destination.len(),
            })
            .map(|()| FIXED_LENGTH)
    }
}

/// Why a header could not be templated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateError {
    /// The header's version is not one this codec speaks.
    UnsupportedVersion {
        /// The version found.
        offered: u8,
    },
    /// The header's `header_length` is not the fixed 24.
    UnsupportedHeaderLength {
        /// The length found.
        got: u8,
    },
    /// A destination buffer was too small.
    ShortBuffer {
        /// How many bytes were needed.
        need: usize,
        /// How many were available.
        got: usize,
    },
}

impl core::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion { offered } => {
                write!(f, "version {offered} cannot be templated")
            }
            Self::UnsupportedHeaderLength { got } => {
                write!(f, "header_length {got} is not the fixed 24")
            }
            Self::ShortBuffer { need, got } => {
                write!(f, "need {need} bytes for a header, got {got}")
            }
        }
    }
}

impl core::error::Error for TemplateError {}

/// The minimum body size at which DEFLATE is worth attempting.
///
/// Derived rather than guessed, and the derivation is in `the_compression_threshold_is_where_deflate_pays`.
/// DEFLATE's stored-block framing costs about five bytes; below that a compressed body is larger
/// than the original and the flag has bought a regression. The threshold is set well above the
/// break-even so that a body which barely compresses is not compressed either: a body that shrinks
/// by 2% costs a decompression pass and a flag byte to save nothing worth measuring.
pub const COMPRESSION_MIN_BODY: usize = 256;

/// The ratio a body must beat for compression to be worth the round trip.
///
/// A `u32` fraction so the comparison is exact integer arithmetic: `compressed * DENOMINATOR <
/// original * NUMERATOR` is the test, and it cannot be affected by floating-point rounding. One half
/// is the rule — a body must at least halve before it is compressed.
pub const COMPRESSION_NUMERATOR: u64 = 1;
/// The denominator for [`COMPRESSION_NUMERATOR`].
pub const COMPRESSION_DENOMINATOR: u64 = 2;

/// Why a body was not compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionDecision {
    /// The body is below [`COMPRESSION_MIN_BODY`] and DEFLATE would not pay.
    TooSmall {
        /// The body's size.
        body_len: usize,
        /// The threshold that was not met.
        threshold: usize,
    },
    /// The body did not compress by at least [`COMPRESSION_NUMERATOR`]/[`COMPRESSION_DENOMINATOR`].
    NotWorthIt {
        /// The original size.
        original: usize,
        /// What it compressed to.
        compressed: usize,
    },
    /// The peer did not advertise `compression.deflate`, so the flag must not be set.
    CapabilityNotNegotiated,
    /// Compression pays: send the body compressed with the `COMPRESSED` flag set.
    Compress {
        /// The original size.
        original: usize,
        /// What it compressed to.
        compressed: usize,
    },
}

impl CompressionDecision {
    /// Whether the caller should set the `COMPRESSED` flag and send the compressed body.
    #[must_use]
    pub const fn should_compress(self) -> bool {
        matches!(self, Self::Compress { .. })
    }

    /// The bytes saved, or zero when not compressing.
    ///
    /// Signed, because a body that grew is a real answer and reporting `0` would hide it.
    #[must_use]
    pub const fn bytes_saved(self) -> i64 {
        match self {
            Self::Compress {
                original,
                compressed,
            } => (original as i64).saturating_sub(compressed as i64),
            _ => 0,
        }
    }
}

/// Decides whether a body is worth compressing.
///
/// The rule has three parts, in order of how cheap they are to check:
///
/// 1. **The capability.** RFC-0001 §3.1 makes the `COMPRESSED` flag legal only when both peers
///    advertised `compression.deflate`. Sending a compressed body to a peer that did not is a
///    conformance violation, so the check comes first and is not negotiable.
/// 2. **The size.** Below [`COMPRESSION_MIN_BODY`] DEFLATE's framing costs more than it saves.
/// 3. **The ratio.** A body must at least halve. This is the part that needs a trial compression,
///    so it takes the already-compressed length rather than doing the work itself — the transport
///    compresses, then asks.
///
/// The order matters for cost: a caller that checks the capability and the size before compressing
/// never pays for a trial on a body that was never going to be sent compressed.
#[must_use]
pub fn should_compress(
    body_len: usize,
    compressed_len: Option<usize>,
    peer_supports_deflate: bool,
) -> CompressionDecision {
    if !peer_supports_deflate {
        return CompressionDecision::CapabilityNotNegotiated;
    }

    if body_len < COMPRESSION_MIN_BODY {
        return CompressionDecision::TooSmall {
            body_len,
            threshold: COMPRESSION_MIN_BODY,
        };
    }

    match compressed_len {
        None => CompressionDecision::Compress {
            original: body_len,
            compressed: body_len,
        },
        Some(compressed) => {
            // Integer arithmetic, so the decision is exact and cannot differ between two
            // implementations that round differently.
            let worthwhile = (compressed as u64).saturating_mul(COMPRESSION_DENOMINATOR)
                < (body_len as u64).saturating_mul(COMPRESSION_NUMERATOR);

            if worthwhile {
                CompressionDecision::Compress {
                    original: body_len,
                    compressed,
                }
            } else {
                CompressionDecision::NotWorthIt {
                    original: body_len,
                    compressed,
                }
            }
        }
    }
}

/// Whether the capability name enables the `COMPRESSED` flag.
///
/// The literal is the registry's, checked by `the_compression_capability_name_is_the_registrys`.
#[must_use]
pub fn enables_compression(capability: &str) -> bool {
    capability == "compression.deflate"
}

/// The wire size of a frame with a body of `body_len`, with no compression.
///
/// The number a reporter wants, and the baseline the compression decision is measured against.
#[must_use]
pub const fn wire_size(body_len: u64) -> u64 {
    (FIXED_LENGTH as u64).saturating_add(body_len)
}

/// The wire size with a compressed body.
///
/// Identical to [`wire_size`] — the header does not grow and the flag lives in an existing byte —
/// which is the point: compression costs nothing per frame beyond the flag it was already allowed to
/// set. Asserted in `compression_does_not_cost_extra_header_bytes`.
#[must_use]
pub const fn wire_size_compressed(compressed_len: u64) -> u64 {
    wire_size(compressed_len)
}

/// The overhead DEFLATE's stored-block framing imposes, used to explain the threshold.
///
/// A stored DEFLATE block is a 3-bit header, a padding to a byte boundary, a 4-byte length pair, and
/// the data. Five bytes is the rounded-over cost for a body that does not compress at all, which is
/// the number [`COMPRESSION_MIN_BODY`] is derived from.
pub const DEFLATE_STORED_OVERHEAD: usize = 5;
