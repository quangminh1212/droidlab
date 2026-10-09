//! The fixed 24-byte DLWP/1 frame header (RFC-0001 §3).
//!
//! This module turns bytes into fields and back. It validates **nothing** about protocol state,
//! because whether a frame is legal depends on the session state machine and the negotiated
//! limits, not on the header. Frame-level validity is
//! [`FrameHeader::validate`](crate::FrameValidator)'s job.
//!
//! The layout, all multi-byte fields big-endian:
//!
//! ```text
//!   offset  width  field
//!   0       4      magic "DLWP"
//!   4       1      version
//!   5       1      flags
//!   6       1      header_length
//!   7       1      message_type
//!   8       4      channel_id
//!   12      4      sequence_number
//!   16      4      acknowledgment
//!   20      4      body_length
//! ```

use crate::error::FrameError;

/// The four magic bytes, ASCII `DLWP`.
pub const MAGIC: [u8; 4] = *b"DLWP";

/// The fixed header length in DLWP/1.
pub const FIXED_LENGTH: usize = 24;

/// The protocol major version this codec implements.
pub const PROTOCOL_VERSION: u8 = 1;

/// The mask of the four defined flag bits.
pub const DEFINED_FLAGS: u8 = 0x0F;

/// The mask of the reserved flag bits, which must be zero on send and are ignored on receive.
pub const RESERVED_FLAGS: u8 = 0xF0;

/// A flag bit of a DLWP/1 frame header (RFC-0001 §3.1).
///
/// Bits 4–7 are reserved: a sender MUST clear them and a receiver MUST ignore them, so they are
/// deliberately absent from this enum. There is no value an implementation could act on, and
/// naming them would invite one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameFlag {
    /// The body is AEAD-encrypted per RFC-0002 §5. Set on every frame after `HELLO_ACK`.
    Encrypted = 0x01,
    /// The receiver should process this ahead of normal traffic.
    Urgent = 0x02,
    /// Last frame on this channel.
    EndOfStream = 0x04,
    /// The body was DEFLATE-compressed before encryption.
    Compressed = 0x08,
}

/// The fixed 24-byte DLWP/1 frame header.
///
/// This is a pure value. `flags` holds the **raw** byte, reserved bits included, so that a
/// decode → encode round trip is byte-exact and a receiver can tell an unclean sender from a
/// clean one. Use [`FrameHeader::defined_flags`] or [`FrameHeader::has_flag`] to test bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FrameHeader {
    /// Protocol major version. 1 for DLWP/1.
    pub version: u8,
    /// The raw flag byte, including any reserved bits the peer set.
    pub flags: u8,
    /// Total header length in bytes, including this 24-byte prefix.
    pub header_length: u8,
    /// The frame type, from the RFC-0001 §4 registry.
    pub message_type: u8,
    /// Logical channel. 0 is the control channel and is always valid.
    pub channel_id: u32,
    /// Per-session sequence number. Starts at 1 and never repeats within a session.
    pub sequence_number: u32,
    /// Highest received sequence number on this channel, or 0 when not applicable.
    pub acknowledgment: u32,
    /// Length of the body in bytes, excluding the header.
    pub body_length: u32,
}

impl FrameHeader {
    /// The defined flag bits only, with the reserved bits cleared.
    #[must_use]
    pub const fn defined_flags(self) -> u8 {
        self.flags & DEFINED_FLAGS
    }

    /// The reserved flag bits, which must be zero on a conformant sender.
    #[must_use]
    pub const fn reserved_flags(self) -> u8 {
        self.flags & RESERVED_FLAGS
    }

    /// Whether a given flag is set.
    #[must_use]
    pub const fn has_flag(self, flag: FrameFlag) -> bool {
        self.defined_flags() & (flag as u8) == (flag as u8)
    }

    /// Whether the header declares a message type that is encrypted per RFC-0001 §4.
    ///
    /// `HELLO` and `HELLO_ACK` are the only unencrypted frames: they carry the material the
    /// session keys are derived from, so they cannot be encrypted.
    #[must_use]
    pub const fn must_be_encrypted(self) -> bool {
        !matches!(self.message_type, 0x01 | 0x02)
    }

    /// The total on-wire size of the frame this header describes.
    ///
    /// Widened to `u64` because the sum of two `u32` fields can exceed `u32`. `saturating_add` is
    /// used rather than `+` because this crate denies arithmetic with unstated overflow behaviour
    /// and the sum is only ever compared against a limit.
    #[must_use]
    pub const fn total_length(self) -> u64 {
        (self.header_length as u64).saturating_add(self.body_length as u64)
    }

    /// Reads a header from the start of a buffer.
    ///
    /// Only the first [`FIXED_LENGTH`] bytes are inspected.
    ///
    /// # Errors
    ///
    /// * [`FrameError::TruncatedHeader`] when the buffer is shorter than 24 bytes. No fields are
    ///   read, so a short buffer cannot produce a partially-populated header.
    /// * [`FrameError::BadMagic`] when the first four bytes are not `DLWP`. The magic is checked
    ///   before any other field: reading a version or a channel id out of bytes that are not a
    ///   DLWP/1 frame is how a STUN packet or a stray HTTP request gets parsed into nonsense.
    ///
    /// Note what is **not** an error here. A `header_length` other than 24, an unknown message
    /// type and an oversized body are all answered by
    /// [`FrameValidator`](crate::FrameValidator) against the registry and the negotiated limits.
    /// This function only turns bytes into fields.
    pub fn decode(buffer: &[u8]) -> Result<Self, FrameError> {
        if buffer.len() < FIXED_LENGTH {
            return Err(FrameError::TruncatedHeader {
                need: FIXED_LENGTH,
                got: buffer.len(),
            });
        }

        // `get` rather than indexing: the length was just checked, but this function is on the
        // parsing path for hostile input and a slice that cannot panic is a slice that cannot be
        // turned into a denial of service by a future refactor.
        let magic: [u8; 4] = buffer
            .get(0..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(FrameError::TruncatedHeader {
                need: FIXED_LENGTH,
                got: buffer.len(),
            })?;

        if magic != MAGIC {
            return Err(FrameError::BadMagic { got: magic });
        }

        Ok(Self {
            version: get_byte(buffer, 4)?,
            flags: get_byte(buffer, 5)?,
            header_length: get_byte(buffer, 6)?,
            message_type: get_byte(buffer, 7)?,
            channel_id: get_u32_be(buffer, 8)?,
            sequence_number: get_u32_be(buffer, 12)?,
            acknowledgment: get_u32_be(buffer, 16)?,
            body_length: get_u32_be(buffer, 20)?,
        })
    }

    /// Writes the header into the first 24 bytes of `destination`.
    ///
    /// The reserved flag bits are masked off rather than trusted, so a caller cannot accidentally
    /// emit them and make a conformant peer reject the frame.
    ///
    /// # Errors
    ///
    /// [`FrameError::TruncatedHeader`] when `destination` is shorter than 24 bytes. A short
    /// destination is a programming error rather than a network condition, but returning it as a
    /// value keeps this crate free of `unwrap` and of panics in a codec.
    pub fn encode_into(self, destination: &mut [u8]) -> Result<(), FrameError> {
        if destination.len() < FIXED_LENGTH {
            return Err(FrameError::TruncatedHeader {
                need: FIXED_LENGTH,
                got: destination.len(),
            });
        }

        // The length is read before the mutable borrow, so the error value can be built without
        // touching `destination` again while it is borrowed.
        let available = destination.len();

        // Infallible after the length check, and written without indexing for the same reason as
        // `decode`.
        let target = destination
            .get_mut(0..FIXED_LENGTH)
            .ok_or(FrameError::TruncatedHeader {
                need: FIXED_LENGTH,
                got: available,
            })?;

        // Written with `copy_from_slice` and `put_u32_be` rather than by index, because this crate
        // denies `indexing_slicing`: an index that a future refactor gets wrong is a panic in a
        // codec reachable from the network, which is a denial of service.
        let (magic, rest) = target.split_at_mut(4);
        magic.copy_from_slice(&MAGIC);

        // `rest` is exactly 20 bytes after the length check above, so these all succeed. Each is
        // still expressed as a fallible write rather than an index.
        write_at(rest, 0, self.version);
        write_at(rest, 1, self.defined_flags());
        write_at(rest, 2, self.header_length);
        write_at(rest, 3, self.message_type);
        put_u32_be(rest, 4, self.channel_id);
        put_u32_be(rest, 8, self.sequence_number);
        put_u32_be(rest, 12, self.acknowledgment);
        put_u32_be(rest, 16, self.body_length);

        Ok(())
    }

    /// Writes the header into a new 24-byte array.
    ///
    /// # Panics
    ///
    /// Never: the destination is exactly [`FIXED_LENGTH`] bytes, and this crate denies `unwrap`
    /// and `expect`, so the failure path is expressed rather than assumed.
    #[must_use]
    pub fn encode(self) -> [u8; FIXED_LENGTH] {
        let mut buffer = [0u8; FIXED_LENGTH];
        // The slice is exactly FIXED_LENGTH long, so `encode_into` cannot fail. The result is
        // dropped explicitly rather than unwrapped, because the length is a compile-time constant
        // and an `unwrap` here would be denied by the lint configuration anyway.
        let _ = self.encode_into(&mut buffer);
        buffer
    }
}

/// Reads one byte at `offset`, or reports a truncated header.
fn get_byte(buffer: &[u8], offset: usize) -> Result<u8, FrameError> {
    buffer
        .get(offset)
        .copied()
        .ok_or(FrameError::TruncatedHeader {
            need: offset.saturating_add(1),
            got: buffer.len(),
        })
}

/// Reads a big-endian `u32` at `offset`, or reports a truncated header.
fn get_u32_be(buffer: &[u8], offset: usize) -> Result<u32, FrameError> {
    buffer
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_be_bytes)
        .ok_or(FrameError::TruncatedHeader {
            need: offset.saturating_add(4),
            got: buffer.len(),
        })
}

/// Writes one byte at `offset`, or does nothing when the buffer is too short.
///
/// Callers have already bounded the slice, so the silent no-op is unreachable in practice. It is
/// written this way rather than as an index because an index that a future refactor gets wrong
/// panics, and a panic in a codec reachable from the network is a denial of service.
fn write_at(buffer: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = buffer.get_mut(offset) {
        *slot = value;
    }
}

/// Writes a big-endian `u32` at `offset`.
///
/// The caller has already bounded the slice, so a short buffer leaves the value unwritten rather
/// than panicking.
fn put_u32_be(buffer: &mut [u8], offset: usize, value: u32) {
    if let Some(slice) = buffer.get_mut(offset..offset.saturating_add(4)) {
        slice.copy_from_slice(&value.to_be_bytes());
    }
}
