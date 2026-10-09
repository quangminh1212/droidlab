//! A deliberately small cbOR reader (RFC 8949), restricted to what DLWP/1 uses.
//!
//! It **rejects** everything else rather than skipping over it. That matters because cbOR is a
//! wide format: a permissive reader accepts many distinct byte sequences for the same logical
//! message. Rejecting them is what makes the vectors' bytes unique, which is what makes three
//! independent codecs provably equivalent (ADR-0003, ADR-0007).
//!
//! The rules come from the `encoding_rules` block of `protocol/vectors/framing-basic.json`:
//! definite lengths only, shortest-form integers, valid UTF-8, no tags, no floats, definite-length
//! maps and arrays.
//!
//! # What is not here
//!
//! No indefinite-length items, no tags, no floats, no bignums. DLWP/1 defines none of them, and a
//! body containing one is `ERR_MALFORMED` rather than something to be interpreted. That is why
//! this reader is a few hundred lines rather than a cbOR library.

use core::fmt;

/// The cbOR major types (RFC 8949 §3.1).
///
/// DLWP/1 uses major types 0 through 5 only. Tags (6) and simple/float values (7) are rejected
/// outright, because the protocol defines no floating-point field and no tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MajorType {
    /// Unsigned integer.
    UnsignedInteger = 0,
    /// Negative integer.
    NegativeInteger = 1,
    /// Byte string.
    ByteString = 2,
    /// UTF-8 text string.
    TextString = 3,
    /// Array.
    Array = 4,
    /// Map.
    Map = 5,
    /// Tag. Not used by DLWP/1; rejected.
    Tag = 6,
    /// Simple value or float. Not used by DLWP/1; rejected.
    SimpleOrFloat = 7,
}

/// Why a cbOR item was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborErrorKind {
    /// The input ended before the item was complete.
    Truncated,
    /// An indefinite-length item was used, which DLWP/1 forbids.
    IndefiniteLength,
    /// An integer was encoded in more bytes than its value requires.
    NonShortestInteger,
    /// A tag appeared, which DLWP/1 forbids.
    TagNotAllowed,
    /// A floating-point value appeared, which DLWP/1 forbids.
    FloatNotAllowed,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// A string or collection declared more elements than are present.
    LengthMismatch,
    /// Seconds, halves and other unspecified simple values.
    UnsupportedSimpleValue,
    /// The map key ordering or type did not match the message schema.
    SchemaViolation,
    /// A required key was absent.
    MissingRequiredKey,
    /// A key's value had the wrong cbOR type.
    WrongValueType,
    /// A fixed-width field had the wrong width.
    WrongWidth,
    /// Trailing bytes followed the top-level item.
    TrailingBytes,
}

/// A cbOR decoding failure.
///
/// Every variant maps to `ERR_MALFORMED`, which RFC-0001 §6.2 registers as fatal. The mapping
/// lives in [`CborError::code`] rather than at each call site so it cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborError {
    /// The decoding defect class.
    pub kind: CborErrorKind,
    /// A static description for the log. Static rather than formatted because this type is `Copy`
    /// and lives in a `Result`, and a body that fails to parse should not allocate.
    pub message: &'static str,
    /// The byte offset within the body where the defect was found.
    pub offset: usize,
}

impl CborError {
    /// The DLWP/1 error code for this defect.
    ///
    /// Always `ERR_MALFORMED`, stated once here rather than inferred at every call site.
    #[must_use]
    pub const fn code(self) -> crate::error::ErrorCode {
        crate::error::ErrorCode::Malformed
    }

    /// Builds an error.
    ///
    /// Public because the conformance tests construct one to check the `ERR_MALFORMED` mapping,
    /// and because a caller reading a registry-provided body may need to report a defect the reader
    /// did not find on its own.
    #[must_use]
    pub const fn new(kind: CborErrorKind, message: &'static str, offset: usize) -> Self {
        Self {
            kind,
            message,
            offset,
        }
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cbOR {:?} at offset {}: {}",
            self.kind, self.offset, self.message
        )
    }
}

impl core::error::Error for CborError {}

/// A value DLWP/1 can carry in a body.
///
/// Deliberately narrower than cbOR. A value this enum cannot represent is a value DLWP/1 does not
/// have, and the reader refuses to produce one rather than inventing a representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An unsigned integer. DLWP/1's only numeric type.
    Unsigned(u64),
    /// A negative integer, held as the magnitude so `-1` is `Negative(0)`.
    ///
    /// The reader can produce one but no DLWP/1 message uses one; it exists so that a body
    /// containing one is *representable* and therefore checkable, rather than being a special
    /// case in the parser.
    Negative(u64),
    /// A byte string.
    ByteString(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// An array.
    Array(Vec<Value>),
    /// A map, in the order the bytes gave it.
    ///
    /// Order is preserved rather than sorted. DLWP/1 requires a specific key order for *encoding*
    /// so that the byte vectors are unique, but a receiver must accept any order, so collapsing
    /// the distinction here would throw away information a test needs.
    Map(Vec<(Value, Value)>),
}

impl Value {
    /// The unsigned integer, if this is one.
    #[must_use]
    pub const fn as_unsigned(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            _ => None,
        }
    }

    /// The text, if this is a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    /// The bytes, if this is a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::ByteString(value) => Some(value),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The pairs, if this is a map.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(Self, Self)]> {
        match self {
            Self::Map(pairs) => Some(pairs),
            _ => None,
        }
    }

    /// A map's value for a text key, searched by key.
    ///
    /// Linear rather than hashed because DLWP/1 bodies have a handful of keys and the allocation a
    /// hash map needs is not worth it on a path that runs per frame.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_map()?
            .iter()
            .find(|(candidate, _)| candidate.as_text() == Some(key))
            .map(|(_, value)| value)
    }

    /// The cbOR encoding of this value, in shortest form.
    ///
    /// # Errors
    ///
    /// When a text key or string is longer than `u32::MAX`, which cannot occur in a DLWP/1 body
    /// and is checked rather than truncated.
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Appends this value's cbOR encoding to `out`.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        match self {
            Self::Unsigned(value) => write_head(out, MajorType::UnsignedInteger, *value)?,
            Self::Negative(magnitude) => write_head(out, MajorType::NegativeInteger, *magnitude)?,
            Self::ByteString(bytes) => {
                write_head(out, MajorType::ByteString, bytes.len() as u64)?;
                out.extend_from_slice(bytes);
            }
            Self::Text(text) => {
                write_head(out, MajorType::TextString, text.len() as u64)?;
                out.extend_from_slice(text.as_bytes());
            }
            Self::Array(items) => {
                write_head(out, MajorType::Array, items.len() as u64)?;

                for item in items {
                    item.encode_into(out)?;
                }
            }
            Self::Map(pairs) => {
                write_head(out, MajorType::Map, pairs.len() as u64)?;

                for (key, value) in pairs {
                    key.encode_into(out)?;
                    value.encode_into(out)?;
                }
            }
        }

        Ok(())
    }
}

/// Writes a cbOR head (initial byte plus argument) in shortest form.
///
/// # Errors
///
/// When `argument` needs nine or more bytes, which cbOR cannot express.
pub(crate) fn write_head(
    out: &mut Vec<u8>,
    major: MajorType,
    argument: u64,
) -> Result<(), CborError> {
    let major_bits = (major as u8) << 5;

    // Shortest form, in the same order the reader's checks expect, so a value this function
    // produces is always one the reader accepts.
    if argument < 24 {
        out.push(major_bits | u8::try_from(argument).unwrap_or(23));
    } else if argument <= u64::from(u8::MAX) {
        out.push(major_bits | 24);
        out.push(u8::try_from(argument).unwrap_or(u8::MAX));
    } else if argument <= u64::from(u16::MAX) {
        out.push(major_bits | 25);

        let bytes = u16::try_from(argument).unwrap_or(u16::MAX).to_be_bytes();

        out.extend_from_slice(&bytes);
    } else if argument <= u64::from(u32::MAX) {
        out.push(major_bits | 26);

        let bytes = u32::try_from(argument).unwrap_or(u32::MAX).to_be_bytes();

        out.extend_from_slice(&bytes);
    } else {
        out.push(major_bits | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }

    Ok(())
}

/// The deepest nesting this reader will follow.
///
/// The protocol's deepest real body is a few levels. This bound only ever trips on a hostile input
/// designed to exhaust the stack, and it is a bound on the *reader's* recursion rather than a
/// protocol limit.
pub const MAX_DEPTH: usize = 32;

/// Reads DLWP/1 body values.
///
/// Borrowing rather than consuming, so a caller can keep the body.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over a body buffer.
    #[must_use]
    pub const fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    /// Whether every byte has been consumed.
    #[must_use]
    pub const fn is_at_end(&self) -> bool {
        self.offset >= self.buffer.len()
    }

    /// The current read offset, for diagnostics.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// How many bytes remain unread.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
    }

    /// The major type of the next item, without consuming it.
    #[must_use]
    pub fn peek_major_type(&self) -> Option<MajorType> {
        self.buffer
            .get(self.offset)
            .map(|initial| major_of(initial >> 5))
    }

    /// Reads the whole body as a single item and requires that nothing follows.
    ///
    /// # Errors
    ///
    /// * Any decoding failure.
    /// * [`CborErrorKind::TrailingBytes`] when bytes follow the top-level item. Trailing bytes are
    ///   an error rather than padding: a body with slack would let two byte sequences decode to
    ///   the same message, which breaks the uniqueness the vectors depend on.
    pub fn read_document(&mut self) -> Result<Value, CborError> {
        let value = self.read_value(0)?;
        self.require_end()?;
        Ok(value)
    }

    /// Fails when bytes remain.
    ///
    /// # Errors
    ///
    /// [`CborErrorKind::TrailingBytes`] when the buffer is not fully consumed.
    pub fn require_end(&self) -> Result<(), CborError> {
        if self.is_at_end() {
            Ok(())
        } else {
            Err(CborError::new(
                CborErrorKind::TrailingBytes,
                "trailing bytes after the top-level item",
                self.offset,
            ))
        }
    }

    /// Reads one item of any supported type.
    ///
    /// # Errors
    ///
    /// Any decoding failure, including a nesting depth beyond [`MAX_DEPTH`].
    pub fn read_value(&mut self, depth: usize) -> Result<Value, CborError> {
        // Checked on entry, so a hostile body is refused before the next frame is pushed rather
        // than after the stack has already grown.
        if depth > MAX_DEPTH {
            return Err(CborError::new(
                CborErrorKind::SchemaViolation,
                "cbOR nesting exceeded the depth limit",
                self.offset,
            ));
        }

        let start = self.offset;
        let (major, argument) = self.read_head()?;

        match major {
            MajorType::UnsignedInteger => Ok(Value::Unsigned(argument)),
            MajorType::NegativeInteger => Ok(Value::Negative(argument)),
            MajorType::ByteString => Ok(Value::ByteString(self.take(argument, start)?.to_vec())),
            MajorType::TextString => {
                let bytes = self.take(argument, start)?;

                match core::str::from_utf8(bytes) {
                    Ok(text) => Ok(Value::Text(text.to_owned())),
                    Err(_) => Err(CborError::new(
                        CborErrorKind::InvalidUtf8,
                        "text string is not valid UTF-8",
                        start,
                    )),
                }
            }
            MajorType::Array => {
                let count = usize::try_from(argument).map_err(|_| {
                    CborError::new(CborErrorKind::LengthMismatch, "array is too long", start)
                })?;

                // A count larger than the remaining bytes cannot be satisfied: every cbOR item is
                // at least one byte. Checking it here turns a hostile count into a refusal rather
                // than a `Vec::with_capacity` that allocates gigabytes.
                if count > self.remaining() {
                    return Err(CborError::new(
                        CborErrorKind::LengthMismatch,
                        "array declares more elements than there are bytes",
                        start,
                    ));
                }

                let mut items = Vec::with_capacity(count);

                for _ in 0..count {
                    items.push(self.read_value(depth.saturating_add(1))?);
                }

                Ok(Value::Array(items))
            }
            MajorType::Map => {
                let count = usize::try_from(argument).map_err(|_| {
                    CborError::new(CborErrorKind::LengthMismatch, "map is too long", start)
                })?;

                // Two items per pair, so the same bound is twice as strict.
                let needed = count.saturating_mul(2);

                if needed > self.remaining() {
                    return Err(CborError::new(
                        CborErrorKind::LengthMismatch,
                        "map declares more pairs than there are bytes",
                        start,
                    ));
                }

                let mut pairs = Vec::with_capacity(count);

                for _ in 0..count {
                    let key = self.read_value(depth.saturating_add(1))?;
                    let value = self.read_value(depth.saturating_add(1))?;

                    pairs.push((key, value));
                }

                Ok(Value::Map(pairs))
            }
            MajorType::Tag => Err(CborError::new(
                CborErrorKind::TagNotAllowed,
                "cbOR tags are not permitted in DLWP/1",
                start,
            )),
            MajorType::SimpleOrFloat => Err(CborError::new(
                CborErrorKind::FloatNotAllowed,
                "cbOR simple and float values are not permitted in DLWP/1",
                start,
            )),
        }
    }

    /// Reads a head, enforcing the shortest-form rule.
    fn read_head(&mut self) -> Result<(MajorType, u64), CborError> {
        let start = self.offset;

        let initial = *self.buffer.get(self.offset).ok_or_else(|| {
            CborError::new(
                CborErrorKind::Truncated,
                "expected an item but the body ended",
                self.offset,
            )
        })?;

        self.offset = self.offset.saturating_add(1);

        let major = major_of(initial >> 5);
        let additional = initial & 0x1F;

        match additional {
            inline @ 0..=23 => Ok((major, u64::from(inline))),
            24 => {
                let value = u64::from(self.read_u8(start)?);

                // Shortest form: a value below 24 must use the inline form. Rejecting this is what
                // makes the vectors' bytes unique -- `0x1817` and `0x17` are the same number and
                // only one of them is DLWP/1.
                if value < 24 {
                    Err(CborError::new(
                        CborErrorKind::NonShortestInteger,
                        "integer below 24 was encoded in one byte",
                        start,
                    ))
                } else {
                    Ok((major, value))
                }
            }
            25 => {
                let value = u64::from(self.read_u16(start)?);

                if value <= u64::from(u8::MAX) {
                    Err(CborError::new(
                        CborErrorKind::NonShortestInteger,
                        "integer below 256 was encoded in two bytes",
                        start,
                    ))
                } else {
                    Ok((major, value))
                }
            }
            26 => {
                let value = u64::from(self.read_u32(start)?);

                if value <= u64::from(u16::MAX) {
                    Err(CborError::new(
                        CborErrorKind::NonShortestInteger,
                        "integer below 65536 was encoded in four bytes",
                        start,
                    ))
                } else {
                    Ok((major, value))
                }
            }
            27 => {
                let value = self.read_u64(start)?;

                if value <= u64::from(u32::MAX) {
                    Err(CborError::new(
                        CborErrorKind::NonShortestInteger,
                        "integer below 2^32 was encoded in eight bytes",
                        start,
                    ))
                } else {
                    Ok((major, value))
                }
            }
            31 => Err(CborError::new(
                CborErrorKind::IndefiniteLength,
                "indefinite-length items are not permitted in DLWP/1",
                start,
            )),
            _ => Err(CborError::new(
                CborErrorKind::UnsupportedSimpleValue,
                "reserved additional-information value",
                start,
            )),
        }
    }

    /// Takes `count` bytes, or reports how short the buffer was.
    fn take(&mut self, count: u64, start: usize) -> Result<&'a [u8], CborError> {
        let count = usize::try_from(count).map_err(|_| {
            CborError::new(
                CborErrorKind::LengthMismatch,
                "length does not fit this platform",
                start,
            )
        })?;

        let end = self.offset.checked_add(count).ok_or_else(|| {
            CborError::new(
                CborErrorKind::LengthMismatch,
                "length overflows the offset",
                start,
            )
        })?;

        let slice = self.buffer.get(self.offset..end).ok_or_else(|| {
            CborError::new(
                CborErrorKind::LengthMismatch,
                "item declares more bytes than remain",
                start,
            )
        })?;

        self.offset = end;

        Ok(slice)
    }

    /// Reads one byte.
    fn read_u8(&mut self, start: usize) -> Result<u8, CborError> {
        let byte = *self.buffer.get(self.offset).ok_or_else(|| {
            CborError::new(CborErrorKind::Truncated, "expected one more byte", start)
        })?;

        self.offset = self.offset.saturating_add(1);

        Ok(byte)
    }

    /// Reads two big-endian bytes.
    fn read_u16(&mut self, start: usize) -> Result<u16, CborError> {
        let bytes = self.take(2, start)?;

        match <[u8; 2]>::try_from(bytes) {
            Ok(array) => Ok(u16::from_be_bytes(array)),
            Err(_) => Err(CborError::new(
                CborErrorKind::Truncated,
                "expected two more bytes",
                start,
            )),
        }
    }

    /// Reads four big-endian bytes.
    fn read_u32(&mut self, start: usize) -> Result<u32, CborError> {
        let bytes = self.take(4, start)?;

        match <[u8; 4]>::try_from(bytes) {
            Ok(array) => Ok(u32::from_be_bytes(array)),
            Err(_) => Err(CborError::new(
                CborErrorKind::Truncated,
                "expected four more bytes",
                start,
            )),
        }
    }

    /// Reads eight big-endian bytes.
    fn read_u64(&mut self, start: usize) -> Result<u64, CborError> {
        let bytes = self.take(8, start)?;

        match <[u8; 8]>::try_from(bytes) {
            Ok(array) => Ok(u64::from_be_bytes(array)),
            Err(_) => Err(CborError::new(
                CborErrorKind::Truncated,
                "expected eight more bytes",
                start,
            )),
        }
    }
}

/// The major type from the top three bits of an initial byte.
const fn major_of(bits: u8) -> MajorType {
    match bits {
        0 => MajorType::UnsignedInteger,
        1 => MajorType::NegativeInteger,
        2 => MajorType::ByteString,
        3 => MajorType::TextString,
        4 => MajorType::Array,
        5 => MajorType::Map,
        6 => MajorType::Tag,
        _ => MajorType::SimpleOrFloat,
    }
}

/// Whether a body is a well-formed DLWP/1 cbOR map.
///
/// This is the check `FrameClassifier` needs and nothing more: it answers *can this body be read
/// at all*, not *does this body mean the right thing*. The distinction matters because an
/// encrypted body is `nonce || ciphertext || tag`, so well-formedness is only checkable on a
/// **plaintext** body -- a caller must have established that before calling this.
#[must_use]
pub fn is_well_formed_map(body: &[u8]) -> bool {
    // The empty body is canonical for a message with no parameters, and a receiver must also
    // accept `0xA0`. Both are well-formed; anything else must parse as a map.
    if body.is_empty() {
        return true;
    }

    let mut reader = Reader::new(body);

    matches!(reader.read_document(), Ok(Value::Map(_)))
}

/// Parses a body as a map.
///
/// # Errors
///
/// Any decoding failure, or a top-level item that is not a map. The empty body and `0xA0` both
/// parse to an empty map, because DLWP/1 treats them as equivalent.
pub fn parse_map(body: &[u8]) -> Result<Vec<(Value, Value)>, CborError> {
    if body.is_empty() {
        return Ok(Vec::new());
    }

    let mut reader = Reader::new(body);

    match reader.read_document()? {
        Value::Map(pairs) => Ok(pairs),
        _other => Err(CborError::new(
            CborErrorKind::WrongValueType,
            "a DLWP/1 body must be a map, or empty",
            reader.offset(),
        )),
    }
}
