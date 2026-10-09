//! The deterministic seed rule, and the key material it produces.
//!
//! RFC-0002 section 4.2 defines one function used everywhere test material is needed:
//!
//! ```text
//! key(seed) = SHA-256("DLWP/1-test-key" || 0x00 || seed)
//! ```
//!
//! It exists so that the conformance vectors contain **no literal key bytes**. Every secret in
//! `crypto-primitives.json` and `crypto-session-keys.json` is produced by this formula from a short
//! readable seed, which is what makes the files auditable: a reader can reproduce any key in the file
//! rather than trusting a hex blob, and there is no copy-paste step that could have introduced a
//! wrong byte.
//!
//! The `0x00` separator is the same domain-separation trick as the labels: it stops a seed that ends
//! in a byte sequence resembling a label suffix from colliding with a different seed.

use sha2::{Digest, Sha256};

/// The ASCII prefix of the seed rule, `"DLWP/1-test-key"`.
pub const SEED_PREFIX: &str = "DLWP/1-test-key";

/// The domain separator between the prefix and the seed.
pub const SEED_SEPARATOR: u8 = 0x00;

/// Derives 32 bytes of test key material from a readable seed.
///
/// Not a KDF and not used by a shipped build: it is a **naming convention with a hash behind it**, so
/// that a vector file can say `seed = "droidlab-test-seed-01"` instead of carrying 64 hex digits the
/// reader cannot check. The tests note this explicitly, because a helper that looks like a key
/// derivation and is not one is exactly the kind of thing a reader should be suspicious of.
#[must_use]
pub fn key_from_seed(seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEED_PREFIX.as_bytes());
    hasher.update([SEED_SEPARATOR]);
    hasher.update(seed);

    hasher.finalize().into()
}

/// Derives a seed's 32 bytes and returns them as lowercase hex.
#[must_use]
pub fn seed_hex(seed: &str) -> String {
    to_hex(&key_from_seed(seed.as_bytes()))
}

/// Renders bytes as lowercase hex.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len().saturating_mul(2));

    for byte in bytes {
        let high = DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let low = DIGITS
            .get(usize::from(byte & 0x0F))
            .copied()
            .unwrap_or(b'0');

        out.push(char::from(high));
        out.push(char::from(low));
    }

    out
}

/// Parses lowercase or uppercase hex into bytes.
///
/// # Errors
///
/// [`HexError`] when the string has an odd length or a character that is not a hex digit. A lenient
/// parser that skipped a bad character would turn a malformed vector into a silently shorter key.
pub fn from_hex(text: &str) -> Result<Vec<u8>, HexError> {
    let digits: Vec<u8> = text.bytes().collect();

    if digits.len() % 2 != 0 {
        return Err(HexError::OddLength {
            length: digits.len(),
        });
    }

    let mut out = Vec::with_capacity(digits.len() / 2);
    let mut index = 0;

    while index < digits.len() {
        let high = digits.get(index).copied().ok_or(HexError::OddLength {
            length: digits.len(),
        })?;
        let low = digits
            .get(index.saturating_add(1))
            .copied()
            .ok_or(HexError::OddLength {
                length: digits.len(),
            })?;

        let high = nibble(high)?;
        let low = nibble(low)?;

        out.push((high << 4) | low);
        index = index.saturating_add(2);
    }

    Ok(out)
}

/// The value of one hex digit.
///
/// A literal table rather than arithmetic on the character codes, so that `b'9' + 1` is not treated
/// as a digit and `b'@'` is not accepted by an off-by-one in a subtraction.
fn nibble(byte: u8) -> Result<u8, HexError> {
    const TABLE: [(u8, i8); 22] = [
        (b'0', 0),
        (b'1', 1),
        (b'2', 2),
        (b'3', 3),
        (b'4', 4),
        (b'5', 5),
        (b'6', 6),
        (b'7', 7),
        (b'8', 8),
        (b'9', 9),
        (b'a', 10),
        (b'b', 11),
        (b'c', 12),
        (b'd', 13),
        (b'e', 14),
        (b'f', 15),
        (b'A', 10),
        (b'B', 11),
        (b'C', 12),
        (b'D', 13),
        (b'E', 14),
        (b'F', 15),
    ];

    TABLE
        .iter()
        .find(|(digit, _)| *digit == byte)
        .map(|(_, value)| u8::try_from(*value).unwrap_or(0))
        .ok_or(HexError::NotHexDigit { byte })
}

/// Why a hex string could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The string had an odd number of characters.
    OddLength {
        /// How many characters were present.
        length: usize,
    },
    /// A character was not a hex digit.
    NotHexDigit {
        /// The offending byte.
        byte: u8,
    },
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OddLength { length } => {
                write!(
                    f,
                    "a hex string of {length} characters has no byte boundary"
                )
            }
            Self::NotHexDigit { byte } => {
                write!(f, "byte 0x{byte:02x} is not a hex digit")
            }
        }
    }
}

impl core::error::Error for HexError {}

/// Renders bytes as URL-safe base64 without padding.
///
/// The vectors use two encodings deliberately, and the distinction is load-bearing: `base64` (with
/// padding) for opaque payloads like signature inputs, and **`base64url` unpadded** for key material,
/// nonces, identifiers and digests. An implementation that decodes with the wrong alphabet gets a
/// wrong key with no error, so the two are kept apart here rather than behind one `decode` function.
#[must_use]
pub fn to_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::new();

    for block in bytes.chunks(3) {
        let length = block.len();
        // Declared inside the loop, so the compiler can see every byte is initialised before use. A
        // hoisted `let mut chunk = [0u8; 3]` outside would be a value assigned and immediately
        // overwritten, which is what the warning was about.
        let mut chunk = [0u8; 3];

        for (index, byte) in block.iter().enumerate() {
            if let Some(slot) = chunk.get_mut(index) {
                *slot = *byte;
            }
        }

        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        // The first two 6-bit groups are always present.
        let groups = [
            b0 >> 2,
            ((b0 & 0x03) << 4) | (b1 >> 4),
            ((b1 & 0x0F) << 2) | (b2 >> 6),
            b2 & 0x3F,
        ];

        // A 3-byte block yields 4 characters, a 2-byte block 3, a 1-byte block 2. No '=' padding is
        // emitted, which is what makes the encoding unpadded.
        let count = match length {
            1 => 2,
            2 => 3,
            _ => 4,
        };

        for group in groups.iter().take(count) {
            if let Some(character) = ALPHABET.get(usize::from(*group)) {
                out.push(char::from(*character));
            }
        }
    }

    out
}

/// Parses URL-safe base64 without padding.
///
/// # Errors
///
/// [`Base64Error`] for a character outside the alphabet, or a length that cannot be a valid encoding
/// (`n mod 4 == 1`). Standard base64 with `+`/`/` or with `=` padding is rejected rather than
/// tolerated: the vectors do not use it, so accepting it would hide a caller using the wrong variant.
pub fn from_base64url(text: &str) -> Result<Vec<u8>, Base64Error> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();

    for character in text.bytes() {
        let value = base64url_value(character)?;

        accumulator = (accumulator << 6) | value;
        bits = bits.saturating_add(6);

        if bits >= 8 {
            bits = bits.saturating_sub(8);

            let shift = bits;
            let byte = u8::try_from((accumulator >> shift) & 0xFF).unwrap_or(0);

            out.push(byte);
        }
    }

    // A remainder of 6 unused bits is a valid tail (one byte); 0 bits is exact. Anything else means
    // the input was truncated, and the message names which case it was.
    match bits {
        0 | 2 | 4 => Ok(out),
        _ => Err(Base64Error::InvalidLength { length: text.len() }),
    }
}

/// The value of one base64url character.
fn base64url_value(byte: u8) -> Result<u32, Base64Error> {
    let value = match byte {
        b'A'..=b'Z' => u32::from(byte).saturating_sub(u32::from(b'A')),
        b'a'..=b'z' => u32::from(byte)
            .saturating_sub(u32::from(b'a'))
            .saturating_add(26),
        b'0'..=b'9' => u32::from(byte)
            .saturating_sub(u32::from(b'0'))
            .saturating_add(52),
        b'-' => 62,
        b'_' => 63,
        _ => return Err(Base64Error::NotInAlphabet { byte }),
    };

    Ok(value)
}

/// Why a base64url string could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// A character is not in the URL-safe alphabet.
    NotInAlphabet {
        /// The offending byte.
        byte: u8,
    },
    /// The length cannot be a valid unpadded encoding.
    InvalidLength {
        /// How many characters were present.
        length: usize,
    },
}

impl core::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInAlphabet { byte } => {
                write!(
                    f,
                    "byte 0x{byte:02x} is outside the URL-safe base64 alphabet"
                )
            }
            Self::InvalidLength { length } => {
                write!(f, "a {length}-character base64url string cannot decode")
            }
        }
    }
}

impl core::error::Error for Base64Error {}

/// Decodes a vector's hex-encoded 32-byte key material.
///
/// # Errors
///
/// [`HexError`] when the text is not hex, and [`HexError::OddLength`] is also the answer for a
/// length that parses but is not 32 bytes — the caller checks that separately, because a hex string
/// of the wrong length is a defect in the vector rather than in the parser.
pub fn key_from_hex(text: &str) -> Result<[u8; 32], HexError> {
    let bytes = from_hex(text)?;

    if bytes.len() != 32 {
        return Err(HexError::OddLength {
            length: bytes.len(),
        });
    }

    let mut out = [0u8; 32];

    for (slot, byte) in out.iter_mut().zip(bytes.iter()) {
        *slot = *byte;
    }

    Ok(out)
}
