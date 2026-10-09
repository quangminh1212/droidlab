//! Loading the conformance vectors from `protocol/vectors/`.
//!
//! The vectors are the interoperability contract (ADR-0007), so the tests must read the **real
//! files** rather than a copy. A test that asserts a transcribed constant proves only that the
//! transcription was typed twice.
//!
//! The path is resolved from `CARGO_MANIFEST_DIR` rather than from the working directory, so the
//! tests behave the same whether they are run from the workspace root, from this crate, or from
//! an IDE.

#![allow(dead_code)]

use serde_json::Value;
use std::path::{Path, PathBuf};

/// The repository's `protocol/vectors` directory.
///
/// Walks up from this crate's manifest directory to the workspace root. The walk is bounded
/// rather than unbounded so a mis-set manifest directory fails loudly instead of looping.
#[must_use]
pub fn vectors_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));

    // crates/droidlab-protocol -> crates -> rust -> <repo root>
    let root = manifest
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("crate manifest directory has no grandparent: {manifest:?}"));

    root.join("protocol").join("vectors")
}

/// Loads a vector file by name, e.g. `"framing-basic.json"`.
///
/// # Panics
///
/// When the file is missing or is not valid JSON. Both are failures of the repository rather than
/// of the code under test, and a test that cannot load its vector must fail rather than silently
/// check nothing.
#[must_use]
pub fn load(file: &str) -> Value {
    let path = vectors_dir().join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

/// The vector file this crate's framing test drives.
pub const FRAMING_BASIC: &str = "framing-basic.json";

/// Decodes a hex string from a vector.
///
/// # Panics
///
/// When the string is not valid hex, which would be a defect in the vector file rather than in
/// the code under test.
#[must_use]
pub fn hex(value: &str) -> Vec<u8> {
    hex_decode(value).unwrap_or_else(|| panic!("vector field is not valid hex: {value:?}"))
}

/// Decodes hex, returning `None` rather than panicking.
#[must_use]
pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }

    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);

    for pair in bytes.chunks_exact(2) {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        out.push((high << 4) | low);
    }

    Some(out)
}

/// The value of a hex digit, or `None`.
///
/// The digits are given as literal values rather than as offsets from `b'0'`, because this crate
/// is built with the overflow lint on and an offset then an addition states its range in two
/// places. A table states it once and reads the same either way.
fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0' => Some(0),
        b'1' => Some(1),
        b'2' => Some(2),
        b'3' => Some(3),
        b'4' => Some(4),
        b'5' => Some(5),
        b'6' => Some(6),
        b'7' => Some(7),
        b'8' => Some(8),
        b'9' => Some(9),
        b'a' | b'A' => Some(10),
        b'b' | b'B' => Some(11),
        b'c' | b'C' => Some(12),
        b'd' | b'D' => Some(13),
        b'e' | b'E' => Some(14),
        b'f' | b'F' => Some(15),
        _ => None,
    }
}

/// Encodes bytes as lowercase hex, for an assertion's message.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));

    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('?'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('?'));
    }

    out
}

/// The `vectors` array of a file, failing loudly when it is absent.
///
/// # Panics
///
/// When the file has no `vectors` array. A test that iterates an empty array passes while
/// checking nothing, which is the failure mode this whole harness exists to prevent.
#[must_use]
pub fn vectors(file: &str) -> Vec<Value> {
    let document = load(file);

    document
        .get("vectors")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{file} has no `vectors` array"))
        .clone()
}

/// A named field of a vector object.
///
/// # Panics
///
/// When the field is missing. Asserted explicitly so a renamed vector field fails here, with the
/// field's name in the message, rather than deep inside an assertion that reports `None`.
#[must_use]
pub fn field<'a>(vector: &'a Value, name: &str) -> &'a Value {
    vector.get(name).unwrap_or_else(|| {
        panic!(
            "vector {:?} has no field {name:?}; it has: {:?}",
            vector.get("id").and_then(Value::as_str).unwrap_or("?"),
            vector
                .as_object()
                .map(|object| object.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        )
    })
}

/// The `id` of a vector, for assertion messages.
#[must_use]
pub fn id(vector: &Value) -> &str {
    vector
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed vector>")
}

/// An unsigned integer field, as `u64`.
#[must_use]
pub fn u64_field(vector: &Value, name: &str) -> u64 {
    field(vector, name).as_u64().unwrap_or_else(|| {
        panic!(
            "vector {:?} field {name:?} is not an unsigned integer",
            id(vector)
        )
    })
}

/// An unsigned integer field narrowed to `u32`, failing when it does not fit.
#[must_use]
pub fn u32_field(vector: &Value, name: &str) -> u32 {
    let value = u64_field(vector, name);

    u32::try_from(value).unwrap_or_else(|_| {
        panic!(
            "vector {:?} field {name:?} is {value}, which does not fit a u32",
            id(vector)
        )
    })
}

/// An unsigned integer field narrowed to `u8`, failing when it does not fit.
#[must_use]
pub fn u8_field(vector: &Value, name: &str) -> u8 {
    let value = u64_field(vector, name);

    u8::try_from(value).unwrap_or_else(|_| {
        panic!(
            "vector {:?} field {name:?} is {value}, which does not fit a u8",
            id(vector)
        )
    })
}

/// A string field.
#[must_use]
pub fn str_field<'a>(vector: &'a Value, name: &str) -> &'a str {
    field(vector, name)
        .as_str()
        .unwrap_or_else(|| panic!("vector {:?} field {name:?} is not a string", id(vector)))
}

/// A field of a nested object.
#[must_use]
pub fn nested<'a>(object: &'a Value, name: &str) -> &'a Value {
    object
        .get(name)
        .unwrap_or_else(|| panic!("object has no field {name:?}"))
}

/// Loads `protocol/registry/dlwp-1.json`.
///
/// The registry is not a vector file, but it is the authority several vector files defer to, so tests
/// read it directly rather than transcribing it. A transcription checked only against itself drifts.
pub fn load_registry() -> serde_json::Value {
    let path = vectors_dir()
        .parent()
        .expect("the vectors directory has a parent")
        .join("registry")
        .join("dlwp-1.json");

    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}
