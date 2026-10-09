//! Version negotiation.
//!
//! The rule is `highest_common_version_or_fail`, and the vectors are careful about three things that
//! separate a correct implementation from a plausible one:
//!
//!   * **Versions compare NUMERICALLY, not lexically.** `"1.10"` is newer than `"1.9"`, and a string
//!     comparison would order them the other way. This is the classic bug in version handling and it
//!     does not appear in the vectors' own data — every version in the file has a single-digit minor —
//!     so the tests construct the case rather than relying on the fixtures to carry it.
//!
//!   * **The list is most-preferred-first on both sides, but the answer is the highest common version.**
//!     `version.both-newer-and-older` has the controller offering `[2.0, 1.1, 1.0]` and the agent
//!     `[1.1, 1.0]`, and the answer is `1.1` — "not the controller's first preference of 2.0". So the
//!     result is NOT the first entry of the first list that the other also contains; it is the maximum
//!     of the intersection.
//!
//!   * **No silent downgrade in either direction.** `version.agent-does-not-downgrade-silently`: the
//!     controller offers only `9.9`, so the agent must refuse "rather than assuming the controller meant
//!     the version it supports". And `version.controller-does-not-downgrade-silently`: the agent answers
//!     with a version the controller never offered, which is "a protocol violation by the agent", so the
//!     controller aborts rather than continuing with an unrequested version.
//!
//! The frame header's `Version` field carries the **major** number only — 1 for every 1.x release — and
//! the full string travels in the `HELLO` body. So a receiver checks the header field first and the body
//! string second, and that order is what lets minor versions be added without changing the frame layout.

/// A parsed protocol version, `major.minor`.
///
/// Stored as two integers rather than a string, so the comparison cannot accidentally be lexical. The
/// parsing is strict: the vectors only ever write `major.minor`, and accepting more shapes than the
/// protocol defines would let two implementations disagree about what a version string means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// The major number. A change here is a breaking wire change.
    pub major: u32,
    /// The minor number. A change here is additive.
    pub minor: u32,
}

impl Version {
    /// Creates a version.
    #[must_use]
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// The DLWP/1 version this crate implements.
    pub const V1_0: Self = Self::new(1, 0);

    /// Parses `major.minor`.
    ///
    /// # Errors
    ///
    /// [`VersionError::NotANumber`] for a component that is not decimal digits, or
    /// [`VersionError::WrongShape`] for anything other than exactly one dot with both sides present.
    pub fn parse(text: &str) -> Result<Self, VersionError> {
        // Exactly one dot, with both sides non-empty. `split_once` plus a check for a second dot is the
        // shape check; `1.` and `.1` and `1.2.3` all fail.
        let Some((major, minor)) = text.split_once('.') else {
            return Err(VersionError::WrongShape);
        };

        if minor.contains('.') {
            return Err(VersionError::WrongShape);
        }

        if major.is_empty() || minor.is_empty() {
            return Err(VersionError::WrongShape);
        }

        Ok(Self {
            major: parse_component(major)?,
            minor: parse_component(minor)?,
        })
    }

    /// The wire form, `major.minor`.
    #[must_use]
    pub fn to_wire_string(self) -> String {
        format!("{}.{}", self.major, self.minor)
    }

    /// Whether this version is compatible with another, meaning they share a major number.
    ///
    /// Minor versions are additive, so any two 1.x peers can talk. A different major cannot, which is
    /// what the header's `Version` field is for.
    #[must_use]
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }

    /// The major number, as the header's `Version` field carries it.
    #[must_use]
    pub const fn header_version_field(self) -> u8 {
        // The field is one byte. A major above 255 cannot be represented, and truncating it would
        // silently advertise a different version, so this saturates rather than wrapping -- a receiver
        // would then see 255 and refuse, which is the safe direction.
        if self.major > 255 {
            255
        } else {
            self.major as u8
        }
    }
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Why a version string could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    /// Not exactly one dot with both sides present.
    WrongShape,
    /// A component was not decimal digits.
    NotANumber,
}

impl core::fmt::Display for VersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongShape => write!(f, "a version is exactly one dot with both sides present"),
            Self::NotANumber => write!(f, "a version component must be decimal digits"),
        }
    }
}

impl core::error::Error for VersionError {}

/// Parses one component, refusing signs, whitespace and non-digits.
fn parse_component(text: &str) -> Result<u32, VersionError> {
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(VersionError::NotANumber);
    }

    text.parse::<u32>().map_err(|_| VersionError::NotANumber)
}

/// What version negotiation concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negotiation {
    /// Both sides agreed on a version.
    Agreed(Version),
    /// There is no common version.
    NoCommonVersion,
}

impl Negotiation {
    /// The agreed version, or `None`.
    #[must_use]
    pub const fn version(self) -> Option<Version> {
        match self {
            Self::Agreed(version) => Some(version),
            Self::NoCommonVersion => None,
        }
    }

    /// Whether the sides agreed.
    #[must_use]
    pub const fn is_agreed(self) -> bool {
        matches!(self, Self::Agreed(_))
    }
}

/// Negotiates the version: the **highest** version both sides support.
///
/// Not the first entry of either list. `version.both-newer-and-older` is the vector that pins it: the
/// controller's own first preference is 2.0 and the agent's is 1.1, and the answer is 1.1.
///
/// The comparison is numeric ([`Version`]'s derived `Ord`), so `1.10` beats `1.9`.
#[must_use]
pub fn negotiate_versions(controller: &[Version], agent: &[Version]) -> Negotiation {
    // The maximum of the intersection. `filter` then `max` is the whole rule, and writing it this way
    // rather than as a scan of the controller's list is what makes the answer independent of the input
    // order -- which is the property the vector is about.
    let agreed = controller
        .iter()
        .filter(|version| agent.contains(version))
        .max()
        .copied();

    match agreed {
        Some(version) => Negotiation::Agreed(version),
        None => Negotiation::NoCommonVersion,
    }
}

/// Whether an agent's answer is one the controller offered.
///
/// `version.controller-does-not-downgrade-silently`: the agent answers with a version the controller
/// never offered, and "the controller must abort rather than continue with an unrequested version".
///
/// A separate function because it is a different question from negotiation: the agent may have agreed
/// to something reasonable from its own point of view while answering with something the controller
/// cannot honour.
#[must_use]
pub fn is_a_valid_answer(controller_offered: &[Version], agreed: Version) -> bool {
    controller_offered.contains(&agreed)
}

/// Whether a change kind is additive, and therefore must NOT bump the version.
///
/// `version.additive-change-is-not-a-major-bump`: adding a frame type, a capability name or an optional
/// body key is additive, and "an old peer must continue to work by ignoring what it does not know."
///
/// The rule matters because the alternative is a version bump for every new capability, which would
/// fragment the ecosystem: an old peer would refuse a new one rather than ignoring what it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// A new message type.
    AddMessageType,
    /// A new capability name.
    AddCapability,
    /// A new optional body key.
    AddOptionalKey,
    /// A change to an existing field's meaning.
    ChangeFieldMeaning,
    /// A removed field.
    RemoveField,
    /// A changed default that breaks an old peer.
    ChangeDefault,
}

impl ChangeKind {
    /// Whether this change is additive, and so requires no version bump.
    #[must_use]
    pub const fn is_additive(self) -> bool {
        matches!(
            self,
            Self::AddMessageType | Self::AddCapability | Self::AddOptionalKey
        )
    }

    /// Whether this change requires a new major version and an RFC.
    #[must_use]
    pub const fn requires_version_bump(self) -> bool {
        !self.is_additive()
    }
}

/// Checks the frame header's `Version` field against the version the body's string claims.
///
/// The header carries the **major** only and the full version travels in the `HELLO` body, so a receiver
/// checks the field first and the string second. `version.major-only-in-version-field` is the vector:
/// the field is 1 and the string is `1.1`.
///
/// Returns the refusal reason when they disagree, and `None` when they are consistent.
///
/// A minor string with a major-1 header is FINE — that is the whole point of the field carrying only the
/// major. A mismatched major is not.
#[must_use]
pub fn check_header_against_body(
    header_version_field: u8,
    body_version: Version,
) -> Option<HeaderBodyMismatch> {
    if header_version_field != body_version.header_version_field() {
        return Some(HeaderBodyMismatch {
            header: header_version_field,
            body_major: body_version.major,
        });
    }

    None
}

/// The header's `Version` field disagrees with the body's version string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderBodyMismatch {
    /// The header's field.
    pub header: u8,
    /// The body string's major number.
    pub body_major: u32,
}

/// Whether a `change_kind` string names an additive change.
///
/// The vectors use a compound name for the additive case, `add_capability_and_message_type`, so this
/// looks for the leading verb rather than requiring an exact match. A name that names no known verb is
/// `None` rather than a guess: an unclassifiable change must not be silently treated as additive, since
/// that is the direction that breaks peers.
#[must_use]
pub fn classify_change(change_kind: &str) -> Option<ChangeKind> {
    if change_kind.starts_with("add_message_type") || change_kind == "add_message_type" {
        return Some(ChangeKind::AddMessageType);
    }

    if change_kind.starts_with("add_capability") {
        return Some(ChangeKind::AddCapability);
    }

    if change_kind.starts_with("add_optional_key") || change_kind.starts_with("add_key") {
        return Some(ChangeKind::AddOptionalKey);
    }

    if change_kind.starts_with("change_default") {
        return Some(ChangeKind::ChangeDefault);
    }

    if change_kind.starts_with("change_field") || change_kind.starts_with("change_meaning") {
        return Some(ChangeKind::ChangeFieldMeaning);
    }

    if change_kind.starts_with("remove_") {
        return Some(ChangeKind::RemoveField);
    }

    None
}
