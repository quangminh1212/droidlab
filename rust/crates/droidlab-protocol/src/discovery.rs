//! Service discovery: the mDNS TXT record, the beacon, and the presence lifecycle.
//!
//! Two canonicalisations live here and they are **deliberately different**, which the vectors say so
//! explicitly:
//!
//!   * The **TXT record** uses a FIXED key order — `v`, `id`, `fp`, `caps`, `port`, then the optional
//!     keys in the RFC-0003 order — joined by `0x0A`, prefixed with the label and a NUL, and with NO
//!     trailing newline. The reason for a fixed order rather than alphabetical is in the vector: "so
//!     that a reader can compare the specification, the vector and the code without consulting a sort
//!     implementation."
//!
//!   * The **beacon** uses ASCENDING key order, because the beacon "carries a JSON object, so it uses
//!     its own deterministic rule."
//!
//! Getting these two the same way round would produce a signature that verifies locally and fails
//! everywhere else, which is the worst kind of bug: it passes every test the author writes.
//!
//! The TXT canonicalisation is byte-exact and the vector records the ARITHMETIC, not just the total:
//! `10 + 1 + 5 + 4 + 4 + ... = 121`. So the tests check the sum term by term, because a total alone
//! would hide a compensating error — and this repository has already found a fixture whose three
//! inserted bytes were compensated by `body_length + 3`, making every length check agree while the
//! meaning was wrong.

/// The mDNS service type.
pub const SERVICE_TYPE: &str = "_droidlab._tcp";

/// The mDNS domain.
pub const DOMAIN: &str = "local";

/// The default TCP port a session listens on.
pub const DEFAULT_PORT: u16 = 45917;

/// The UDP port the beacon is broadcast on.
pub const BEACON_PORT: u16 = 45918;

/// The record's TTL in seconds.
pub const TTL_SECONDS: u32 = 120;

/// The largest TXT record set that may be produced, in bytes.
///
/// The vector's reasoning: "A record set larger than the mDNS budget cannot be delivered reliably in one
/// response, so the agent must not produce it." So this is a limit on GENERATION, not on acceptance.
pub const MAX_TXT_BYTES: usize = 1300;

/// The required keys, in the fixed order the canonicalisation uses.
pub const REQUIRED_KEYS: [&str; 5] = ["v", "id", "fp", "caps", "port"];

/// The optional keys, in the RFC-0003 order they are appended in.
pub const OPTIONAL_KEYS: [&str; 6] = ["model", "android", "sdk", "busy", "loc", "tls"];

/// Whether a key is one the canonicalisation knows.
#[must_use]
pub fn is_known_txt_key(key: &str) -> bool {
    REQUIRED_KEYS.contains(&key) || OPTIONAL_KEYS.contains(&key)
}

/// The keys, required first then optional, in canonical order.
#[must_use]
pub fn canonical_key_order() -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = REQUIRED_KEYS.to_vec();
    keys.extend(OPTIONAL_KEYS);
    keys
}

/// A TXT advertisement's fields.
///
/// A `Vec` of pairs rather than a map, because the ORDER is part of the canonical form and a map would
/// discard it. `build_txt` sorts nothing: it walks [`canonical_key_order`] and takes what is present.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxtFields {
    /// The key/value pairs, in any order.
    pub pairs: Vec<(String, String)>,
}

impl TxtFields {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Adds a pair. A duplicate key replaces the earlier value, so a caller cannot produce a record with
    /// the same key twice by accident.
    pub fn set(&mut self, key: &str, value: &str) {
        let key = key.to_owned();

        if let Some(existing) = self.pairs.iter_mut().find(|(entry, _)| *entry == key) {
            existing.1 = value.to_owned();
            return;
        }

        self.pairs.push((key, value.to_owned()));
    }

    /// Reads a value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(entry, _)| entry == key)
            .map(|(_, value)| value.as_str())
    }

    /// Reads a value as an integer.
    #[must_use]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|value| value.parse().ok())
    }

    /// Whether a key is present, meaning present with a non-empty value.
    ///
    /// Emptiness matters: an optional key with an empty value would add `key=` and a separator to the
    /// canonical form for no information, and would change the length. Not emitting it is the only
    /// choice that keeps two implementations agreeing.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some_and(|value| !value.is_empty())
    }
}

/// The TXT canonical form: label, NUL, then the known keys joined by `0x0A`, with no trailing newline.
///
/// Only keys in [`canonical_key_order`] are emitted, and only when present and non-empty. An unknown key
/// is DROPPED rather than appended, because appending it would change the canonical form and its length
/// — and a controller that verified a signature over a form with an unknown key would compute a
/// different digest from the agent that produced it.
///
/// Returns the bytes, which are UTF-8.
#[must_use]
pub fn canonical_txt(fields: &TxtFields) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    out.extend_from_slice(crate::labels::TXT_LABEL.as_bytes());
    out.push(0x00);

    let mut first = true;

    for key in canonical_key_order() {
        if !fields.has(key) {
            continue;
        }

        if !first {
            out.push(0x0A);
        }

        first = false;

        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(fields.get(key).unwrap_or("").as_bytes());
    }

    out
}

/// The canonical form as a `String`, for comparison with a vector's recorded text.
///
/// # Panics
///
/// Never in practice — the canonical form is built from UTF-8 string slices — but returns a lossy
/// conversion rather than panicking if a value were somehow not UTF-8.
#[must_use]
pub fn canonical_txt_string(fields: &TxtFields) -> String {
    String::from_utf8_lossy(&canonical_txt(fields)).into_owned()
}

/// Why a TXT record cannot be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxtError {
    /// The canonical form is larger than the budget.
    TooLarge {
        /// The size that would be produced.
        size: usize,
        /// The budget.
        limit: usize,
    },
    /// A required key is absent or empty.
    MissingKey {
        /// The key.
        key: &'static str,
    },
    /// The port is zero, which is not a port a listener can be reached on.
    PortOutOfRange {
        /// The value.
        port: u64,
    },
}

impl core::fmt::Display for TxtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { size, limit } => {
                write!(
                    f,
                    "the record would be {size} bytes, over the limit of {limit}"
                )
            }
            Self::MissingKey { key } => write!(f, "the required key {key:?} is absent"),
            Self::PortOutOfRange { port } => write!(f, "port {port} is not a usable port"),
        }
    }
}

impl core::error::Error for TxtError {}

/// Whether a port is one an advertisement may carry.
///
/// The vector's case is a port of **0**, which a controller must not connect to. Ports 1..=65535 are
/// usable; 0 means "any port" in a bind, which is not an address a peer can reach.
#[must_use]
pub const fn is_usable_port(port: u64) -> bool {
    port >= 1 && port <= 65_535
}

/// Builds a TXT record, checking the required keys and the size budget.
///
/// # Errors
///
/// [`TxtError::MissingKey`] for an absent required key, [`TxtError::PortOutOfRange`] for a bad port, or
/// [`TxtError::TooLarge`] when the canonical form exceeds `limit`.
pub fn build_txt(fields: &TxtFields, limit: usize) -> Result<Vec<u8>, TxtError> {
    for key in REQUIRED_KEYS {
        if !fields.has(key) {
            return Err(TxtError::MissingKey { key });
        }
    }

    let port = fields.get_u64("port").unwrap_or(0);

    if !is_usable_port(port) {
        return Err(TxtError::PortOutOfRange { port });
    }

    let canonical = canonical_txt(fields);

    if canonical.len() > limit {
        return Err(TxtError::TooLarge {
            size: canonical.len(),
            limit,
        });
    }

    Ok(canonical)
}

/// Truncates a capability list to a byte budget, dropping whole names.
///
/// `discovery.txt.caps-truncated`: "When the capability list would push the record past the size budget
/// the agent truncates it and sets a trailing comma-free prefix."
///
/// The rule that matters is **trailing-comma-free**: a truncated list must not end in a comma, because
/// `"a,b,"` splits to `["a", "b", ""]` and an empty capability name is a name a peer would have to
/// decide whether to ignore. Dropping whole names rather than cutting mid-name matters for the same
/// reason.
///
/// The note also says what a controller must do with the result: "treat the list as advisory and call
/// GET_CAPABILITIES after connecting, because a truncated list is not evidence that a capability is
/// missing." That is a statement about trust, not about truncation, and it is why the advertised list is
/// a hint and only the `CAPABILITIES` frame after authentication is authoritative.
#[must_use]
pub fn truncate_capabilities(capabilities: &[String], budget: usize) -> String {
    let mut out = String::new();

    for name in capabilities {
        // The length if this name were added: the name, plus a comma if there is already a name.
        let addition = if out.is_empty() {
            name.len()
        } else {
            name.len().saturating_add(1)
        };

        if out.len().saturating_add(addition) > budget {
            break;
        }

        if !out.is_empty() {
            out.push(',');
        }

        out.push_str(name);
    }

    // The invariant, asserted rather than assumed: a truncated list never ends in a comma, and never
    // contains an empty entry.
    //
    // The empty case is excluded because `"".split(',')` yields `[""]`, which is an artifact of splitting
    // an empty string rather than an empty capability name. My first version asserted it unconditionally
    // and a `debug_assert` in the test binary fired on a budget of zero.
    debug_assert!(!out.ends_with(','));
    debug_assert!(out.is_empty() || !out.split(',').any(str::is_empty));

    out
}

/// The beacon's canonical form: ascending key order, joined by `0x0A`, no whitespace.
///
/// Deliberately different from [`canonical_txt`], and the beacon vector says why: the beacon "carries a
/// JSON object, so it uses its own deterministic rule." There is also no label and no NUL, because the
/// beacon is not a TXT record.
///
/// `sig` is excluded, and the vector says so: "every field except sig is covered by the signature."
/// Including `sig` in its own signed payload is the classic mistake, and it is unsatisfiable — the field
/// would have to contain a signature over a document containing that signature.
#[must_use]
pub fn canonical_beacon(pairs: &[(String, String)]) -> Vec<u8> {
    // Ascending key order. Sorted here because the beacon's rule IS alphabetical, unlike the TXT
    // record's. Sorting by the key's bytes is the deterministic order both sides can agree on without
    // a locale.
    let mut entries: Vec<(&str, &str)> = pairs
        .iter()
        .filter(|(key, value)| key != "sig" && !value.is_empty())
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();

    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    let mut out: Vec<u8> = Vec::new();

    for (index, (key, value)) in entries.iter().enumerate() {
        if index > 0 {
            out.push(0x0A);
        }

        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
    }

    out
}

/// The beacon's canonical form as a `String`.
#[must_use]
pub fn canonical_beacon_string(pairs: &[(String, String)]) -> String {
    String::from_utf8_lossy(&canonical_beacon(pairs)).into_owned()
}

/// The presence state of a discovered device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The device is advertising normally.
    Online,
    /// The device is advertising with `busy=1`: at its session limit.
    Busy,
    /// The record's TTL has expired without a re-announcement.
    Offline,
    /// The advertisement failed a check and the device is listed without being trusted.
    Unverified,
    /// The advertised version is not one this controller implements.
    Incompatible,
}

impl Presence {
    /// Whether the device should still be listed to the user.
    ///
    /// True for everything except [`Presence::Online`] and [`Presence::Busy`] being offline is still a
    /// listable state, because "the pairing survives" a TTL expiry and an offline device "stays in the
    /// saved list so the user can see it and reconnect later."
    ///
    /// This is the function that decides whether a UI shows a device, so it is worth being explicit that
    /// being offline is NOT the same as being gone.
    #[must_use]
    pub const fn is_listed(self) -> bool {
        true
    }

    /// Whether a controller may connect automatically, without asking the user.
    #[must_use]
    pub const fn allows_automatic_connect(self) -> bool {
        matches!(self, Self::Online | Self::Busy)
    }
}

/// What to do with a received advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertisementVerdict {
    /// The advertisement is good; list the device as online.
    Accept,
    /// Good, but the device is at its session limit.
    AcceptBusy,
    /// Ignore it: the advertisement itself is malformed, so there is nothing to list.
    IgnoreAdvertisement,
    /// List the device, but do not connect automatically.
    ListAsUnverified,
    /// List the device, but do not connect automatically: the advertised identity changed.
    RefuseAutomaticConnect,
    /// List the device as incompatible with this controller's versions.
    ListAsIncompatible,
    /// The advertisement cannot be generated as it stands; the agent must regenerate it.
    RegenerateRecord,
}

impl AdvertisementVerdict {
    /// The presence this verdict implies.
    #[must_use]
    pub const fn presence(self) -> Option<Presence> {
        match self {
            Self::Accept => Some(Presence::Online),
            Self::AcceptBusy => Some(Presence::Busy),
            Self::IgnoreAdvertisement => None,
            Self::ListAsUnverified => Some(Presence::Unverified),
            Self::RefuseAutomaticConnect => Some(Presence::Unverified),
            Self::ListAsIncompatible => Some(Presence::Incompatible),
            Self::RegenerateRecord => None,
        }
    }

    /// Whether the user should be offered a manual connect.
    ///
    /// True for the cases that list a device the controller will not connect to on its own. The
    /// signature-mismatch vector is explicit about it: "It must also not quietly remove the device: an
    /// attacker may be jamming the real agent, so the UI keeps the device listed as unverified and offers
    /// a manual connect."
    ///
    /// That reasoning is the whole point. Silently dropping a forged advertisement would hide the attack
    /// FROM THE USER and remove their own device, which is a worse outcome than either connecting or
    /// removing it.
    #[must_use]
    pub const fn offers_manual_connect(self) -> bool {
        matches!(self, Self::ListAsUnverified | Self::RefuseAutomaticConnect)
    }
}

/// Evaluates a received TXT advertisement.
///
/// `pairing` is `Some((fingerprint, signature_valid))` when the controller holds a pairing record for the
/// advertised id. `None` means the device is unknown, in which case a signature cannot be checked
/// against anything and the advertisement is listed as unverified rather than trusted.
#[must_use]
pub fn evaluate_advertisement(
    fields: &TxtFields,
    pairing: Option<(&str, bool)>,
    controller_versions: &[&str],
) -> (AdvertisementVerdict, &'static str) {
    // A required key or the port. `build_txt`'s checks, applied to what was received.
    for key in REQUIRED_KEYS {
        if !fields.has(key) {
            return (
                AdvertisementVerdict::IgnoreAdvertisement,
                "a required key is absent, so the advertisement is malformed",
            );
        }
    }

    if !is_usable_port(fields.get_u64("port").unwrap_or(0)) {
        return (
            AdvertisementVerdict::IgnoreAdvertisement,
            "the advertised port is not one a listener can be reached on",
        );
    }

    // The size budget. A record over it "cannot be delivered reliably in one response".
    let canonical = canonical_txt(fields);

    if canonical.len() > MAX_TXT_BYTES {
        return (
            AdvertisementVerdict::RegenerateRecord,
            "the record is over the mDNS budget and must not be produced",
        );
    }

    // The version, before the signature: a device this controller cannot talk to is not one to spend a
    // signature check on, and the incompatibility is a fact about the version rather than about trust.
    let version = fields.get("v").unwrap_or("");

    if !controller_versions.contains(&version) {
        return (
            AdvertisementVerdict::ListAsIncompatible,
            "the advertised version is not one this controller implements",
        );
    }

    // The pairing checks.
    if let Some((known_fingerprint, signature_valid)) = pairing {
        // The fingerprint first, because a changed identity is a different device and its signature
        // would be checked against the wrong key.
        if fields.get("fp") != Some(known_fingerprint) {
            return (
                AdvertisementVerdict::RefuseAutomaticConnect,
                "the id matches a pairing record but the fingerprint changed: possible impersonation",
            );
        }

        if !signature_valid {
            return (
                AdvertisementVerdict::ListAsUnverified,
                "the signature does not verify, so the advertisement is forged",
            );
        }

        // A paired, verified device at its limit is still listed, with the reason shown.
        if fields.get("busy") == Some("1") {
            return (
                AdvertisementVerdict::AcceptBusy,
                "the paired device is at its session limit",
            );
        }

        return (
            AdvertisementVerdict::Accept,
            "a paired device with a valid signature",
        );
    }

    // An unpaired device is listed but not trusted, which is why its busy flag does not change the
    // verdict: there is nothing to connect to automatically either way.
    (
        AdvertisementVerdict::ListAsUnverified,
        "no pairing record for this id, so the advertisement cannot be verified",
    )
}

/// Whether the beacon may be emitted.
///
/// The vector's case: `discovery_enabled` is false, and the expectation is `no_beacon`. The note adds a
/// second rule — "the agent must not unicast it to an address it has not itself been contacted from" —
/// which is a rule about the beacon's destination rather than about emitting it.
///
/// A broadcast beacon advertises a device's presence to the whole LAN. If the operator turned discovery
/// off, that is exactly what they asked not to happen, so the beacon must stop even though a listening
/// socket would still work.
#[must_use]
pub const fn may_emit_beacon(discovery_enabled: bool) -> bool {
    discovery_enabled
}

/// Whether a goodbye record must be sent when discovery stops.
///
/// `discovery.goodbye-on-disable`: "Turning discovery off sends a goodbye with TTL 0 so controllers drop
/// the device promptly instead of waiting out the record TTL."
///
/// The TTL is **0**, not a short nonzero value. A goodbye is a re-announcement with TTL 0, and a
/// controller that treated a small TTL as "about to leave" would keep the device listed for that long,
/// which is the delay the goodbye exists to avoid.
#[must_use]
pub const fn goodbye_ttl() -> u32 {
    0
}

/// Whether an interface address change requires re-registering the service.
///
/// `discovery.reannounce-after-address-change`: "A Wi-Fi roam or DHCP renewal changes the address, and
/// the advertisement must carry the new one. This is the most common cause of a device appearing online
/// but being unreachable."
///
/// The consequence named in the note is why this is a lifecycle event rather than a detail: the record
/// stays valid, so the device looks online, and the address inside it is stale.
///
/// Not `const`: `matches!` on a `&str` is not const-callable (`PartialEq` is not yet stable as a const
/// trait), and making it const would mean a byte comparison by hand for no gain.
#[must_use]
pub fn requires_reregistration(trigger: &str) -> bool {
    matches!(
        trigger,
        "interface_address_changed" | "interface_changed" | "address_changed" | "dhcp_renewal"
    )
}

/// Whether presence has expired.
///
/// The comparison is `elapsed >= ttl`, so a TTL of 120 with 120 seconds elapsed is EXPIRED. The vector's
/// case is 121, which does not pin the boundary; the boundary is asserted separately because
/// `elapsed > ttl` and `elapsed >= ttl` differ only at exactly the TTL, which is the one value a fixture
/// is least likely to carry.
#[must_use]
pub const fn is_expired(elapsed_seconds: u32, ttl_seconds: u32) -> bool {
    elapsed_seconds >= ttl_seconds
}

/// Whether a device at its session limit should advertise, and with what `busy` value.
///
/// `discovery.busy-agent-still-advertises`: "An agent at its session limit keeps advertising with busy=1,
/// so a controller can show a reason rather than 'device not found'."
///
/// The alternative — withdrawing the advertisement — would make a busy device indistinguishable from a
/// powered-off one, and the user's remedy is different in the two cases.
#[must_use]
pub const fn advertises_when_busy(active_sessions: u32, max_sessions: u32) -> (bool, u64) {
    let busy = active_sessions >= max_sessions;

    (true, if busy { 1 } else { 0 })
}
