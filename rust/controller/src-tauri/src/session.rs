//! The DLWP/1 handshake, driven from the controller's side.
//!
//! # What this module owns, and what it does not
//!
//! It owns the **order** of the handshake and the **checks** each step's answer must pass. It owns
//! none of the arithmetic: the transcript, the key schedule, the proofs and the fingerprint all
//! come from `droidlab_protocol`, which is the point of ADR-0009. This crate reads bytes off a
//! socket and decides what to say next; every rule about what those bytes *mean* lives one layer
//! down, where three implementations agree on it.
//!
//! ```text
//!   controller                                     agent
//!       |---- HELLO      (versions, nonce) --------->|
//!       |<--- HELLO_ACK  (version, nonce, limits) ----|
//!       |---- AUTH       (client_id, proof) --------->|
//!       |<--- AUTH_OK    (agent_id, proof) -----------|
//!       |== established: record-protected frames from here ==>
//! ```
//!
//! # Why the transcript gates the key derivation
//!
//! The keys are derived *from the transcript's hash*, so the transcript has to be complete before
//! any key exists. That is not an implementation detail — it is what binds the keys to the
//! handshake that produced them, and it means a peer that altered a single byte of `HELLO_ACK`
//! derives a different key rather than a key that happens to decrypt nothing.

use std::time::Duration;

use droidlab_protocol::{
    derive_session_keys, AuthProofs, Fingerprint, FrameHeader, Limits, PairingSecret, SessionKeys,
    Transcript, Value,
};

use crate::transport::{Frame, Transport, TransportError};

/// How long each handshake step waits for the peer's answer.
///
/// Tighter than the transport's per-frame timeout. A handshake is four small frames between two
/// machines already on the same LAN, so a peer that needs longer than this to answer a `HELLO` is
/// not slow — it is absent, and the user is watching a spinner.
pub const HANDSHAKE_STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// The registry's code for `HELLO`.
const HELLO: u8 = 1;
/// The registry's code for `HELLO_ACK`.
const HELLO_ACK: u8 = 2;
/// The registry's code for `AUTH`.
const AUTH: u8 = 3;
/// The registry's code for `AUTH_OK`.
const AUTH_OK: u8 = 4;
/// The registry's code for `ERROR`, which is what an agent refuses with.
const ERROR: u8 = 60;

/// The wire name of the controller's role in a `HELLO`.
const ROLE_CONTROLLER: &str = "controller";

/// Everything that can go wrong during a handshake.
///
/// Each variant names a *distinguishable* failure, because the remedy differs: a version mismatch
/// is a user upgrading one side, a rejected proof is a user re-pairing, and a timeout is a user
/// checking their network. Collapsing them into "handshake failed" would throw that away.
#[derive(Debug)]
pub enum HandshakeError {
    /// A frame could not be read or written.
    Transport(TransportError),
    /// The peer's answer was not the message the sequence requires at this point.
    OutOfSequence {
        /// What the sequence required.
        expected: &'static str,
        /// The numeric type that actually arrived. A number rather than a name because naming it
        /// would need the registry's name table, and the number is enough to look it up.
        got: u8,
    },
    /// No protocol version both sides accept.
    NoSharedVersion {
        /// The highest version this controller speaks.
        ours: u16,
        /// The versions the peer offered.
        theirs: Vec<u16>,
    },
    /// The peer's body was missing a field the specification requires.
    MissingField {
        /// The message that lacked it.
        message: &'static str,
        /// The field's name, as the specification spells it.
        field: &'static str,
    },
    /// A field was present but of the wrong type.
    WrongFieldType {
        /// The message that carried it.
        message: &'static str,
        /// The field's name.
        ///
        /// An owned `String` rather than a borrow, even though most callers pass a literal. The
        /// name of a *limit* comes from the peer's own frame, so a borrowed version would make
        /// this error's lifetime depend on a frame that the handshake has already moved past —
        /// and an error is the one value the caller keeps after everything else is dropped.
        field: String,
        /// What the specification requires.
        expected: &'static str,
    },
    /// A field that must be a fixed width was not.
    WrongFieldWidth {
        /// The field's name.
        field: &'static str,
        /// What the specification requires.
        expected: usize,
        /// What arrived.
        got: usize,
    },
    /// The peer refused authentication. Carries the agent's own error code, because the agent
    /// knows why better than this side can infer from a refusal.
    Rejected {
        /// The error code the agent reported, if it sent one.
        code: Option<String>,
    },
    /// The agent's fingerprint differs from the one this side computed.
    ///
    /// The most useful failure in the handshake: both sides completed every step and still
    /// disagree about what happened, which points at the transcript rather than at the crypto.
    FingerprintMismatch {
        /// The fingerprint computed here.
        ours: String,
        /// The fingerprint the agent reported.
        theirs: String,
    },
    /// The agent's own authentication proof did not verify.
    ///
    /// Distinct from [`HandshakeError::Rejected`]: the agent did not say no, it said yes with a
    /// proof of a different secret. That is a wrong pairing stored on this machine, or a peer that
    /// does not have the pairing secret at all, and it must never be treated as success.
    BadAgentProof,
    /// The step did not complete within [`HANDSHAKE_STEP_TIMEOUT`].
    TimedOut {
        /// The name of the step that stalled.
        step: &'static str,
    },
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "{error}"),
            Self::OutOfSequence { expected, got } => {
                write!(f, "expected {expected} but received message type {got}")
            }
            Self::NoSharedVersion { ours, theirs } => write!(
                f,
                "no shared protocol version: this controller speaks up to {ours}, \
                 the device offers {theirs:?}"
            ),
            Self::MissingField { message, field } => {
                write!(f, "{message} did not include the required field '{field}'")
            }
            Self::WrongFieldType {
                message,
                field,
                expected,
            } => write!(
                f,
                "{message} field '{field}' should be {expected} but was not"
            ),
            Self::WrongFieldWidth {
                field,
                expected,
                got,
            } => write!(
                f,
                "{field} should be {expected} bytes but was {got}"
            ),
            Self::Rejected { code } => match code {
                Some(code) => write!(f, "the device refused authentication: {code}"),
                None => write!(f, "the device refused authentication"),
            },
            Self::FingerprintMismatch { ours, theirs } => write!(
                f,
                "the pairing fingerprint did not match: this controller computed {ours}, \
                 the device reported {theirs}"
            ),
            Self::BadAgentProof => write!(
                f,
                "the device's authentication proof did not verify against the stored pairing"
            ),
            Self::TimedOut { step } => write!(f, "the device did not answer {step} in time"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::OutOfSequence { .. }
            | Self::NoSharedVersion { .. }
            | Self::MissingField { .. }
            | Self::WrongFieldType { .. }
            | Self::WrongFieldWidth { .. }
            | Self::Rejected { .. }
            | Self::FingerprintMismatch { .. }
            | Self::BadAgentProof
            | Self::TimedOut { .. } => None,
        }
    }
}

impl From<TransportError> for HandshakeError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// What the controller knows about itself and the device before the handshake begins.
///
/// Passed as one struct rather than as five arguments so that a caller cannot transpose two
/// `[u8; 32]`s at the call site. A swapped nonce or identity key is a bug that compiles and
/// produces a fingerprint mismatch a long way from its cause.
#[derive(Debug)]
pub struct HandshakeInputs<'a> {
    /// This controller's identity public key, 32 bytes.
    pub client_pub: &'a [u8; 32],
    /// The paired device's identity public key, 32 bytes.
    pub agent_pub: &'a [u8; 32],
    /// The pairing secret, derived during QR pairing.
    pub pairing_secret: &'a PairingSecret,
    /// The X25519 shared secret for this pairing, 32 bytes.
    ///
    /// A field of its own rather than something recomputed here, because it comes from the pairing
    /// exchange and is not recoverable from the pairing secret.
    pub shared_secret: &'a [u8; 32],
    /// The session identifier, from the pairing record.
    pub session_id: &'a [u8],
    /// The peer's human-readable identifier, part of the transcript.
    pub agent_id: &'a str,
    /// This controller's human-readable identifier, part of the transcript.
    pub client_id: &'a str,
    /// The protocol versions this controller accepts, newest first.
    pub supported_versions: &'a [u16],
}

/// The result of a completed handshake.
///
/// Carries the key material and the negotiated limits but **no state machine**: this is the
/// handshake's output, and the caller decides what to do with it. Keeping "what the handshake
/// established" apart from "what the session is currently doing" keeps two different lifetimes
/// from being tangled in one type.
#[derive(Debug)]
pub struct Established {
    /// The keys both sides derived.
    ///
    /// Never logged and never serialised. `SessionKeys`' own `Debug` prints lengths rather than
    /// bytes, and `zeroize` clears it on drop, but a caller that copies these fields out has
    /// defeated both.
    pub keys: SessionKeys,
    /// The protocol version that was agreed.
    pub version: u16,
    /// The limits the agent reported.
    pub limits: Limits,
    /// The pairing fingerprint, for the user to compare on both screens.
    pub fingerprint: Fingerprint,
    /// The nonce this controller contributed. Needed later to bind the session to this handshake.
    pub client_nonce: [u8; 32],
    /// The nonce the agent contributed.
    pub agent_nonce: [u8; 32],
    /// The hash of the completed transcript, which the record keys were derived against.
    pub transcript_hash: [u8; 32],
}

/// Runs the controller half of a DLWP/1 handshake.
///
/// # Errors
///
/// Every way the handshake can fail is a [`HandshakeError`], including a peer that is not speaking
/// DLWP/1 at all. The socket is deliberately left open on failure — this function never closes it —
/// because a caller that wants to retry or to read a trailing error frame would otherwise have to
/// reconnect just to find out what happened.
pub async fn perform(
    transport: &mut Transport,
    inputs: &HandshakeInputs<'_>,
) -> Result<Established, HandshakeError> {
    // ---- HELLO -------------------------------------------------------------
    let client_nonce = random_nonce();
    let hello = Frame::new(
        control_header(HELLO, 0),
        hello_body(inputs.supported_versions, &client_nonce),
    );
    step(transport.write_frame(&hello), "HELLO").await?;

    // ---- HELLO_ACK ---------------------------------------------------------
    let ack = step(transport.read_frame(), "HELLO_ACK").await?;
    if ack.header.message_type != HELLO_ACK {
        return Err(HandshakeError::OutOfSequence {
            expected: "HELLO_ACK",
            got: ack.header.message_type,
        });
    }

    let agent_nonce = fixed_nonce(&ack.body, "HELLO_ACK", "nonce")?;
    let agent_versions = optional_version_array(&ack.body, "HELLO_ACK", "versions")?;
    let version = agree_version(inputs.supported_versions, &agent_versions)?;
    let limits = read_limits(&ack.body)?;

    // ---- the transcript, and the keys derived from it ----------------------
    //
    // Built here rather than incrementally, because `Transcript::new` takes all six fields at once:
    // the two identifiers, the two nonces and the two identity public keys. That is deliberate on
    // the codec's part — a transcript that could be appended to field by field is one a caller can
    // build in the wrong order and never notice.
    let transcript = Transcript::new(
        inputs.client_id,
        inputs.agent_id,
        &client_nonce,
        &agent_nonce,
        inputs.client_pub,
        inputs.agent_pub,
    )
    .map_err(|_| HandshakeError::Rejected { code: None })?;

    let transcript_hash = transcript.hash();

    let keys = derive_session_keys(
        inputs.session_id,
        inputs.shared_secret,
        inputs.pairing_secret.as_bytes(),
        &transcript_hash,
    )
    .map_err(|_| HandshakeError::Rejected { code: None })?;

    // ---- AUTH --------------------------------------------------------------
    let proofs = inputs.pairing_secret.auth_proofs(&transcript_hash);
    let auth = Frame::new(
        control_header(AUTH, 0),
        auth_body(inputs.client_pub, &proofs),
    );
    step(transport.write_frame(&auth), "AUTH").await?;

    // ---- AUTH_OK -----------------------------------------------------------
    let auth_ok = step(transport.read_frame(), "AUTH_OK").await?;

    // An agent refuses with `ERROR` rather than with a silence or a closed socket, so the refusal
    // is caught here and its code surfaced. Falling through to the "out of sequence" branch would
    // report a refusal as a protocol violation, which is the wrong diagnosis and the wrong remedy.
    if auth_ok.header.message_type == ERROR {
        return Err(HandshakeError::Rejected {
            code: error_code_of(&auth_ok.body),
        });
    }
    if auth_ok.header.message_type != AUTH_OK {
        return Err(HandshakeError::OutOfSequence {
            expected: "AUTH_OK",
            got: auth_ok.header.message_type,
        });
    }

    // The agent must prove it holds the same secret. Without this check the controller would accept
    // `AUTH_OK` from anyone who can complete `HELLO_ACK`, and the pairing would authenticate the
    // device to the controller without authenticating the controller to the device — half a
    // handshake, which is not one.
    let agent_proof = fixed_width(&auth_ok.body, "AUTH_OK", "proof", 32)?;
    if !droidlab_protocol::verify_proof(&proofs.agent, &agent_proof) {
        return Err(HandshakeError::BadAgentProof);
    }

    // The fingerprint is what the user compares on both screens. Checked only when the agent sends
    // one, because the field is optional in the exchange — but when it is sent and does not match,
    // that is a hard failure and not a warning.
    let fingerprint = Fingerprint::from_public_key(inputs.agent_pub);
    if let Some(reported) = text_field(&auth_ok.body, "fingerprint") {
        let ours = fingerprint.to_string();
        if reported != ours {
            return Err(HandshakeError::FingerprintMismatch {
                ours,
                theirs: reported,
            });
        }
    }

    Ok(Established {
        keys,
        version,
        limits,
        fingerprint,
        client_nonce,
        agent_nonce,
        transcript_hash,
    })
}

/// Awaits one step, mapping a transport timeout to the name of the step that stalled.
///
/// The mapping matters for diagnosis: `TransportError::TimedOut` says a frame was late, and this
/// says *which* frame, which is the difference between a log line a user can act on and one they
/// can only report.
async fn step<T>(
    future: impl std::future::Future<Output = Result<T, TransportError>>,
    name: &'static str,
) -> Result<T, HandshakeError> {
    match tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(TransportError::TimedOut)) | Err(_) => Err(HandshakeError::TimedOut { step: name }),
        Ok(Err(error)) => Err(HandshakeError::Transport(error)),
    }
}

/// Builds the `HELLO` body.
///
/// A function so the wire field names appear exactly once. They come from the specification, and a
/// typo in one would look like a peer that omits a required field rather than like a bug here.
#[must_use]
fn hello_body(versions: &[u16], nonce: &[u8; 32]) -> Value {
    Value::Map(vec![
        (
            Value::Text("versions".to_owned()),
            Value::Array(
                versions
                    .iter()
                    .map(|version| Value::Unsigned(u64::from(*version)))
                    .collect(),
            ),
        ),
        (
            Value::Text("nonce".to_owned()),
            Value::ByteString(nonce.to_vec()),
        ),
        (
            Value::Text("role".to_owned()),
            Value::Text(ROLE_CONTROLLER.to_owned()),
        ),
    ])
}

/// Builds the `AUTH` body.
#[must_use]
fn auth_body(client_pub: &[u8; 32], proofs: &AuthProofs) -> Value {
    Value::Map(vec![
        (
            Value::Text("client_id".to_owned()),
            Value::ByteString(client_pub.to_vec()),
        ),
        (
            Value::Text("proof".to_owned()),
            Value::ByteString(proofs.client.to_vec()),
        ),
    ])
}

/// A control-channel header.
///
/// The handshake's four frames have fixed sequence numbers — the sequence-numbering rules begin at
/// the first record-protected frame — so this always writes zero.
#[must_use]
fn control_header(message_type: u8, flags: u8) -> FrameHeader {
    FrameHeader {
        version: 1,
        flags,
        header_length: 24,
        message_type,
        channel_id: 0,
        sequence_number: 0,
        acknowledgment: 0,
        body_length: 0,
    }
}

/// Picks the highest version both sides speak.
///
/// Highest, not lowest: both sides list what they support and the newest common one is the intent.
/// Falling back to the oldest would silently downgrade a capable pair.
fn agree_version(ours: &[u16], theirs: &[u16]) -> Result<u16, HandshakeError> {
    let agreed = ours
        .iter()
        .filter(|version| theirs.contains(version))
        .max()
        .copied();

    agreed.ok_or_else(|| HandshakeError::NoSharedVersion {
        ours: ours.iter().copied().max().unwrap_or(0),
        theirs: theirs.to_vec(),
    })
}

/// 32 bytes from the OS entropy source.
///
/// OS entropy rather than a userspace PRNG: a repeated nonce across two handshakes with the same
/// device would repeat the transcript, and the transcript is what the keys are bound to.
fn random_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Reads a byte-string field that must be exactly `width` bytes.
///
/// The width is checked here rather than left to the codec below, because the error it would
/// produce there says "bad length" without saying which field, and a handshake has several fields
/// of the same width.
fn fixed_width(
    body: &Value,
    message: &'static str,
    field: &'static str,
    width: usize,
) -> Result<Vec<u8>, HandshakeError> {
    match lookup(body, field) {
        Some(Value::ByteString(bytes)) => {
            if bytes.len() == width {
                Ok(bytes.clone())
            } else {
                Err(HandshakeError::WrongFieldWidth {
                    field,
                    expected: width,
                    got: bytes.len(),
                })
            }
        }
        Some(_) => Err(HandshakeError::WrongFieldType {
            message,
            field: field.to_owned(),
            expected: "a byte string",
        }),
        None => Err(HandshakeError::MissingField { message, field }),
    }
}

/// Reads a 32-byte nonce into an array.
///
/// Separate from [`fixed_width`] because the length is part of the *type* here: a nonce that reaches
/// the key schedule untested is one that can be the wrong size, and `Transcript::new` would refuse
/// it a long way from the message that carried it.
fn fixed_nonce(
    body: &Value,
    message: &'static str,
    field: &'static str,
) -> Result<[u8; 32], HandshakeError> {
    let bytes = fixed_width(body, message, field, 32)?;
    let mut nonce = [0u8; 32];
    for (slot, byte) in nonce.iter_mut().zip(bytes.iter()) {
        *slot = *byte;
    }
    Ok(nonce)
}

/// Reads an optional array of version numbers, defaulting to empty.
///
/// Optional because a peer that supports exactly one version may omit the field, and treating its
/// absence as "no versions" would reject a legal peer.
fn optional_version_array(
    body: &Value,
    message: &'static str,
    field: &'static str,
) -> Result<Vec<u16>, HandshakeError> {
    let Some(value) = lookup(body, field) else {
        return Ok(Vec::new());
    };

    let Value::Array(items) = value else {
        return Err(HandshakeError::WrongFieldType {
            message,
            field: field.to_owned(),
            expected: "an array of version numbers",
        });
    };

    let mut versions = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Unsigned(version) => {
                versions.push(u16::try_from(*version).map_err(|_| {
                    HandshakeError::WrongFieldType {
                        message,
                        field: field.to_owned(),
                        expected: "a version number below 65536",
                    }
                })?);
            }
            _ => {
                return Err(HandshakeError::WrongFieldType {
                    message,
                    field: field.to_owned(),
                    expected: "an array of version numbers",
                })
            }
        }
    }
    Ok(versions)
}

/// Reads the agent's limits, falling back to the specification's defaults.
///
/// A missing `limits` field is not an error: the defaults are the floor, and a peer that omits the
/// field is asking for them. The individual limit values are read with the defaults as their base,
/// so a peer that names three of the nine gets the other six by default rather than a rejection.
fn read_limits(body: &Value) -> Result<Limits, HandshakeError> {
    let Some(Value::Map(entries)) = lookup(body, "limits") else {
        return Ok(Limits::default());
    };

    let mut limits = Limits::default();
    for (key, value) in entries {
        let Value::Text(name) = key else {
            continue;
        };
        let Some(number) = value.as_unsigned() else {
            return Err(HandshakeError::WrongFieldType {
                message: "HELLO_ACK",
                field: "limits".to_owned(),
                expected: "a map of limit names to unsigned integers",
            });
        };

        // Each arm narrows a `u64` from the wire into the field's own width. A value that does not
        // fit is refused rather than truncated: a truncated limit is a limit that is silently
        // wrong, and every one of these is a safety bound.
        match name.as_str() {
            "max_frame_bytes" => limits.max_frame_bytes = number,
            "max_channels" => {
                limits.max_channels = narrow(name, number, "a 32-bit count")?;
            }
            "max_video_width" => {
                limits.max_video_width = narrow(name, number, "a 32-bit width")?;
            }
            "max_video_height" => {
                limits.max_video_height = narrow(name, number, "a 32-bit height")?;
            }
            "max_video_fps" => {
                limits.max_video_fps = narrow(name, number, "a 32-bit frame rate")?;
            }
            "max_video_bitrate" => {
                limits.max_video_bitrate = narrow(name, number, "a 32-bit bitrate")?;
            }
            "max_file_chunk" => {
                limits.max_file_chunk = narrow(name, number, "a 32-bit byte count")?;
            }
            "shell_timeout_ms" => {
                limits.shell_timeout_ms = narrow(name, number, "a 32-bit millisecond count")?;
            }
            "max_gesture_steps" => {
                limits.max_gesture_steps = narrow(name, number, "a 32-bit step count")?;
            }
            // An unknown limit name is ignored rather than refused. A peer built against a later
            // revision of the specification will name limits this build has never heard of, and
            // rejecting the handshake over one would make every such peer unusable.
            _ => {}
        }
    }
    Ok(limits)
}

/// Narrows a wire `u64` into a `u32`, refusing rather than truncating.
///
/// The field name is borrowed from the message rather than required to be `'static`, because it
/// comes from a registry entry in the peer's frame. The caller owns the message for as long as the
/// error lives, which is long enough — an error is reported, not stored.
fn narrow(field: &str, value: u64, expected: &'static str) -> Result<u32, HandshakeError> {
    u32::try_from(value).map_err(|_| HandshakeError::WrongFieldType {
        message: "HELLO_ACK",
        field: field.to_owned(),
        expected,
    })
}

/// Extracts a text field, if the body has one by that name.
fn text_field(body: &Value, field: &str) -> Option<String> {
    match lookup(body, field)? {
        Value::Text(text) => Some(text.clone()),
        _ => None,
    }
}

/// Extracts an error code from an `ERROR` frame, if it carries one.
fn error_code_of(body: &Value) -> Option<String> {
    text_field(body, "code")
}

/// Looks a field up in a map body.
///
/// Written by hand rather than with a `serde` derive: the body is a cbOR [`Value`], and going
/// through `serde` would put the wire field names in a second place — the derive and the
/// specification — where the two could drift apart without either being wrong on its own.
fn lookup<'a>(body: &'a Value, field: &str) -> Option<&'a Value> {
    match body {
        Value::Map(entries) => entries.iter().find_map(|(key, value)| match key {
            Value::Text(name) if name == field => Some(value),
            _ => None,
        }),
        _ => None,
    }
}
