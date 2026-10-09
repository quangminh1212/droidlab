//! The negotiated session limits (RFC-0001 §5).
//!
//! Every limit here is a **ceiling that the two peers agree on**, not a value either one may apply
//! unilaterally. The agent offers its own maximums; the controller may ask for less; the session
//! uses the smaller. That is why these are a struct passed around rather than constants read from
//! the registry at the point of use: a `max_frame_bytes` that differs between the two sides is a
//! frame one side sends and the other refuses, and the way to make that impossible is to have one
//! value in the session rather than two defaults that happen to match.
//!
//! [`Limits::DEFAULT`] mirrors `default_limits` in `protocol/registry/dlwp-1.json`, which is
//! normative. The conformance suite asserts the two agree, so the mirror cannot drift.

/// The limits in force for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    /// Largest permitted frame, header and body together, in bytes.
    ///
    /// Applied to the **declared** total before the body is read, so an oversized frame is refused
    /// without a buffer being allocated for it.
    pub max_frame_bytes: u64,
    /// Largest number of simultaneously open channels.
    ///
    /// **Includes the control channel**, which is channel 0 and is always open. So a value of 8
    /// permits the control channel plus 7 others, not 8 others. The session state machine relies on
    /// this rather than re-deriving it.
    pub max_channels: u32,
    /// Largest video width in pixels.
    pub max_video_width: u32,
    /// Largest video height in pixels.
    pub max_video_height: u32,
    /// Largest video frame rate.
    pub max_video_fps: u32,
    /// Largest video bitrate in bits per second.
    pub max_video_bitrate: u32,
    /// Largest file chunk in bytes.
    pub max_file_chunk: u32,
    /// Longest permitted shell command, in milliseconds.
    pub shell_timeout_ms: u32,
    /// Largest number of steps in a single gesture.
    pub max_gesture_steps: u32,
}

impl Limits {
    /// The registry's `default_limits`, mirrored.
    ///
    /// Asserted against the registry by `every_limit_matches_the_registry` in the conformance suite.
    pub const DEFAULT: Self = Self {
        max_frame_bytes: 16_777_216,
        max_channels: 8,
        max_video_width: 1920,
        max_video_height: 1080,
        max_video_fps: 60,
        max_video_bitrate: 16_000_000,
        max_file_chunk: 262_144,
        shell_timeout_ms: 30_000,
        max_gesture_steps: 256,
    };

    /// The largest frame size as a `usize`, saturating on a narrow platform.
    ///
    /// A caller comparing against a buffer length wants `usize`; the conversion is stated here
    /// rather than at each call site so the saturation policy is visible. On any platform this
    /// crate supports the value fits, so the saturation is unreachable — but it is expressed rather
    /// than assumed, because this crate denies arithmetic with unstated overflow behaviour.
    #[must_use]
    pub const fn max_frame_bytes_usize(self) -> usize {
        if self.max_frame_bytes > usize::MAX as u64 {
            usize::MAX
        } else {
            self.max_frame_bytes as usize
        }
    }

    /// Whether a frame of `total_bytes` is within the limit.
    ///
    /// Takes the total, header included, because that is what the limit is stated over and what a
    /// receiver can check before reading the body.
    #[must_use]
    pub const fn permits_frame_of(self, total_bytes: u64) -> bool {
        total_bytes <= self.max_frame_bytes
    }

    /// Whether `open_channels` channels may be open alongside the control channel.
    ///
    /// The control channel is counted, per the field's documentation: `max_channels` of 8 permits
    /// the control channel and 7 data channels. Expressed as a helper because getting the off-by-one
    /// wrong in one of the several places that ask is exactly how the two peers come to disagree.
    #[must_use]
    pub const fn permits_open_channel(self, open_channels: u32) -> bool {
        open_channels < self.max_channels
    }

    /// The number of channels available for data, excluding the control channel.
    ///
    /// Saturating rather than subtracting: a `max_channels` of 0 is a misconfiguration, and
    /// reporting "no data channels" is better than a subtraction that wraps to `u32::MAX`.
    #[must_use]
    pub const fn data_channels(self) -> u32 {
        self.max_channels.saturating_sub(1)
    }

    /// The smallest of two limit sets, field by field.
    ///
    /// This is how negotiation combines an offer with a request: the result is what both sides can
    /// honour. Taking the minimum rather than the maximum is the whole point — a limit either side
    /// cannot meet is not a negotiated limit.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            max_frame_bytes: min_u64(self.max_frame_bytes, other.max_frame_bytes),
            max_channels: min_u32(self.max_channels, other.max_channels),
            max_video_width: min_u32(self.max_video_width, other.max_video_width),
            max_video_height: min_u32(self.max_video_height, other.max_video_height),
            max_video_fps: min_u32(self.max_video_fps, other.max_video_fps),
            max_video_bitrate: min_u32(self.max_video_bitrate, other.max_video_bitrate),
            max_file_chunk: min_u32(self.max_file_chunk, other.max_file_chunk),
            shell_timeout_ms: min_u32(self.shell_timeout_ms, other.shell_timeout_ms),
            max_gesture_steps: min_u32(self.max_gesture_steps, other.max_gesture_steps),
        }
    }

    /// Whether `other` is no more permissive than this set, field by field.
    ///
    /// Used to decide whether a peer's advertised limits can be honoured rather than renegotiated.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.max_frame_bytes >= other.max_frame_bytes
            && self.max_channels >= other.max_channels
            && self.max_video_width >= other.max_video_width
            && self.max_video_height >= other.max_video_height
            && self.max_video_fps >= other.max_video_fps
            && self.max_video_bitrate >= other.max_video_bitrate
            && self.max_file_chunk >= other.max_file_chunk
            && self.shell_timeout_ms >= other.shell_timeout_ms
            && self.max_gesture_steps >= other.max_gesture_steps
    }

    /// This set with every field set to zero, for a negotiation that has not happened yet.
    ///
    /// Zero is the correct starting point rather than the defaults: intersecting it with an offer
    /// gives zero, and a session that is using zero limits instead of the real ones refuses every
    /// frame, which is a loud failure rather than a silent default.
    pub const ZERO: Self = Self {
        max_frame_bytes: 0,
        max_channels: 0,
        max_video_width: 0,
        max_video_height: 0,
        max_video_fps: 0,
        max_video_bitrate: 0,
        max_file_chunk: 0,
        shell_timeout_ms: 0,
        max_gesture_steps: 0,
    };
}

impl Default for Limits {
    /// The registry defaults.
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The smaller of two `u64` values.
const fn min_u64(left: u64, right: u64) -> u64 {
    if left < right {
        left
    } else {
        right
    }
}

/// The smaller of two `u32` values.
const fn min_u32(left: u32, right: u32) -> u32 {
    if left < right {
        left
    } else {
        right
    }
}
