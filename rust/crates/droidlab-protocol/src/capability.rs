//! Capability negotiation and limit clamping.
//!
//! The negotiated capability set is the **three-way intersection** of what the agent implements, what
//! the operator left enabled, and what the controller asked for. Three terms, not two, and the third is
//! the one implementations miss: a capability the operator turned off on the device must be absent even
//! though both peers implement and offer it, "because this is the rule that makes the device-side switch
//! meaningful."
//!
//! Two properties are worth stating because both are easy to get backwards:
//!
//!   * **An empty intersection is not an error.** Both sides complete the handshake and report an empty
//!     set. The `capabilities.json` note is explicit, and the reason is diagnosable sessions:
//!     `GET_CAPABILITIES`, `CAPABILITIES` and `ERROR` are ungated, so a controller that offered nothing
//!     can still ask what the device supports and still receive the refusal. What is *not* ungated is
//!     everything else -- including `DEVICE_INFO`, which the registry gates under `device.info`, so a
//!     controller that offered nothing must not read device metadata. An earlier revision of that note
//!     claimed the "device information and error channels" stay usable; the fixture records the
//!     correction and this module follows the registry.
//!
//!   * **An unknown capability name is ignored, not refused.** That is what lets a newer peer advertise
//!     something new without breaking an older one, in both the offer and the answer.
//!
//! Channel ids are partitioned by parity so the two sides can allocate concurrently without a race: the
//! controller takes odd ids, the agent even ones. The vectors pin the sequences.

use crate::limits::Limits;

/// The capabilities DLWP/1 defines, in the registry's order.
///
/// Transcribed from `protocol/registry/dlwp-1.json`'s `capabilities` array and cross-checked against
/// `capabilities.json`'s `capability_registry` by the tests.
pub const CAPABILITIES: &[&str] = &[
    "screen.mirror",
    "screen.record",
    "input.touch",
    "input.key",
    "input.text",
    "input.gesture",
    "clipboard.read",
    "clipboard.write",
    "shell.exec",
    "file.read",
    "file.write",
    "log.stream",
    "app.install",
    "app.launch",
    "device.info",
    "adb.wireless",
    "compression.deflate",
    "telemetry.stats",
];

/// The one capability that changes how the wire is used rather than what it may carry.
pub const COMPRESSION: &str = "compression.deflate";

/// Whether a capability name is one DLWP/1 defines.
#[must_use]
pub fn is_known_capability(name: &str) -> bool {
    CAPABILITIES.contains(&name)
}

/// The capabilities a controller may rely on **without** negotiating them.
///
/// The three ungated message types. Every other type is gated on a capability, so a session with an
/// empty negotiated set can do exactly this much and no more.
///
/// The distinction is worth a named function because a session with an empty set must remain
/// diagnosable: if `CAPABILITIES` were gated, a controller that offered nothing could not even learn
/// what the device supports, and the empty set would be an unexplained failure rather than a report.
#[must_use]
pub fn ungated_message_types() -> [u8; 3] {
    [
        crate::registry::GET_CAPABILITIES_CODE,
        crate::registry::CAPABILITIES_CODE,
        crate::registry::ERROR,
    ]
}

/// The result of negotiating capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The negotiated capabilities, **sorted**, with duplicates removed.
    pub capabilities: Vec<String>,
    /// Names that were offered but are not DLWP/1 capabilities, deduplicated and sorted.
    ///
    /// Reported rather than silently dropped, so a log can say which names a peer sent that this
    /// implementation does not know. This is not an error.
    pub unknown: Vec<String>,
}

impl Negotiated {
    /// Whether a capability is in the negotiated set.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.capabilities.iter().any(|entry| entry == name)
    }

    /// Whether the set is empty, which is legal.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

/// Negotiates the capability set.
///
/// `agent_capabilities` is what the agent implements; `agent_disabled` is what the operator turned off
/// (or what a platform permission denied); `controller_offered` is what the controller asked for.
///
/// A name must appear in all three positive sets and in neither negative one. Order in the result is
/// **sorted**, because two peers comparing their sets must agree on order for the comparison to be
/// meaningful, and because a set is not a sequence.
#[must_use]
pub fn negotiate(
    agent_capabilities: &[String],
    agent_disabled: &[String],
    controller_offered: &[String],
) -> Negotiated {
    let mut capabilities: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();

    for offered in controller_offered {
        // Ignore what this implementation does not know, in both directions. Checked against the
        // agent's FIRST term as well, so a name the controller invented is reported as unknown rather
        // than as merely unsupported.
        if !is_known_capability(offered) {
            if !unknown.iter().any(|entry| entry == offered) {
                unknown.push(offered.clone());
            }
            continue;
        }

        let implemented = agent_capabilities.iter().any(|entry| entry == offered);
        let disabled = agent_disabled.iter().any(|entry| entry == offered);

        // The three terms. A duplicate in either input contributes once, because this checks membership
        // rather than counting: "a duplicated capability name is harmless; the negotiated list must
        // contain it once."
        if implemented && !disabled && !capabilities.iter().any(|entry| entry == offered) {
            capabilities.push(offered.clone());
        }
    }

    capabilities.sort();
    unknown.sort();

    Negotiated {
        capabilities,
        unknown,
    }
}

/// A video size request, as the controller asks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoRequest {
    /// The requested width in pixels.
    pub width: u32,
    /// The requested height in pixels.
    pub height: u32,
    /// The requested frame rate.
    pub fps: u32,
}

/// A video size, as the agent applies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoApplied {
    /// The applied width.
    pub width: u32,
    /// The applied height.
    pub height: u32,
    /// The applied frame rate.
    pub fps: u32,
}

/// Clamps a video request to the agent's limits **and** to the screen's own size.
///
/// Two distinct clamps, and the vectors separate them:
///
///   * `limits.video-clamp-to-agent-maximum`: the agent clamps to its own maxima rather than refusing.
///     The vector's note: "the agent clamps rather than refusing, and reports the clamped values so the
///     UI can show what is actually happening."
///
///   * `limits.video-clamp-to-screen-size`: "Asking for more pixels than the screen has wastes bitrate,
///     so the effective size is the smaller of the requested size and the screen size, preserving
///     aspect ratio."
///
/// The aspect-ratio step is the one that is easy to get wrong, and the vector pins it numerically:
/// a 1920x1080 request against a 1080x2400 screen gives **486x1080**, not 1080x2400. The requested
/// ASPECT is preserved while the AREA is capped -- the requested box (1920x1080, a 16:9 landscape
/// request) is fitted inside the screen (1080x2400, a 9:20 portrait panel), so the limiting dimension
/// is the width and the height lands on the screen's 1080.
///
/// The rounding note matters as much as the numbers: "486 x 1080 preserves the 1080:2400 ratio to
/// within one pixel and both dimensions are even, as H.264 requires." So the result is rounded DOWN to
/// an even number in both dimensions -- a codec requirement, not a cosmetic one, and one that a
/// straightforward multiply-divide would violate by producing an odd dimension.
#[must_use]
pub fn clamp_video(
    request: VideoRequest,
    limits: &Limits,
    screen: Option<(u32, u32)>,
) -> VideoApplied {
    // First the agent's own maxima. A zero in a limit means "the agent did not state one" in this
    // crate's `Limits::ZERO`, but `DEFAULT` states all three, and a clamp to zero would be a
    // degenerate video. So a zero limit is treated as unconstrained rather than as a ceiling of zero.
    let width = if limits.max_video_width == 0 {
        request.width
    } else {
        request.width.min(limits.max_video_width)
    };

    let height = if limits.max_video_height == 0 {
        request.height
    } else {
        request.height.min(limits.max_video_height)
    };

    let fps = if limits.max_video_fps == 0 {
        request.fps
    } else {
        request.fps.min(limits.max_video_fps)
    };

    // Then the screen.
    //
    // The rule is not "fit the request inside the screen", which is what I first implemented and what
    // the vector caught. The vectors' numbers: a 1920x1080 request against a 1080x2400 screen gives
    // 486x1080, and 486/1080 = 1080/2400 = 0.45 exactly. So the result takes the SCREEN's aspect
    // ratio, not the request's -- the requested size is a ceiling on PIXELS, and what is rendered is
    // the screen's own shape at the largest height the ceiling and the screen allow.
    //
    // That is why "preserving aspect ratio" in the vector's note is a statement about the screen rather
    // than about the request: the request's own 16:9 shape is discarded because rendering a landscape
    // 16:9 crop of a portrait screen would letterbox away most of the panel. Fitting the request inside
    // the screen instead gives 1080x607, which the vector does not record.
    let (width, height) = match screen {
        Some((screen_width, screen_height)) if screen_width > 0 && screen_height > 0 => {
            // The height is the smaller of what was asked for and the screen's own.
            let height = height.min(screen_height);

            // The width follows the screen's ratio at that height, rounded down to even.
            let width = u64::from(height)
                .saturating_mul(u64::from(screen_width))
                .checked_div(u64::from(screen_height))
                .unwrap_or(0);

            (u32::try_from(width).unwrap_or(u32::MAX), height)
        }
        _ => (width, height),
    };

    VideoApplied {
        width: even_floor(width),
        height: even_floor(height),
        fps,
    }
}

/// Fits a `width`x`height` box inside `bound_width`x`bound_height`, preserving the box's aspect ratio.
///
/// Note that [`clamp_video`] does NOT use this for the screen fit, and the reason is in the vector: the
/// screen fit takes the SCREEN's aspect ratio rather than preserving the request's. This function is the
/// general "fit a box inside a bound" primitive, used where preserving the input's shape is correct.
///
/// It SCALES UP as well as down, so it is a fit rather than a cap. A caller wanting a cap must check
/// first.
///
/// Computed by comparing the two scale factors, which avoids the floating point a ratio comparison
/// would need: if `width * bound_height` exceeds `bound_width * height`, the width is the limiting
/// dimension.
///
/// Uses `u64` intermediates because `width * bound_height` overflows a `u32` for realistic inputs --
/// 1920 * 2400 is 4_608_000, which is fine, but 65_535 * 65_535 is not, and a request is untrusted.
#[must_use]
pub fn fit_inside(width: u32, height: u32, bound_width: u32, bound_height: u32) -> (u32, u32) {
    if width == 0 || height == 0 || bound_width == 0 || bound_height == 0 {
        return (0, 0);
    }

    let wide = u64::from(width).saturating_mul(u64::from(bound_height));
    let tall = u64::from(bound_width).saturating_mul(u64::from(height));

    if wide > tall {
        // The box is relatively wider than the bound, so the bound's width limits.
        let scaled = u64::from(bound_width)
            .saturating_mul(u64::from(height))
            .checked_div(u64::from(width))
            .unwrap_or(0);

        (bound_width, u32::try_from(scaled).unwrap_or(u32::MAX))
    } else {
        // The bound's height limits.
        let scaled = u64::from(bound_height)
            .saturating_mul(u64::from(width))
            .checked_div(u64::from(height))
            .unwrap_or(0);

        (u32::try_from(scaled).unwrap_or(u32::MAX), bound_height)
    }
}

/// Rounds a dimension down to an even number.
///
/// H.264 requires even dimensions, and the vectors' rounding note says so. Rounding DOWN rather than to
/// nearest keeps the result inside the bound: rounding up could produce a dimension one pixel larger
/// than the screen, which is the failure the whole clamp exists to prevent.
#[must_use]
pub const fn even_floor(value: u32) -> u32 {
    value & !1
}

/// What a limit clamp concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClampOutcome {
    /// The request is within the limit and is applied unchanged.
    Applied,
    /// The request is larger than the limit and is refused.
    Rejected,
}

/// Clamps a file-chunk size.
///
/// The vector is explicit that this one is a **refusal, not a truncation**: "A file chunk larger than
/// max_file_chunk must be refused before allocation, not truncated silently."
///
/// The difference from the video clamp is deliberate and worth stating. A video size is a preference,
/// so clamping down and reporting what was chosen is helpful. A file chunk is a claim about how many
/// bytes follow: truncating the number without truncating the data would desynchronise the stream, and
/// honouring the number would allocate a buffer the peer asked for. So the only safe answer is no.
///
/// Returns `None` when the request is refused.
#[must_use]
pub fn clamp_file_chunk(requested: u32, limits: &Limits) -> Option<u32> {
    if limits.max_file_chunk == 0 || requested <= limits.max_file_chunk {
        Some(requested)
    } else {
        None
    }
}

/// Clamps a shell timeout.
///
/// The agent's deadline wins, and the vector adds the consequence: "the truncated flag is set if output
/// was cut short." That flag is the caller's business, but the clamp is this function's.
#[must_use]
pub fn clamp_shell_timeout(requested: u32, limits: &Limits) -> u32 {
    if limits.shell_timeout_ms == 0 {
        requested
    } else {
        requested.min(limits.shell_timeout_ms)
    }
}

/// Which side allocates channel ids of a given parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAllocator {
    /// The controller. Allocates odd ids: 1, 3, 5, ...
    Controller,
    /// The agent. Allocates even ids: 2, 4, 6, ...
    Agent,
}

impl ChannelAllocator {
    /// The first id this allocator may use.
    #[must_use]
    pub const fn first(self) -> u32 {
        match self {
            Self::Controller => 1,
            Self::Agent => 2,
        }
    }

    /// The `index`th id this allocator may use, counting from zero.
    ///
    /// The vectors pin `[1, 3, 5, 7]` for the controller and `[2, 4, 6, 8]` for the agent, so the
    /// stride is two from the first id.
    ///
    /// Channel ids are partitioned by parity so the two sides can allocate concurrently without a race.
    /// The alternative -- a single counter, or a negotiation per channel -- would need either a lock or
    /// a round trip for every channel a session opens.
    #[must_use]
    pub const fn nth(self, index: u32) -> u32 {
        // `index * 2` is the stride; the doubling cannot overflow for an index that would fit a channel
        // id, and `saturating` makes that explicit rather than a wrapping surprise.
        self.first().saturating_add(index.saturating_mul(2))
    }

    /// The first `count` ids, which is the shape the vectors record.
    #[must_use]
    pub fn take(self, count: u32) -> Vec<u32> {
        (0..count).map(|index| self.nth(index)).collect()
    }

    /// Whether an id belongs to this allocator.
    #[must_use]
    pub const fn owns(self, channel_id: u32) -> bool {
        match self {
            // Zero is the control channel and belongs to neither.
            Self::Controller => channel_id != 0 && channel_id % 2 == 1,
            Self::Agent => channel_id != 0 && channel_id % 2 == 0,
        }
    }
}

/// Whether a channel id may be reopened.
///
/// The vector: "Reusing a channel id without closing it first is a state error, because the peer may
/// still have queued frames addressed to the old channel." The answer is `ERR_BAD_STATE`, and the
/// consequence named in the note is the reason -- queued frames addressed to the old channel would
/// arrive at a new one.
#[must_use]
pub fn may_reopen(channel_id: u32, open_channels: &[u32]) -> bool {
    !open_channels.contains(&channel_id)
}
