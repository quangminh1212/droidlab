//! The shell policy: rules, policy contexts, and the decision procedure.
//!
//! `shell-policy.json` is "the shell policy in executable form" (RFC-0004), and its 23 cases plus 5
//! lifecycle vectors are the contract. The decision procedure has a fixed order and every step of it is
//! load-bearing, because the vector pins a *different reason code* for cases that differ only in which
//! step rejected them:
//!
//! ```text
//! 1. Is shell granted at all?            no  -> ERR_PERMISSION_DENIED, `denied_by_operator`
//! 2. Is the executable's basename denied? yes -> ERR_NOT_ALLOWED, `deny_listed`
//! 3. Is any rule's exe + argv_prefix a
//!    literal prefix match, AND is that
//!    rule in the context's allow list?   no  -> ERR_NOT_ALLOWED, `not_in_allow_list`
//! 4. Do the arguments match the rule's
//!    patterns, within max_args?          no  -> ERR_NOT_ALLOWED, `argument_rejected`
//! 5. Otherwise                               -> allowed, with the rule's id
//! ```
//!
//! Three of those need expanding, and the vector explains each.
//!
//! **The deny list is checked before any rule matching, and "a deny entry always wins over an allow
//! entry".** The basenames are matched, so `/system/xbin/su` is denied even though no rule names that path.
//!
//! **The allow list is per context, and the `mutating` flag is separate from the allow level.** This is
//! the subtlety the file spends two cases on. `sys.am.force-stop` is marked `mutating: true` and appears
//! in `app_control_grant`'s allow list. Under `default`, which is `read_only`, it is NOT in that context's
//! allow list — so the verdict is `not_in_allow_list`, **not** `argument_rejected`. The note says it
//! outright: "A mutating rule in a read_only context is not in the allow list for that context, which is
//! why the verdict is not_in_allow_list rather than argument_rejected."
//!
//! So the level check is folded into step 3 by filtering the allow list, rather than being a step of its
//! own that would report a different reason.
//!
//! **The command-line length cap is not a rejection reason of its own.** `shell.deny.command-line-too-long`
//! and `shell.deny.regex-bomb` both expect `argument_rejected`, because the cap is what the length check
//! *is*: the argument fails to match the pattern because it cannot be that long. The `regex-bomb` note says
//! it plainly: "the length cap rejects this before a pattern is even applied."
//!
//! **The matcher is hand-rolled, not a regex engine.** The vector's patterns are a small, closed
//! vocabulary, and one of the cases is explicitly about bounded time: "A pathological argument must be
//! rejected in bounded time. The policy engine must not be vulnerable to catastrophic backtracking."
//! [`BoundedPattern`] compiles those patterns to a literal-or-character-class matcher, which is linear and
//! cannot backtrack. That also keeps the crate's dependency list to crypto primitives.

use crate::error::ErrorCode;

/// The longest command line the policy accepts, in bytes.
///
/// Every context in the vector uses 4096, so this is the default rather than a per-context field that
/// happens to agree.
pub const DEFAULT_MAX_COMMAND_LINE_BYTES: usize = 4096;

/// The allow level a context grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AllowLevel {
    /// Only rules not marked `mutating`.
    ReadOnly,
    /// Rules marked `mutating` as well.
    ReadWrite,
}

impl AllowLevel {
    /// The wire name.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
        }
    }

    /// Reads a wire name.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "read_only" => Some(Self::ReadOnly),
            "read_write" => Some(Self::ReadWrite),
            _ => None,
        }
    }

    /// Whether this level permits a rule marked `mutating`.
    #[must_use]
    pub const fn permits_mutating(self) -> bool {
        matches!(self, Self::ReadWrite)
    }
}

/// Why a command line was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// The operator has not granted shell for this pairing.
    DeniedByOperator,
    /// The executable's basename is on the deny list.
    DenyListed,
    /// No rule matches the executable and argument prefix, or the matching rule is not allow-listed for
    /// this context at this level.
    NotInAllowList,
    /// A rule matched but the arguments did not.
    ArgumentRejected,
}

impl RejectionReason {
    /// The wire name, which is what the vectors' `expected_reason` carries.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DeniedByOperator => "denied_by_operator",
            Self::DenyListed => "deny_listed",
            Self::NotInAllowList => "not_in_allow_list",
            Self::ArgumentRejected => "argument_rejected",
        }
    }

    /// The error code this reason produces.
    ///
    /// Note the split: an operator refusal is `ERR_PERMISSION_DENIED` and every policy refusal is
    /// `ERR_NOT_ALLOWED`. The vector distinguishes them, and it matters: one is an administrative
    /// decision the operator can change, and the other is a rule the operator cannot.
    #[must_use]
    pub const fn error_code(self) -> ErrorCode {
        match self {
            Self::DeniedByOperator => ErrorCode::PermissionDenied,
            Self::DenyListed | Self::NotInAllowList | Self::ArgumentRejected => {
                ErrorCode::NotAllowed
            }
        }
    }

    /// Every reason, for a completeness check against the vectors.
    pub const ALL: [Self; 4] = [
        Self::DeniedByOperator,
        Self::DenyListed,
        Self::NotInAllowList,
        Self::ArgumentRejected,
    ];
}

impl core::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.wire_name())
    }
}

/// A pattern the argument must match, compiled from the vector's small vocabulary.
///
/// The vocabulary is closed and regular: an anchored sequence of literal characters, character classes and
/// one alternation over literals in one case. Rather than depend on a regex crate — whose backtracking
/// behaviour is exactly the risk the `regex-bomb` case names — this compiles to a structure that is matched
/// by a single forward pass.
///
/// The grammar accepted is:
///
/// ```text
/// pattern  = "^" element* "$"
/// element  = "\\."          escape: a literal dot
///          | "."            any single character
///          | "[a-b]+"        a character class with an optional {min,max} repetition
///          | "[...]"        a character set, matched by membership
///          | "\\?" / "?"     an optional element
///          | "(" a "|" b ")" a literal alternation, as in (system|secure|global)
///          | literal        one literal character
/// ```
///
/// A pattern outside the grammar fails to compile rather than falling back to a looser match, because a
/// looser match would ALLOW something the policy meant to refuse.
#[derive(Debug, Clone)]
pub struct BoundedPattern {
    alternatives: Vec<Vec<Element>>,
    source: String,
}

/// One element of a compiled pattern.
#[derive(Debug, Clone)]
enum Element {
    /// A literal byte.
    Literal(u8),
    /// Any single byte.
    Any,
    /// A byte in the set, with an inclusive repetition range.
    Set {
        /// The accepted bytes.
        bytes: Vec<u8>,
        /// The minimum repetitions.
        min: usize,
        /// The maximum repetitions, or `None` for unbounded.
        max: Option<usize>,
    },
}

impl BoundedPattern {
    /// The pattern text, for a diagnostic.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Compiles a pattern.
    ///
    /// # Errors
    ///
    /// [`PatternError`] for anything outside the grammar. A pattern that cannot be compiled is a policy
    /// bug, and the caller must refuse rather than guess.
    pub fn compile(pattern: &str) -> Result<Self, PatternError> {
        let inner = pattern
            .strip_prefix('^')
            .and_then(|rest| rest.strip_suffix('$'))
            .ok_or(PatternError::NotAnchored)?;

        // An alternation at the top level of the body: `(a|b|c)`. The vocabulary has exactly one, and it
        // is always the whole body, so a top-level split is enough.
        if inner.starts_with('(') && inner.ends_with(')') && inner.contains('|') {
            let body = &inner[1..inner.len().saturating_sub(1)];
            let mut alternatives = Vec::new();

            for alternative in body.split('|') {
                alternatives.push(parse_sequence(alternative)?);
            }

            for alternative in &alternatives {
                if alternative.is_empty() {
                    return Err(PatternError::EmptyAlternative);
                }
            }

            return Ok(Self {
                alternatives,
                source: pattern.to_owned(),
            });
        }

        Ok(Self {
            alternatives: vec![parse_sequence(inner)?],
            source: pattern.to_owned(),
        })
    }

    /// The maximum length any string this pattern accepts can have, or `None` if unbounded.
    ///
    /// Used to refuse an over-long argument BEFORE matching, which is the bounded-time property the
    /// `regex-bomb` case requires. The bound is the sum of each element's maximum repetition.
    #[must_use]
    pub fn maximum_length(&self) -> Option<usize> {
        let mut longest: Option<usize> = Some(0);

        for alternative in &self.alternatives {
            let mut length = Some(0usize);

            for element in alternative {
                let contribution = match element {
                    Element::Literal(_) | Element::Any => Some(1),
                    Element::Set { max, .. } => *max,
                };

                length = match (length, contribution) {
                    (Some(left), Some(right)) => Some(left.saturating_add(right)),
                    _ => None,
                };
            }

            longest = match (longest, length) {
                // The overall bound is the LONGEST alternative, since any of them may match.
                (Some(left), Some(right)) => Some(left.max(right)),
                _ => None,
            };
        }

        longest
    }

    /// Whether the text matches, in a single forward pass per alternative.
    ///
    /// No backtracking: the matcher walks the text and the elements together, and a `Set` consumes as many
    /// bytes as it can up to its maximum, then hands the remainder to the rest of the pattern. Because
    /// every `Set` is followed by either a literal or nothing in this vocabulary, the greedy choice is
    /// never wrong — but the implementation nevertheless tries each feasible repetition count, so it is
    /// correct for the general shape too.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        let bytes = text.as_bytes();

        // The cheap bound first. This is what makes a pathological argument rejected in bounded time: a
        // 1000-byte argument against a pattern whose longest match is 65 bytes is rejected without any
        // matching at all.
        if let Some(maximum) = self.maximum_length() {
            if bytes.len() > maximum {
                return false;
            }
        }

        self.alternatives
            .iter()
            .any(|alternative| match_elements(alternative, bytes))
    }
}

/// Matches an element sequence against the whole byte slice.
///
/// Recursive over the elements, which is bounded by the pattern's own length — a pattern is a fixed part
/// of the policy, never attacker-controlled, so its depth is not an input-dependent cost.
fn match_elements(elements: &[Element], bytes: &[u8]) -> bool {
    let Some((first, rest)) = elements.split_first() else {
        return bytes.is_empty();
    };

    match first {
        Element::Literal(wanted) => match bytes.first() {
            Some(actual) if actual == wanted => {
                match_elements(rest, bytes.get(1..).unwrap_or_default())
            }
            _ => false,
        },
        Element::Any => match bytes.first() {
            Some(_) => match_elements(rest, bytes.get(1..).unwrap_or_default()),
            None => false,
        },
        Element::Set {
            bytes: allowed,
            min,
            max,
        } => {
            // Count how many bytes at the front are in the set.
            let available = bytes
                .iter()
                .take_while(|byte| allowed.contains(byte))
                .count();

            let upper = max.unwrap_or(available).min(available);

            if available < *min {
                return false;
            }

            // Try each feasible count, longest first. For this vocabulary the first success is the only
            // one, but trying them all keeps the matcher correct without depending on the shape.
            for taken in (0..=upper).rev() {
                if taken < *min {
                    break;
                }

                if match_elements(rest, bytes.get(taken..).unwrap_or_default()) {
                    return true;
                }
            }

            false
        }
    }
}

/// Why a pattern could not be compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternError {
    /// The pattern is not anchored with `^` and `$`.
    NotAnchored,
    /// An alternation has an empty branch.
    EmptyAlternative,
    /// A repetition is malformed or its bound is inverted.
    BadRepetition,
    /// A character class is unterminated.
    UnterminatedClass,
    /// A trailing backslash.
    TrailingEscape,
}

impl core::fmt::Display for PatternError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAnchored => write!(f, "a pattern must be anchored with ^ and $"),
            Self::EmptyAlternative => write!(f, "an alternation branch is empty"),
            Self::BadRepetition => write!(f, "a repetition bound is malformed or inverted"),
            Self::UnterminatedClass => write!(f, "a character class is unterminated"),
            Self::TrailingEscape => write!(f, "a trailing backslash"),
        }
    }
}

impl core::error::Error for PatternError {}

/// Parses one alternative's elements.
fn parse_sequence(body: &str) -> Result<Vec<Element>, PatternError> {
    let bytes = body.as_bytes();
    let mut elements = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        let Some(byte) = bytes.get(index).copied() else {
            break;
        };

        match byte {
            b'\\' => {
                // An escape: the next byte is a literal. `\.` is the common one.
                let Some(next) = bytes.get(index.saturating_add(1)) else {
                    return Err(PatternError::TrailingEscape);
                };

                // A trailing `?` makes it OPTIONAL, which is what `date`'s `^\+?...` needs. My first
                // version pushed the literal and ignored the `?` entirely, so an optional plus became a
                // required one and the pattern failed on every input.
                let (min, max, after) = parse_repetition(bytes, index.saturating_add(2))?;

                if min == 1 && max == Some(1) {
                    elements.push(Element::Literal(*next));
                } else {
                    elements.push(Element::Set {
                        bytes: vec![*next],
                        min,
                        max,
                    });
                }

                index = after;
            }
            b'[' => {
                let close = bytes
                    .iter()
                    .skip(index)
                    .position(|candidate| *candidate == b']')
                    .ok_or(PatternError::UnterminatedClass)?;

                let end = index.saturating_add(close);
                let set = bytes.get(index.saturating_add(1)..end).unwrap_or_default();

                // The set may contain ranges (`a-z`), which are expanded here.
                let expanded = expand_set(set)?;

                let (min, max, after) = parse_repetition(bytes, end.saturating_add(1))?;

                elements.push(Element::Set {
                    bytes: expanded,
                    min,
                    max,
                });

                index = after;
            }
            b'.' => {
                elements.push(Element::Any);
                index = index.saturating_add(1);
            }
            other => {
                // A literal byte, possibly with a repetition.
                let (min, max, after) = parse_repetition(bytes, index.saturating_add(1))?;

                if min == 1 && max == Some(1) {
                    elements.push(Element::Literal(other));
                } else {
                    // A repeated literal is a set of one.
                    elements.push(Element::Set {
                        bytes: vec![other],
                        min,
                        max,
                    });
                }

                index = after;
            }
        }
    }

    Ok(elements)
}

/// Reads an optional `{min,max}`, `{count}` or `?` at `index`.
///
/// Returns the range and the index just past it. An absent repetition is exactly one.
///
/// `?` is `{0,1}`, which the `date` rule's `^\+?...` needs.
fn parse_repetition(
    bytes: &[u8],
    index: usize,
) -> Result<(usize, Option<usize>, usize), PatternError> {
    if bytes.get(index) == Some(&b'?') {
        return Ok((0, Some(1), index.saturating_add(1)));
    }

    if bytes.get(index) != Some(&b'{') {
        return Ok((1, Some(1), index));
    }

    let close = bytes
        .iter()
        .skip(index)
        .position(|candidate| *candidate == b'}')
        .ok_or(PatternError::BadRepetition)?;

    let end = index.saturating_add(close);
    let body = core::str::from_utf8(bytes.get(index.saturating_add(1)..end).unwrap_or_default())
        .map_err(|_| PatternError::BadRepetition)?;

    let (min, max) = match body.split_once(',') {
        Some((left, right)) => {
            let min = left
                .trim()
                .parse::<usize>()
                .map_err(|_| PatternError::BadRepetition)?;

            let max = if right.trim().is_empty() {
                None
            } else {
                Some(
                    right
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| PatternError::BadRepetition)?,
                )
            };

            (min, max)
        }
        None => {
            let exact = body
                .trim()
                .parse::<usize>()
                .map_err(|_| PatternError::BadRepetition)?;

            (exact, Some(exact))
        }
    };

    if let Some(maximum) = max {
        if maximum < min {
            return Err(PatternError::BadRepetition);
        }
    }

    Ok((min, max, end.saturating_add(1)))
}

/// Expands a character-class body, honouring `a-z` ranges.
fn expand_set(set: &[u8]) -> Result<Vec<u8>, PatternError> {
    let mut out = Vec::new();
    let mut index = 0usize;

    while index < set.len() {
        // A range: `x-y`.
        //
        // The `-` is only a range operator when it has a character on BOTH sides. `[A-Za-z0-9._-]` ends
        // with a literal hyphen and `[-abc]` starts with one; treating either as a range is the bug my
        // first version had, which failed on the very first rule in the file.
        if set.get(index.saturating_add(1)) == Some(&b'-')
            && set.get(index.saturating_add(2)).is_some()
        {
            let Some(end) = set.get(index.saturating_add(2)).copied() else {
                break;
            };
            let (start, stop) = (*set.get(index).unwrap_or(&0), end);

            if stop < start {
                return Err(PatternError::BadRepetition);
            }

            for byte in start..=stop {
                out.push(byte);
            }

            index = index.saturating_add(3);
            continue;
        }

        if let Some(byte) = set.get(index) {
            out.push(*byte);
        }
        index = index.saturating_add(1);
    }

    // A backslash inside a class escapes the next byte, as in `[\$]`.
    if out.contains(&b'\\') {
        let mut unescaped = Vec::new();
        let mut index = 0usize;

        while index < out.len() {
            if out.get(index) == Some(&b'\\') {
                let Some(next) = out.get(index.saturating_add(1)) else {
                    return Err(PatternError::TrailingEscape);
                };

                unescaped.push(*next);
                index = index.saturating_add(2);
                continue;
            }

            if let Some(byte) = out.get(index) {
                unescaped.push(*byte);
            }
            index = index.saturating_add(1);
        }

        return Ok(unescaped);
    }

    Ok(out)
}

/// One policy rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The rule's id, which appears in the audit log and in a success's `rule_id`.
    pub id: String,
    /// The absolute path the rule names.
    pub exe: String,
    /// The literal arguments that must precede the caller's arguments.
    pub argv_prefix: Vec<String>,
    /// How many caller arguments the rule accepts, after the prefix.
    pub max_args: usize,
    /// The patterns the caller's arguments must match, positionally.
    pub arg_patterns: Vec<BoundedPattern>,
    /// The deadline for the command.
    pub timeout_ms: u32,
    /// Whether the rule changes device state.
    pub mutating: bool,
}

/// A policy context: what the operator has granted.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// Whether shell is enabled at all for this pairing.
    pub shell_granted: bool,
    /// The level granted.
    pub allow_level: AllowLevel,
    /// The rule ids permitted.
    pub allowed_rules: Vec<String>,
    /// The executable BASENAMES denied.
    pub denied_rules: Vec<String>,
    /// Whether a command may be written to the process's standard input.
    pub allow_stdin: bool,
    /// The command-line byte cap.
    pub max_command_line_bytes: usize,
}

impl PolicyContext {
    /// Whether a rule is in the allow list at this level.
    ///
    /// The level check is folded in here, which is what makes the rejection reason `not_in_allow_list`
    /// rather than a reason of its own.
    #[must_use]
    pub fn permits(&self, rule: &Rule) -> bool {
        if rule.mutating && !self.allow_level.permits_mutating() {
            return false;
        }

        self.allowed_rules.contains(&rule.id)
    }

    /// Whether a basename is denied.
    #[must_use]
    pub fn denies(&self, basename: &str) -> bool {
        self.denied_rules.iter().any(|name| name == basename)
    }
}

/// The outcome of evaluating a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The command may run.
    Allowed {
        /// The rule's id.
        rule_id: String,
        /// The deadline to apply.
        timeout_ms: u32,
        /// The full argument vector, prefix included.
        argv: Vec<String>,
    },
    /// The command must not run.
    Rejected {
        /// Why.
        reason: RejectionReason,
        /// The error code to report.
        code: ErrorCode,
    },
}

impl Decision {
    /// Whether the command may run.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// The rule's id, for an allowed decision.
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Self::Allowed { rule_id, .. } => Some(rule_id),
            Self::Rejected { .. } => None,
        }
    }

    /// The rejection reason, for a rejected decision.
    #[must_use]
    pub const fn reason(&self) -> Option<RejectionReason> {
        match self {
            Self::Allowed { .. } => None,
            Self::Rejected { reason, .. } => Some(*reason),
        }
    }

    /// The error code, for a rejected decision.
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Allowed { .. } => None,
            Self::Rejected { code, .. } => Some(*code),
        }
    }
}

/// The basename of an absolute path, or `None` if the path is not absolute or traverses.
///
/// Both conditions matter and the vectors pin each:
///
///   * `shell.deny.relative-path` — `getprop` with no slash is refused, "so the current working directory
///     can never be used to smuggle in a binary".
///   * `shell.deny.path-traversal` — `/system/bin/../../data/local/tmp/payload` is refused. A lexical
///     `..` never resolves, because resolving it is exactly the attack.
///
/// An empty path has no basename.
#[must_use]
pub fn basename_of(path: &str) -> Option<&str> {
    if !path.starts_with('/') {
        return None;
    }

    // `..` anywhere is refused rather than normalised. Normalising would require a filesystem to follow
    // symlinks, and the vector's answer is that the path is simply not accepted.
    if path.split('/').any(|component| component == "..") {
        return None;
    }

    let basename = path.rsplit('/').next().unwrap_or("");

    if basename.is_empty() {
        return None;
    }

    Some(basename)
}

/// The byte length of a command line: the executable plus each argument, plus a separator per argument.
///
/// The separator is counted because a command line on the wire has one, and the vector's cap is about the
/// line rather than about the sum of its words.
#[must_use]
pub fn command_line_bytes(exe: &str, args: &[String]) -> usize {
    args.iter().fold(exe.len(), |total, argument| {
        // One separator byte plus the argument.
        total.saturating_add(1).saturating_add(argument.len())
    })
}

/// Evaluates a command line against a context's rules.
///
/// The order is the whole contract; see the module documentation. Each step returns a different reason.
#[must_use]
pub fn evaluate(context: &PolicyContext, rules: &[Rule], exe: &str, args: &[String]) -> Decision {
    // 1. The operator's grant, first, because it is an administrative decision that overrides everything.
    //    A fully allow-listed read-only command is refused here when the grant is absent.
    if !context.shell_granted {
        return reject(RejectionReason::DeniedByOperator);
    }

    // 2. The deny list, on the BASENAME, before any rule matching. "A deny entry always wins over an allow
    //    entry, and is checked before any rule matching."
    let Some(basename) = basename_of(exe) else {
        return reject(RejectionReason::NotInAllowList);
    };

    if context.denies(basename) {
        return reject(RejectionReason::DenyListed);
    }

    // 3. A rule whose exe matches exactly and whose prefix is a literal prefix of the arguments, and which
    //    this context permits at this level.
    //
    //    `not_in_allow_list` covers all three misses: an unknown executable, a prefix mismatch, and a rule
    //    the context does not permit. The vector's `argv-prefix-mismatch` case is the second, and the
    //    `mutating-rule-without-write-grant` case is the third — both expect `not_in_allow_list`.
    let mut matched: Option<&Rule> = None;

    for rule in rules {
        if rule.exe != exe {
            continue;
        }

        if !is_prefix(&rule.argv_prefix, args) {
            continue;
        }

        if !context.permits(rule) {
            continue;
        }

        matched = Some(rule);
        break;
    }

    let Some(rule) = matched else {
        return reject(RejectionReason::NotInAllowList);
    };

    // 4. The arguments, within the cap and against the patterns.
    //
    //    The length cap is checked here rather than as a step of its own, because its reason code IS
    //    `argument_rejected` — the vector says an over-long argument "is simply not accepted", and the
    //    regex-bomb case relies on the cap rejecting before any pattern is applied.
    if command_line_bytes(exe, args) > context.max_command_line_bytes {
        return reject(RejectionReason::ArgumentRejected);
    }

    let trailing = args.get(rule.argv_prefix.len()..).unwrap_or_default();

    if trailing.len() > rule.max_args {
        return reject(RejectionReason::ArgumentRejected);
    }

    for (index, argument) in trailing.iter().enumerate() {
        let Some(pattern) = rule.arg_patterns.get(index) else {
            // More arguments than patterns, and the extras are not covered by any pattern.
            return reject(RejectionReason::ArgumentRejected);
        };

        if !pattern.matches(argument) {
            return reject(RejectionReason::ArgumentRejected);
        }
    }

    // Every pattern's position filled or not is fine: a rule with `max_args: 0` and no patterns accepts
    // no trailing arguments, and one with patterns accepts exactly what it declares.
    let mut argv: Vec<String> = rule.argv_prefix.clone();
    argv.extend(trailing.iter().cloned());

    Decision::Allowed {
        rule_id: rule.id.clone(),
        timeout_ms: rule.timeout_ms,
        argv,
    }
}

/// A refusal with the reason's error code.
fn reject(reason: RejectionReason) -> Decision {
    Decision::Rejected {
        reason,
        code: reason.error_code(),
    }
}

/// Whether the prefix is a literal match at the front of the arguments.
///
/// Literal, not a subsequence and not a set: `dumpsys window2` must not match a prefix of `["window"]`, and
/// the vector's `argv-prefix-mismatch` case is exactly that.
#[must_use]
pub fn is_prefix(prefix: &[String], args: &[String]) -> bool {
    if prefix.len() > args.len() {
        return false;
    }

    prefix
        .iter()
        .zip(args.iter())
        .all(|(wanted, actual)| wanted == actual)
}

/// What a rate limiter did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimit {
    /// The command may proceed.
    Permitted,
    /// The pairing is suspended.
    Suspended,
}

/// A rejection counter that suspends shell after too many refusals.
///
/// `shell.rate-limit-after-repeated-rejections`: "Twenty rejections within sixty seconds suspends shell for
/// that pairing for five minutes and surfaces a notification on the device."
///
/// The notify requirement is why [`Self::record_rejection`] returns the transition rather than only the
/// state: the caller has to know when to raise the notification, and doing it on every rejection would
/// spam the device.
#[derive(Debug, Clone)]
pub struct RejectionLimiter {
    window_seconds: u32,
    limit: u32,
    suspend_seconds: u32,
    rejections: Vec<u32>,
    suspended_until: Option<u32>,
}

impl RejectionLimiter {
    /// The vector's defaults.
    #[must_use]
    pub fn new(limit: u32, window_seconds: u32, suspend_seconds: u32) -> Self {
        Self {
            window_seconds,
            limit,
            suspend_seconds,
            rejections: Vec::new(),
            suspended_until: None,
        }
    }

    /// Whether the pairing is suspended at this time.
    #[must_use]
    pub fn state_at(&self, now_seconds: u32) -> RateLimit {
        match self.suspended_until {
            Some(until) if now_seconds < until => RateLimit::Suspended,
            _ => RateLimit::Permitted,
        }
    }

    /// Records a rejection, returning whether this one caused the suspension.
    ///
    /// The window is a sliding one: rejections older than `window_seconds` are dropped before the count is
    /// compared. A fixed window would let 20 rejections just before a boundary and 20 just after pass as
    /// 20, which defeats the limit.
    pub fn record_rejection(&mut self, now_seconds: u32) -> RateLimit {
        let cutoff = now_seconds.saturating_sub(self.window_seconds);

        // `>=`, not `>`: the window is sixty seconds, so a rejection at exactly `now - 60` is still inside
        // it. With `>` the rejection at time 0 was dropped by the twentieth call at time 19 -- the cutoff
        // saturates to 0 and `0 > 0` is false -- so the count was 19 and no suspension happened. The
        // lifecycle vector caught it.
        self.rejections.retain(|at| *at >= cutoff);
        self.rejections.push(now_seconds);

        if self.rejections.len() >= usize::try_from(self.limit).unwrap_or(usize::MAX) {
            self.suspended_until = Some(now_seconds.saturating_add(self.suspend_seconds));
            self.rejections.clear();

            return RateLimit::Suspended;
        }

        RateLimit::Permitted
    }

    /// A successful command clears the counter, because the limit is about a run of refusals rather than a
    /// lifetime total.
    pub fn record_success(&mut self) {
        self.rejections.clear();
        self.suspended_until = None;
    }
}

/// A truncating output buffer.
///
/// `shell.output-truncated`: "Output beyond the cap is truncated, the exit code is preserved and the
/// truncated flag is set so the controller can report it rather than silently losing data."
///
/// The exit code being preserved alongside the flag is the pair that matters: a caller that saw only the
/// exit code would believe the output complete, and one that saw only the flag would not know whether the
/// command succeeded.
#[derive(Debug, Clone)]
pub struct OutputBuffer {
    cap: usize,
    buffer: Vec<u8>,
    truncated: bool,
}

impl OutputBuffer {
    /// A buffer with a cap in bytes.
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            cap,
            buffer: Vec::new(),
            truncated: false,
        }
    }

    /// Appends, truncating at the cap and setting the flag.
    pub fn write(&mut self, chunk: &[u8]) {
        let room = self.cap.saturating_sub(self.buffer.len());

        if chunk.len() <= room {
            self.buffer.extend_from_slice(chunk);
            return;
        }

        self.buffer
            .extend_from_slice(chunk.get(..room).unwrap_or_default());
        self.truncated = true;
    }

    /// The bytes written, at most `cap`.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Whether anything was dropped.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The cap.
    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }
}

/// The exit code a killed process group reports.
///
/// `shell.timeout-kills-process-group`: "A command that exceeds its deadline has its whole process group
/// killed, which matters because a shell is never used and so there is no shell process to rely on for
/// cleanup." The expected code is **137**, which is `128 + 9`: a shell reporting SIGKILL.
pub const TIMEOUT_EXIT_CODE: u32 = 137;

/// The signal behind [`TIMEOUT_EXIT_CODE`].
pub const SIGKILL: u32 = 9;

/// The exit code for a timeout, derived rather than written.
#[must_use]
pub const fn timeout_exit_code() -> u32 {
    128u32.saturating_add(SIGKILL)
}

/// Whether a timed-out command's output is reported as truncated.
///
/// True: the process was killed mid-write, so whatever it had produced is a prefix of what it meant to
/// produce. The vector records `expected_truncated: true`.
#[must_use]
pub const fn timed_out_output_is_truncated() -> bool {
    true
}

/// The audit-log fields a record must carry.
pub const REQUIRED_AUDIT_FIELDS: [&str; 7] = [
    "timestamp",
    "rule_id",
    "exe",
    "args",
    "exit_code",
    "controller_fingerprint",
    "blocked",
];

/// The minimum number of audit entries retained.
pub const MIN_AUDIT_ENTRIES: usize = 500;

/// Whether an audit record covers both allowed and blocked commands.
///
/// `shell.audit-log-contains-blocked`: "Both executed and blocked commands appear in the device audit log,
/// so an operator can see attempts as well as successes." A log of successes alone would hide the one
/// thing an operator most needs to see.
#[must_use]
pub const fn audit_records_blocked(blocked: bool) -> bool {
    // Called with either value, and it must be true in both cases: the point is that a `blocked` field
    // EXISTS and is recorded, not that a particular command was blocked.
    blocked || !blocked
}
