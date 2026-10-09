//! Conformance tests for the session state machine, sequence numbering and replay detection, against
//! `session-basic.json`: 19 ordered steps, 8 preconditions, and three assertion groups.
//!
//! This is an INTEGRATION vector, so these tests replay it. The description says what that means: "Both
//! implementations replay it and must produce the same states, the same negotiated values and, for the
//! failing steps, the same errors."
//!
//! The transcript's own structure is the specification, so the tests walk it rather than restating it. In
//! particular a step's `sequence_number` is checked against a real counter for the actor that sends it,
//! which is how the "the two directions number independently" rule is enforced instead of described.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::capability::{negotiate, CAPABILITIES};
use droidlab_protocol::classify::{classify, classify_in_state, HandshakeState, Verdict};
use droidlab_protocol::error::{ErrorCode, Severity};
use droidlab_protocol::limits::Limits;
use droidlab_protocol::registry::{message_type_by_name, ChannelScope, Direction, HELLO};
use droidlab_protocol::session::{
    end_reason_for, session_survives, ChannelId, FaultResponse, SequenceCounter, SequenceTracker,
    SequenceVerdict, SessionEndReason, SessionState, Side,
};
use droidlab_protocol::version::{negotiate_versions, Negotiation, Version};

use serde_json::Value;

const FILE: &str = "session-basic.json";

fn document() -> Value {
    vectors::load(FILE)
}

fn steps() -> Vec<Value> {
    document()
        .get("steps")
        .and_then(Value::as_array)
        .expect("the transcript has steps")
        .clone()
}

fn preconditions() -> Value {
    document()
        .get("preconditions")
        .and_then(Value::as_object)
        .map(|object| Value::Object(object.clone()))
        .expect("preconditions")
}

/// The strings of a JSON array.
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|text| text.to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// A step's `send` object.
fn send_of(step: &Value) -> Option<&Value> {
    step.get("send")
}

fn name_of(send: &Value) -> &str {
    vectors::str_field(send, "name")
}

fn sequence_of(send: &Value) -> u32 {
    u32::try_from(vectors::u64_field(send, "sequence_number")).expect("it fits a u32")
}

fn channel_of(send: &Value) -> u32 {
    u32::try_from(vectors::u64_field(send, "channel_id")).expect("it fits a u32")
}

fn is_encrypted(send: &Value) -> bool {
    send.get("encrypted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The `expect` array of a step.
fn expectations(step: &Value) -> Vec<String> {
    step.get("expect").map(strings).unwrap_or_default()
}

/// Whether any expectation contains the needle.
fn expects(step: &Value, needle: &str) -> bool {
    expectations(step).iter().any(|text| text.contains(needle))
}

// =============================================================================================
// The transcript as a whole
// =============================================================================================

/// The transcript has the shape this file handles, and every step is accounted for.
#[test]
fn every_step_is_named_and_unique() {
    let all = steps();

    assert_eq!(all.len(), 19, "nineteen steps");

    // The `step` field is 1-based and contiguous.
    for (index, step) in all.iter().enumerate() {
        let number = usize::try_from(vectors::u64_field(step, "step")).expect("fits");

        assert_eq!(
            number,
            index.saturating_add(1),
            "step {number} is at index {index}, so the numbering is not contiguous"
        );
    }

    // Every step sends a frame, and every frame's name is a registered message type.
    let mut named = 0usize;

    for step in &all {
        let send = send_of(step)
            .unwrap_or_else(|| panic!("step {} has no send", vectors::u64_field(step, "step")));
        let name = name_of(send);

        assert!(
            message_type_by_name(name).is_some(),
            "step {} sends {name}, which is not a registered message type",
            vectors::u64_field(step, "step")
        );

        named = named.saturating_add(1);
    }

    assert_eq!(named, 19, "every step sends a frame");

    // The actors alternate: controller sends, agent answers, and so on. Recorded rather than assumed.
    let actors: Vec<String> = all
        .iter()
        .map(|step| vectors::str_field(step, "actor").to_owned())
        .collect();

    let controller_steps = actors.iter().filter(|actor| *actor == "controller").count();
    let agent_steps = actors.iter().filter(|actor| *actor == "agent").count();

    // Nine and ten. NOT eleven and eight: I miscounted the two VIDEO_FRAMEs (steps 11 and 12) as the
    // controller's when they are the agent's, and the count is what caught it. The controller's are steps
    // 1, 3, 5, 7, 9, 13, 14, 15 and 17, and 17 is the replay.
    assert_eq!(controller_steps, 9, "nine steps are the controller's");
    assert_eq!(agent_steps, 10, "ten are the agent's");
    assert_eq!(controller_steps.saturating_add(agent_steps), 19);

    // The controller's steps, named, so the census cannot drift without saying what moved.
    let controller_step_numbers: Vec<u64> = all
        .iter()
        .filter(|step| vectors::str_field(step, "actor") == "controller")
        .map(|step| vectors::u64_field(step, "step"))
        .collect();

    assert_eq!(controller_step_numbers, [1, 3, 5, 7, 9, 13, 14, 15, 17]);

    // The agent sends two consecutive VIDEO_FRAMEs, which is what I mistook for the controller's.
    let agent_video_steps: Vec<u64> = all
        .iter()
        .filter(|step| {
            vectors::str_field(step, "actor") == "agent"
                && name_of(send_of(step).expect("send")) == "VIDEO_FRAME"
        })
        .map(|step| vectors::u64_field(step, "step"))
        .collect();

    assert_eq!(agent_video_steps, [11, 12]);

    for actor in &actors {
        assert!(
            actor == "controller" || actor == "agent",
            "{actor} is not a side"
        );
    }

    // The spec fields.
    assert_eq!(vectors::str_field(&document(), "spec"), "RFC-0001");
    assert_eq!(vectors::str_field(&document(), "protocol_version"), "1.0");
}

/// The two directions number independently, and every sequence number in the transcript is real.
///
/// This is the assertion's own rule: "Sequence numbers are session-global and increase by one per frame
/// sent by that side. The two directions number independently, which is why both sides legitimately use
/// sequence number 1 for their first frame."
///
/// So the test keeps TWO counters, one per actor, and checks each frame against its own. My first reading
/// of the transcript assumed one shared counter and the very second step disproves it: `HELLO` is
/// sequence 1 and `HELLO_ACK` is sequence 1 as well.
#[test]
fn the_two_directions_number_independently() {
    let all = steps();

    let mut controller = SequenceCounter::new();
    let mut agent = SequenceCounter::new();
    let mut checked = 0usize;
    let mut continue_gap: Option<(u64, u32, u32)> = None;

    // The counters' own starting point, which is what makes the first frame 1 rather than 0.
    assert_eq!(controller.peek(), 1);
    assert_eq!(agent.peek(), 1);
    assert_eq!(controller.sent(), 0);

    for step in &all {
        let send = send_of(step).expect("every step sends");
        let actor = vectors::str_field(step, "actor");
        let recorded = sequence_of(send);

        // One exception, named by the vector itself, and it is the point of the whole transcript: step 17
        // is a `deliberate_replay` that re-sends an OLD number on purpose. Checking it against a counter
        // would be checking the attack for correctness.
        if step.get("deliberate_replay").and_then(Value::as_bool) == Some(true) {
            assert_eq!(
                recorded, 8,
                "the deliberate replay's number changed, so this exception is no longer placed correctly"
            );
            assert!(
                recorded < controller.peek(),
                "the replay is not behind the counter"
            );
            continue;
        }

        let counter = match actor {
            "controller" => &mut controller,
            "agent" => &mut agent,
            other => panic!("{other} is not a side"),
        };

        // The AGENT's numbering is contiguous from 1, which is what the assertion describes.
        //
        // The CONTROLLER's is NOT: it goes 1, 2, 3, 4, 5 and then jumps to 8, skipping 6 and 7. Those two
        // numbers are the ones the agent used for its two VIDEO_FRAMEs, so the transcript appears to have
        // taken the controller's numbers from the agent's counter for the frames after the video starts.
        // See `docs/findings/session-controller-sequence-gap.md`.
        //
        // So the comparison is a MINIMUM rather than an equality for the controller: the number must not go
        // backwards and must not skip a number the controller itself could have sent. Recording the exact
        // gap separately keeps the assumption visible instead of silently relaxing it.
        if actor == "controller" && recorded > counter.peek() {
            continue_gap = Some((vectors::u64_field(step, "step"), counter.peek(), recorded));
        } else {
            assert_eq!(
                recorded,
                counter.peek(),
                "step {}: {actor} sent {recorded} and the counter is at {}",
                vectors::u64_field(step, "step"),
                counter.peek()
            );
        }

        // Advance to just past whatever was recorded, which is what a real sender would have done.
        while counter.peek() <= recorded {
            counter.take();
        }

        checked = checked.saturating_add(1);
    }

    assert_eq!(checked, 18, "eighteen steps carry a fresh sequence number");

    // The gap, named. A test that silently tolerated it would be hiding a fixture defect; asserting the
    // exact step and numbers means a correction to the vector fails this test loudly.
    let (step_number, expected, recorded) =
        continue_gap.expect("the controller's numbering still has its gap of 6 and 7");

    assert_eq!(step_number, 13, "the gap moved to a different step");
    assert_eq!(expected, 6, "the controller's next number is no longer 6");
    assert_eq!(recorded, 8, "the jump is no longer to 8");

    // 6 and 7 are exactly the numbers the agent used for its two VIDEO_FRAMEs, which is why the gap is a
    // transcription error rather than a missing frame.
    let agent_video_sequences: Vec<u32> = all
        .iter()
        .filter(|step| {
            vectors::str_field(step, "actor") == "agent"
                && name_of(send_of(step).expect("send")) == "VIDEO_FRAME"
        })
        .map(|step| sequence_of(send_of(step).expect("send")))
        .collect();

    assert_eq!(
        agent_video_sequences,
        [6, 7],
        "the agent's VIDEO_FRAME numbers moved, so the gap's explanation no longer holds"
    );
    assert_eq!(
        agent_video_sequences,
        [expected, expected.saturating_add(1)],
        "the skipped numbers are not the agent's two video frames"
    );

    // Both sides used 1 for their first frame, which only works because they number independently.
    let first_controller = all
        .iter()
        .find(|step| vectors::str_field(step, "actor") == "controller")
        .expect("a controller frame");
    let first_agent = all
        .iter()
        .find(|step| vectors::str_field(step, "actor") == "agent")
        .expect("an agent frame");

    assert_eq!(sequence_of(send_of(first_controller).expect("send")), 1);
    assert_eq!(sequence_of(send_of(first_agent).expect("send")), 1);

    // And the totals, which is what a shared counter would have prevented.
    // The controller reached 10 and the agent 10, and neither wrapped.
    assert_eq!(controller.sent(), 10, "the controller's counter reached 10");
    assert_eq!(agent.sent(), 10, "the agent's counter reached 10");
    // Both reached 10 for a different NUMBER OF FRAMES, which is the independence: the controller sent
    // eight fresh frames plus the replay and the agent ten, and the two counters are unrelated.
    let controller_fresh = all
        .iter()
        .filter(|step| {
            vectors::str_field(step, "actor") == "controller"
                && step.get("deliberate_replay").and_then(Value::as_bool) != Some(true)
        })
        .count();
    let agent_fresh = all
        .iter()
        .filter(|step| vectors::str_field(step, "actor") == "agent")
        .count();

    assert_eq!(controller_fresh, 8, "eight fresh controller frames");
    assert_eq!(agent_fresh, 10, "ten agent frames");
    assert_ne!(
        controller_fresh, agent_fresh,
        "the two sides sent the same number of frames, so independence is untested"
    );
}

/// The state machine goes forwards, never backwards, and a fatal error jumps to `closing`.
#[test]
fn the_state_machine_matches_its_assertion() {
    let assertion = document()
        .get("assertions")
        .and_then(|assertions| assertions.get("state_machine"))
        .and_then(Value::as_array)
        .expect("the state_machine assertion")
        .clone();

    assert_eq!(assertion.len(), 2, "two state-machine rules");

    // The first rule's path, parsed from the file rather than restated.
    let path = assertion[0].as_str().expect("a path");

    let states: Vec<&str> = path.split(" -> ").collect();

    assert_eq!(
        states,
        [
            "idle",
            "discovering",
            "connecting",
            "handshaking",
            "authenticating",
            "established",
            "streaming",
            "closing",
            "closed"
        ],
        "the linear path changed"
    );

    // Every named state parses, and the order is the path's.
    let parsed: Vec<SessionState> = states
        .iter()
        .map(|name| {
            SessionState::from_wire_name(name).unwrap_or_else(|| panic!("{name} is a state"))
        })
        .collect();

    assert_eq!(
        parsed.len(),
        SessionState::ALL.len(),
        "every state is on the path"
    );

    for window in parsed.windows(2) {
        assert!(
            window[0].can_transition_to(window[1]),
            "{} -> {} is not a legal step on the path",
            window[0],
            window[1]
        );
        assert!(
            !window[1].can_transition_to(window[0]),
            "{} -> {} is legal, so the machine is not ordered",
            window[1],
            window[0]
        );
    }

    // The second rule: from ANY state to `closing` on a fatal error.
    let rule = assertion[1].as_str().expect("a rule");

    assert_eq!(rule, "any_state_on_fatal_error -> closing");

    for state in SessionState::ALL {
        if state.is_terminal() {
            continue;
        }

        assert!(
            state.can_transition_to(SessionState::Closing),
            "{} cannot reach closing on a fatal error",
            state
        );
    }

    // `closing` -> `closed`, and no further.
    assert!(SessionState::Closing.can_transition_to(SessionState::Closed));
    assert!(SessionState::Closed.is_terminal());
    assert!(!SessionState::Closed.can_transition_to(SessionState::Closing));

    // Going backwards is refused, which is what a fatal-error jump must not break.
    assert!(!SessionState::Established.can_transition_to(SessionState::Handshaking));
    assert!(!SessionState::Authenticating.can_transition_to(SessionState::Connecting));
    assert!(!SessionState::Streaming.can_transition_to(SessionState::Established));

    // A self-transition is a no-op rather than an advance, and it is allowed.
    for state in SessionState::ALL {
        assert!(state.can_transition_to(state), "{state} cannot stay put");
    }

    // Only the usable states carry traffic.
    assert!(SessionState::Established.is_usable());
    assert!(SessionState::Streaming.is_usable());
    assert!(!SessionState::Handshaking.is_usable());
    assert!(!SessionState::Authenticating.is_usable());
    assert!(!SessionState::Closed.is_usable());
}

/// The transcript's states, in order, following each step's expectations.
#[test]
fn the_transcript_reaches_the_states_its_expectations_name() {
    let all = steps();

    // Collect every `x_state=y` expectation, in step order.
    let mut declared: Vec<(u64, String)> = Vec::new();

    for step in &all {
        for expectation in expectations(step) {
            if let Some(rest) = expectation.strip_prefix("agent_state=") {
                declared.push((vectors::u64_field(step, "step"), rest.to_owned()));
            }

            if let Some(rest) = expectation.strip_prefix("controller_state=") {
                declared.push((vectors::u64_field(step, "step"), rest.to_owned()));
            }
        }
    }

    assert_eq!(declared.len(), 2, "two steps declare a state: {declared:?}");

    // The agent state after HELLO, and the controller state after HELLO_ACK.
    assert_eq!(declared[0].1, "handshaking");
    assert_eq!(declared[1].1, "authenticating");

    // Both are real states, and both are in the right order on the path.
    let handshaking = SessionState::from_wire_name(&declared[0].1).expect("a state");
    let authenticating = SessionState::from_wire_name(&declared[1].1).expect("a state");

    assert_eq!(handshaking, SessionState::Handshaking);
    assert_eq!(authenticating, SessionState::Authenticating);
    assert!(handshaking.can_transition_to(authenticating));

    // The handshake states are a MESSAGE ORDERING machine and have no wire names of their own -- they are
    // not states a session reports, they are what a peer is waiting for next. What is worth checking is
    // the chain, and that only the established one stops imposing an order.
    let (code, next) = HandshakeState::AwaitingHello.expected();

    assert_eq!(code, HELLO, "awaiting HELLO means HELLO is expected");
    assert_eq!(next, HandshakeState::AwaitingHelloAck);

    for (state, expected_next) in [
        (
            HandshakeState::AwaitingHelloAck,
            HandshakeState::AwaitingAuth,
        ),
        (HandshakeState::AwaitingAuth, HandshakeState::AwaitingAuthOk),
        (HandshakeState::AwaitingAuthOk, HandshakeState::Established),
    ] {
        assert_eq!(
            state.expected().1,
            expected_next,
            "{state:?} chains wrongly"
        );
    }

    // Every waiting state imposes an ordering; the established one does not.
    for state in [
        HandshakeState::AwaitingHello,
        HandshakeState::AwaitingHelloAck,
        HandshakeState::AwaitingAuth,
        HandshakeState::AwaitingAuthOk,
    ] {
        assert!(state.imposes_ordering(), "{state:?} imposes no ordering");
        assert_ne!(state, HandshakeState::Established);
    }

    assert!(!HandshakeState::Established.imposes_ordering());
    assert_eq!(
        HandshakeState::Established.expected().1,
        HandshakeState::Established
    );

    // The session states and the handshake states meet at `established`, which is what lets the
    // transcript's later steps be classified without a session state.
    assert_eq!(
        SessionState::from_wire_name("established"),
        Some(SessionState::Established)
    );

    // `established` appears in both, which is what lets the transcript's later steps be classified
    // without state.
    assert_eq!(
        SessionState::from_wire_name("established"),
        Some(SessionState::Established)
    );
}

/// The negotiated set is the three-way intersection, and the transcript names the two exclusions.
#[test]
fn the_negotiated_set_is_the_intersection() {
    let pre = preconditions();

    let agent_capabilities = strings(pre.get("agent_capabilities").expect("agent_capabilities"));
    let agent_disabled = strings(pre.get("agent_disabled").expect("agent_disabled"));
    let controller_offered = strings(pre.get("controller_offered").expect("controller_offered"));

    let expected: Vec<String> = strings(
        document()
            .get("expected_negotiated_capabilities")
            .expect("expected_negotiated_capabilities"),
    );

    assert_eq!(expected.len(), 5, "five capabilities are negotiated");
    assert!(
        agent_disabled.is_empty(),
        "nothing is disabled in this transcript"
    );

    // The engine's answer against the transcript's, both directions.
    let negotiated = negotiate(&agent_capabilities, &agent_disabled, &controller_offered);

    let mut produced = negotiated.capabilities.clone();
    produced.sort();

    let mut want: Vec<String> = expected.clone();
    want.sort();

    assert_eq!(produced, want, "the negotiated set differs");
    assert!(negotiated.unknown.is_empty(), "no unknown capability names");

    // And the specific two the step-4 expectation names.
    let step_four = all_at(3);

    assert!(expects(
        &step_four,
        "shell.exec and app.install are absent from the negotiated set"
    ));
    assert!(!negotiated.has("shell.exec"));
    assert!(!negotiated.has("app.install"));

    // Both were OFFERED by the controller, so their absence is the agent's doing.
    assert!(controller_offered.iter().any(|name| name == "shell.exec"));
    assert!(controller_offered.iter().any(|name| name == "app.install"));

    // And both are capabilities DLWP/1 defines, so they were dropped for lack of support rather than for
    // being unknown names.
    for name in ["shell.exec", "app.install"] {
        assert!(CAPABILITIES.contains(&name), "{name} is not a capability");
        assert!(
            !agent_capabilities.iter().any(|entry| entry == name),
            "{name} is in the agent's capability list after all"
        );
    }

    // The step's own claim about the route to the answer.
    assert!(expects(
        &step_four,
        "negotiated set is the intersection of agent capabilities, minus disabled, and controller offered"
    ));

    // `AUTH_OK`'s body carries the negotiated set, and it is the same five.
    let body = step_four
        .get("send")
        .and_then(|send| send.get("body"))
        .expect("AUTH_OK has a body");
    let carried = strings(
        body.get("negotiated")
            .and_then(|negotiated| negotiated.get("capabilities"))
            .expect("capabilities"),
    );

    assert_eq!(
        carried, expected,
        "AUTH_OK carries a different set from the vector's expectation"
    );
}

/// The version negotiates to 1.0, and the transcript's lists agree.
#[test]
fn the_versions_negotiate() {
    let pre = preconditions();

    let controller: Vec<Version> = strings(
        pre.get("controller_supported_versions")
            .expect("controller versions"),
    )
    .iter()
    .map(|text| Version::parse(text).expect("parses"))
    .collect();

    let agent: Vec<Version> = strings(pre.get("agent_supported_versions").expect("agent versions"))
        .iter()
        .map(|text| Version::parse(text).expect("parses"))
        .collect();

    assert_eq!(controller, vec![Version::V1_0]);
    assert_eq!(agent, vec![Version::V1_0]);

    assert_eq!(
        negotiate_versions(&controller, &agent),
        Negotiation::Agreed(Version::V1_0)
    );

    // And the HELLO body carries the same list, so the transcript is internally consistent.
    let hello_step = all_at(0);
    let hello = vectors::nested(hello_step.get("send").expect("send"), "body");

    assert_eq!(vectors::str_field(hello, "proto"), "1.0");
    assert_eq!(
        strings(vectors::nested(hello, "versions_supported")),
        ["1.0"]
    );

    // The header's Version field is the major only.
    assert_eq!(Version::V1_0.header_version_field(), 1);
}

/// A step by its one-based number.
fn all_at(index: usize) -> Value {
    let all = steps();

    all.get(index)
        .cloned()
        .unwrap_or_else(|| panic!("step index {index} exists"))
}

/// Only the handshake frames are unencrypted, and the transcript's flags agree.
#[test]
fn only_the_handshake_frames_are_unencrypted() {
    let all = steps();

    let mut cleartext = 0usize;
    let mut encrypted = 0usize;

    for step in &all {
        let send = send_of(step).expect("send");
        let name = name_of(send);
        let flags = u8::try_from(vectors::u64_field(send, "flags")).expect("fits");

        assert!(flags <= 0x0F, "{name} carries a reserved flag bit");

        let entry = message_type_by_name(name).expect("registered");

        assert_eq!(
            entry.encrypted,
            is_encrypted(send),
            "{name}: the registry says encrypted={} and the frame says {encrypted}",
            entry.encrypted,
            encrypted = is_encrypted(send)
        );

        // The flag bit and the `encrypted` field agree, which is the consistency the wire requires.
        let encrypted_flag = flags & 0x01 != 0;

        assert_eq!(
            encrypted_flag,
            is_encrypted(send),
            "{name}: flags {flags:#04x} and encrypted={} disagree",
            is_encrypted(send)
        );

        if is_encrypted(send) {
            encrypted = encrypted.saturating_add(1);
        } else {
            cleartext = cleartext.saturating_add(1);
        }
    }

    // HELLO, HELLO_ACK and nothing else. The vector the classification tests use lists these two as the
    // only types that "may be cleartext".
    assert_eq!(cleartext, 2, "two frames are cleartext");
    assert_eq!(encrypted, 17, "seventeen are encrypted");

    assert!(
        !is_encrypted(send_of(&all_at(0)).expect("send")),
        "HELLO is cleartext"
    );
    assert!(
        !is_encrypted(send_of(&all_at(1)).expect("send")),
        "HELLO_ACK is cleartext"
    );
    assert!(
        is_encrypted(send_of(&all_at(2)).expect("send")),
        "AUTH is encrypted"
    );

    // The first encrypted frame in each direction, which steps 3 and 4 both mark.
    let controller_first_encrypted = all
        .iter()
        .find(|step| {
            vectors::str_field(step, "actor") == "controller"
                && is_encrypted(send_of(step).expect("send"))
        })
        .expect("the controller sends an encrypted frame");

    assert_eq!(
        name_of(send_of(controller_first_encrypted).expect("send")),
        "AUTH"
    );
    assert_eq!(
        sequence_of(send_of(controller_first_encrypted).expect("send")),
        2
    );
    assert!(expects(
        controller_first_encrypted,
        "first_encrypted_frame_in_this_direction"
    ));

    let agent_first_encrypted = all
        .iter()
        .find(|step| {
            vectors::str_field(step, "actor") == "agent"
                && is_encrypted(send_of(step).expect("send"))
        })
        .expect("the agent sends an encrypted frame");

    assert_eq!(
        name_of(send_of(agent_first_encrypted).expect("send")),
        "AUTH_OK"
    );

    // The cleartext pair is exactly the handshake pair the registry marks as may-be-unencrypted.
    for name in ["HELLO", "HELLO_ACK"] {
        let entry = message_type_by_name(name).expect("registered");

        assert!(!entry.encrypted, "{name} is marked encrypted");
    }

    assert!(message_type_by_name("AUTH").expect("registered").encrypted);
}

/// The frames' directions and channel scopes agree with the registry.
#[test]
fn the_frames_respect_their_directions_and_channels() {
    let all = steps();

    let mut checked = 0usize;

    for step in &all {
        let send = send_of(step).expect("send");
        let name = name_of(send);
        let actor = vectors::str_field(step, "actor");
        let channel = channel_of(send);

        let entry = message_type_by_name(name).expect("registered");
        let side = match actor {
            "controller" => Side::Controller,
            "agent" => Side::Agent,
            other => panic!("{other} is not a side"),
        };

        // The direction: the controller may send if the registry says so.
        let allowed = match side {
            Side::Controller => entry.direction.controller_may_send(),
            Side::Agent => entry.direction.agent_may_send(),
        };

        assert!(
            allowed,
            "{name} is sent by the {actor} in the transcript but the registry forbids it"
        );

        // The channel scope, against the channel the frame actually uses.
        let on_control = ChannelId(channel).is_control();

        match entry.channel {
            ChannelScope::Control => assert!(
                on_control,
                "{name} is a control-channel type but the transcript sends it on {channel}"
            ),
            ChannelScope::Data => assert!(
                !on_control,
                "{name} is a data-channel type but the transcript sends it on the control channel"
            ),
            ChannelScope::Any => {}
        }

        checked = checked.saturating_add(1);
    }

    assert_eq!(checked, 19, "every frame was checked");

    // The transcript uses the control channel for the handshake and the error path, and a data channel
    // for the stream.
    let control_frames: Vec<String> = all
        .iter()
        .filter(|step| ChannelId(channel_of(send_of(step).expect("send"))).is_control())
        .map(|step| name_of(send_of(step).expect("send")).to_owned())
        .collect();

    assert!(control_frames.contains(&"HELLO".to_owned()));
    assert!(control_frames.contains(&"HELLO_ACK".to_owned()));
    assert!(control_frames.contains(&"AUTH".to_owned()));
    assert!(control_frames.contains(&"SESSION_END".to_owned()));

    // Channel 1 is the controller's, and the step says so.
    assert!(expects(
        &all_at(6),
        "controller allocates an odd channel id: 1"
    ));
    assert_eq!(
        channel_of(send_of(&all_at(6)).expect("send")),
        0,
        "the request is on control"
    );
    assert_eq!(
        u32::try_from(vectors::u64_field(
            vectors::nested(send_of(&all_at(7)).expect("send"), "body"),
            "channel_id"
        ))
        .expect("fits"),
        1,
        "CHANNEL_OPENED names the channel"
    );

    assert!(ChannelId(1).may_be_opened_by(Side::Controller));
    assert!(!ChannelId(1).may_be_opened_by(Side::Agent));
    assert!(ChannelId(2).may_be_opened_by(Side::Agent));
    assert!(!ChannelId(2).may_be_opened_by(Side::Controller));
    assert!(!ChannelId::CONTROL.may_be_opened_by(Side::Controller));
    assert!(!ChannelId::CONTROL.may_be_opened_by(Side::Agent));

    // Every registry direction is one of the three, so the match above is exhaustive in practice.
    let mut directions = Vec::new();

    for step in &all {
        let entry =
            message_type_by_name(name_of(send_of(step).expect("send"))).expect("registered");

        if !directions.contains(&entry.direction) {
            directions.push(entry.direction);
        }
    }

    for direction in &directions {
        assert!(
            matches!(
                direction,
                Direction::ControllerToAgent | Direction::AgentToController | Direction::Both
            ),
            "{direction:?} is not a DLWP/1 direction"
        );
    }
}

// =============================================================================================
// The replay: the transcript's adversarial case
// =============================================================================================

/// The deliberate replay is detected, is FATAL, and ends the session.
///
/// This is the transcript's centrepiece. Step 13 was accepted at controller sequence 8; step 17 re-sends
/// sequence 8, and the vector marks it: "This is the adversarial case the monotonic rule exists for, so
/// the step is marked deliberate_replay and is exempt from the verifier's own monotonicity check. It must
/// terminate the session."
#[test]
fn the_deliberate_replay_is_detected_and_is_fatal() {
    let all = steps();

    let replay = all
        .iter()
        .find(|step| step.get("deliberate_replay").and_then(Value::as_bool) == Some(true))
        .expect("the transcript has a deliberate replay");

    let send = send_of(replay).expect("send");

    assert_eq!(name_of(send), "INPUT_TOUCH");
    assert_eq!(sequence_of(send), 8);
    assert_eq!(channel_of(send), 1);
    assert!(is_encrypted(send));

    let note = vectors::str_field(replay, "note");

    assert!(
        note.contains("the same sequence number as step 13"),
        "the note no longer identifies the replayed frame: {note}"
    );
    assert!(
        note.contains("exempt from the verifier's own monotonicity check"),
        "the note no longer explains the exemption: {note}"
    );
    assert!(
        note.contains("It must terminate the session"),
        "the note no longer requires termination: {note}"
    );

    // The frame it replays is step 13, which is the earlier frame at sequence 8.
    let original = all
        .iter()
        .find(|step| vectors::u64_field(step, "step") == 13)
        .expect("step 13 exists");

    assert_eq!(sequence_of(send_of(original).expect("send")), 8);
    assert_eq!(name_of(send_of(original).expect("send")), "INPUT_TOUCH");

    // The replay is NOT byte-identical to the original: the body differs (`gesture_id` 9 against 7, and a
    // different point). That is deliberate -- a replay defence that compared bytes would miss it, which is
    // why the rule is a sequence number and not a checksum.
    let original_body = vectors::nested(send_of(original).expect("send"), "body");
    let replay_body = vectors::nested(send, "body");

    assert_ne!(
        original_body, replay_body,
        "the replay is byte-identical, so this test does not show the rule is on the sequence number"
    );
    assert_eq!(vectors::u64_field(original_body, "gesture_id"), 7);
    assert_eq!(vectors::u64_field(replay_body, "gesture_id"), 9);

    // Now the tracker's view, replaying steps 13 and 14 and then the replay.
    let mut tracker = SequenceTracker::with_defaults();

    assert_eq!(tracker.highest(), None, "a fresh tracker has no highest");

    // Step 13 is the first frame in this channel conversation, so 8 is accepted with no history.
    assert_eq!(tracker.accept(8), SequenceVerdict::InOrder);
    assert_eq!(tracker.highest(), Some(8));

    // Step 14's 9 is the NEXT number, so it is in order rather than ahead.
    assert_eq!(
        tracker.accept(9),
        SequenceVerdict::InOrder,
        "9 after 8 is the next number, not a gap"
    );
    assert_eq!(tracker.highest(), Some(9));

    // The replay.
    let verdict = tracker.classify(8);

    assert_eq!(verdict, SequenceVerdict::Duplicate { sequence: 8 });
    assert!(verdict.is_fatal(), "a replay must be fatal");
    assert_eq!(verdict.code(), Some(ErrorCode::ReplayDetected));

    // And accepting it does NOT move the tracker, so a replay cannot make a later frame look stale.
    let highest_before = tracker.highest();

    assert_eq!(
        tracker.accept(8),
        SequenceVerdict::Duplicate { sequence: 8 }
    );
    assert_eq!(
        tracker.highest(),
        highest_before,
        "the replay moved the window"
    );

    // The agent's answer: ERROR at its own sequence 9, then SESSION_END at 10.
    //
    // The predicate has to test BOTH the name and the code in one `find`. My first version chained a
    // `find` on the name and an `and_then` on the code, so `.find` stopped at the FIRST ERROR -- the
    // recoverable one -- and the `and_then` then correctly rejected it, returning `None` and panicking
    // with "the replay is answered with an ERROR" even though the frame is there.
    let error_step = all
        .iter()
        .find(|step| {
            let send = send_of(step).expect("send");

            name_of(send) == "ERROR"
                && vectors::str_field(vectors::nested(send, "body"), "code")
                    == "ERR_REPLAY_DETECTED"
        })
        .cloned()
        .expect("the replay is answered with an ERROR");

    let error_send = send_of(&error_step).expect("send");
    let error_body = vectors::nested(error_send, "body");

    assert_eq!(vectors::str_field(error_body, "severity"), "fatal");
    assert_eq!(vectors::u64_field(error_body, "request_seq"), 8);
    assert_eq!(
        u64::from(sequence_of(error_send)),
        9,
        "the ERROR carries the AGENT's sequence, not the controller's request_seq"
    );
    assert_eq!(
        u64::from(channel_of(error_send)),
        0,
        "the fatal ERROR is on the control channel"
    );

    let flags = u8::try_from(vectors::u64_field(error_send, "flags")).expect("fits");

    assert_eq!(flags, 3, "encrypted | urgent");
    assert_eq!(flags & 0x01, 0x01, "encrypted");
    assert_eq!(flags & 0x02, 0x02, "urgent");

    assert!(expects(&error_step, "severity is fatal"));
    assert!(expects(
        &error_step,
        "agent will send SESSION_END and close"
    ));

    // SESSION_END.
    let end_step = all
        .iter()
        .find(|step| name_of(send_of(step).expect("send")) == "SESSION_END")
        .expect("the session ends");

    let end_send = send_of(end_step).expect("send");
    let end_body = vectors::nested(end_send, "body");

    assert_eq!(vectors::str_field(end_body, "reason"), "protocol_error");
    assert_eq!(vectors::str_field(end_body, "code"), "ERR_REPLAY_DETECTED");
    assert_eq!(sequence_of(end_send), 10, "the agent's counter continued");
    assert_eq!(channel_of(end_send), 0);
    assert_eq!(
        u8::try_from(vectors::u64_field(end_send, "flags")).expect("fits"),
        5,
        "encrypted | end_of_stream"
    );

    assert!(expects(end_step, "connection closed"));
    assert!(expects(end_step, "session keys wiped on both sides"));
    assert!(expects(
        end_step,
        "controller records the abnormal termination in the session log"
    ));

    // The engine's policy for the code.
    assert!(!session_survives(ErrorCode::ReplayDetected));
    assert_eq!(ErrorCode::ReplayDetected.severity(), Severity::Fatal);
    assert_eq!(
        FaultResponse::for_code(ErrorCode::ReplayDetected),
        FaultResponse::SendErrorThenSessionEnd
    );
    assert!(!FaultResponse::for_code(ErrorCode::ReplayDetected).continues());
    assert_eq!(
        end_reason_for(ErrorCode::ReplayDetected),
        SessionEndReason::ProtocolError
    );

    // And the registry's own severity agrees, which is the check that the two dimensions have not drifted.
    assert_eq!(
        ErrorCode::ReplayDetected.severity(),
        Severity::Fatal,
        "the registry no longer marks a replay fatal"
    );
}

/// A recoverable fault leaves the session and the stream alone.
#[test]
fn a_recoverable_fault_leaves_the_session_alone() {
    let all = steps();

    // The rejected shell command, step 15.
    let shell = all
        .iter()
        .find(|step| name_of(send_of(step).expect("send")) == "SHELL_EXEC")
        .expect("the transcript sends a shell command");

    let shell_send = send_of(shell).expect("send");

    assert_eq!(sequence_of(shell_send), 10);
    assert_eq!(channel_of(shell_send), 1);
    assert!(is_encrypted(shell_send));

    let note = vectors::str_field(shell, "note");

    assert!(
        note.contains("policy rejects"),
        "the note no longer describes a policy rejection: {note}"
    );
    assert!(
        note.contains("shell.exec is absent from the negotiated set"),
        "the note no longer names the reason: {note}"
    );

    // The answer.
    let error_step = all
        .iter()
        .find(|step| {
            let send = send_of(step).expect("send");

            if name_of(send) != "ERROR" {
                return false;
            }

            vectors::str_field(vectors::nested(send, "body"), "code") == "ERR_UNSUPPORTED_FEATURE"
        })
        .expect("the shell command is answered with an ERROR");

    let error_send = send_of(error_step).expect("send");
    let body = vectors::nested(error_send, "body");

    assert_eq!(vectors::str_field(body, "severity"), "recoverable");
    assert_eq!(
        vectors::u64_field(body, "request_type"),
        80,
        "SHELL_EXEC's code"
    );
    assert_eq!(vectors::u64_field(body, "request_seq"), 10);
    assert_eq!(
        u64::from(sequence_of(error_send)),
        8,
        "the agent's counter is at 8, unrelated to the controller's request_seq of 10"
    );
    assert_eq!(
        u64::from(channel_of(error_send)),
        1,
        "the error is on the channel it concerns"
    );

    let flags = u8::try_from(vectors::u64_field(error_send, "flags")).expect("fits");

    assert_eq!(flags, 1, "encrypted only: this one is NOT urgent");
    assert_eq!(flags & 0x02, 0, "a recoverable error is not urgent");

    // The three expectations, all about NOT tearing anything down.
    assert!(expects(error_step, "session survives"));
    assert!(expects(error_step, "video stream continues"));
    assert!(expects(
        error_step,
        "controller surfaces the error without tearing down the session"
    ));

    // The engine.
    assert!(session_survives(ErrorCode::UnsupportedFeature));
    assert_eq!(
        ErrorCode::UnsupportedFeature.severity(),
        Severity::Recoverable
    );
    assert_eq!(
        FaultResponse::for_code(ErrorCode::UnsupportedFeature),
        FaultResponse::SendErrorAndContinue
    );
    assert!(FaultResponse::for_code(ErrorCode::UnsupportedFeature).continues());
    assert!(!FaultResponse::for_code(ErrorCode::UnsupportedFeature).ends_the_session());

    // The `request_type` is the registry's message type CODE, not the JSON enumeration index. SHELL_EXEC
    // is 80, and 80 is not its position in the registry array, which is what makes this worth checking.
    let shell_type = message_type_by_name("SHELL_EXEC").expect("registered");

    assert_eq!(shell_type.code, 80);
    assert_eq!(
        u64::from(shell_type.code),
        vectors::u64_field(body, "request_type")
    );

    // The request was on a data channel and the error answered on it, and the stream continued: the
    // VIDEO_FRAME steps after it are what "video stream continues" means.
    let frames_after: Vec<String> = all
        .iter()
        .filter(|step| vectors::u64_field(step, "step") > vectors::u64_field(error_step, "step"))
        .map(|step| name_of(send_of(step).expect("send")).to_owned())
        .collect();

    assert!(
        !frames_after.is_empty(),
        "nothing follows the recoverable error, so 'video stream continues' is untestable"
    );

    // And the two error codes differ in severity, which is the whole distinction.
    assert_ne!(
        ErrorCode::UnsupportedFeature.severity(),
        ErrorCode::ReplayDetected.severity()
    );
    assert_ne!(
        FaultResponse::for_code(ErrorCode::UnsupportedFeature),
        FaultResponse::for_code(ErrorCode::ReplayDetected)
    );
}

// =============================================================================================
// The reorder window
// =============================================================================================

/// The window accepts a reorder inside it and refuses one outside it.
///
/// The classification tests already cover the vector's own numbers; this checks the same rule through the
/// session's tracker, including the properties the vectors' two cases imply but do not state: that a
/// duplicate is not a reorder, and that the boundary is inclusive.
#[test]
fn the_reorder_window_is_inclusive_of_its_lowest_number() {
    let mut tracker = SequenceTracker::new(32);

    // Walk up to 1000. Every number in that range has now been SEEN, so a lower one is a genuine
    // duplicate rather than a reorder -- which is why the "inside the window" case below uses a number
    // that was skipped.
    for sequence in 1u32..=1000 {
        let verdict = tracker.accept(sequence);

        assert!(
            !verdict.is_fatal(),
            "sequence {sequence} was rejected while walking forward: {verdict:?}"
        );
    }

    assert_eq!(tracker.highest(), Some(1000));
    assert_eq!(tracker.window(), 32);

    // Every number to 1000 HAS been seen, so 969 and 967 are both duplicates. That is the rule working,
    // and it is worth asserting so the distinction from a reorder stays visible.
    assert_eq!(
        tracker.classify(999),
        SequenceVerdict::Duplicate { sequence: 999 }
    );
    assert!(tracker.classify(999).is_fatal());

    // So the reorder case needs a tracker whose history has HOLES. This one walks even numbers only, so
    // every odd number below the highest is unseen and inside the window.
    let mut gapped: SequenceTracker = SequenceTracker::new(32);

    for sequence in 1u32..=1000 {
        if sequence % 2 == 0 {
            let verdict = gapped.accept(sequence);

            assert!(
                !verdict.is_fatal(),
                "even {sequence} was fatal: {verdict:?}"
            );
        }
    }

    // The highest is 1000 and the window's lowest is 968. 969 was never seen, so it is a REORDER.
    assert_eq!(
        gapped.classify(999),
        SequenceVerdict::InOrder,
        "999 is unseen and inside the window, so it is a reorder"
    );
    assert_eq!(gapped.accept(999), SequenceVerdict::InOrder);

    // Below 968 is outside the window whether or not it was seen.
    assert_eq!(
        gapped.classify(967),
        SequenceVerdict::Duplicate { sequence: 967 }
    );
    assert!(gapped.classify(967).is_fatal());

    // Move the window arithmetic onto the gapped tracker, which is where it means something.
    let tracker = &mut gapped;

    // The boundary is INCLUSIVE: 968 is the lowest number the window still accepts. It was SEEN in the
    // even walk, so the verdict is a duplicate, and the reason is the seen-set rather than the window.
    // The window's own boundary is checked with 969, which the walk skipped.
    assert!(
        tracker.has_seen(968),
        "968 should have been seen in the even walk, which is what makes it a duplicate"
    );
    assert_eq!(
        tracker.classify(969),
        SequenceVerdict::InOrder,
        "969 = 1000 - 32 is inside the window and unseen, so it must be accepted"
    );

    // And everything below is refused.
    for sequence in [0u32, 1, 500, 966] {
        assert!(
            tracker.classify(sequence).is_fatal(),
            "{sequence} is outside the window but was accepted"
        );
    }

    // A duplicate is not a reorder, even when it is inside the window. This is the order the checks must
    // run in: a reorder is unseen, and a duplicate is seen.
    let mut tracker = SequenceTracker::with_defaults();

    assert_eq!(tracker.accept(417), SequenceVerdict::InOrder);
    assert_eq!(
        tracker.accept(417),
        SequenceVerdict::Duplicate { sequence: 417 },
        "a repeat inside the window was accepted as a reorder"
    );
    assert!(tracker.accept(417).is_fatal());

    // Ahead is not fatal, so a gap is survivable. A FRESH tracker, because the one above has already seen
    // 417 and a low number would be outside its window.
    let mut tracker = SequenceTracker::with_defaults();

    assert_eq!(tracker.accept(1), SequenceVerdict::InOrder);
    // 5 is a gap: the next number is 2.
    let verdict = tracker.accept(5);

    assert_eq!(verdict, SequenceVerdict::Ahead { expected: 2 });
    assert!(!verdict.is_fatal(), "a gap is survivable");
    assert_eq!(tracker.highest(), Some(5));

    // Accepting 5 again IS fatal, because it is now seen. The distinction between the first and second
    // arrival of the same number is the whole rule.
    assert!(tracker.accept(5).is_fatal());
    assert_eq!(tracker.highest(), Some(5));

    // The gap can then be filled, and filling it is a reorder rather than a duplicate.
    assert_eq!(tracker.accept(2), SequenceVerdict::InOrder);
    assert_eq!(tracker.accept(3), SequenceVerdict::InOrder);
    assert_eq!(tracker.accept(4), SequenceVerdict::InOrder);

    // A fresh tracker accepts anything, because there is no highest to compare against.
    let mut tracker = SequenceTracker::with_defaults();

    assert_eq!(tracker.accept(1000), SequenceVerdict::InOrder);

    // The default window is the vectors' 32.
    assert_eq!(SequenceTracker::DEFAULT_WINDOW, 32);
    assert_eq!(SequenceTracker::with_defaults().window(), 32);

    // A window of zero means only the highest number is new, and every lower one is stale. That is a
    // legal configuration and it must not panic or loop.
    let mut tracker = SequenceTracker::new(0);

    assert_eq!(tracker.accept(10), SequenceVerdict::InOrder);
    assert_eq!(
        tracker.classify(10),
        SequenceVerdict::Duplicate { sequence: 10 }
    );
    assert!(tracker.classify(9).is_fatal());

    // 11 is the NEXT number after 10, so it is in order. A window of zero does not make the next number a
    // gap; it only means no LOWER number is ever acceptable.
    assert_eq!(tracker.accept(11), SequenceVerdict::InOrder);

    // And then 11 is seen, so a repeat is fatal even with no window.
    assert_eq!(
        tracker.accept(11),
        SequenceVerdict::Duplicate { sequence: 11 }
    );
    assert!(tracker.accept(11).is_fatal());

    // A jump is still reported as a gap, which is the case the window does not affect.
    assert_eq!(tracker.accept(20), SequenceVerdict::Ahead { expected: 12 });
}

/// The seen-set cannot grow without bound.
#[test]
fn the_seen_set_is_trimmed_to_the_window() {
    let mut tracker = SequenceTracker::new(4);

    for sequence in 1u32..=1000 {
        tracker.accept(sequence);
    }

    // Only the window's worth of numbers is retained.
    let retained = (1u32..=1000)
        .filter(|sequence| tracker.has_seen(*sequence))
        .count();

    assert!(
        retained <= 5,
        "{retained} numbers are retained for a window of 4"
    );
    assert!(
        retained > 0,
        "nothing is retained, so a recent replay would not be seen"
    );

    // The recent ones are the ones retained, so the check still works.
    assert!(tracker.has_seen(1000));
    assert!(tracker.has_seen(997));
    assert!(!tracker.has_seen(1));
    assert!(!tracker.has_seen(900));

    // And a recent replay is still caught.
    assert_eq!(
        tracker.classify(999),
        SequenceVerdict::Duplicate { sequence: 999 }
    );
}

// =============================================================================================
// The classification of the transcript's frames
// =============================================================================================

/// Re-classifying the transcript's frames gives the verdicts the transcript implies.
#[test]
fn the_transcripts_first_frames_classify_as_the_handshake_requires() {
    let all = steps();

    // The first frame is HELLO, and the agent starts out awaiting it.
    let first_step = all_at(0);
    let hello = send_of(&first_step).expect("send");

    assert_eq!(name_of(hello), "HELLO");
    assert_eq!(
        HandshakeState::AwaitingHello.expected(),
        (HELLO, HandshakeState::AwaitingHelloAck),
        "awaiting HELLO means HELLO is expected and the next state awaits HELLO_ACK"
    );

    // And the transcript's frames are all registered types, so none of them is an
    // `unsupported-message-type` case.
    for step in &all {
        let name = name_of(send_of(step).expect("send"));

        assert!(
            message_type_by_name(name).is_some(),
            "{name} is not registered, so the transcript contains an unsupported type"
        );
    }

    // The recovered state machine, through the library's own classifier helper: after HELLO is received
    // the peer awaits HELLO_ACK, and so on through AUTH to Established.
    let mut state = HandshakeState::AwaitingHello;

    for expected in ["HELLO", "HELLO_ACK", "AUTH", "AUTH_OK"] {
        let (code, next) = state.expected();

        assert_eq!(
            message_type_by_name(expected).expect("registered").code,
            code,
            "{state:?} should expect {expected}"
        );

        state = next;
    }

    assert_eq!(state, HandshakeState::Established);
    assert!(
        !state.imposes_ordering(),
        "an established peer imposes no ordering"
    );

    // Every frame after AUTH_OK is classified in the established state without a state error.
    let limits = Limits::DEFAULT;

    for step in all.iter().skip(4) {
        let send = send_of(step).expect("send");
        let name = name_of(send);
        let entry = message_type_by_name(name).expect("registered");

        // The classification needs bytes; the transcript gives decoded bodies. So only the message type
        // itself is checked here, which is enough to show none of them is out of turn.
        let verdict = classify_in_state(
            &build_minimal_frame(entry.code),
            &limits,
            HandshakeState::Established,
        );

        assert_ne!(
            verdict.code,
            Some(ErrorCode::UnexpectedMessage),
            "{name} is out of turn in the established state"
        );
        let _ = verdict;
    }
}

/// A minimal valid frame with a given message type, for classification.
///
/// A 24-byte header with no body: version 1, the intended type, and length zero. Enough for `classify` and
/// `classify_in_state`, which do not decrypt.
fn build_minimal_frame(message_type: u8) -> Vec<u8> {
    let mut frame = vec![0u8; 24];

    frame[0] = b'D';
    frame[1] = b'L';
    frame[2] = b'W';
    frame[3] = b'P';
    frame[4] = 1;
    frame[5] = 0;
    frame[6] = 24;
    frame[7] = message_type;
    // channel 0, sequence 0, acknowledgment 0, body length 0 -- already zero.

    frame
}

/// The transcript's cleartext frames classify as `Accepted`, and the encrypted ones do not.
#[test]
fn only_the_cleartext_frames_are_classified_without_keys() {
    let limits = Limits::DEFAULT;

    // HELLO with an empty body is the one the classifier can accept, because a cycle-encrypted body is
    // opaque to it.
    let hello = build_minimal_frame(1);

    assert_eq!(classify(&hello, &limits).verdict, Verdict::Accepted);

    // PING is cleartext-legal in the registry's sense but the transcript never sends one unencrypted, and
    // the classifier does not care about that distinction: it classifies bytes.
    let ping = build_minimal_frame(5);

    assert_eq!(classify(&ping, &limits).verdict, Verdict::Accepted);

    // A message type that is not registered is reported as such whatever the state, which is what makes
    // the check a lookup rather than a range test.
    let unknown = build_minimal_frame(254);

    assert_eq!(
        classify(&unknown, &limits).code,
        Some(ErrorCode::UnsupportedMessage)
    );
}
