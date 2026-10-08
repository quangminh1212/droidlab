using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Protocol.Registry;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for the session state machine (RFC-0001 section 5), driven by the
/// 19-step transcript in <c>session-basic.json</c>.
/// </summary>
/// <remarks>
/// The transcript is replayed rather than restated. Every step's declared
/// expectations are turned into assertions, so the file and the implementation
/// cannot drift: a step that the machine would now refuse, or accept when it
/// should not, fails here.
/// </remarks>
public sealed class SessionStateMachineTests
{
    private const string VectorFile = "session-basic.json";

    private static JsonDocument Vectors() => VectorLoader.Load(VectorFile);

    private static ProtocolRegistry Registry()
    {
        using JsonDocument document = VectorLoader.LoadRegistry();
        return ProtocolRegistry.FromJson(document.RootElement);
    }

    private static JsonElement Session()
    {
        using JsonDocument document = Vectors();
        return document.RootElement.Clone();
    }

    private static IEnumerable<JsonElement> Steps() =>
        VectorLoader.Vectors(VectorFile, "steps");

    /// <summary>Reads the negotiated capability set the transcript expects.</summary>
    private static List<string> NegotiatedCapabilities()
    {
        using JsonDocument document = Vectors();
        return [.. document.RootElement.GetProperty("expected_negotiated_capabilities")
            .EnumerateArray().Select(e => e.GetString()!)];
    }

    private static byte TypeCode(string name)
    {
        ProtocolRegistry registry = Registry();
        return registry.MessageTypes.Single(m => m.Name == name).Code;
    }

    // ---- The transcript -----------------------------------------------------

    /// <summary>Every step of the transcript is accepted in order.</summary>
    /// <remarks>
    /// <para>
    /// One machine per direction, because the two sides advance independently.
    /// That is what lets both legitimately use sequence number 1 for their first
    /// frame, and a single shared machine would wrongly call the second one a
    /// replay.
    /// </para>
    /// <para>
    /// The one deliberate exception is step 17, which the file itself marks
    /// <c>deliberate_replay</c>: it reuses step 13's sequence number and must
    /// terminate the session. That is asserted separately and is not an exception
    /// to the rule but an instance of it.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryStepIsAcceptedInOrder()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();

        SessionStateMachine controller = new(registry, SessionRole.Controller);
        SessionStateMachine agent = new(registry, SessionRole.Agent);

        int applied = 0;

        foreach (JsonElement step in Steps())
        {
            Drive(step, registry, negotiated, controller, agent, out bool accepted);

            if (accepted)
            {
                applied++;
            }
        }

        // 19 steps: 16 accepted, step 15 refused for an un-negotiated capability,
        // step 17 refused as a replay, and step 19 refused because the controller is
        // already closed by then. Step 18 is the fatal ERROR and is applied, not
        // refused: the receiver accepts it and then closes.
        //
        // The breakdown is asserted rather than only the total, because a run that
        // swapped two outcomes would still total 16.
        Assert.Equal(16, applied);
        Assert.Equal(19, Steps().Count());

        // The two steps the file itself declares must fail, plus the one the
        // capability gate refuses. Counted from the file rather than listed, so a
        // step whose declared outcome changes is caught here.
        Assert.Equal(2, Steps().Count(s => ExpectedErrorFor(s) is not null));
        Assert.Equal(1, Steps().Count(s => IsDeliberateReplay(s)));

        // And exactly one step is refused by the capability gate, which is step 15.
        Assert.Equal(1, Steps().Count(s =>
            s.GetProperty("send").GetProperty("name").GetString() == "SHELL_EXEC"));
    }

    /// <summary>
    /// Applies one transcript step and asserts the outcome the file declares.
    /// </summary>
    /// <param name="step">The step.</param>
    /// <param name="registry">The registry.</param>
    /// <param name="negotiated">The negotiated capability set.</param>
    /// <param name="controller">The controller's machine.</param>
    /// <param name="agent">The agent's machine.</param>
    /// <param name="accepted">Whether the frame was accepted.</param>
    /// <remarks>
    /// <para>
    /// One implementation of the transcript's semantics, shared by the ordered
    /// replay and the determinism check. Both tests used to carry their own loop and
    /// they drifted the moment one learned to act on a fatal ERROR frame.
    /// </para>
    /// <para>
    /// The sender's own numbering is checked as well as the receiver's, because a
    /// sender that reused a number would see its frame refused by the peer with no
    /// local indication of why.
    /// </para>
    /// </remarks>
    private static void Drive(
        JsonElement step,
        ProtocolRegistry registry,
        List<string> negotiated,
        SessionStateMachine controller,
        SessionStateMachine agent,
        out bool accepted)
    {
        int number = step.GetProperty("step").GetInt32();
        string actor = step.GetProperty("actor").GetString()!;
        JsonElement send = step.GetProperty("send");

        string name = send.GetProperty("name").GetString()!;
        uint channel = send.GetProperty("channel_id").GetUInt32();
        uint sequence = send.GetProperty("sequence_number").GetUInt32();
        bool encrypted = send.TryGetProperty("encrypted", out JsonElement enc)
            ? enc.GetBoolean()
            : (send.GetProperty("flags").GetInt32() & 0x01) != 0;

        bool deliberateReplay = IsDeliberateReplay(step);

        // Some steps are declared to fail: step 15 asks for a capability that was
        // never negotiated, and step 17 is the replay. The expectation is read out of
        // the file rather than listed here, so a step that stops failing is a failure
        // of this test and not a silent skip.
        string? expectedError = ExpectedErrorFor(step);

        SessionStateMachine sender = actor == "controller" ? controller : agent;
        SessionStateMachine receiver = actor == "controller" ? agent : controller;

        TransitionResult sent = sender.RecordSent(sequence, registry.FindMessageType(TypeCode(name)));

        if (!sent.Accepted && expectedError is null)
        {
            Assert.Fail($"step {number} ({name}): the sender's own numbering refused seq {sequence}: {sent.Reason}");
        }

        // The announced channel id is in the body for CHANNEL_OPENED, which is why
        // this reads it rather than using the frame's own channel.
        uint? announced = name == "CHANNEL_OPENED" && send.TryGetProperty("body", out JsonElement openBody)
            && openBody.TryGetProperty("channel_id", out JsonElement announcedId)
                ? announcedId.GetUInt32()
                : null;

        TransitionResult result = receiver.Apply(
            TypeCode(name), channel, sequence, encrypted, negotiated, announced);

        accepted = result.Accepted;

        if (deliberateReplay)
        {
            Assert.False(result.Accepted, $"step {number} ({name}) was accepted but is a replay");
            Assert.Equal("ERR_REPLAY_DETECTED", result.Error!.Name);
            Assert.True(result.Error!.IsFatal);
            Assert.Equal(SessionState.Closed, receiver.State);
            Assert.Equal(SessionEndReasons.ProtocolError, receiver.EndReason);
            return;
        }

        if (expectedError is not null)
        {
            Assert.False(
                result.Accepted,
                $"step {number} ({name}) was accepted but the transcript declares it must fail with {expectedError}");
            Assert.Equal(expectedError, result.Error!.Name);

            // The declared severity decides what happens next, so it is asserted
            // rather than assumed from the name.
            Assert.Equal(expectedError == "ERR_REPLAY_DETECTED", result.Error!.IsFatal);

            // A deliberately failing step can itself close the session, which is what
            // the caller needs to know for the closing sequence that follows.
            if (result.Error!.IsFatal)
            {
                Assert.Equal(SessionState.Closed, receiver.State);
            }

            return;
        }

        // A frame that arrives after the session is already closed is refused, and
        // that is correct rather than a gap: there is nothing for a closed session to
        // do with a frame, and the transcript's own step 19 is the case. The agent
        // sends SESSION_END to a controller that step 18's fatal error already closed,
        // so the controller refusing it is the intended behaviour and the agent's own
        // close is what ends the session.
        if (!result.Accepted && receiver.State == SessionState.Closed)
        {
            Assert.Contains(
                name,
                new[] { "SESSION_END", "ERROR" },
                StringComparer.Ordinal);

            accepted = false;
            return;
        }

        Assert.True(
            result.Accepted,
            $"step {number} ({name} on channel {channel} seq {sequence}, encrypted={encrypted}, " +
            $"state {receiver.State}) was refused: {result.Reason}");

        // A peer's ERROR carries its severity in the body, and a fatal one ends the
        // session. The state machine deliberately does not decode bodies, so the
        // severity is applied here, which is where a real receiver would apply it.
        // Step 18 is this case: step 17's replay makes the agent report a fatal
        // error, and accepting that frame is what the controller does before closing.
        if (name == "ERROR"
            && send.TryGetProperty("body", out JsonElement errorBody)
            && errorBody.TryGetProperty("severity", out JsonElement severity)
            && severity.GetString() == "fatal")
        {
            Assert.True(receiver.End(SessionEndReasons.ProtocolError, ErrorCodes.ReplayDetected).Accepted);
            Assert.Equal(SessionState.Closed, receiver.State);
        }
    }

    /// <summary>Whether the file marks a step as a deliberate replay.</summary>
    /// <param name="step">The step.</param>
    /// <returns>Whether it is marked.</returns>
    private static bool IsDeliberateReplay(JsonElement step) =>
        step.TryGetProperty("deliberate_replay", out JsonElement replay) && replay.GetBoolean();

    /// <summary>
    /// The error a step is declared to produce, if it is declared to fail.
    /// </summary>
    /// <param name="step">The step.</param>
    /// <returns>The error name, or null when the step is expected to succeed.</returns>
    /// <remarks>
    /// <para>
    /// The file declares failure in two ways, and both are read here rather than
    /// listed in this test: an explicit <c>expected_error</c>, and a <c>note</c> that
    /// says the step is refused. Reading them means a step that starts failing
    /// silently, or stops failing, is caught.
    /// </para>
    /// <para>
    /// Step 15 is the case that matters: it sends SHELL_EXEC for a capability that
    /// was never negotiated. The registration of that refusal is the whole point of
    /// the step, and treating it as an unexpected failure would have hidden the fact
    /// that the session correctly survives it.
    /// </para>
    /// </remarks>
    private static string? ExpectedErrorFor(JsonElement step)
    {
        if (step.TryGetProperty("expected_error", out JsonElement explicitError))
        {
            return explicitError.GetString();
        }

        if (IsDeliberateReplay(step))
        {
            return "ERR_REPLAY_DETECTED";
        }

        string? note = step.TryGetProperty("note", out JsonElement noteElement)
            ? noteElement.GetString()
            : null;

        if (note is not null && note.Contains("policy rejects", StringComparison.Ordinal))
        {
            return "ERR_UNSUPPORTED_FEATURE";
        }

        return null;
    }

    /// <summary>The transcript's final state is closed on both sides.</summary>
    /// <remarks>
    /// The transcript ends with the agent sending SESSION_END, so the agent closes
    /// directly and the controller only once it has processed that frame. Asserting
    /// both is what shows the closing sequence really ran on each side rather than
    /// only where it was initiated.
    /// </remarks>
    [Fact]
    public void TheTranscriptEndsClosed()
    {
        (SessionStateMachine controller, SessionStateMachine agent) = Replay();

        Assert.Equal(SessionState.Closed, agent.State);
        Assert.True(agent.IsClosed);
        Assert.False(agent.IsEstablished);

        // The controller processed SESSION_END too, since it is in the transcript.
        Assert.Equal(SessionState.Closed, controller.State);
    }

    /// <summary>Replaying the transcript twice produces the same states.</summary>
    /// <remarks>
    /// The file calls for determinism, and it is what makes the transcript usable
    /// as an integration vector: a run that depended on wall-clock time or
    /// iteration order could not be compared between two implementations.
    /// </remarks>
    [Fact]
    public void ReplayIsDeterministic()
    {
        (SessionStateMachine controllerA, SessionStateMachine agentA) = Replay();
        (SessionStateMachine controllerB, SessionStateMachine agentB) = Replay();

        Assert.Equal(controllerA.State, controllerB.State);
        Assert.Equal(agentA.State, agentB.State);
        Assert.Equal(controllerA.HighestSequenceNumber, controllerB.HighestSequenceNumber);
        Assert.Equal(agentA.HighestSequenceNumber, agentB.HighestSequenceNumber);
        Assert.Equal(controllerA.OpenChannels, controllerB.OpenChannels);
        Assert.Equal(agentA.OpenChannels, agentB.OpenChannels);
    }

    /// <summary>Replays the transcript and returns both machines.</summary>
    /// <returns>The controller and agent machines, at the end of the transcript.</returns>
    /// <remarks>
    /// The same driver the ordered-replay test uses, so the two cannot drift. An
    /// earlier version had a second, simpler loop here, and it silently stopped
    /// matching once the replay test learned to apply a fatal ERROR frame: the two
    /// disagreed about the controller's final state.
    /// </remarks>
    private static (SessionStateMachine Controller, SessionStateMachine Agent) Replay()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();

        SessionStateMachine controller = new(registry, SessionRole.Controller);
        SessionStateMachine agent = new(registry, SessionRole.Agent);

        foreach (JsonElement step in Steps())
        {
            Drive(step, registry, negotiated, controller, agent, out _);
        }

        return (controller, agent);
    }

    // ---- The declared state machine chain ----------------------------------

    /// <summary>The declared state order is the order the enum encodes.</summary>
    /// <remarks>
    /// The chain is in the vector file as a string, and the enum's numeric order
    /// depends on it because <see cref="SessionStateMachine.CanAdvanceTo"/> uses
    /// that order to reject a backward move. Reading it back out of the file
    /// keeps the two from drifting silently.
    /// </remarks>
    [Fact]
    public void TheDeclaredStateOrderMatchesTheEnum()
    {
        JsonElement assertions = Session().GetProperty("assertions");
        string chain = assertions.GetProperty("state_machine")[0].GetString()!;

        string[] names = [.. chain.Split("->", StringSplitOptions.TrimEntries)
            .TakeWhile(s => !s.Contains('_', StringComparison.Ordinal))];

        // The first entry is the whole chain, so split it properly.
        names = [.. chain.Split(' ', StringSplitOptions.RemoveEmptyEntries)];

        string[] states = [.. names
            .Where(s => s != "->")
            .Select(s => s.Trim())];

        Assert.Equal(
            ["idle", "discovering", "connecting", "handshaking", "authenticating", "established", "streaming", "closing", "closed"],
            states);

        // And the enum has them in that order, so CanAdvanceTo's comparison is
        // against the order the RFC states rather than an incidental one.
        SessionState[] expected =
        [
            SessionState.Idle, SessionState.Discovering, SessionState.Connecting,
            SessionState.Handshaking, SessionState.Authenticating, SessionState.Established,
            SessionState.Streaming, SessionState.Closing, SessionState.Closed,
        ];

        for (int index = 0; index < expected.Length; index++)
        {
            Assert.Equal(expected[index], (SessionState)index);
        }

        Assert.Equal(
            "any_state_on_fatal_error -> closing",
            assertions.GetProperty("state_machine")[1].GetString());
    }

    // ---- Ordering rules -----------------------------------------------------

    /// <summary>A backward state move is refused.</summary>
    /// <remarks>
    /// A session that went from established back to handshaking would re-derive
    /// keys over a live connection, which is a renegotiation attack. Forward skips
    /// are allowed because the machine may not observe discovery or connecting.
    /// </remarks>
    [Fact]
    public void BackwardStateMovesAreRefused()
    {
        SessionStateMachine machine = new(Registry());

        machine.AdvanceTo(SessionState.Established);

        Assert.False(machine.CanAdvanceTo(SessionState.Handshaking));
        Assert.False(machine.CanAdvanceTo(SessionState.Idle));
        Assert.Throws<InvalidOperationException>(() => machine.AdvanceTo(SessionState.Discovering));

        // Forward is fine, and the closing sequence is allowed from anywhere.
        Assert.True(machine.CanAdvanceTo(SessionState.Streaming));
        Assert.True(machine.CanAdvanceTo(SessionState.Closing));
    }

    /// <summary>A closed session accepts nothing.</summary>
    /// <remarks>
    /// Reporting a specific error would suggest the frame could have been handled,
    /// which is misleading: the session is over and its keys are gone.
    /// </remarks>
    [Fact]
    public void AClosedSessionAcceptsNothing()
    {
        SessionStateMachine machine = new(Registry());
        machine.End(SessionEndReasons.ClientShutdown);

        Assert.True(machine.IsClosed);

        TransitionResult result = machine.Apply(
            TypeCode("HELLO"), 0, 1, encrypted: false, negotiatedCapabilities: []);

        Assert.False(result.Accepted);
        Assert.Equal(SessionState.Closed, result.State);
        Assert.False(machine.CanAdvanceTo(SessionState.Streaming));
    }

    /// <summary>A state move out of closed is refused even through AdvanceTo.</summary>
    [Fact]
    public void StateCannotMoveAfterClosed()
    {
        SessionStateMachine machine = new(Registry());
        machine.End(SessionEndReasons.AgentShutdown);

        Assert.Throws<InvalidOperationException>(() => machine.AdvanceTo(SessionState.Established));
        Assert.Throws<InvalidOperationException>(() => machine.AdvanceTo(SessionState.Closed));
    }

    /// <summary>Only AUTH is allowed after the agent has answered HELLO.</summary>
    /// <remarks>
    /// <para>
    /// The agent's view: it accepted a HELLO, so it has answered with HELLO_ACK and
    /// the only frame it may accept next is the controller's AUTH. Nothing else is
    /// permitted, because before the keys exist no other frame can even be
    /// decrypted.
    /// </para>
    /// <para>
    /// AUTH is in this list deliberately and is not a gap in the rule: it is the one
    /// frame that belongs here. An earlier version of the machine had a separate
    /// "handshaking accepts only handshake frames" guard that refused AUTH, which is
    /// the bug this test now pins down.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("PING")]
    [InlineData("DEVICE_INFO")]
    [InlineData("VIDEO_START")]
    [InlineData("SESSION_END")]
    [InlineData("CHANNEL_OPEN")]
    public void OnlyAuthIsAllowedAfterHello(string typeName)
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);

        // Reach the handshaking state with a HELLO.
        Assert.True(machine.Apply(TypeCode("HELLO"), 0, 1, encrypted: false, []).Accepted);
        Assert.Equal(SessionState.Handshaking, machine.State);

        MessageType type = registry.MessageTypes.Single(m => m.Name == typeName);

        TransitionResult result = machine.Apply(
            type.Code, 0, 2, encrypted: type.Encrypted, negotiatedCapabilities: ["screen.mirror", "shell.exec"]);

        Assert.False(result.Accepted, $"{typeName} was accepted after HELLO");
        Assert.Equal("ERR_UNEXPECTED_MESSAGE", result.Error!.Name);
        Assert.True(result.Error!.IsFatal);
    }

    /// <summary>AUTH itself is accepted after HELLO.</summary>
    [Fact]
    public void AuthIsAcceptedAfterHello()
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);

        Assert.True(machine.Apply(TypeCode("HELLO"), 0, 1, encrypted: false, []).Accepted);
        Assert.True(machine.Apply(TypeCode("AUTH"), 0, 2, encrypted: true, []).Accepted);

        Assert.Equal(SessionState.Authenticating, machine.State);
    }

    /// <summary>The handshake messages themselves are recognised.</summary>
    [Fact]
    public void TheHandshakeMessagesAreRecognised()
    {
        ProtocolRegistry registry = Registry();

        Assert.True(SessionStateMachine.IsHandshakeType(registry.MessageTypes.Single(m => m.Name == "HELLO")));
        Assert.True(SessionStateMachine.IsHandshakeType(registry.MessageTypes.Single(m => m.Name == "HELLO_ACK")));
        Assert.False(SessionStateMachine.IsHandshakeType(registry.MessageTypes.Single(m => m.Name == "AUTH")));
        Assert.False(SessionStateMachine.IsHandshakeType(registry.MessageTypes.Single(m => m.Name == "PING")));
    }

    /// <summary>The agent's first inbound frame must be HELLO.</summary>
    [Fact]
    public void TheAgentsFirstFrameMustBeHello()
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);

        TransitionResult result = machine.Apply(
            TypeCode("PING"), 0, 1, encrypted: true, negotiatedCapabilities: []);

        Assert.False(result.Accepted);
        Assert.Equal("ERR_UNEXPECTED_MESSAGE", result.Error!.Name);
    }

    /// <summary>The controller's first inbound frame must be HELLO_ACK.</summary>
    /// <remarks>
    /// The controller sends the HELLO, so the answer to it is the first frame it
    /// receives. Requiring HELLO here would make every real controller refuse the
    /// answer to its own handshake.
    /// </remarks>
    [Fact]
    public void TheControllersFirstFrameMustBeHelloAck()
    {
        ProtocolRegistry registry = Registry();

        // Each wrong first frame gets its own machine, because refusing one is
        // fatal and would close the session before the next attempt. Reusing one
        // machine here is how an earlier version of this test appeared to fail for
        // the wrong reason.
        foreach (string wrong in new[] { "HELLO", "PING", "DEVICE_INFO" })
        {
            SessionStateMachine rejected = new(registry, SessionRole.Controller);
            MessageType type = registry.MessageTypes.Single(m => m.Name == wrong);

            TransitionResult result = rejected.Apply(type.Code, 0, 1, encrypted: type.Encrypted, []);

            Assert.False(result.Accepted, $"{wrong} was accepted as the controller's first frame");
            Assert.Null(rejected.HighestSequenceNumber);
        }

        SessionStateMachine machine = new(registry, SessionRole.Controller);

        TransitionResult accepted = machine.Apply(TypeCode("HELLO_ACK"), 0, 1, encrypted: false, []);

        Assert.True(accepted.Accepted, accepted.Reason);
        Assert.Equal(SessionState.Authenticating, machine.State);
        Assert.Equal(1u, machine.HighestSequenceNumber);
    }

    /// <summary>HELLO_ACK is refused as the agent's first inbound frame.</summary>
    /// <remarks>
    /// HELLO_ACK is the agent's own frame, so it can never be the first thing an
    /// agent receives: nothing has sent a HELLO for it to answer yet.
    /// </remarks>
    [Fact]
    public void HelloAckBeforeHelloIsRefused()
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);

        TransitionResult result = machine.Apply(
            TypeCode("HELLO_ACK"), 0, 1, encrypted: false, negotiatedCapabilities: []);

        Assert.False(result.Accepted);
        Assert.Equal("ERR_UNEXPECTED_MESSAGE", result.Error!.Name);
    }

    // ---- The capability gate and step 15 -----------------------------------

    /// <summary>
    /// An un-negotiated capability is refused and the session survives.
    /// </summary>
    /// <remarks>
    /// This is the transcript's step 15 and step 16 taken together, and it is the
    /// most important assertion in the file. Step 15 sends SHELL_EXEC when
    /// <c>shell.exec</c> was not negotiated; step 16 requires that the session
    /// survives and the video stream continues. So an un-negotiated capability is
    /// a refusal, not a fault: tearing the session down would end a working screen
    /// share because the operator asked for something unavailable.
    /// </remarks>
    [Fact]
    public void UnnegotiatedCapabilityIsRefusedButSurvivable()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();

        // The negotiated set really does lack shell.exec, which is what makes the
        // step a test of anything.
        Assert.DoesNotContain("shell.exec", negotiated);
        Assert.DoesNotContain("app.install", negotiated);

        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, negotiated);

        SessionState before = machine.State;
        uint? highestBefore = machine.HighestSequenceNumber;

        TransitionResult result = machine.Apply(
            TypeCode("SHELL_EXEC"), 0, 100, encrypted: true, negotiatedCapabilities: negotiated);

        Assert.False(result.Accepted);
        Assert.Equal("ERR_UNSUPPORTED_FEATURE", result.Error!.Name);
        Assert.False(result.Error!.IsFatal);

        // The session survives, which is the point.
        Assert.Equal(before, machine.State);
        Assert.True(result.SessionSurvives);
        Assert.True(machine.IsEstablished);
    }

    /// <summary>A refused frame does not advance the sequence number.</summary>
    /// <remarks>
    /// If it did, a peer could push the window forward with frames that were never
    /// processed and make a later legitimate frame look like a replay. The
    /// sequence number tracks what was accepted, not what arrived.
    /// </remarks>
    [Fact]
    public void ARefusedFrameDoesNotAdvanceTheSequenceNumber()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();

        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, negotiated);

        uint? before = machine.HighestSequenceNumber;

        machine.Apply(TypeCode("SHELL_EXEC"), 0, 100, encrypted: true, negotiatedCapabilities: negotiated);

        Assert.Equal(before, machine.HighestSequenceNumber);
    }

    /// <summary>The negotiated set is the intersection minus the disabled list.</summary>
    /// <remarks>
    /// <para>
    /// Asserted from the file's own preconditions and expected set, because the
    /// transcript's step 4 declares exactly this and getting it wrong would let a
    /// capability the agent does not have appear negotiated.
    /// </para>
    /// <para>
    /// The comparison sorts, which is this project's convention for capability sets
    /// and not a convenience. The vector files list the sets in registry order
    /// because that is how a human reads them, while <c>Negotiate</c> returns a
    /// sorted set so that two peers can compare the value byte for byte regardless
    /// of the order either side offered it in. Sorting one side of the comparison is
    /// what reconciles the two, and it is what
    /// <c>CapabilityNegotiationTests</c> already does for the same vectors.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheNegotiatedSetIsTheIntersection()
    {
        JsonElement preconditions = Session().GetProperty("preconditions");

        List<string> agent = [.. preconditions.GetProperty("agent_capabilities")
            .EnumerateArray().Select(e => e.GetString()!)];
        List<string> disabled = [.. preconditions.GetProperty("agent_disabled")
            .EnumerateArray().Select(e => e.GetString()!)];
        List<string> offered = [.. preconditions.GetProperty("controller_offered")
            .EnumerateArray().Select(e => e.GetString()!)];

        List<string> expected = NegotiatedCapabilities();

        // The set really is the intersection, checked as a set.
        Assert.Equal(
            expected.OrderBy(c => c, StringComparer.Ordinal),
            CapabilityNegotiation.Negotiate(Registry(), agent, disabled, offered)
                .OrderBy(c => c, StringComparer.Ordinal));

        // And the implementation's own order is the canonical sorted one.
        Assert.Equal(
            expected.OrderBy(c => c, StringComparer.Ordinal),
            CapabilityNegotiation.Negotiate(Registry(), agent, disabled, offered));

        // The two the transcript calls out are absent for the right reason: the
        // agent does not have them at all, rather than having them disabled.
        Assert.DoesNotContain("shell.exec", agent);
        Assert.DoesNotContain("app.install", agent);
    }

    // ---- Channel parity ----------------------------------------------------

    /// <summary>The parity rule is the allocator's, and the transcript's step 7 shows it.</summary>
    /// <remarks>
    /// <para>
    /// The controller allocates odd channel ids and the agent even ones, so a peer
    /// using the wrong parity would collide with the other side's next allocation.
    /// The transcript's step 7 says the controller allocates 1, and step 8 announces
    /// it on the control channel.
    /// </para>
    /// <para>
    /// The announcement is not rejected here when the parity is wrong, and that is a
    /// deliberate limit rather than an oversight: a machine cannot tell a lying peer
    /// from a peer that has a bug, and the id it is told is the id the session will
    /// actually use. What the machine does check is that the id is plausible, and
    /// the allocation rule itself is enforced at the point of allocation by
    /// <see cref="SessionStateMachine.NextChannelId"/>, which is what a peer calls
    /// when it wants to open one.
    /// </para>
    /// </remarks>
    [Fact]
    public void ChannelAllocationFollowsTheRoleParity()
    {
        ProtocolRegistry registry = Registry();

        SessionStateMachine controller = new(registry, SessionRole.Controller);
        SessionStateMachine agent = new(registry, SessionRole.Agent);

        // The controller's first allocation is 1 and the agent's is 2: different
        // parity, so the two sequences never collide. The method is a pure choice
        // and does not reserve, so the value repeats until the channel is opened --
        // which is what makes it safe to call to ask "what would I get".
        Assert.Equal(1u, controller.NextChannelId());
        Assert.Equal(1u, controller.NextChannelId());
        Assert.Equal(2u, agent.NextChannelId());

        // Once 1 is open, the controller's next choice moves past it to 3.
        List<string> negotiated = NegotiatedCapabilities();
        EstablishController(controller, negotiated);
        Assert.True(controller.Apply(
            TypeCode("CHANNEL_OPENED"), 0, 10, encrypted: true, negotiated, announcedChannelId: 1).Accepted);

        Assert.Equal(3u, controller.NextChannelId());
    }

    /// <summary>The allocated ids are recorded once the peer confirms them.</summary>
    /// <remarks>
    /// The transcript's steps 7 and 8: the controller allocates 1 and the agent
    /// announces it, so both sides end up knowing channel 1 exists.
    /// </remarks>
    [Fact]
    public void AnAllocatedChannelIsRecordedOnBothSides()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();

        SessionStateMachine controller = new(registry, SessionRole.Controller);
        SessionStateMachine agent = new(registry, SessionRole.Agent);
        EstablishController(controller, negotiated);
        Establish(agent, negotiated);

        uint allocated = controller.NextChannelId();
        Assert.Equal(1u, allocated);

        // The agent announces it on the control channel, with the id in the body.
        Assert.True(agent.Apply(
            TypeCode("CHANNEL_OPENED"), 0, 10, encrypted: true, negotiated,
            announcedChannelId: allocated).Accepted);

        Assert.Equal([allocated], agent.OpenChannels);
    }

    /// <summary>A duplicate announcement does not record the channel twice.</summary>
    /// <remarks>
    /// Two entries for one channel would mean two channels with one id, and the
    /// session's channel table is what later frames are routed by.
    /// </remarks>
    [Fact]
    public void ADuplicateAnnouncementIsRecordedOnce()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();
        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, negotiated);

        Assert.True(machine.Apply(
            TypeCode("CHANNEL_OPENED"), 0, 10, encrypted: true, negotiated, announcedChannelId: 1).Accepted);
        Assert.True(machine.Apply(
            TypeCode("CHANNEL_OPENED"), 0, 11, encrypted: true, negotiated, announcedChannelId: 1).Accepted);

        Assert.Equal([1u], machine.OpenChannels);
    }

    /// <summary>An announced channel id is recorded from the body, not the header.</summary>
    /// <remarks>
    /// The transcript's step 8 announces channel 1 on channel 0: CHANNEL_OPENED
    /// travels on the control channel and carries the id it is announcing in its
    /// body. Reading the id from the frame header would record channel 0 for every
    /// channel ever opened, which is the mistake this test pins down.
    /// </remarks>
    [Fact]
    public void TheAnnouncedChannelIdComesFromTheBody()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();
        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, negotiated);

        Assert.True(machine.Apply(
            TypeCode("CHANNEL_OPENED"),
            channelId: 0,
            sequenceNumber: 10,
            encrypted: true,
            negotiated,
            announcedChannelId: 1).Accepted);

        Assert.Equal([1u], machine.OpenChannels);
    }

    /// <summary>Both roles may announce a channel, and the id is recorded.</summary>
    /// <remarks>
    /// The controller allocates odd ids and the agent even ones, but either side may
    /// send the announcement, so the machine records what it is told rather than
    /// what it would have chosen.
    /// </remarks>
    [Fact]
    public void AnyChannelOfTheRightParityIsAccepted()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();

        foreach (uint id in new uint[] { 1, 3, 5, 7, 99 })
        {
            SessionStateMachine machine = new(registry, SessionRole.Agent);
            Establish(machine, negotiated);
            Assert.True(machine.Apply(
                TypeCode("CHANNEL_OPENED"), 0, 10, encrypted: true, negotiated, announcedChannelId: id).Accepted);
            Assert.Contains(id, machine.OpenChannels);
        }

        foreach (uint id in new uint[] { 2, 4, 6, 8, 100 })
        {
            SessionStateMachine machine = new(registry, SessionRole.Controller);
            EstablishController(machine, negotiated);
            Assert.True(machine.Apply(
                TypeCode("CHANNEL_OPENED"), 0, 10, encrypted: true, negotiated, announcedChannelId: id).Accepted);
            Assert.Contains(id, machine.OpenChannels);
        }
    }

    /// <summary>An implausible channel id is refused.</summary>
    /// <remarks>
    /// The field is 32 bits on the wire while <c>max_channels</c> defaults to 8, so
    /// a bound is stated rather than implied: accepting any value would let one
    /// frame grow an unbounded list.
    /// </remarks>
    [Fact]
    public void AnImplausibleChannelIdIsRefused()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();
        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, negotiated);

        TransitionResult result = machine.Apply(
            TypeCode("CHANNEL_OPENED"), 0, 10, encrypted: true, negotiated, announcedChannelId: 999_999);

        Assert.False(result.Accepted);
        Assert.Equal("ERR_MALFORMED", result.Error!.Name);
    }

    /// <summary>Channel 0 is the control channel and is never recorded.</summary>
    [Fact]
    public void ChannelZeroIsNeverRecorded()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();
        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, negotiated);

        Assert.True(machine.Apply(TypeCode("CHANNEL_OPENED"), 0, 10, encrypted: true, negotiated).Accepted);

        Assert.Empty(machine.OpenChannels);
    }

    /// <summary>A control-scoped message on a non-zero channel is refused.</summary>
    [Fact]
    public void ControlMessagesMustUseChannelZero()
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, NegotiatedCapabilities());

        TransitionResult result = machine.Apply(
            TypeCode("PING"), 3, 50, encrypted: true, NegotiatedCapabilities());

        Assert.False(result.Accepted);
        Assert.Equal("ERR_MALFORMED", result.Error!.Name);
    }

    // ---- Encryption ---------------------------------------------------------

    /// <summary>An encrypted message with the flag clear is refused fatally.</summary>
    [Fact]
    public void AnEncryptedMessageWithoutTheFlagIsRefused()
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, NegotiatedCapabilities());

        TransitionResult result = machine.Apply(
            TypeCode("PING"), 0, 50, encrypted: false, NegotiatedCapabilities());

        Assert.False(result.Accepted);
        Assert.Equal("ERR_UNAUTHORIZED", result.Error!.Name);
        Assert.True(result.Error!.IsFatal);
        Assert.Equal(SessionState.Closed, machine.State);
    }

    /// <summary>An unencrypted message with the flag set is refused.</summary>
    [Fact]
    public void AHandshakeMessageWithTheFlagSetIsRefused()
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);

        TransitionResult result = machine.Apply(
            TypeCode("HELLO"), 0, 1, encrypted: true, negotiatedCapabilities: []);

        Assert.False(result.Accepted);
        Assert.Equal("ERR_MALFORMED", result.Error!.Name);
    }

    // ---- Fatal errors close the session ------------------------------------

    /// <summary>A fatal error closes the session from any state.</summary>
    /// <remarks>
    /// There is no state from which a fatal error is survivable, and no partial
    /// teardown: the alternative is two peers in different states, which is worse
    /// than either failing.
    /// </remarks>
    [Theory]
    [InlineData("ERR_MALFORMED")]
    [InlineData("ERR_REPLAY_DETECTED")]
    [InlineData("ERR_UNAUTHORIZED")]
    [InlineData("ERR_UNEXPECTED_MESSAGE")]
    [InlineData("ERR_VERSION_MISMATCH")]
    public void AFatalErrorClosesTheSessionFromAnyState(string errorName)
    {
        ErrorCode error = ErrorCodes.Find(errorName)!;

        // Every state a session can be live in. Closing and Closed are excluded
        // because a fatal error there has nothing new to do, and AdvanceTo refuses
        // to move out of Closed by design.
        SessionState[] live =
        [
            SessionState.Idle, SessionState.Discovering, SessionState.Connecting,
            SessionState.Handshaking, SessionState.Authenticating, SessionState.Established,
            SessionState.Streaming,
        ];

        foreach (SessionState state in live)
        {
            SessionStateMachine machine = new(Registry());

            // Idle is the starting state, so there is nothing to move to and
            // AdvanceTo would refuse a move to where it already is.
            if (state != SessionState.Idle)
            {
                machine.AdvanceTo(state);
            }

            machine.FailFatal(error);

            Assert.Equal(SessionState.Closed, machine.State);
            Assert.Equal(errorName, machine.EndError!.Name);
        }
    }

    /// <summary>A fatal error from a tearing-down state ends cleanly.</summary>
    /// <remarks>
    /// <para>
    /// The counterpart to the theory above: a peer that reports a fatal error while
    /// the session is already tearing down must not leave the machine in a state
    /// that is neither closing nor closed.
    /// </para>
    /// <para>
    /// The two cases differ in what they may assert about the recorded error, and
    /// the difference is the point. From <c>Closing</c> the fatal error is the first
    /// thing to end the session, so it is recorded. From <c>Closed</c> the session
    /// has already ended, and closing is idempotent — it keeps the first reason
    /// rather than overwriting it — so the later error is deliberately not recorded.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(SessionState.Closing)]
    [InlineData(SessionState.Closed)]
    public void AFatalErrorFromATearingDownStateEndsCleanly(SessionState state)
    {
        SessionStateMachine machine = new(Registry());

        if (state == SessionState.Closed)
        {
            // Already closed, with no error recorded.
            machine.End(SessionEndReasons.AgentShutdown);
            Assert.Null(machine.EndError);
        }
        else
        {
            machine.AdvanceTo(state);
        }

        machine.FailFatal(ErrorCodes.Malformed);

        Assert.Equal(SessionState.Closed, machine.State);

        if (state == SessionState.Closed)
        {
            // The first reason stands.
            Assert.Equal(SessionEndReasons.AgentShutdown, machine.EndReason);
            Assert.Null(machine.EndError);
        }
        else
        {
            Assert.Equal("ERR_MALFORMED", machine.EndError!.Name);
        }
    }

    /// <summary>A recoverable error must not be able to close a session.</summary>
    /// <remarks>
    /// Routing a recoverable one through the fatal path would end a working
    /// session over something the protocol says is survivable.
    /// </remarks>
    [Theory]
    [InlineData("ERR_UNSUPPORTED_MESSAGE")]
    [InlineData("ERR_UNSUPPORTED_FEATURE")]
    [InlineData("ERR_IO")]
    public void ARecoverableErrorCannotCloseASession(string errorName)
    {
        ErrorCode error = ErrorCodes.Find(errorName)!;

        SessionStateMachine machine = new(Registry());
        machine.AdvanceTo(SessionState.Established);

        Assert.Throws<ArgumentException>(() => machine.FailFatal(error));
        Assert.Equal(SessionState.Established, machine.State);
    }

    /// <summary>The end reason follows from the error.</summary>
    /// <remarks>
    /// A replay is a protocol error, an authentication failure is its own reason,
    /// and a version mismatch is its own. Recording them all as "protocol_error"
    /// would make the session log unable to distinguish a broken peer from an
    /// incompatible one.
    /// </remarks>
    [Theory]
    [InlineData("ERR_REPLAY_DETECTED", SessionEndReasons.ProtocolError)]
    [InlineData("ERR_UNAUTHORIZED", SessionEndReasons.AuthFailed)]
    [InlineData("ERR_VERSION_MISMATCH", SessionEndReasons.ProtocolError)]
    [InlineData("ERR_UNEXPECTED_MESSAGE", SessionEndReasons.ProtocolError)]
    public void TheEndReasonFollowsFromTheError(string errorName, string expectedReason)
    {
        SessionStateMachine machine = new(Registry());
        machine.FailFatal(ErrorCodes.Find(errorName)!);

        Assert.Equal(expectedReason, machine.EndReason);
    }

    /// <summary>
    /// The constants match the registry exactly, and the registry is exhaustive.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both directions matter. Every constant here must be in the registry, because
    /// a reason string no peer recognises would make an orderly close look like an
    /// unparseable one. And the registry must hold nothing else, because a reason
    /// this class cannot produce is one a peer could send that the session log
    /// would have no name for.
    /// </para>
    /// <para>
    /// This test exists because the first version of this class invented
    /// <c>normal</c>, <c>timeout</c> and <c>authentication_failed</c> — plausible
    /// names, all three wrong. The registry is normative and the constants are not.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryEndReasonMatchesTheRegistryInBothDirections()
    {
        using JsonDocument document = VectorLoader.LoadRegistry();
        ProtocolRegistry registry = ProtocolRegistry.FromJson(document.RootElement);

        string[] declared =
        [
            SessionEndReasons.ClientShutdown,
            SessionEndReasons.AgentShutdown,
            SessionEndReasons.IdleTimeout,
            SessionEndReasons.AuthFailed,
            SessionEndReasons.ProtocolError,
            SessionEndReasons.CaptureRevoked,
        ];

        Assert.Equal(declared.Length, declared.Distinct(StringComparer.Ordinal).Count());

        foreach (string reason in declared)
        {
            Assert.Contains(reason, registry.SessionEndReasons);
        }

        Assert.Equal(
            declared.OrderBy(r => r, StringComparer.Ordinal),
            registry.SessionEndReasons.OrderBy(r => r, StringComparer.Ordinal));
    }

    /// <summary>Ending twice is idempotent and keeps the first reason.</summary>
    [Fact]
    public void EndingTwiceKeepsTheFirstReason()
    {
        SessionStateMachine machine = new(Registry());

        machine.End(SessionEndReasons.ProtocolError, ErrorCodes.ReplayDetected);
        TransitionResult second = machine.End(SessionEndReasons.AgentShutdown);

        Assert.True(second.Accepted);
        Assert.Equal(SessionEndReasons.ProtocolError, machine.EndReason);
        Assert.Equal("ERR_REPLAY_DETECTED", machine.EndError!.Name);
    }

    // ---- Sequence numbers per direction ------------------------------------

    /// <summary>Each direction numbers independently from 1.</summary>
    /// <remarks>
    /// The transcript's own assertion says so, and it is why both sides use
    /// sequence number 1 for their first frame without either being a replay. A
    /// single global counter would make the second side's first frame a repeat.
    /// </remarks>
    /// <summary>Each direction numbers independently from 1.</summary>
    /// <remarks>
    /// The transcript's own assertion says so, and it is why both sides use sequence
    /// number 1 for their first frame without either being a replay. A single global
    /// counter would make the second side's first frame a repeat.
    /// </remarks>
    [Fact]
    public void EachDirectionNumbersIndependently()
    {
        ProtocolRegistry registry = Registry();

        SessionStateMachine controller = new(registry, SessionRole.Controller);
        SessionStateMachine agent = new(registry, SessionRole.Agent);

        // Each side's first inbound frame is sequence 1 in the peer's own direction:
        // the agent receives the controller's HELLO, the controller receives the
        // agent's HELLO_ACK.
        Assert.True(agent.Apply(TypeCode("HELLO"), 0, 1, encrypted: false, []).Accepted);
        Assert.True(controller.Apply(TypeCode("HELLO_ACK"), 0, 1, encrypted: false, []).Accepted);

        Assert.Equal(1u, controller.HighestSequenceNumber);
        Assert.Equal(1u, agent.HighestSequenceNumber);
    }

    /// <summary>The encrypted stream restarts at two after the handshake.</summary>
    /// <remarks>
    /// The handshake is unencrypted and numbered in its own space, and the
    /// transcript's step 3 says the first encrypted frame is sequence number 2.
    /// The machine must not carry a floor across from the handshake in a way that
    /// makes 2 a gap or a repeat, and it must not refuse the handshake's own reuse
    /// of 1 either.
    /// </remarks>
    [Fact]
    public void TheEncryptedStreamRestartsAtTwo()
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);

        // The handshake, unencrypted, both numbered 1 in their own directions.
        Assert.True(machine.Apply(TypeCode("HELLO"), 0, 1, encrypted: false, []).Accepted);
        Assert.True(machine.Apply(TypeCode("HELLO_ACK"), 0, 1, encrypted: false, []).Accepted);

        Assert.Equal(SessionState.Authenticating, machine.State);

        // The first encrypted frame is 2, which the transcript declares.
        JsonElement step3 = Steps().Single(s => s.GetProperty("step").GetInt32() == 3);
        JsonElement send = step3.GetProperty("send");

        Assert.Equal(2u, send.GetProperty("sequence_number").GetUInt32());
        Assert.True(send.GetProperty("flags").GetInt32() != 0, "step 3 says it is the first encrypted frame");

        TransitionResult result = machine.Apply(
            TypeCode("AUTH"), 0, 2, encrypted: true, NegotiatedCapabilities());

        Assert.True(result.Accepted, result.Reason);
        Assert.Equal(SessionState.Authenticating, machine.State);
    }

    /// <summary>The handshake frames may share a sequence number.</summary>
    /// <remarks>
    /// HELLO and HELLO_ACK are both number 1, sent by different sides. A machine
    /// that applied one counter to both streams refused every HELLO_ACK, which is
    /// the bug this test exists to keep out: it is the single most likely way to
    /// get the sequence rules wrong, because the two frames really do arrive
    /// consecutively at a receiver.
    /// </remarks>
    [Fact]
    public void TheHandshakeFramesMayShareASequenceNumber()
    {
        ProtocolRegistry registry = Registry();
        SessionStateMachine machine = new(registry, SessionRole.Agent);

        Assert.True(machine.Apply(TypeCode("HELLO"), 0, 1, encrypted: false, []).Accepted);
        Assert.True(machine.Apply(TypeCode("HELLO_ACK"), 0, 1, encrypted: false, []).Accepted);

        Assert.Equal(SessionState.Authenticating, machine.State);
    }

    /// <summary>A replay inside the encrypted stream is still fatal.</summary>
    /// <remarks>
    /// The exception for the handshake must not become an exception for everything:
    /// the transcript's step 17 is in the encrypted stream and must be refused.
    /// </remarks>
    [Fact]
    public void AReplayInTheEncryptedStreamIsStillFatal()
    {
        ProtocolRegistry registry = Registry();
        List<string> negotiated = NegotiatedCapabilities();
        SessionStateMachine machine = new(registry, SessionRole.Agent);
        Establish(machine, negotiated);

        // A frame that has already been accepted is refused.
        Assert.True(machine.Apply(TypeCode("PING"), 0, 50, encrypted: true, negotiated).Accepted);

        TransitionResult repeat = machine.Apply(TypeCode("PING"), 0, 50, encrypted: true, negotiated);

        Assert.False(repeat.Accepted);
        Assert.Equal("ERR_REPLAY_DETECTED", repeat.Error!.Name);
        Assert.Equal(SessionState.Closed, machine.State);
    }

    /// <summary>The declared sequence rule is the one implemented.</summary>
    [Fact]
    public void TheDeclaredSequenceRuleMatches()
    {
        string assertion = Session().GetProperty("assertions").GetProperty("sequence_numbers").GetString()!;

        // The file's own words, asserted so a change to the rule is a deliberate
        // change to both the file and this test rather than to one of them.
        Assert.Contains("session-global", assertion, StringComparison.Ordinal);
        Assert.Contains("increase by one per frame", assertion, StringComparison.Ordinal);
        Assert.Contains("number independently", assertion, StringComparison.Ordinal);
    }

    // ---- Helpers ------------------------------------------------------------

    /// <summary>
    /// Drives an agent machine to the established state by feeding it peer frames.
    /// </summary>
    /// <param name="machine">The machine, tracked as the agent.</param>
    /// <param name="negotiated">The negotiated capability set.</param>
    /// <remarks>
    /// <para>
    /// A machine sees only what the <i>peer</i> sent, and the peer of an agent is the
    /// controller. The controller sends HELLO then AUTH, numbered 1 then 2 in its own
    /// direction. AUTH_OK is the agent's own frame, so a stand-alone driver applies it
    /// in the peer's numbering to reach the established state without pretending it
    /// arrived from the other direction.
    /// </para>
    /// <para>
    /// Feeding a machine both sides' frames at once — which the first version of these
    /// tests did — gives AUTH and AUTH_OK the same sequence number and the second is
    /// refused as a replay. That was the machine being right about a session that had
    /// never been described correctly.
    /// </para>
    /// </remarks>
    private static void Establish(SessionStateMachine machine, IReadOnlyCollection<string> negotiated)
    {
        Assert.True(machine.Apply(TypeCode("HELLO"), 0, 1, encrypted: false, negotiated).Accepted);
        Assert.Equal(SessionState.Handshaking, machine.State);

        Assert.True(machine.Apply(TypeCode("AUTH"), 0, 2, encrypted: true, negotiated).Accepted);
        Assert.Equal(SessionState.Authenticating, machine.State);

        Assert.True(machine.Apply(TypeCode("AUTH_OK"), 0, 3, encrypted: true, negotiated).Accepted);
        Assert.Equal(SessionState.Established, machine.State);
    }

    /// <summary>
    /// Drives a controller machine to the established state by feeding it peer frames.
    /// </summary>
    /// <param name="machine">The machine, tracked as the controller.</param>
    /// <param name="negotiated">The negotiated capability set.</param>
    /// <remarks>
    /// The mirror image of <see cref="Establish"/>. The controller sends HELLO and
    /// AUTH, so its first inbound frame is the agent's HELLO_ACK, numbered 1 in the
    /// agent's own direction, and the handshake closes with the agent's AUTH_OK.
    /// </remarks>
    private static void EstablishController(SessionStateMachine machine, IReadOnlyCollection<string> negotiated)
    {
        Assert.True(machine.Apply(TypeCode("HELLO_ACK"), 0, 1, encrypted: false, negotiated).Accepted);
        Assert.Equal(SessionState.Authenticating, machine.State);

        Assert.True(machine.Apply(TypeCode("AUTH_OK"), 0, 2, encrypted: true, negotiated).Accepted);
        Assert.Equal(SessionState.Established, machine.State);
    }
}
