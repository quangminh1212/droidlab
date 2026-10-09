// Mutation-tests the conformance gate: it breaks the mirrored logic on purpose, one change at a
// time, and asserts that the gate notices.
//
// WHY THIS EXISTS
//
// `check-kotlin-vectors.cjs` reimplements the Kotlin's arithmetic in JavaScript and runs it
// against the real vectors. That makes it the only thing in this repository that can catch a
// logic error in the Android protocol core, since the Kotlin has never been through a compiler
// here. So a check that cannot fail is the worst possible outcome: it reports coverage of a rule
// nothing is testing.
//
// It has already happened twice, and both times this kind of testing is what found it:
//
//   * The video clamp's scale-down-only guard was inert for every vector input. Deleting it left
//     all 317 checks green.
//   * Three checks in the crypto mirror could not fail: the pairing code's byte order (every
//     other check only required six digits, and a little-endian read gives six digits too), the
//     zero padding (no input ever produced a value below 100000), and the null high-water mark
//     in the replay window (every number used was above the boundary under both readings).
//
// Each mutation below is one of those, or one like it. A mutation that SURVIVES means the gate
// has a hole and the list is a bug report, not a statistic.
//
// The mutations are declared as literal text replacements rather than as AST edits, because the
// point is to change the code the way a person might plausibly get it wrong. A mutation that
// cannot be expressed as a small edit is usually a mutation of the test rather than of the
// implementation.
//
// Usage:  node protocol/tools/mutation-check.cjs
// Exits 0 when every mutation is caught, 1 otherwise.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const repoRoot = path.resolve(__dirname, '..', '..');
const gate = path.join(repoRoot, 'protocol', 'tools', 'check-kotlin-vectors.cjs');

/**
 * The mutations, each a single edit to the gate's mirrored logic.
 *
 * Every entry names the rule it is probing and the check that ought to catch it, so a survivor
 * reads as "this rule is not covered" rather than as an opaque failure.
 */
const MUTATIONS = [
  {
    rule: 'frame classifier: a bad magic closes without an error frame',
    from: '  if (bytes.length >= 4 && !hasMagic(bytes)) {',
    to: '  if (false) {',
  },
  {
    rule: 'frame classifier: a repeated sequence number is a replay',
    from: '  if (seenBefore !== null && seenBefore.has(sequenceNumber)) {',
    to: '  if (false) {',
  },
  {
    rule: 'frame classifier: the reorder window is inclusive of its far edge',
    from: '  if (sequenceNumber < oldestAcceptable) {',
    to: '  if (sequenceNumber <= oldestAcceptable) {',
  },
  {
    rule: 'handshake transcript: the label length is sixteen bytes',
    from: 'const TRANSCRIPT_LABEL_LENGTH = 16;',
    to: 'const TRANSCRIPT_LABEL_LENGTH = 17;',
  },
  {
    rule: 'handshake transcript: the separator is written between the identifiers',
    from: '    Buffer.from([0]),\n    clientPrefix,',
    to: '    clientPrefix,',
  },
  {
    rule: 'capability negotiation: the result is sorted, because the order is part of the contract',
    from: '  return negotiated.sort();',
    to: '  return negotiated;',
  },
  {
    rule: 'capability negotiation: a disabled capability is removed even when both sides support it',
    from: '    (name) => offered.has(name) && !disabled.has(name) && CAPABILITY_REGISTRY.includes(name),',
    to: '    (name) => offered.has(name) && CAPABILITY_REGISTRY.includes(name),',
  },
  {
    rule: 'capability negotiation: a name outside the registry is dropped',
    from: '    (name) => offered.has(name) && !disabled.has(name) && CAPABILITY_REGISTRY.includes(name),',
    to: '    (name) => offered.has(name) && !disabled.has(name),',
  },
  {
    rule: 'capability negotiation: the video clamp scales the screen, not the request',
    from: '  const scale = Math.min(ceilingWidth / screenWidth, ceilingHeight / screenHeight);',
    to: '  const scale = Math.min(ceilingWidth / ceilingWidth, ceilingHeight / ceilingHeight);',
  },
  {
    rule: 'capability negotiation: capture never upscales a screen smaller than the ceiling',
    from: '  const effectiveScale = Math.min(1.0, scale);',
    to: '  const effectiveScale = scale;',
  },
  {
    rule: 'capability negotiation: the channel limit counts the control channel',
    from: '  if (openChannels.size >= maxChannels) return { accepted: false, error: \'ERR_CHANNEL_LIMIT\' };',
    to: '  if (openChannels.size - 1 >= maxChannels) return { accepted: false, error: \'ERR_CHANNEL_LIMIT\' };',
  },
  {
    rule: 'capability negotiation: a file chunk over the limit is refused, not truncated',
    from: '  if (requestedChunk > agentMaxFileChunk) {',
    to: '  if (false) {',
  },
  {
    rule: 'capability negotiation: the controller allocates odd channel ids',
    from: '  const first = controller ? 1 : 2;',
    to: '  const first = controller ? 2 : 1;',
  },
  {
    rule: 'version negotiation: the highest common version wins',
    from: '  const best = common.reduce((x, y) => (compareVersion(y, x) > 0 ? y : x));',
    to: '  const best = common[0];',
  },
  {
    rule: 'version negotiation: versions compare numerically, so 1.10 sorts above 1.9',
    from: '  if (a.major !== b.major) return a.major - b.major;\n  return a.minor - b.minor;',
    to: '  if (a.major !== b.major) return a.major - b.major;\n  return String(a.minor).localeCompare(String(b.minor));',
  },
  {
    rule: 'version negotiation: an answer the controller never offered is refused',
    from: '  if (!isOffered) return { version: null, error: \'ERR_VERSION_MISMATCH\' };',
    to: '  if (false) return { version: null, error: \'ERR_VERSION_MISMATCH\' };',
  },
  {
    rule: 'version negotiation: an unclassifiable change kind is refused, not defaulted',
    from: 'throw new Error(`unknown change kind "${changeKind}"`);',
    to: 'return false;',
  },
  {
    rule: 'crypto: every label carries its separator',
    from: "  return Buffer.concat([Buffer.from(label, 'ascii'), Buffer.from([0])]);",
    to: "  return Buffer.from(label, 'ascii');",
  },
  {
    rule: 'crypto: the labels object carries a note that is not a label',
    from: "    Object.entries(crypto.labels).filter(([k]) => k !== 'note'),",
    to: '    Object.entries(crypto.labels),',
  },
  {
    rule: 'crypto: a fingerprint is uppercase hex',
    from: "  const hex = digest.subarray(0, 8).toString('hex').toUpperCase();",
    to: "  const hex = digest.subarray(0, 8).toString('hex');",
  },
  {
    rule: 'crypto: the pairing code reads the digest big-endian',
    from: '  const value = (digest[0] * 0x1000000) + (digest[1] * 0x10000) + (digest[2] * 0x100) + digest[3];',
    to: '  const value = digest[0] + (digest[1] * 0x100) + (digest[2] * 0x10000) + (digest[3] * 0x1000000);',
  },
  {
    rule: 'crypto: the pairing code is zero padded to six digits',
    from: "  return String(value % 1000000).padStart(6, '0');",
    to: '  return String(value % 1000000);',
  },
  {
    rule: 'crypto: the contributory check reads every byte of the shared secret',
    from: '  let accumulator = 0;\n  for (const byte of sharedSecret) accumulator |= byte;\n\n  return accumulator !== 0;',
    to: '  return sharedSecret[0] !== 0;',
  },
  {
    rule: 'discovery: the separator goes between fields, not after each one',
    from: "    const hasPredecessor = ordered.slice(0, index).some((k) => Object.prototype.hasOwnProperty.call(fields, k) && fields[k] !== undefined);\n    if (hasPredecessor) text += '\\u000A';",
    to: "    text += '\\u000A';",
  },
  {
    rule: 'discovery: the label is followed by a NUL',
    from: "  let text = DISCOVERY.TXT_LABEL + '\\u0000';",
    to: '  let text = DISCOVERY.TXT_LABEL;',
  },
  {
    rule: 'discovery: a missing required key is refused',
    from: "      if (DISCOVERY.REQUIRED_KEYS.includes(key)) {\n        throw new Error('the required key \"' + key + '\" is missing');\n      }\n      continue;",
    to: '      continue;',
  },
  {
    rule: 'discovery: a value containing a newline is refused',
    from: "    if (String(value).includes('\\n')) {\n      throw new Error('the value of \"' + key + '\" contains a newline');\n    }",
    to: '    ',
  },
  {
    rule: 'discovery: the optional keys are appended after the required ones',
    from: "  const ordered = [...DISCOVERY.REQUIRED_KEYS, ...DISCOVERY.OPTIONAL_KEYS];",
    to: '  const ordered = [...DISCOVERY.REQUIRED_KEYS];',
  },
  {
    rule: 'discovery: the beacon is canonicalised in ascending key order',
    from: '  const ordered = Object.keys(fields).sort();',
    to: '  const ordered = Object.keys(fields);',
  },
  {
    rule: 'discovery: port zero is not a usable address',
    from: '  return port >= 1 && port <= 65535;',
    to: '  return port >= 0 && port <= 65535;',
  },
  {
    rule: 'discovery: the TXT budget is a maximum, not a target',
    from: '  return byteCount >= 0 && byteCount <= DISCOVERY.MAX_TXT_BYTES;',
    to: '  return byteCount >= 0;',
  },
  {
    rule: 'discovery: the beacon port is not the service port',
    from: '  BEACON_PORT: 45918,',
    to: '  BEACON_PORT: 45917,',
  },
  {
    rule: 'discovery: a beacon is only sent when discovery is enabled',
    from: '  return discoveryEnabled === true;',
    to: '  return true;',
  },
  {
    rule: 'session: the message codes are the registry 1-based codes, not the JSON keys',
    from: 'const SESSION_MESSAGES = {\n  HELLO: 1,',
    to: 'const SESSION_MESSAGES = {\n  HELLO: 0,',
  },
  {
    rule: 'session: HELLO is only legal from idle or connecting',
    from: "      require_(from === SESSION_STATE.IDLE || from === SESSION_STATE.CONNECTING, 'HELLO is sent from idle or connecting, not from ' + from);",
    to: '      require_(true, "HELLO");',
  },
  {
    rule: 'session: only the controller sends HELLO',
    from: "      require_(role === 'controller', 'only the controller sends HELLO');",
    to: '      require_(true, "HELLO role");',
  },
  {
    rule: 'session: HELLO_ACK answers HELLO, so the state is handshaking',
    from: "      require_(from === SESSION_STATE.HANDSHAKING, 'HELLO_ACK answers HELLO, so the state is handshaking, not ' + from);",
    to: '      require_(true, "HELLO_ACK");',
  },
  {
    rule: 'session: sending AUTH leaves the controller authenticating, not established',
    // The needle stops at the return, which is unique once the AUTH case's own comment is
    // included. A first version included the apostrophe in "agent's", and the escaping mangled
    // it into a literal backslash-quote so the needle matched nothing -- reported as an
    // unappliable mutation, which is the tool working.
    from:
      "      require_(from === SESSION_STATE.AUTHENTICATING, 'AUTH is sent while authenticating, not from ' + from);\n" +
      '\n' +
      '      // Sending AUTH does NOT establish the session: the session is established when the\n' +
      '      // HANDSHAKE completes, which is when both proofs have been exchanged. The controller has\n' +
      '      // sent its proof but has not checked the agent' +
      "'" +
      's, so it remains authenticating.\n' +
      '      return SESSION_STATE.AUTHENTICATING;',
    to:
      "      require_(from === SESSION_STATE.AUTHENTICATING, 'AUTH is sent while authenticating, not from ' + from);\n" +
      '      return SESSION_STATE.ESTABLISHED;',
  },
  {
    rule: 'session: only the video frames move the session into streaming',
    from: "    case SESSION_MESSAGES.VIDEO_START:\n    case SESSION_MESSAGES.VIDEO_CONFIG:\n      require_(isEstablished(from), 'video starts after authentication, not from ' + from);\n      return SESSION_STATE.STREAMING;",
    to: "    case SESSION_MESSAGES.VIDEO_START:\n    case SESSION_MESSAGES.VIDEO_CONFIG:\n      require_(isEstablished(from), 'video starts after authentication, not from ' + from);\n      return from;",
  },
  {
    rule: 'session: a frame from before authentication is refused',
    from: "      require_(isEstablished(from), 'a channel is opened after authentication, not from ' + from);",
    to: '      require_(true, "channel");',
  },
  {
    rule: 'session: a repeated sequence number is fatal',
    from: "    if (this.received.has(sequenceNumber) || (floor !== null && sequenceNumber < floor)) {\n      this.state = SESSION_STATE.CLOSING;\n      return { kind: 'fatal', code: 'ERR_REPLAY_DETECTED' };\n    }",
    to: '    ',
  },
  {
    rule: 'session: a repeated sequence number is fatal and not merely recoverable',
    from: "      return { kind: 'fatal', code: 'ERR_REPLAY_DETECTED' };",
    to: "      return { kind: 'recoverable', code: 'ERR_REPLAY_DETECTED' };",
  },
  {
    rule: 'session: an out-of-state frame is recoverable, not fatal',
    from: "      return { kind: 'recoverable', code: 'ERR_UNEXPECTED_MESSAGE' };",
    to: "      return { kind: 'fatal', code: 'ERR_UNEXPECTED_MESSAGE' };",
  },
  {
    rule: 'session: an outgoing sequence number must advance',
    from: '    if (this.lastSent !== null && sequenceNumber <= this.lastSent) {\n      throw new Error(\'outgoing sequence number \' + sequenceNumber + \' does not advance past \' + this.lastSent);\n    }',
    to: '    ',
  },
  {
    rule: 'session: a closed session accepts no frames',
    from: "  require_(from !== SESSION_STATE.CLOSED, 'the session is closed and accepts no frames');",
    to: '  require_(true, "closed");',
  },
  {
    rule: 'session: the unencrypted set is exactly the handshake pair',
    from: 'const SESSION_UNENCRYPTED = new Set([SESSION_MESSAGES.HELLO, SESSION_MESSAGES.HELLO_ACK]);',
    to: 'const SESSION_UNENCRYPTED = new Set([SESSION_MESSAGES.HELLO, SESSION_MESSAGES.HELLO_ACK, SESSION_MESSAGES.ERROR]);',
  },
  {
    rule: 'shell: the operator grant is checked first and alone',
    from: "  if (!context.shell_granted) {\n    return { allowed: false, error: 'ERR_PERMISSION_DENIED', reason: 'denied_by_operator' };\n  }",
    to: '  ',
  },
  {
    rule: 'shell: the deny list is checked before any rule matching',
    from: "  if (context.denied_rules.includes(basename)) {\n    return { allowed: false, error: 'ERR_NOT_ALLOWED', reason: 'deny_listed' };\n  }",
    to: '  ',
  },
  {
    rule: 'shell: the deny list matches by basename, not by path',
    from: "  const basename = executable.includes('/') ? executable.slice(executable.lastIndexOf('/') + 1) : executable;",
    to: '  const basename = executable;',
  },
  {
    rule: 'shell: the directory is compared for EQUALITY, not by prefix',
    from: '  return SHELL_VETTED_DIRECTORIES.includes(directory);',
    to: '  return SHELL_VETTED_DIRECTORIES.some((candidate) => executable.startsWith(candidate));',
  },
  {
    rule: 'shell: the basename must name a program, so a directory is not executable',
    from: "  if (basename === '' || basename === '.' || basename === '..') return false;",
    to: '  ',
  },
  {
    rule: 'shell: the level gate removes a mutating rule from a read_only context',
    from: "  const permits = (mutating) => !mutating || context.allow_level === 'read_write';",
    to: '  const permits = (mutating) => true;',
  },
  {
    rule: 'shell: the argv prefix identifies the rule, so a mismatch is not_in_allow_list',
    from: "      permits(ruleIsMutating(rule)) &&\n      ruleSignatureMatches(rule, executable, args),",
    to: '      permits(ruleIsMutating(rule)) &&\n      rule.exe === executable,',
  },
  {
    rule: 'shell: a matched rule with a bad argument is argument_rejected',
    from: "  const matched = applicable.find((rule) => ruleArgumentsMatch(rule, executable, args));\n\n  if (matched === undefined) {\n    return { allowed: false, error: 'ERR_NOT_ALLOWED', reason: 'argument_rejected' };\n  }",
    to: '  const matched = applicable.find((rule) => ruleArgumentsMatch(rule, executable, args));\n\n  if (matched === undefined) {\n    return { allowed: false, error: \'ERR_NOT_ALLOWED\', reason: \'not_in_allow_list\' };\n  }',
  },
  {
    rule: 'shell: the argument count is capped',
    from: '  if (rest.length > rule.max_args) return false;',
    to: '  ',
  },
  {
    rule: 'shell: every permitted argument is matched against its pattern',
    from: '    if (!new RegExp(pattern).test(rest[index])) return false;',
    to: '    ',
  },
  {
    rule: 'shell: an argument with no pattern of its own is refused, not accepted',
    from: '    if (pattern === undefined) return false;',
    to: '    if (pattern === undefined) continue;',
  },
  {
    rule: 'shell: the argv prefix must match literally at the front',
    from: '    if (args[index] !== rule.argv_prefix[index]) return false;',
    to: '    ',
  },
  {
    rule: 'shell: the command-line cap is enforced',
    from: '  if (commandLineLength(executable, args) > (context.max_command_line_bytes || SHELL_MAX_COMMAND_LINE_BYTES)) {\n    return { allowed: false, error: \'ERR_NOT_ALLOWED\', reason: \'argument_rejected\' };\n  }',
    to: '  ',
  },
  {
    rule: 'shell: the command-line length is counted in bytes, not characters',
    from: "    args.reduce((total, argument) => total + Buffer.byteLength(argument, 'utf8'), 0) +",
    to: '    args.reduce((total, argument) => total + argument.length, 0) +',
  },
  {
    rule: 'shell: the suspension threshold is twenty rejections',
    from: 'const SHELL_REJECTIONS_BEFORE_SUSPENSION = 20;',
    to: 'const SHELL_REJECTIONS_BEFORE_SUSPENSION = 21;',
  },
  {
    rule: 'shell: the output cap is a maximum',
    from: '  return produced > SHELL_OUTPUT_CAP_BYTES;',
    to: '  return false;',
  },
  {
    rule: 'crypto: nothing accepted yet is not the number zero',
    from: '  if (highestAccepted === null || highestAccepted === undefined) {\n    return { accepted: true, replay: false };\n  }',
    to: '  if (highestAccepted === undefined) highestAccepted = 0;',
  },
];

/** Runs the gate and reports whether it passed. */
function runGate() {
  try {
    const out = execFileSync(process.execPath, [gate], { encoding: 'utf8', cwd: repoRoot });
    return { passed: true, out };
  } catch (error) {
    return { passed: false, out: (error.stdout || '') + (error.stderr || '') };
  }
}

/** The number of checks the gate reports, for the summary. */
function checkCount(out) {
  const match = out.match(/ok\s+(\d+) Kotlin-mirrored/);
  return match ? Number(match[1]) : null;
}

function main() {
  const original = fs.readFileSync(gate, 'utf8');

  // Restoring in a `finally` is not enough on its own: the process can be interrupted, so the
  // restore also happens after every single mutation rather than once at the end. A gate left
  // holding a mutation would be a much worse outcome than a failed run.
  const restore = () => fs.writeFileSync(gate, original);

  process.on('SIGINT', () => {
    restore();
    process.exit(130);
  });

  const baseline = runGate();

  if (!baseline.passed) {
    console.error('FAIL  the gate does not pass unmutated, so nothing here would be meaningful.');
    console.error('      Run `npm run check:kotlin` and fix that first.');
    return 1;
  }

  const count = checkCount(baseline.out);

  console.log(`ok    baseline passes${count === null ? '' : ` with ${count} checks`}`);
  console.log(`ok    ${MUTATIONS.length} mutations declared`);
  console.log();
  console.log('      Each mutation breaks one rule on purpose and expects the gate to notice. The');
  console.log('      FAIL lines below are those expected failures, not a broken build. A mutation');
  console.log('      that reports SURVIVED, or one whose target text has moved, fails this run.');
  console.log();

  const survivors = [];
  const skipped = [];

  // The same normalisation the apply step uses, so the pre-check and the edit cannot disagree
  // about whether a needle is present. A CRLF gate against a `\n` needle is the mismatch this
  // avoids: the check would report a skip for a mutation that would in fact have applied.
  const normaliseForMatch = (text) => text.replace(/\r\n/g, '\n');
  const matchableOriginal = normaliseForMatch(original);

  for (const mutation of MUTATIONS) {
    if (!matchableOriginal.includes(normaliseForMatch(mutation.from))) {
      // A mutation whose needle no longer matches is a hole in THIS tool, not a pass. It is
      // reported as a failure so that a refactor of the gate cannot quietly reduce the coverage
      // of the thing that checks the coverage.
      skipped.push(mutation);
      continue;
    }

    // The needle and the gate are compared with line endings NORMALISED. The gate is checked in
    // with CRLF, and a mutation declared with `\n` in its needle would otherwise match nothing --
    // which is how sixteen of the shell mutations silently failed to apply. Normalising here
    // rather than writing `\r\n` in every needle keeps the declarations readable and makes the
    // match independent of whichever platform last touched either file.
    const normalise = (text) => text.replace(/\r\n/g, '\n');
    const normalisedOriginal = normalise(original);
    const normalisedFrom = normalise(mutation.from);

    // The mutated gate is written back with the ORIGINAL file's line endings, so a mutated run
    // differs from the clean one only by the mutation itself.
    const usesCrlf = original.includes('\r\n');
    const mutated = normalisedOriginal.replace(normalisedFrom, normalise(mutation.to));

    if (mutated === normalisedOriginal) {
      console.log(`FAIL      ${mutation.rule}`);
      console.log('          the needle matched nothing, so no mutation was applied');
      restore();
      continue;
    }

    fs.writeFileSync(gate, usesCrlf ? mutated.replace(/\n/g, '\r\n') : mutated);

    const result = runGate();

    // Restored immediately, before any reporting, so an exception in the reporting cannot
    // leave the gate mutated.
    restore();

    if (result.passed) {
      survivors.push(mutation);
      console.log(`SURVIVED  ${mutation.rule}`);
      continue;
    }

    const failures = (result.out.match(/^FAIL/m) || []).length;
    const first = result.out.split('\n').find((line) => line.startsWith('FAIL'));

    console.log(`caught    ${mutation.rule}`);
    if (first) console.log(`          ${first.trim().replace(/^FAIL\s+/, '')}${failures > 1 ? ` (+${failures - 1} more)` : ''}`);
  }

  restore();

  const restored = runGate();

  console.log();

  if (skipped.length > 0) {
    console.error(`FAIL  ${skipped.length} mutation(s) could not be applied:`);
    for (const mutation of skipped) console.error(`      ${mutation.rule}`);
    console.error('      A mutation whose target text has moved is not a mutation, so this is a');
    console.error('      failure of this tool rather than a pass of the gate.');
    return 1;
  }

  if (survivors.length > 0) {
    console.error(`FAIL  ${survivors.length} of ${MUTATIONS.length} mutations survived:`);
    for (const mutation of survivors) console.error(`      ${mutation.rule}`);
    console.error();
    console.error('      A surviving mutation means the gate does not check that rule. Add a');
    console.error('      check that fails when the rule is broken, then re-run this.');
    return 1;
  }

  if (!restored.passed) {
    console.error('FAIL  the gate does not pass after restoring, which means this tool left it broken.');
    return 1;
  }

  console.log(`ok    all ${MUTATIONS.length} mutations caught`);
  console.log('ok    the gate passes again after restoring');
  console.log();
  console.log('NOTE  Catching a mutation shows the gate checks that rule. It does not show the');
  console.log('      rule is right, and it says nothing about whether the Kotlin compiles.');

  return 0;
}

process.exitCode = main();
