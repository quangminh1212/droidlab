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

  for (const mutation of MUTATIONS) {
    if (!original.includes(mutation.from)) {
      // A mutation whose needle no longer matches is a hole in THIS tool, not a pass. It is
      // reported as a failure so that a refactor of the gate cannot quietly reduce the coverage
      // of the thing that checks the coverage.
      skipped.push(mutation);
      continue;
    }

    fs.writeFileSync(gate, original.replace(mutation.from, mutation.to));

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
