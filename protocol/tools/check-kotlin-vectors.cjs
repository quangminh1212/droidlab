// Validates the Kotlin sibling's logic against the real conformance vectors.
//
// WHAT THIS IS FOR
// android/core-protocol cannot be compiled in this environment: there is no Android SDK
// and no Gradle. Every Kotlin assertion therefore rests on an argument rather than a run,
// and an argument that is never checked is how a wrong claim gets committed.
//
// So the arithmetic and the fixture assumptions of the Kotlin tests are ported here and
// run against the same files under protocol/vectors/. This is a real gate: it runs in
// `npm run check`, so a vector that moves out from under the Kotlin test fails here even
// though the Kotlin test cannot itself be executed.
//
// WHAT THIS IS NOT
// It is NOT evidence that the Kotlin compiles. A type error, a wrong import or an
// unresolved reference will pass every check in this file. The only thing that can settle
// that is a compiler, and this repository does not have one for Kotlin. Nothing here may
// be cited as "the Kotlin tests pass".
//
// Every check below states which Kotlin declaration it stands in for, so the mapping is
// auditable in both directions: if a Kotlin expectation changes, the check that mirrors it
// is named here and will need changing too.
//
// Run from the repository root:  node protocol/tools/check-kotlin-vectors.cjs
const fs = require('fs');
const path = require('path');

const vectorsDir = path.join(__dirname, '..', 'vectors');

/** Reads and parses a vector file. */
function load(fileName) {
  const file = path.join(vectorsDir, fileName);
  if (!fs.existsSync(file)) {
    throw new Error(`vector file ${fileName} is missing from ${vectorsDir}`);
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/** Decodes hex, asserting it is hex so a bad fixture fails loudly. */
function hex(text) {
  if (typeof text !== 'string' || text.length % 2 !== 0 || /[^0-9a-fA-F]/.test(text)) {
    throw new Error(`not valid hex: ${String(text).slice(0, 40)}`);
  }
  return Buffer.from(text, 'hex');
}

const problems = [];
const checks = [];

function expect(condition, description) {
  if (condition) {
    checks.push(description);
  } else {
    problems.push(description);
  }
}

// ---------------------------------------------------------------------------
// FrameHeaderCodec / FrameCodec  --  mirror of FrameHeaderCodec.kt and FrameCodec.kt
// ---------------------------------------------------------------------------

const HEADER_LENGTH = 24;
const DEFAULT_MAX_FRAME_BYTES = 16777216;

/** Mirror of FrameHeaderCodec.decode plus FrameCodec.read. */
function readFrame(bytes, offset = 0, maxFrameBytes = DEFAULT_MAX_FRAME_BYTES) {
  const available = bytes.length - offset;

  if (offset < 0 || offset > bytes.length) {
    return { kind: 'failure', error: 'ERR_MALFORMED' };
  }

  // A short header is not malformed: it is how every frame starts, and how a frame looks
  // when a transport splits it.
  if (available < HEADER_LENGTH) {
    return { kind: 'needMore', neededBytes: offset + HEADER_LENGTH };
  }

  if (bytes.subarray(offset, offset + 4).toString('latin1') !== 'DLWP') {
    return { kind: 'failure', error: 'ERR_MALFORMED' };
  }

  const version = bytes[offset + 4];
  if (version !== 1) {
    return { kind: 'failure', error: 'ERR_VERSION_MISMATCH' };
  }

  const headerLength = bytes[offset + 6];
  if (headerLength === 0) {
    return { kind: 'failure', error: 'ERR_MALFORMED' };
  }
  if (headerLength !== HEADER_LENGTH) {
    return { kind: 'failure', error: 'ERR_UNSUPPORTED_HEADER' };
  }

  const bodyLength = bytes.readUInt32BE(offset + 20);

  // Refused from the header alone, before any body is read: the point of the limit is to
  // refuse before allocating.
  if (bodyLength > maxFrameBytes) {
    return { kind: 'failure', error: 'ERR_FRAME_TOO_LARGE' };
  }

  const total = HEADER_LENGTH + bodyLength;
  if (total > 0x7fffffff) {
    return { kind: 'failure', error: 'ERR_FRAME_TOO_LARGE' };
  }

  if (available < total) {
    return { kind: 'needMore', neededBytes: offset + total };
  }

  return {
    kind: 'ok',
    consumed: total,
    frame: {
      version,
      flags: bytes[offset + 5],
      headerLength,
      messageType: bytes[offset + 7],
      channelId: bytes.readUInt32BE(offset + 8),
      sequenceNumber: bytes.readUInt32BE(offset + 12),
      acknowledgment: bytes.readUInt32BE(offset + 16),
      bodyLength,
      body: bytes.subarray(offset + HEADER_LENGTH, offset + total),
    },
  };
}

/** Mirror of FrameCodec.buildAad: the AAD carries the PLAINTEXT length, not the wire's. */
function buildAad(header, plaintextLength) {
  const aad = Buffer.alloc(HEADER_LENGTH);
  aad.write('DLWP', 0, 'latin1');
  aad.writeUInt8(header.version, 4);
  aad.writeUInt8(header.flags, 5);
  aad.writeUInt8(header.headerLength, 6);
  aad.writeUInt8(header.messageType, 7);
  aad.writeUInt32BE(header.channelId, 8);
  aad.writeUInt32BE(header.sequenceNumber, 12);
  aad.writeUInt32BE(header.acknowledgment, 16);
  aad.writeUInt32BE(plaintextLength, 20);
  return aad;
}

// ---- FramingBasicTest.everyFramingVectorDecodesAsDeclared ---------------------
{
  const framing = load('framing-basic.json');
  expect(Array.isArray(framing.vectors), 'framing-basic.json has a vectors array');
  expect(framing.vectors.length >= 6, 'framing-basic.json declares at least 6 vectors');

  let decoded = 0;
  for (const vector of framing.vectors) {
    const id = vector.id;
    const bytes = hex(vector.frame);
    const result = readFrame(bytes);

    expect(result.kind === 'ok', `${id} decodes`);
    if (result.kind !== 'ok') continue;

    const header = vector.decoded.header;
    const frame = result.frame;

    expect(frame.version === header.version, `${id} version`);
    expect(frame.flags === header.flags, `${id} flags`);
    expect(frame.headerLength === header.header_length, `${id} header length`);
    expect(frame.messageType === header.message_type, `${id} message type`);
    expect(frame.channelId === header.channel_id, `${id} channel id`);
    expect(frame.sequenceNumber === header.sequence_number, `${id} sequence number`);
    expect(frame.acknowledgment === header.acknowledgment, `${id} acknowledgment`);
    expect(frame.bodyLength === header.body_length, `${id} body length`);

    // The body is the tail of the frame, which is what the Kotlin test compares.
    const body = hex(vector.body_hex);
    expect(frame.body.equals(body), `${id} body bytes are body_hex`);
    expect(result.consumed === bytes.length, `${id} consumes the whole frame`);

    decoded++;
  }

  expect(decoded === framing.vectors.length, 'every framing vector decoded');
}

// ---- FramingBasicTest.everyPrefixOfAFrameReportsHowMuchIsMissing --------------
{
  const framing = load('framing-basic.json');
  let prefixes = 0;
  let good = true;

  for (const vector of framing.vectors) {
    const full = hex(vector.frame);

    for (let length = 0; length < full.length; length++) {
      const result = readFrame(full.subarray(0, length));
      prefixes++;

      if (result.kind !== 'needMore') {
        problems.push(`${vector.id} truncated to ${length} must ask for more, got ${result.kind}`);
        good = false;
        continue;
      }

      if (!(result.neededBytes > length) || !(result.neededBytes <= full.length)) {
        problems.push(
          `${vector.id} truncated to ${length} asked for ${result.neededBytes}, ` +
            `which is not within (${length}, ${full.length}]`,
        );
        good = false;
      }
    }
  }

  if (good) {
    checks.push(`every prefix of every frame asks for more bytes (${prefixes} prefixes)`);
  }
}

// ---- FramingBasicTest.everyFramingVectorRoundTrips ---------------------------
{
  const framing = load('framing-basic.json');
  let roundTripped = 0;

  for (const vector of framing.vectors) {
    const bytes = hex(vector.frame);
    const result = readFrame(bytes);
    if (result.kind !== 'ok') continue;

    // Rebuild by hand the way FrameCodec.build does.
    const header = result.frame;
    const rebuilt = Buffer.alloc(HEADER_LENGTH + header.bodyLength);
    rebuilt.write('DLWP', 0, 'latin1');
    rebuilt.writeUInt8(header.version, 4);
    rebuilt.writeUInt8(header.flags, 5);
    rebuilt.writeUInt8(header.headerLength, 6);
    rebuilt.writeUInt8(header.messageType, 7);
    rebuilt.writeUInt32BE(header.channelId, 8);
    rebuilt.writeUInt32BE(header.sequenceNumber, 12);
    rebuilt.writeUInt32BE(header.acknowledgment, 16);
    rebuilt.writeUInt32BE(header.bodyLength, 20);
    header.body.copy(rebuilt, HEADER_LENGTH);

    expect(rebuilt.equals(bytes), `${vector.id} round-trips byte-identically`);
    roundTripped++;
  }

  expect(roundTripped === framing.vectors.length, 'every framing vector round-tripped');
}

// ---- FramingBasicTest.anOversizedDeclaredBodyIsRefusedBeforeTheBodyIsRead -----
{
  const headerOnly = hex('444c575001011832000000000000000100000000ffffffff');
  expect(headerOnly.length === HEADER_LENGTH, 'the oversized probe is a bare header');

  const result = readFrame(headerOnly);
  expect(
    result.kind === 'failure' && result.error === 'ERR_FRAME_TOO_LARGE',
    'an oversized declared body is refused from the header alone with ERR_FRAME_TOO_LARGE',
  );
}

// ---- FramingBasicTest.theAadUsesThePlaintextLength ---------------------------
{
  const keys = load('crypto-session-keys.json');
  const aead = (keys.aead_vectors || []).find((v) => v.id === 'aead.header-is-associated-data');

  expect(!!aead, 'the AAD vector aead.header-is-associated-data exists');

  if (aead) {
    const expected = hex(aead.aad_bytes);
    expect(expected.length === aead.aad_length, "the AAD vector's declared length matches its bytes");
    expect(aead.aad_length === HEADER_LENGTH, 'the AAD is the 24-byte header');

    const d = aead.aad_decoded;
    const rebuilt = buildAad(
      {
        version: d.version,
        flags: d.flags,
        headerLength: d.header_length,
        messageType: d.message_type,
        channelId: d.channel_id,
        sequenceNumber: d.sequence_number,
        acknowledgment: d.acknowledgment,
      },
      0, // the plaintext length
    );

    expect(rebuilt.equals(expected), 'the AAD rebuilt with the plaintext length matches the vector');

    // The vector only tests the substitution if the two lengths actually differ, which is
    // the assertion the Kotlin test makes too.
    expect(d.body_length === 0, "the vector's AAD body_length field is the empty plaintext length");
    expect(28 !== d.body_length, 'the wire body length (28) differs from the AAD plaintext length (0)');
  }
}

// ---- FramingBasicTest.reservedFlagBitsArePreserved --------------------------
{
  const bytes = hex('444c575001f1180500000000000000010000000000000000');
  const result = readFrame(bytes);

  expect(result.kind === 'ok', 'a frame with reserved flag bits decodes rather than being refused');

  if (result.kind === 'ok') {
    expect(result.frame.flags === 0xf1, 'the reserved flag bits are preserved on decode');
    expect((result.frame.flags & 0xf0) === 0xf0, 'bits 4-7 are the reserved ones');
    expect((result.frame.flags & 0x01) === 0x01, 'bit 0 is still the encrypted flag');
  }
}

// ---------------------------------------------------------------------------
// CborReader  --  mirror of cbor/CborReader.kt
// ---------------------------------------------------------------------------

/** Mirror of the shortest-encoding rule in CborReader.readBigEndian. */
function shortestEncodingLength(value) {
  if (value < 24) return 0;
  if (value <= 0xff) return 1;
  if (value <= 0xffff) return 2;
  if (value <= 0xffffffff) return 4;
  return 8;
}

// ---- CborCodecTests: the reader refuses what DLWP/1 does not use -------------
{
  // The boundaries of the shortest-encoding table, which is where a wrong comparison
  // silently accepts a second encoding of the same value.
  expect(shortestEncodingLength(0) === 0, 'cbOR 0 uses no extra bytes');
  expect(shortestEncodingLength(23) === 0, 'cbOR 23 uses no extra bytes');
  expect(shortestEncodingLength(24) === 1, 'cbOR 24 uses one extra byte');
  expect(shortestEncodingLength(255) === 1, 'cbOR 255 uses one extra byte');
  expect(shortestEncodingLength(256) === 2, 'cbOR 256 uses two extra bytes');
  expect(shortestEncodingLength(65535) === 2, 'cbOR 65535 uses two extra bytes');
  expect(shortestEncodingLength(65536) === 4, 'cbOR 65536 uses four extra bytes');

  // A value of 5 sent in one extra byte is not the shortest form, so the Kotlin rule
  // (length > minimum) rejects it. This is the vector the file carries.
  expect(1 > shortestEncodingLength(5), 'a non-shortest encoding of 5 is rejected');
  expect(1 > shortestEncodingLength(23), 'a non-shortest encoding of 23 is rejected');

  // The empty body is zero bytes and is canonical for a parameterless message.
  const framing = load('framing-basic.json');
  const ping = framing.vectors.find((v) => v.id === 'framing.ping.empty-body');
  expect(!!ping, 'the empty-body PING vector exists');
  if (ping) {
    expect(ping.decoded.header.body_length === 0, 'PING declares a zero-length body');
    expect(hex(ping.frame).length === HEADER_LENGTH, 'a parameterless frame is exactly 24 bytes');
    expect(hex(ping.body_hex).length === 0, 'the empty body is zero bytes, not 0xA0');
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

// The counts let a reader see how much of the Kotlin surface is actually mirrored here,
// so the "verified" claim cannot overreach silently.
if (problems.length > 0) {
  console.error('');
  for (const problem of problems) console.error(`FAIL  ${problem}`);
  console.error('');
  console.error(`${problems.length} problem(s), ${checks.length} check(s) passed`);
  process.exit(1);
}

console.log(`ok    ${checks.length} Kotlin-mirrored checks hold against the real vectors`);
console.log('ok    framing decode, prefix arithmetic, round-trip, AAD and reserved flags');
console.log('ok    cbOR shortest-encoding boundaries and the canonical empty body');
console.log('');
console.log('NOTE  This validates the Kotlin logic, NOT that the Kotlin compiles.');
console.log('      android/core-protocol has never been through a compiler here.');
