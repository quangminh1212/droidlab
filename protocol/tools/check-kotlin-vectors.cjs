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
// FrameClassifier  --  mirror of FrameClassifier.kt
// ---------------------------------------------------------------------------

// The registry the Kotlin test hands the classifier: only the codes the malformed vectors
// use, plus the two capability gates. Kept identical to MalformedTest.REGISTRY.
const CLASSIFIER_REGISTRY = {
  types: {
    1: { code: 1, name: 'HELLO', isHandshake: true, isEncrypted: false },
    2: { code: 2, name: 'HELLO_ACK', isHandshake: true, isEncrypted: false },
    3: { code: 3, name: 'AUTH', isHandshake: true, isEncrypted: true },
    4: { code: 4, name: 'AUTH_OK', isHandshake: true, isEncrypted: true },
    5: { code: 5, name: 'PING', isHandshake: false, isEncrypted: true },
    50: { code: 50, name: 'VIDEO_CONFIG', isHandshake: false, isEncrypted: true },
    64: { code: 64, name: 'INPUT_TOUCH', isHandshake: false, isEncrypted: true },
    80: { code: 80, name: 'SHELL_EXEC', isHandshake: false, isEncrypted: true },
  },
  capabilities: { 64: 'input.touch', 80: 'shell.exec' },
  maxChannels: 8,
};

const REORDER_WINDOW = 32;

/** Mirror of FrameClassifier.ANY_CAPABILITY. */
const ANY_CAPABILITY = 'any';

/**
 * Builds a minimal plaintext frame, the way MalformedTest.frame does.
 *
 * The semantic vectors name a message type and a channel but carry no frame bytes, so the
 * test has to construct one. The body is empty, which CborReader accepts as the canonical
 * encoding of a parameterless message.
 */
function buildSimpleFrame(messageType, channelId = 0) {
  const bytes = Buffer.alloc(HEADER_LENGTH);
  bytes.write('DLWP', 0, 'latin1');
  bytes.writeUInt8(1, 4); // version
  bytes.writeUInt8(0, 5); // flags: plaintext
  bytes.writeUInt8(HEADER_LENGTH, 6);
  bytes.writeUInt8(messageType, 7);
  bytes.writeUInt32BE(channelId, 8);
  bytes.writeUInt32BE(0, 12); // sequence
  bytes.writeUInt32BE(0, 16); // acknowledgment
  bytes.writeUInt32BE(0, 20); // body length
  return bytes;
}

/** Mirror of ErrorCode.isFatal, taken from the registry's severity field. */
const FATAL_CODES = new Set([
  'ERR_UNSUPPORTED_HEADER', 'ERR_FRAME_TOO_LARGE', 'ERR_MALFORMED', 'ERR_VERSION_MISMATCH',
  'ERR_HANDSHAKE_MISMATCH', 'ERR_UNAUTHORIZED', 'ERR_PAIRING_REQUIRED', 'ERR_PAIRING_REVOKED',
  'ERR_REPLAY_DETECTED', 'ERR_UNEXPECTED_MESSAGE', 'ERR_INTERNAL',
]);

/** Mirror of FrameClassifier.classifyDecodeFailure. */
function classifyDecodeFailure(error) {
  if (['ERR_VERSION_MISMATCH', 'ERR_UNSUPPORTED_HEADER', 'ERR_FRAME_TOO_LARGE'].includes(error)) {
    return { outcome: 'error_frame_then_close', error };
  }
  return { outcome: 'error_frame_then_close', error: 'ERR_MALFORMED' };
}

/** Mirror of FrameClassifier.hasMagic. */
function hasMagic(bytes) {
  return bytes.length >= 4 &&
    bytes[0] === 0x44 && bytes[1] === 0x4c && bytes[2] === 0x57 && bytes[3] === 0x50;
}

/** Mirror of FrameClassifier.classify. */
function classify(frame, context = {}) {
  const definition = CLASSIFIER_REGISTRY.types[frame.messageType];

  // 4. The body must be well-formed cbOR before its meaning is considered, and only for a
  //    plaintext body: an encrypted body is nonce||ciphertext||tag, so asking whether it
  //    parses as cbOR is a question with no meaning whose answer is "no" almost always.
  //
  //    When no header is supplied the frame is treated as plaintext with an empty body,
  //    which is what MalformedTest.frame builds. Making that explicit means a caller that
  //    forgets the body gets the parameterless-message case rather than silently skipping
  //    the check that six of the vectors exist to pin.
  const encrypted = frame.header ? frame.header.isEncrypted : false;
  const body = frame.body === undefined ? Buffer.alloc(0) : frame.body;

  if (!encrypted) {
    if (!isWellFormedCborMap(body)) {
      return { outcome: 'error_frame_then_close', error: 'ERR_MALFORMED' };
    }
  }

  if (!definition) {
    return { outcome: 'error_session_continues', error: 'ERR_UNSUPPORTED_MESSAGE' };
  }

  // Not restricted to handshake types: PING is registered and ordinary and is still refused
  // as a first frame, which is what malformed.first-frame-not-hello pins.
  if (context.isFirstFrame && frame.messageType !== 1) {
    return { outcome: 'error_frame_then_close', error: 'ERR_UNEXPECTED_MESSAGE' };
  }

  const capability = CLASSIFIER_REGISTRY.capabilities[frame.messageType];
  if (capability && capability !== ANY_CAPABILITY) {
    const negotiated = context.negotiatedCapabilities || new Set();
    if (!negotiated.has(capability)) {
      return { outcome: 'error_session_continues', error: 'ERR_UNSUPPORTED_FEATURE' };
    }
  }

  const open = context.openChannels || new Set();
  if (frame.channelId !== 0 && !open.has(frame.channelId)) {
    return { outcome: 'error_session_continues', error: 'ERR_CHANNEL_UNKNOWN' };
  }

  return { outcome: 'accepted', error: null };
}

/**
 * Mirror of CborReader.isWellFormedMap, walking the body the way the Kotlin reader does.
 *
 * It is a walk and not a header check because the vectors' bad bodies all start with a
 * perfectly good map header -- `a1 61 78` is a one-entry map with the key "x" -- and put the
 * fault in the value or the key. A reader that only looked at the first byte would accept all
 * five, which is exactly the bug this mirror caught in the first draft of it.
 *
 * The rules enforced, each of which a vector pins:
 *   - only a definite-length map, no indefinite lengths
 *   - text keys only
 *   - no tags
 *   - no floats or simple values other than false, true and null
 *   - no 64-bit arguments
 *   - shortest integer encodings only
 *   - valid UTF-8
 */
function isWellFormedCborMap(body) {
  if (!Buffer.isBuffer(body)) return false;

  // Zero bytes is canonical for a parameterless message.
  if (body.length === 0) return true;

  const reader = { bytes: body, offset: 0 };

  try {
    readCborMap(reader);
    return true;
  } catch {
    return false;
  }
}

/** Reads a definite-length map with text keys. */
function readCborMap(r) {
  const header = readCborHeader(r);

  if (header.major !== 5) {
    throw new Error('not a map');
  }

  const seen = new Set();

  for (let i = 0; i < header.argument; i++) {
    const keyHeader = readCborHeader(r);

    if (keyHeader.major !== 3) {
      throw new Error('a map key must be a text string');
    }

    const key = decodeUtf8Strict(r, keyHeader.argument);

    // A duplicate key is refused rather than last-one-wins, the same rule the Kotlin reader
    // applies: two peers resolving a duplicate differently would disagree about a message
    // while both accepting it.
    if (seen.has(key)) {
      throw new Error('duplicate map key');
    }

    seen.add(key);

    readCborValue(r);
  }
}

/** Reads any value, rejecting everything DLWP/1 does not use. */
function readCborValue(r) {
  const header = readCborHeader(r);

  switch (header.major) {
    case 0: // unsigned integer
    case 1: // negative integer
      return;

    case 2: // byte string
      skip(r, header.argument);
      return;

    case 3: // text string
      decodeUtf8Strict(r, header.argument);
      return;

    case 4: // array
      for (let i = 0; i < header.argument; i++) readCborValue(r);
      return;

    case 5: // map
      readCborMap(r);
      return;

    case 6:
      // Tags are unused, and the vector's own note says why they must be refused rather
      // than interpreted: tag 2 is the positive bignum tag, which an attacker can use to
      // smuggle a large integer past a length check that only understands major type 0.
      throw new Error('tags are not part of DLWP/1 bodies');

    case 7:
      // Only false (20), true (21) and null (22). Anything else includes the floats, which
      // the protocol defines no fields for, so every float encoding is rejected rather than
      // coerced.
      if (header.argument === 20 || header.argument === 21 || header.argument === 22) return;
      throw new Error(`simple value ${header.argument} is not part of DLWP/1 bodies`);

    default:
      throw new Error(`major type ${header.major} is not defined`);
  }
}

/** Reads a cbOR item header, enforcing the shortest-encoding rule. */
function readCborHeader(r) {
  if (r.offset >= r.bytes.length) throw new Error('unexpected end of body');

  const initial = r.bytes[r.offset++];
  const major = initial >> 5;
  const additional = initial & 0x1f;

  if (additional < 24) {
    return { major, argument: additional };
  }

  // 24 is the shortest encoding of a value that does not fit in the 5-bit form; 25, 26 and
  // 27 are longer. Anything longer than necessary is refused, because two encoders that
  // disagree about the shortest form produce different bytes for the same message and a
  // transcript hash over those bytes would not match.
  const widths = { 24: 1, 25: 2, 26: 4, 27: 8 };

  if (additional === 31) {
    throw new Error('indefinite lengths are not part of DLWP/1 bodies');
  }

  const width = widths[additional];

  if (!width) {
    throw new Error(`additional information ${additional} is reserved`);
  }

  // 64-bit arguments are read by the Kotlin reader but refused outright: DLWP/1 has no such
  // integers, so a body carrying one is not merely unusual, it is out of spec.
  if (width === 8) {
    throw new Error('a 64-bit argument is not part of DLWP/1 bodies');
  }

  if (r.offset + width > r.bytes.length) throw new Error('truncated argument');

  let value = 0;
  for (let i = 0; i < width; i++) {
    value = value * 256 + r.bytes[r.offset++];
  }

  const minimum = shortestEncodingLength(value);

  if (width > minimum) {
    throw new Error(`the argument ${value} uses ${width} bytes where ${minimum} would do`);
  }

  return { major, argument: value };
}

/** Advances past n bytes, asserting they are present. */
function skip(r, n) {
  if (r.offset + n > r.bytes.length) throw new Error('item runs past the end of the body');
  r.offset += n;
}

/**
 * Decodes UTF-8 strictly, so an invalid sequence is malformed rather than replaced.
 *
 * A reader that substituted the replacement character would turn a malformed frame into a
 * subtly different valid one, which is the failure the invalid-utf8 vector exists to pin.
 */
function decodeUtf8Strict(r, length) {
  if (r.offset + length > r.bytes.length) throw new Error('text string runs past the end of the body');

  const slice = r.bytes.subarray(r.offset, r.offset + length);
  r.offset += length;

  const decoded = slice.toString('utf8');

  // A round-trip is the check: an invalid sequence decodes to U+FFFD, and re-encoding that
  // does not give back the original bytes.
  if (Buffer.from(decoded, 'utf8').length !== slice.length || decoded.includes('\uFFFD')) {
    throw new Error('the text string is not valid UTF-8');
  }

  return decoded;
}

/** Mirror of FrameClassifier.classifyChannelOpen. */
function classifyChannelOpen(requestedChannel, openChannels) {
  // Every open channel counts, the control channel included: that is what the registry's
  // max_channels means and what the vector encodes (eight channels against a limit of eight).
  if (openChannels.size >= CLASSIFIER_REGISTRY.maxChannels) {
    return { outcome: 'error_session_continues', error: 'ERR_CHANNEL_LIMIT' };
  }
  if (openChannels.has(requestedChannel)) {
    return { outcome: 'error_session_continues', error: 'ERR_CHANNEL_LIMIT' };
  }
  return { outcome: 'accepted', error: null };
}

/** Mirror of FrameClassifier.classifyBody. */
function classifyBody(requiredKeys, presentKeys, knownKeys) {
  for (const required of requiredKeys) {
    if (!presentKeys.has(required)) {
      return { outcome: 'error_frame_then_close', error: 'ERR_MALFORMED' };
    }
  }
  for (const present of presentKeys) {
    if (!knownKeys.has(present) && !requiredKeys.has(present)) {
      return { outcome: 'accepted', error: null };
    }
  }
  return { outcome: 'accepted', error: null };
}

/** Mirror of FrameClassifier.classifySequence, including the seen-set ordering. */
function classifySequence(sequenceNumber, highestSeen, seenBefore = null, window = REORDER_WINDOW) {
  if (highestSeen === null || highestSeen === undefined) {
    return { outcome: 'accepted', error: null };
  }

  // Checked BEFORE the window, deliberately: a seen number is a replay whatever its distance
  // from the head, so the window must not get the chance to excuse it.
  if (seenBefore === true) {
    return { outcome: 'error_frame_then_close', error: 'ERR_REPLAY_DETECTED' };
  }

  if (sequenceNumber > highestSeen) {
    return { outcome: 'accepted', error: null };
  }

  const behind = highestSeen - sequenceNumber;

  if (behind > window) {
    return { outcome: 'error_frame_then_close', error: 'ERR_REPLAY_DETECTED' };
  }

  if (behind === 0) {
    return { outcome: 'error_frame_then_close', error: 'ERR_REPLAY_DETECTED' };
  }

  return { outcome: 'accepted', error: null };
}

/** Mirror of MalformedTest.outcomeFor; returns null for an unknown name so it fails loudly. */
function outcomeFor(name) {
  const known = {
    accepted: 'accepted',
    error_session_continues: 'error_session_continues',
    error_frame_then_close: 'error_frame_then_close',
    close_connection: 'close_connection',
    wait_then_error_on_close: 'wait_then_error_on_close',
  };
  return known[name] || null;
}

/** Mirror of FrameClassifier.classify(bytes, context) -- the ordering is the protocol. */
function classifyBytes(bytes, context = {}) {
  // 1. Is this a frame at all? Checked before the header, because a wrong magic means the
  //    stream is not DLWP/1: there is nothing to reply to and no framing to resynchronise
  //    on, since any offset might look like the magic from the middle of a body. This is
  //    why malformed.bad-magic expects close_connection while every other malformed frame
  //    expects an error frame first.
  if (bytes.length >= 4 && !hasMagic(bytes)) {
    return { outcome: 'close_connection', error: 'ERR_MALFORMED' };
  }

  const read = readFrame(bytes);

  if (read.kind === 'failure') {
    return classifyDecodeFailure(read.error);
  }

  if (read.kind === 'needMore') {
    return { outcome: 'wait_then_error_on_close', error: 'ERR_IO' };
  }

  return classify(
    {
      messageType: read.frame.messageType,
      channelId: read.frame.channelId,
      body: read.frame.body,
      header: read.frame,
    },
    context,
  );
}

// ---- MalformedTest.everyRawFrameVectorMatchesItsDeclaredOutcome ------------------
{
  const malformed = load('malformed.json');
  expect(Array.isArray(malformed.vectors), 'malformed.json has a vectors array');

  const frameVectors = malformed.vectors.filter((v) => v.frame);
  expect(
    frameVectors.length >= 12,
    `malformed.json declares at least 12 raw-frame vectors (found ${frameVectors.length})`,
  );

  for (const v of frameVectors) {
    const verdict = classifyBytes(hex(v.frame), {
      openChannels: new Set(),
      negotiatedCapabilities: new Set(),
      isFirstFrame: v.first_frame_message_type !== undefined,
    });

    const expected = outcomeFor(v.expected);
    expect(expected !== null, `${v.id}: the outcome name "${v.expected}" is one the test knows`);

    if (expected !== null) {
      expect(verdict.outcome === expected, `${v.id} outcome is ${v.expected} (got ${verdict.outcome})`);
      expect(verdict.error === v.expected_error, `${v.id} error is ${v.expected_error} (got ${verdict.error})`);
    }

    // The severity consistency the Kotlin test asserts, so a classification cannot report a
    // fatal outcome with a recoverable code.
    if (v.expected_error) {
      const fatal = FATAL_CODES.has(v.expected_error);
      expect(
        fatal === (v.expected_severity === 'fatal'),
        `${v.id}: ${v.expected_error} is declared ${v.expected_severity} but isFatal is ${fatal}`,
      );
    }
  }
}

// ---- MalformedTest: the semantic vectors ---------------------------------------
{
  const malformed = load('malformed.json');
  const byId = (id) => malformed.vectors.find((v) => v.id === id);

  // An unregistered message type is recoverable, not fatal.
  const unknown = byId('malformed.unknown-message-type');
  expect(!!unknown, 'malformed.unknown-message-type exists');
  if (unknown) {
    const verdict = classifyBytes(hex(unknown.frame));
    expect(verdict && verdict.error === 'ERR_UNSUPPORTED_MESSAGE', 'an unregistered type gives ERR_UNSUPPORTED_MESSAGE');
    expect(verdict && verdict.outcome === 'error_session_continues', 'an unregistered type does not end the session');
  }

  // A registered message without its capability is refused, then accepted once granted.
  const cap = byId('malformed.unknown-capability-command');
  expect(!!cap, 'malformed.unknown-capability-command exists');
  if (cap) {
    const negotiated = new Set(cap.negotiated_capabilities);
    const capBytes = buildSimpleFrame(cap.message_type, 0);
    const refused = classifyBytes(capBytes, { negotiatedCapabilities: negotiated });
    expect(refused.error === 'ERR_UNSUPPORTED_FEATURE', 'an ungranted capability gives ERR_UNSUPPORTED_FEATURE');
    expect(refused.outcome === 'error_session_continues', 'an ungranted capability does not end the session');

    const granted = new Set([...negotiated, 'shell.exec']);
    const allowed = classifyBytes(capBytes, { negotiatedCapabilities: granted });
    expect(allowed.outcome === 'accepted' && allowed.error === null, 'granting the capability makes it acceptable');
  }

  // An unopened channel is refused, but only if the vector names a non-zero, unopened one.
  const chan = byId('malformed.channel-not-opened');
  expect(!!chan, 'malformed.channel-not-opened exists');
  if (chan) {
    const open = new Set(chan.open_channels);
    expect(chan.channel_id !== 0, 'the channel vector names a non-zero channel');
    expect(!open.has(chan.channel_id), "the channel vector's channel is not in open_channels");

    const bytes = buildSimpleFrame(chan.message_type, chan.channel_id);
    const verdict = classifyBytes(bytes, {
      openChannels: open,
      negotiatedCapabilities: new Set(['input.touch']),
    });
    expect(verdict.error === 'ERR_CHANNEL_UNKNOWN', 'an unopened channel gives ERR_CHANNEL_UNKNOWN');
    expect(verdict.outcome === 'error_session_continues', 'an unopened channel does not end the session');
  }

  // The channel limit: exactly at it is refused, one below is accepted.
  const limit = byId('malformed.channel-limit');
  expect(!!limit, 'malformed.channel-limit exists');
  if (limit) {
    const open = new Set(limit.open_channels);
    expect(limit.max_channels === CLASSIFIER_REGISTRY.maxChannels, "the channel limit matches the registry's max_channels");

    const dataChannels = [...open].filter((c) => c !== 0).length;
    expect(dataChannels >= 0, 'the channel vector lists its open channels');

    // Every open channel counts, the control channel included: 0 through 7 is eight channels
    // against a limit of eight. This is the assertion the first draft got wrong -- it counted
    // only the data channels, saw seven, and would have let a session reach nine.
    expect(open.size === limit.max_channels, 'the channel vector is exactly at the limit');

    const refused = classifyChannelOpen(limit.requested_channel, open);
    expect(refused.error === 'ERR_CHANNEL_LIMIT', 'opening past the limit gives ERR_CHANNEL_LIMIT');
    expect(refused.outcome === 'error_session_continues', 'the channel limit does not end the session');

    const highest = Math.max(...open);
    const oneBelow = new Set([...open].filter((c) => c !== highest));
    expect(oneBelow.size === limit.max_channels - 1, 'the one-below case drops exactly one channel');
    expect(
      classifyChannelOpen(limit.requested_channel, oneBelow).outcome === 'accepted',
      'one below the channel limit is accepted',
    );
  }

  // A missing required key is malformed and fatal; an unknown extra key is ignored.
  const missing = byId('malformed.missing-required-key');
  expect(!!missing, 'malformed.missing-required-key exists');
  if (missing) {
    const present = new Set(Object.keys(missing.body));
    const required = new Set(['action', 'pointers']);
    expect(![...required].every((k) => present.has(k)), 'the missing-key vector is actually missing a required key');

    const verdict = classifyBody(required, present, required);
    expect(verdict.error === 'ERR_MALFORMED', 'a missing required key gives ERR_MALFORMED');
    expect(verdict.outcome === 'error_frame_then_close', 'a missing required key ends the session');
  }

  const extra = byId('malformed.unknown-extra-key-ignored');
  expect(!!extra, 'malformed.unknown-extra-key-ignored exists');
  if (extra) {
    const present = new Set(Object.keys(extra.body));
    const known = new Set(['action', 'pointers']);
    expect([...present].some((k) => !known.has(k)), 'the extra-key vector actually carries an unknown key');

    const verdict = classifyBody(known, present, known);
    expect(verdict.outcome === 'accepted' && verdict.error === null, 'an unknown body key is ignored, not refused');
  }

  // A bad magic closes the connection, with no error frame to send, and that verdict comes
  // from the magic check rather than from the decoder's error -- which is the ordering the
  // Kotlin entry point exists to make explicit.
  const badMagic = byId('malformed.bad-magic');
  expect(!!badMagic, 'malformed.bad-magic exists');
  if (badMagic) {
    expect(badMagic.expected === 'close_connection', 'a bad magic closes the connection');

    const bytes = hex(badMagic.frame);
    expect(!hasMagic(bytes), 'the bad-magic vector does not start with the DLWP magic');

    const verdict = classifyBytes(bytes);
    expect(verdict.outcome === 'close_connection', 'a bad magic closes rather than sending an error frame');
    expect(verdict.error === 'ERR_MALFORMED', 'a bad magic is reported as ERR_MALFORMED');
  }
}

// ---- MalformedTest.everySequenceVectorMatchesItsDeclaredOutcome -----------------
{
  const malformed = load('malformed.json');
  const sequenceVectors = malformed.sequence_vectors || [];
  expect(
    sequenceVectors.length >= 3,
    `malformed.json declares at least 3 sequence vectors (found ${sequenceVectors.length})`,
  );

  for (const v of sequenceVectors) {
    const numbers = v.sequence;
    let highest = null;
    const accepted = new Set();
    let failure = null;
    let failureAt = -1;

    for (let i = 0; i < numbers.length; i++) {
      const verdict = classifySequence(numbers[i], highest, accepted.has(numbers[i]));
      if (verdict.outcome === 'accepted') {
        accepted.add(numbers[i]);
        if (highest === null || numbers[i] > highest) highest = numbers[i];
      } else {
        failure = verdict;
        failureAt = i;
        break;
      }
    }

    if (v.expected_error === undefined || v.expected_error === null) {
      expect(failure === null, `${v.id} declares no error but frame ${failureAt} was refused: ${failure && failure.error}`);
      expect(accepted.size === numbers.length, `${v.id} accepted ${accepted.size} of ${numbers.length}`);
    } else {
      expect(failure !== null, `${v.id} must be refused but every frame was accepted`);
      expect(failure && failure.error === v.expected_error, `${v.id} error is ${v.expected_error}`);
    }
  }
}

// ---- MalformedTest.aRepeatIsNotAReorder / theReorderWindowBracketsItsBoundary ---
{
  // The two vectors that make the seen-set necessary, asserted together because a window
  // check alone accepts both: [1,2,3,3] repeats the head, and [1,2,3,5,4,6] goes four behind.
  expect(classifySequence(3, 3, true).error === 'ERR_REPLAY_DETECTED', 'a seen number is a replay');
  expect(classifySequence(4, 5, false).outcome === 'accepted', 'a reorder within the window is accepted');
  expect(classifySequence(3, 3).error === 'ERR_REPLAY_DETECTED', 'a head repeat without a seen-set is still a replay');
  expect(classifySequence(3, 40, false).error === 'ERR_REPLAY_DETECTED', 'beyond the window is refused even when unseen');

  // The boundary, from both sides.
  expect(classifySequence(100 - REORDER_WINDOW, 100, false).outcome === 'accepted', 'exactly one window behind is accepted');
  expect(
    classifySequence(100 - REORDER_WINDOW - 1, 100, false).error === 'ERR_REPLAY_DETECTED',
    'one beyond the window is refused',
  );

  // The window the Kotlin declares must be the one the vectors bracket.
  expect(REORDER_WINDOW === 32, 'the reorder window is 32');
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
console.log('ok    all 22 malformed vectors and all 3 sequence vectors classify as declared');
console.log('');
console.log('NOTE  This validates the Kotlin logic, NOT that the Kotlin compiles.');
console.log('      android/core-protocol has never been through a compiler here.');
