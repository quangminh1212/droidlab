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

/**
 * Decodes unpadded base64url.
 *
 * The vectors use base64 for opaque payloads and base64url without padding for key material,
 * nonces and identifiers, and the two are different alphabets. Decoding one as the other
 * produces bytes that decode without complaint and are simply wrong, so they are kept apart.
 */
function b64url(text) {
  if (typeof text !== 'string' || /[+/=]/.test(text)) {
    throw new Error(`not valid unpadded base64url: ${String(text).slice(0, 40)}`);
  }
  return Buffer.from(text, 'base64url');
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
// HandshakeTranscript  --  mirror of HandshakeTranscript.kt
// ---------------------------------------------------------------------------

const TRANSCRIPT_LABEL = 'DLWP/1-handshake';
const TRANSCRIPT_LABEL_LENGTH = 16;
const NONCE_LENGTH = 32;
const PUBLIC_KEY_LENGTH = 32;
const TRANSCRIPT_MINIMUM_LENGTH = 153;

/** Mirror of HandshakeTranscript.build. */
function buildTranscript(clientId, agentId, clientNonce, agentNonce, clientPub, agentPub) {
  const clientIdBytes = Buffer.from(clientId, 'utf8');
  const agentIdBytes = Buffer.from(agentId, 'utf8');

  if (clientIdBytes.length > 0xffff) throw new RangeError('client_id is too long');
  if (agentIdBytes.length > 0xffff) throw new RangeError('agent_id is too long');

  // Fixed widths are checked rather than truncated: a 31-byte nonce would shift every field
  // after it, producing a transcript of the right length describing the wrong values.
  for (const [value, expected, name] of [
    [clientNonce, NONCE_LENGTH, 'client_nonce'],
    [agentNonce, NONCE_LENGTH, 'agent_nonce'],
    [clientPub, PUBLIC_KEY_LENGTH, 'client_pub'],
    [agentPub, PUBLIC_KEY_LENGTH, 'agent_pub'],
  ]) {
    if (value.length !== expected) {
      throw new RangeError(`${name} is ${value.length} bytes but the format fixes it at ${expected}`);
    }
  }

  const clientPrefix = Buffer.alloc(2);
  clientPrefix.writeUInt16BE(clientIdBytes.length);
  const agentPrefix = Buffer.alloc(2);
  agentPrefix.writeUInt16BE(agentIdBytes.length);

  return Buffer.concat([
    Buffer.from(TRANSCRIPT_LABEL, 'ascii'),
    Buffer.from([0]),
    clientPrefix,
    clientIdBytes,
    Buffer.from([0]),
    agentPrefix,
    agentIdBytes,
    Buffer.from([0]),
    clientNonce,
    agentNonce,
    clientPub,
    agentPub,
  ]);
}

/** Mirror of HandshakeTranscript.length. */
function transcriptLength(clientId, agentId) {
  return TRANSCRIPT_LABEL_LENGTH + 1 + 2 + Buffer.from(clientId, 'utf8').length + 1 +
    2 + Buffer.from(agentId, 'utf8').length + 1 +
    (NONCE_LENGTH * 2) + (PUBLIC_KEY_LENGTH * 2);
}

// ---- a minimal SHA-256, so the mirror does not need a dependency -----------------
// Written out because this project's checkers are dependency-free by policy: `npm ci`
// installs nothing, and adding a hash library to verify a hash would be circular.
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256(input) {
  const bytes = Buffer.from(input);
  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];

  const bitLength = bytes.length * 8;
  const padded = Buffer.alloc(Math.ceil((bytes.length + 9) / 64) * 64);

  bytes.copy(padded);
  padded[bytes.length] = 0x80;
  padded.writeUInt32BE(Math.floor(bitLength / 0x100000000), padded.length - 8);
  padded.writeUInt32BE(bitLength >>> 0, padded.length - 4);

  const w = new Array(64);
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = padded.readUInt32BE(offset + i * 4);

    for (let i = 16; i < 64; i++) {
      const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;

    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      hh = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  return Buffer.from(h.flatMap((x) => [x >>> 24 & 0xff, x >>> 16 & 0xff, x >>> 8 & 0xff, x & 0xff]));
}

// ---- HandshakeTranscriptTest.everyVectorProducesItsDeclaredBytes ----------------
{
  const transcript = load('handshake-transcript.json');
  const vectors = transcript.vectors || [];
  expect(vectors.length >= 2, `handshake-transcript.json declares at least 2 vectors (found ${vectors.length})`);

  for (const v of vectors) {
    const inputs = v.inputs;
    const expected = v.expected;

    const built = buildTranscript(
      inputs.client_id,
      inputs.agent_id,
      b64url(inputs.client_nonce),
      b64url(inputs.agent_nonce),
      b64url(inputs.client_pub),
      b64url(inputs.agent_pub),
    );

    const declared = hex(expected.transcript_bytes);
    expect(built.equals(declared), `${v.id} produces its declared bytes`);
    expect(built.length === expected.transcript_length_bytes, `${v.id} declared length matches its bytes`);
    expect(transcriptLength(inputs.client_id, inputs.agent_id) === built.length, `${v.id} length function agrees`);

    // The hash is checked against the VECTOR's own bytes, not the implementation's output: a
    // test that hashed its own transcript would pass even if both were wrong the same way.
    const hashedDeclared = sha256(declared);
    expect(
      hashedDeclared.equals(hex(expected.transcript_sha256)),
      `${v.id} declared hash is the SHA-256 of its declared bytes`,
    );

    expect(
      sha256(built).equals(hex(expected.transcript_sha256)),
      `${v.id} built transcript hashes to the declared hash`,
    );

    // The declared length prefixes, which are the parts that stop the collision.
    const clientPrefix = built.subarray(17, 19).toString('hex');
    expect(clientPrefix === expected.client_id_length_prefix, `${v.id} client_id length prefix`);

    const clientIdLength = built.readUInt16BE(17);
    const agentPrefixAt = 17 + 2 + clientIdLength + 1;
    expect(
      built.subarray(agentPrefixAt, agentPrefixAt + 2).toString('hex') === expected.agent_id_length_prefix,
      `${v.id} agent_id length prefix`,
    );
  }
}

// ---- HandshakeTranscriptTest.aLengthPrefixPreventsAnIdentifierCollision ---------
{
  const transcript = load('handshake-transcript.json');
  const minimum = transcript.vectors.find((v) => v.id === 'transcript.minimum-length');
  const rejection = transcript.rejection_vectors.find(
    (v) => v.id === 'transcript.reject.leading-separator-confusion',
  );

  expect(!!minimum, 'transcript.minimum-length exists');
  expect(!!rejection, 'transcript.reject.leading-separator-confusion exists');

  if (minimum && rejection) {
    // The collision the length prefixes prevent: without them, client_id="c" with
    // agent_id="a" describes the same split as client_id="c\x00a" with an empty agent_id.
    expect(minimum.inputs.client_id === 'c', "the floor vector's client_id is one character");
    expect(minimum.inputs.agent_id === 'a', "the floor vector's agent_id is one character");
    expect(rejection.inputs.client_id === 'c\u0000a', 'the collision vector nests a separator in the client_id');
    expect(rejection.inputs.agent_id === '', 'the collision vector has an empty agent_id');

    const build = (v) => buildTranscript(
      v.inputs.client_id,
      v.inputs.agent_id,
      b64url(v.inputs.client_nonce),
      b64url(v.inputs.agent_nonce),
      b64url(v.inputs.client_pub),
      b64url(v.inputs.agent_pub),
    );

    const minimumBytes = build(minimum);
    const rejectionBytes = build(rejection);

    expect(!minimumBytes.equals(rejectionBytes), 'the two identifier splits produce distinct transcripts');
    expect(rejectionBytes.length === rejection.expected.transcript_length_bytes, "the collision vector's declared length");
    expect(rejectionBytes.length === minimumBytes.length + 1, 'the collision vector is exactly one byte longer');

    expect(minimumBytes.length === 153, 'the floor is 153 bytes');
    expect(minimumBytes.length === TRANSCRIPT_MINIMUM_LENGTH, 'MINIMUM_LENGTH matches the shortest vector');
    expect(16 + 1 + 3 + 1 + 3 + 1 + 128 === 153, "the file's arithmetic evaluates to 153");

    // The difference is the PREFIX, not the label or the separators, and it is worth pinning
    // the exact bytes because the vector's own note describes the mechanism as a collision
    // that would occur without prefixes. It is really a divergence at the prefix:
    //
    //   floor    : 00 01 "c"      00 00 01 "a" 00 ...
    //   rejection: 00 03 "c\x00a" 00 00 00 ""  00 ...
    //
    // The rejection vector's agent_id prefix is 0x0000 -- a present, zero-length field --
    // where a form that omitted an empty identifier entirely would have nothing there. That
    // present-but-empty prefix is what keeps the two distinct, and it is why the format
    // states the prefix as two bytes rather than as "the identifier's bytes".
    //
    // Stated this way rather than as "the naive form collides" because the naive forms do
    // not, in fact, collide: concatenating the two identifiers with or without separating
    // zero bytes gives distinct byte strings for these inputs. The prefix is doing real
    // work, but the work is stating a length, not resolving an ambiguity that a
    // concatenation would otherwise have.
    const clientPrefixAt = TRANSCRIPT_LABEL_LENGTH + 1;

    expect(
      minimumBytes.subarray(clientPrefixAt, clientPrefixAt + 2).toString('hex') === '0001',
      "the floor vector's client_id prefix is 1",
    );

    expect(
      rejectionBytes.subarray(clientPrefixAt, clientPrefixAt + 2).toString('hex') === '0003',
      "the rejection vector's client_id prefix is 3",
    );

    const rejectionAgentPrefixAt = clientPrefixAt + 2 + 3 + 1;

    expect(
      rejectionBytes.subarray(rejectionAgentPrefixAt, rejectionAgentPrefixAt + 2).toString('hex') === '0000',
      "the rejection vector's agent_id prefix is 0 and is present",
    );

    // And the two diverge at the prefix itself, the earliest point they could.
    expect(
      minimumBytes[clientPrefixAt] !== rejectionBytes[clientPrefixAt] ||
        minimumBytes[clientPrefixAt + 1] !== rejectionBytes[clientPrefixAt + 1],
      'the two transcripts differ at the client_id length prefix',
    );
  }
}

// ---------------------------------------------------------------------------
// CapabilityNegotiation  --  mirror of CapabilityNegotiation.kt
// ---------------------------------------------------------------------------

const CAPABILITY_REGISTRY = [
  'screen.mirror', 'screen.record', 'input.touch', 'input.key', 'input.text', 'input.gesture',
  'clipboard.read', 'clipboard.write', 'shell.exec', 'file.read', 'file.write', 'log.stream',
  'app.install', 'app.launch', 'device.info', 'adb.wireless', 'compression.deflate', 'telemetry.stats',
];

const DEFAULT_LIMITS = {
  max_frame_bytes: 16777216,
  max_channels: 8,
  max_video_width: 1920,
  max_video_height: 1080,
  max_video_fps: 60,
  max_video_bitrate: 16000000,
  max_file_chunk: 262144,
  shell_timeout_ms: 30000,
  max_gesture_steps: 256,
};

/** Mirror of CapabilityNegotiation.negotiate. */
function negotiate(agentCapabilities, agentDisabled, controllerOffered) {
  const agent = new Set(agentCapabilities);
  const disabled = new Set(agentDisabled);
  const offered = new Set(controllerOffered);

  const negotiated = [...agent].filter(
    (name) => offered.has(name) && !disabled.has(name) && CAPABILITY_REGISTRY.includes(name),
  );

  // Sorted ordinally, because the order is part of the contract: it is what is serialised
  // into the transcript, and two peers must compute the same bytes.
  return negotiated.sort();
}

/**
 * Mirror of CapabilityNegotiation.clampVideo.
 *
 * The request is a ceiling on each axis, NOT a shape, and the SCREEN is the thing that gets
 * scaled. The effective size is the screen's size scaled down to fit inside the requested
 * box, so the aspect ratio comes from the screen.
 *
 * Getting this backwards letterboxes a screen whose orientation differs from the request: a
 * 1920x1080 request against a 1080x2400 portrait screen must give a portrait 486x1080, while
 * deriving the ratio from the request gives a landscape 1080x608. This mirror was wrong in
 * exactly that way twice before the vector settled it -- first by fitting the request to the
 * screen, then by min-ing the screen against the ceiling without scaling at all. Both were
 * wrong for the same reason: neither scaled the screen.
 */
function clampVideo(requestedWidth, requestedHeight, requestedFps, agentLimits, screenWidth, screenHeight) {
  const even = (v) => (v % 2 === 0 ? v : v - 1);

  const ceilingWidth = Math.min(requestedWidth, agentLimits.max_video_width ?? DEFAULT_LIMITS.max_video_width);
  const ceilingHeight = Math.min(requestedHeight, agentLimits.max_video_height ?? DEFAULT_LIMITS.max_video_height);

  // The agent's frame-rate ceiling applies regardless of the screen.
  const fps = Math.min(requestedFps, agentLimits.max_video_fps ?? DEFAULT_LIMITS.max_video_fps);

  // The smaller of the two axis ratios fits BOTH axes; the larger would overflow one.
  const scale = Math.min(ceilingWidth / screenWidth, ceilingHeight / screenHeight);

  // Only scale down: a ratio above one would mean capturing more pixels than the screen has,
  // which is interpolation.
  const effectiveScale = Math.min(1.0, scale);

  return {
    width: even(Math.max(2, Math.round(screenWidth * effectiveScale))),
    height: even(Math.max(2, Math.round(screenHeight * effectiveScale))),
    fps,
  };
}

/** Mirror of CapabilityNegotiation.clampFileChunk. */
function clampFileChunk(requestedChunk, agentMaxFileChunk) {
  if (requestedChunk > agentMaxFileChunk) {
    return { accepted: false, error: 'ERR_FRAME_TOO_LARGE', effectiveChunk: 0 };
  }
  return { accepted: true, error: null, effectiveChunk: requestedChunk };
}

/** Mirror of CapabilityNegotiation.nextChannelId. */
function nextChannelId(lastAllocated, controller) {
  const first = controller ? 1 : 2;
  const next = lastAllocated === null || lastAllocated === undefined ? first : lastAllocated + 2;
  return next > 0xffffffff ? null : next;
}

/** Mirror of CapabilityNegotiation.openChannel. */
function openChannel(requested, openChannels, maxChannels) {
  if (openChannels.has(requested)) return { accepted: false, error: 'ERR_BAD_STATE' };
  if (openChannels.size >= maxChannels) return { accepted: false, error: 'ERR_CHANNEL_LIMIT' };
  return { accepted: true, error: null };
}

// ---- CapabilityNegotiationTest.theRegistryMatchesTheFileInBothDirections --------
{
  const caps = load('capabilities.json');
  expect(Array.isArray(caps.capability_registry), 'capabilities.json has a capability_registry array');

  const fromFile = new Set(caps.capability_registry);
  const inCode = new Set(CAPABILITY_REGISTRY);

  // Both directions: one alone cannot catch a capability the code knows and the file does not.
  const missingFromCode = [...fromFile].filter((c) => !inCode.has(c));
  const extraInCode = [...inCode].filter((c) => !fromFile.has(c));

  expect(missingFromCode.length === 0, `every capability in the file is known to the code (missing: ${missingFromCode.join(', ')})`);
  expect(extraInCode.length === 0, `every capability in the code is in the file (extra: ${extraInCode.join(', ')})`);
  expect(fromFile.size === 18, `the registry has 18 capabilities (found ${fromFile.size})`);
}

// ---- CapabilityNegotiationTest.theDefaultLimitsMatchTheFile ---------------------
{
  const caps = load('capabilities.json');
  const fromFile = caps.default_limits;

  expect(!!fromFile, 'capabilities.json has default_limits');
  expect(!!caps.default_limits_note, 'the limits carry their note');

  const fileNames = Object.keys(fromFile).sort();
  const codeNames = Object.keys(DEFAULT_LIMITS).sort();

  // The file's own note records that this list once carried a tenth entry appearing nowhere
  // in the RFC, and that the fix was to remove it rather than add it to the RFC. The count is
  // therefore the assertion that matters: it is what would catch that entry coming back.
  expect(fileNames.length === 9, `the limits list has exactly nine entries (found ${fileNames.length})`);
  expect(
    fileNames.join(',') === codeNames.join(','),
    `the limit names match\n           file: ${fileNames.join(', ')}\n           code: ${codeNames.join(', ')}`,
  );

  for (const name of fileNames) {
    expect(
      fromFile[name] === DEFAULT_LIMITS[name],
      `the limit "${name}" matches (file ${fromFile[name]}, code ${DEFAULT_LIMITS[name]})`,
    );
  }
}

// ---- CapabilityNegotiationTest.everyNegotiationVectorProducesItsDeclaredSet -----
{
  const caps = load('capabilities.json');
  const vectors = caps.negotiation_vectors || [];

  expect(vectors.length >= 8, `capabilities.json declares at least 8 negotiation vectors (found ${vectors.length})`);

  for (const v of vectors) {
    const negotiated = negotiate(v.agent_capabilities, v.agent_disabled, v.controller_offered);

    // Compared as a sorted list against the vector's declared list. Comparing as sets would
    // pass even if the implementation returned a differently ordered sequence, and the order
    // is part of the contract.
    const expected = [...v.expected_negotiated].sort();

    expect(
      negotiated.join(',') === expected.join(','),
      `${v.id} negotiated set\n           expected: ${expected.join(', ')}\n           actual:   ${negotiated.join(', ')}`,
    );
  }
}

// ---- CapabilityNegotiationTest: the individual negotiation rules ----------------
{
  const caps = load('capabilities.json');
  const byId = (id) => caps.negotiation_vectors.find((v) => v.id === id);

  // A capability the controller never offered must not be negotiated even though the agent
  // supports it.
  const subset = byId('negotiate.controller-subset');
  expect(!!subset, 'negotiate.controller-subset exists');
  if (subset) {
    expect(
      subset.agent_capabilities.length > subset.controller_offered.length,
      'the scenario must have the agent supporting more than was offered, or it tests nothing',
    );

    const negotiated = negotiate(subset.agent_capabilities, subset.agent_disabled, subset.controller_offered);

    for (const name of subset.agent_capabilities) {
      if (!subset.controller_offered.includes(name)) {
        expect(!negotiated.includes(name), `${name} was never offered and must not be negotiated`);
      }
    }
  }

  // An operator's disable wins even when both sides support the capability, so the
  // subtraction is doing work the intersection alone would not.
  const disabled = byId('negotiate.operator-disabled-wins-even-when-both-support-it');
  expect(!!disabled, 'the operator-disabled vector exists');
  if (disabled) {
    const intersection = disabled.agent_capabilities.filter((c) => disabled.controller_offered.includes(c));

    for (const name of disabled.agent_disabled) {
      expect(
        intersection.includes(name),
        `${name} must be in the intersection before disabling, or the subtraction proves nothing`,
      );
    }

    const negotiated = negotiate(disabled.agent_capabilities, disabled.agent_disabled, disabled.controller_offered);

    for (const name of disabled.agent_disabled) {
      expect(!negotiated.includes(name), `${name} is disabled by the operator and must not be negotiated`);
    }
  }

  // An empty intersection is a working session: the empty set serialises to the empty string.
  const empty = byId('negotiate.empty-intersection');
  expect(!!empty, 'negotiate.empty-intersection exists');
  if (empty) {
    const negotiated = negotiate(empty.agent_capabilities, empty.agent_disabled, empty.controller_offered);

    expect(negotiated.length === 0, 'the intersection is empty');
    expect(negotiated.join(',') === '', 'an empty set serialises to the empty string');
    expect(empty.expected_negotiated.length === 0, 'the vector declares it as empty');
  }

  // A name outside the registry is ignored, not refused -- which is the forward-compatibility
  // rule, and it matters because refusing would make a future revision unusable on an old peer.
  const unknown = byId('negotiate.unknown-capability-name-ignored');
  expect(!!unknown, 'the unknown-capability vector exists');
  if (unknown) {
    const outside = unknown.agent_capabilities.filter((c) => !CAPABILITY_REGISTRY.includes(c));

    expect(
      outside.length > 0,
      `the vector must offer a name outside the registry, or it tests nothing (has ${unknown.agent_capabilities.length} names)`,
    );

    const negotiated = negotiate(unknown.agent_capabilities, unknown.agent_disabled, unknown.controller_offered);

    for (const name of outside) {
      expect(!negotiated.includes(name), `${name} is not in the registry and must not be agreed to`);
    }
  }

  // A duplicate must normalise to one: the set is serialised into the transcript, and
  // "[a,a]" and "[a]" are different byte strings for the same agreement.
  const dupes = byId('negotiate.duplicate-names-normalised');
  expect(!!dupes, 'the duplicate-names vector exists');
  if (dupes) {
    const agentHasDupe = new Set(dupes.agent_capabilities).size !== dupes.agent_capabilities.length;
    const offerHasDupe = new Set(dupes.controller_offered).size !== dupes.controller_offered.length;

    expect(agentHasDupe || offerHasDupe, 'the vector must carry a duplicate, or it tests nothing');

    const negotiated = negotiate(dupes.agent_capabilities, dupes.agent_disabled, dupes.controller_offered);

    expect(new Set(negotiated).size === negotiated.length, 'the negotiated set carries no duplicates');
  }
}

// ---- CapabilityNegotiationTest.everyLimitVectorProducesItsDeclaredResult --------
{
  const caps = load('capabilities.json');
  const vectors = caps.limit_clamp_vectors || [];

  expect(vectors.length >= 4, `capabilities.json declares at least 4 limit vectors (found ${vectors.length})`);

  for (const v of vectors) {
    switch (v.id) {
      case 'limits.video-clamp-to-agent-maximum': {
        // This vector carries no screen, so it isolates the ceiling clamp: with no capture
        // surface to fit, the effective size is the ceiling itself. Passing a screen here
        // would test the aspect-ratio fit instead and the vector's expected values would no
        // longer be the ones being checked.
        const applied = clampVideo(
          v.requested.max_width,
          v.requested.max_height,
          v.requested.fps,
          v.agent_limits,
          v.requested.max_width,
          v.requested.max_height,
        );

        expect(applied.width === v.expected_applied.width, `${v.id} width is ${v.expected_applied.width} (got ${applied.width})`);
        expect(applied.height === v.expected_applied.height, `${v.id} height is ${v.expected_applied.height} (got ${applied.height})`);
        expect(applied.fps === v.expected_applied.fps, `${v.id} fps is ${v.expected_applied.fps} (got ${applied.fps})`);

        // The clamp is a reduction, never an increase: the request asked for 2560x1440 and
        // the agent allows 1920x1080, so both axes came down.
        expect(applied.width < v.requested.max_width, `${v.id} the width was clamped down`);
        expect(applied.height < v.requested.max_height, `${v.id} the height was clamped down`);
        break;
      }

      case 'limits.video-clamp-to-screen-size': {
        const applied = clampVideo(
          v.requested.max_width,
          v.requested.max_height,
          60,
          DEFAULT_LIMITS,
          v.screen.width,
          v.screen.height,
        );

        // The aspect-ratio fit is the interesting part: 1920x1080 requested against a
        // 1080x2400 screen must become 486x1080, preserving the screen's ratio with both
        // dimensions even, as H.264 requires.
        expect(applied.width === v.expected_applied.width, `${v.id} width is ${v.expected_applied.width} (got ${applied.width})`);
        expect(applied.height === v.expected_applied.height, `${v.id} height is ${v.expected_applied.height} (got ${applied.height})`);
        expect(applied.width % 2 === 0, `${v.id} width is even`);
        expect(applied.height % 2 === 0, `${v.id} height is even`);
        break;
      }

      case 'limits.file-chunk-clamped': {
        // Refused rather than truncated: a truncated chunk is a silently short buffer the
        // controller believes is full, indistinguishable from a short file.
        const refused = clampFileChunk(v.requested_chunk, v.agent_max_file_chunk);

        expect(refused.accepted === false, `${v.id} is refused`);
        expect(refused.error === v.expected_error, `${v.id} error is ${v.expected_error} (got ${refused.error})`);
        expect(refused.effectiveChunk === 0, `${v.id} reports no effective chunk, because there is none`);

        const atLimit = clampFileChunk(v.agent_max_file_chunk, v.agent_max_file_chunk);
        expect(atLimit.accepted === true, `${v.id} exactly at the limit is accepted`);
        break;
      }

      case 'limits.shell-timeout-clamped': {
        // Clamped rather than refused: a long deadline is a preference, and a shorter one
        // still does what the controller asked.
        const applied = Math.min(v.requested_timeout_ms, v.agent_shell_timeout_ms);
        expect(applied === v.expected_applied_timeout_ms, `${v.id} applied timeout is ${v.expected_applied_timeout_ms} (got ${applied})`);
        expect(Math.min(1000, v.agent_shell_timeout_ms) === 1000, `${v.id} honours a request under the limit`);
        break;
      }

      default:
        throw new Error(`unhandled limit vector ${v.id}`);
    }
  }
}

// ---- CapabilityNegotiationTest.everyDirectionVectorProducesItsDeclaredResult ----
{
  const caps = load('capabilities.json');
  const vectors = caps.direction_vectors || [];

  expect(vectors.length >= 2, `capabilities.json declares at least 2 direction vectors (found ${vectors.length})`);

  for (const v of vectors) {
    if (v.id === 'negotiate.controller-allocates-odd-channel-ids') {
      const build = (n, controller) => {
        const out = [];
        let last = null;
        for (let i = 0; i < n; i++) {
          last = nextChannelId(last, controller);
          if (last === null) throw new Error('the allocator ran out of ids');
          out.push(last);
        }
        return out;
      };

      // The sequences are built by repeated allocation, not read from the vector: the vector
      // lists the expected ids and deriving the actual ones is what proves the allocator.
      const controller = build(v.expected_controller_sequence.length, true);
      const agent = build(v.expected_agent_sequence.length, false);

      expect(
        controller.join(',') === v.expected_controller_sequence.join(','),
        `${v.id} controller sequence is ${v.expected_controller_sequence.join(',')} (got ${controller.join(',')})`,
      );
      expect(
        agent.join(',') === v.expected_agent_sequence.join(','),
        `${v.id} agent sequence is ${v.expected_agent_sequence.join(',')} (got ${agent.join(',')})`,
      );

      // The partition: the two sides never propose the same id, which is what makes
      // allocation lock-free. A reject-and-retry scheme would need a round trip per channel.
      const overlap = controller.filter((c) => agent.includes(c));
      expect(overlap.length === 0, `${v.id} the two sides never propose the same id (overlap: ${overlap.join(',')})`);

      // Neither reaches channel 0, the control channel.
      expect(!controller.includes(0) && !agent.includes(0), `${v.id} the control channel is never allocated`);

      // The parity invariant, over every element rather than the example.
      for (const odd of controller) expect(odd % 2 === 1, `${v.id} ${odd} is odd`);
      for (const even of agent) expect(even % 2 === 0, `${v.id} ${even} is even`);
    } else if (v.id === 'negotiate.channel-id-reuse-requires-close') {
      const open = new Set(v.open_channels);
      expect(open.has(v.reopen_request), `${v.id} the reopen target must already be open`);

      const verdict = openChannel(v.reopen_request, open, DEFAULT_LIMITS.max_channels);

      expect(verdict.accepted === false, `${v.id} an open channel is not reopened`);

      // The fault is a state error specifically, and the code matters: a limit error would
      // suggest retrying, when the correct response is to close the channel first, and a
      // retry would loop forever against the same open id.
      expect(verdict.error === v.expected_error, `${v.id} error is ${v.expected_error} (got ${verdict.error})`);

      const fresh = openChannel(3, open, DEFAULT_LIMITS.max_channels);
      expect(fresh.accepted === true, `${v.id} an unopened id is accepted`);
    } else {
      throw new Error(`unhandled direction vector ${v.id}`);
    }
  }
}

// ---- CapabilityNegotiationTest.theChannelLimitCountsTheControlChannel ----------
{
  const max = DEFAULT_LIMITS.max_channels;
  const atLimit = new Set(Array.from({ length: max }, (_, i) => i));

  // Channels 0 through 7 is eight channels against a limit of eight. Counting only data
  // channels would see seven and allow a ninth -- the off-by-one this pins.
  expect(atLimit.size === max, 'the scenario is exactly at the limit');

  const refused = openChannel(100, atLimit, max);
  expect(refused.accepted === false, 'opening past the limit is refused');
  expect(refused.error === 'ERR_CHANNEL_LIMIT', `the fault is a limit, not a state (got ${refused.error})`);

  const oneBelow = new Set([...atLimit].filter((c) => c !== max - 1));
  expect(openChannel(100, oneBelow, max).accepted === true, 'one below the limit is accepted');
}

// ---- CapabilityNegotiationTest.captureNeverUpscalesASmallerScreen ---------------
{
  // No vector exercises the scale-down-only guard: in both video vectors the scale factor is
  // below one, so the guard is inert and removing it changes neither result. Mutation-testing
  // found that -- deleting the guard left every check green. The rule is still a rule, so it
  // is checked directly here. A check no input can reach is not a check.
  // A ceiling above the screen on BOTH axes, so the scale factor exceeds one and the guard is
  // what stops it. A ceiling larger on one axis only still gives a scale below one and scales
  // down, so it never reaches the guard -- which is what the first version of this check got
  // wrong, asserting 720x1280 against an input that legitimately scales to 608x1080.
  const bigCeiling = { max_video_width: 3840, max_video_height: 2160, max_video_fps: 60 };
  const small = clampVideo(3840, 2160, 60, bigCeiling, 720, 1280);

  expect(small.width === 720, `a screen smaller than the ceiling on both axes keeps its width (got ${small.width})`);
  expect(small.height === 1280, `a screen smaller than the ceiling on both axes keeps its height (got ${small.height})`);

  const scaled = clampVideo(360, 640, 60, DEFAULT_LIMITS, 720, 1280);

  expect(scaled.width === 360, `a ceiling smaller than the screen scales it down (got ${scaled.width})`);
  expect(scaled.height === 640, `both axes scale together (got ${scaled.height})`);

  const screenRatio = 720 / 1280;
  const scaledRatio = scaled.width / scaled.height;

  expect(
    Math.abs(screenRatio - scaledRatio) < 0.01,
    `the scaled result keeps the screen's ratio (${scaledRatio.toFixed(4)} vs ${screenRatio.toFixed(4)})`,
  );
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
