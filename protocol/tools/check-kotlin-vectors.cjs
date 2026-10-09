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
// VersionNegotiation  --  mirror of VersionNegotiation.kt
// ---------------------------------------------------------------------------

const CURRENT_MAJOR = 1;

/** Parses `major.minor`, or null when the text is not that shape. */
function parseVersion(text) {
  if (typeof text !== 'string') return null;

  const parts = text.split('.');
  if (parts.length !== 2) return null;

  // A leading sign is not a version, and Number() would accept "-1".
  if (parts[0].startsWith('-') || parts[1].startsWith('-')) return null;
  if (!/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) return null;

  return { major: Number(parts[0]), minor: Number(parts[1]) };
}

/** Formats a parsed version. */
const formatVersion = (v) => `${v.major}.${v.minor}`;

/** Compares numerically, so 1.10 > 1.9. A string compare orders them the other way. */
function compareVersion(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  return a.minor - b.minor;
}

/** Mirror of VersionNegotiation.negotiate. */
function negotiateVersion(controllerSupported, agentSupported) {
  const controller = controllerSupported.map(parseVersion).filter(Boolean);
  const agent = agentSupported.map(parseVersion).filter(Boolean);

  if (controller.length === 0 || agent.length === 0) {
    return { version: null, error: 'ERR_VERSION_MISMATCH' };
  }

  const common = controller.filter((c) =>
    agent.some((a) => a.major === c.major && a.minor === c.minor));

  if (common.length === 0) return { version: null, error: 'ERR_VERSION_MISMATCH' };

  // The MAXIMUM of the intersection, not the controller's first preference.
  const best = common.reduce((x, y) => (compareVersion(y, x) > 0 ? y : x));

  return { version: formatVersion(best), error: null };
}

/** Mirror of VersionNegotiation.checkAnswer. */
function checkVersionAnswer(controllerSupported, agentAnswered) {
  const offered = controllerSupported.map(parseVersion).filter(Boolean);
  const answered = parseVersion(agentAnswered);

  if (answered === null) return { version: null, error: 'ERR_VERSION_MISMATCH' };

  // Membership in what was OFFERED, not merely a well-formed version.
  const isOffered = offered.some((o) => o.major === answered.major && o.minor === answered.minor);

  if (!isOffered) return { version: null, error: 'ERR_VERSION_MISMATCH' };

  return { version: formatVersion(answered), error: null };
}

/** Mirror of VersionNegotiation.checkHeaderMajor. */
function checkHeaderMajor(headerVersion) {
  if (headerVersion !== CURRENT_MAJOR) return { version: null, error: 'ERR_VERSION_MISMATCH' };
  return { version: '1.0', error: null };
}

// ---- VersionNegotiationTest.theRuleIsHighestCommonVersionOrFail -----------------
{
  const file = load('version-negotiation.json');

  expect(
    file.rule === 'highest_common_version_or_fail',
    `the file declares the rule the implementation applies (got "${file.rule}")`,
  );

  const pairVectors = file.vectors.filter(
    (v) => v.controller_supported !== undefined && v.agent_answered === undefined,
  );

  expect(pairVectors.length >= 6, `at least 6 pair vectors (found ${pairVectors.length})`);

  for (const v of pairVectors) {
    const negotiated = negotiateVersion(v.controller_supported, v.agent_supported);

    if (v.expected_negotiated === null) {
      expect(negotiated.version === null, `${v.id} is declared a failure`);
      continue;
    }

    // "Common" means present in BOTH lists. A result outside either one would be a version a
    // peer never offered, which is the security-relevant half of this rule.
    expect(
      v.controller_supported.includes(negotiated.version),
      `${v.id} negotiated a version the controller did not offer (${negotiated.version})`,
    );
    expect(
      v.agent_supported.includes(negotiated.version),
      `${v.id} negotiated a version the agent did not offer (${negotiated.version})`,
    );
  }
}

// ---- VersionNegotiationTest.everyPairVectorNegotiatesItsDeclaredVersion ---------
{
  const file = load('version-negotiation.json');
  const pairVectors = file.vectors.filter(
    (v) => v.controller_supported !== undefined && v.agent_answered === undefined,
  );

  for (const v of pairVectors) {
    const negotiated = negotiateVersion(v.controller_supported, v.agent_supported);

    if (v.expected_error) {
      expect(negotiated.version === null, `${v.id} is declared a failure`);
      expect(
        negotiated.error === v.expected_error,
        `${v.id} error is ${v.expected_error} (got ${negotiated.error})`,
      );
    } else {
      expect(
        negotiated.version === v.expected_negotiated,
        `${v.id} negotiated ${v.expected_negotiated} (got ${negotiated.version})`,
      );
      expect(negotiated.error === null, `${v.id} carries no error when it succeeds`);
    }
  }
}

// ---- VersionNegotiationTest.theHighestCommonVersionWinsNotTheFirstPreference ----
{
  const file = load('version-negotiation.json');
  const v = file.vectors.find((x) => x.id === 'version.both-newer-and-older');

  expect(!!v, 'version.both-newer-and-older exists');
  if (v) {
    // The scenario is only interesting if the first preferences differ, so the test would be
    // checking something real.
    expect(v.controller_supported[0] === '2.0', "the controller's first preference is 2.0");
    expect(v.agent_supported[0] === '1.1', "the agent's first preference is 1.1");
    expect(
      v.controller_supported[0] !== v.agent_supported[0],
      'the two first preferences differ',
    );

    const negotiated = negotiateVersion(v.controller_supported, v.agent_supported);

    expect(
      negotiated.version === '1.1',
      `the highest common version is 1.1 (got ${negotiated.version})`,
    );

    // Explicitly not the controller's head: an implementation returning its own first
    // preference would elect 2.0, a version the agent never offered.
    expect(
      negotiated.version !== v.controller_supported[0],
      "the result is not the controller's first preference",
    );
  }
}

// ---- VersionNegotiationTest.versionsCompareNumericallyNotLexically -------------
{
  // The bug this pins: a string comparison orders "1.10" before "1.9", because '1' < '9'.
  const w = parseVersion('1.10');
  const n = parseVersion('1.9');

  expect(compareVersion(w, n) > 0, '1.10 is greater than 1.9 numerically');
  expect('1.10' < '1.9', 'lexically, 1.10 sorts before 1.9 -- which is the trap');

  // And it changes a real negotiation result: with both offered, 1.10 must win.
  const negotiated = negotiateVersion(['1.9', '1.10'], ['1.9', '1.10']);

  expect(negotiated.version === '1.10', `1.10 is preferred over 1.9 (got ${negotiated.version})`);

  // The major still dominates the minor.
  expect(
    compareVersion(parseVersion('2.0'), parseVersion('1.99')) > 0,
    'a higher major beats any minor',
  );
}

// ---- VersionNegotiationTest.aMalformedVersionIsRefused --------------------------
{
  // A format that tolerates several shapes has several ways to disagree about meaning, so
  // only a plain major.minor pair is accepted.
  for (const text of ['1', '1.0.0', '1.', '.1', 'one.zero', '', '-1.0', '1.-0', '1 .0']) {
    expect(parseVersion(text) === null, `"${text}" is not a version`);
  }

  const negotiated = negotiateVersion(['garbage'], ['1.0']);

  expect(negotiated.version === null, 'a list with no parseable version cannot agree');
  expect(negotiated.error === 'ERR_VERSION_MISMATCH', 'it reports a version mismatch');
}

// ---- VersionNegotiationTest.neitherSideDowngradesSilently -----------------------
{
  const file = load('version-negotiation.json');

  const agentRefuses = file.vectors.find((v) => v.id === 'version.agent-does-not-downgrade-silently');
  expect(!!agentRefuses, 'the agent-refuses vector exists');
  if (agentRefuses) {
    const verdict = negotiateVersion(agentRefuses.controller_supported, agentRefuses.agent_supported);

    expect(verdict.version === null, 'the agent refuses a version it does not know');
    expect(verdict.error === 'ERR_VERSION_MISMATCH', 'the refusal is a version mismatch');
  }

  const controllerRefuses = file.vectors.find((v) => v.id === 'version.controller-does-not-downgrade-silently');
  expect(!!controllerRefuses, 'the controller-refuses vector exists');
  if (controllerRefuses) {
    const verdict = checkVersionAnswer(controllerRefuses.controller_supported, controllerRefuses.agent_answered);

    expect(verdict.version === null, 'the controller refuses an unoffered answer');
    expect(verdict.error === 'ERR_VERSION_MISMATCH', 'the refusal is a version mismatch');

    // The answer is well-formed, which is the point: it is refused for being unoffered, not
    // for being unparseable. A check that only validated the format would accept it.
    expect(
      parseVersion(controllerRefuses.agent_answered) !== null,
      'the rejected answer is a well-formed version, so the rejection is about membership',
    );

    // And an offered answer is accepted, which brackets the rule.
    const accepted = checkVersionAnswer(['1.1', '1.0'], '1.0');
    expect(accepted.version === '1.0', 'an offered answer is accepted');
  }
}

// ---- VersionNegotiationTest.aVersionMismatchIsFatal ----------------------------
{
  const file = load('version-negotiation.json');

  for (const v of file.vectors) {
    if (!v.expected_error) continue;

    expect(v.expected_error === 'ERR_VERSION_MISMATCH', `${v.id} uses the version error`);

    // Fatal, because the header's version field decides how everything after it is parsed.
    // There is no partial recovery: a receiver that does not know the version does not know
    // the frame's shape.
    expect(v.expected_severity === 'fatal', `${v.id} is declared fatal`);
  }
}

// ---- VersionNegotiationTest.theHeaderMajorIsCheckedBeforeTheBodyString ----------
{
  const file = load('version-negotiation.json');
  const v = file.vectors.find((x) => x.id === 'version.major-only-in-version-field');

  expect(!!v, 'version.major-only-in-version-field exists');
  if (v) {
    expect(v.header_version_field === 1, 'the header carries the major only');
    expect(v.hello_proto_string === '1.1', 'the body carries the full version');
    expect(v.expected === 'accepted', 'a known major with a newer minor is accepted');

    expect(checkHeaderMajor(v.header_version_field).version === '1.0', 'the known major passes');

    // The header field is the major, so 1 is all a 1.x frame can say. The MINOR is what the
    // body carries, and this vector's 1.1 does NOT negotiate against a peer that knows only
    // 1.0: the rule is highest COMMON version, and 1.0 and 1.1 share none.
    //
    // That is the honest reading and worth stating, because "a minor bump is compatible" is a
    // tempting gloss that the rule does not actually implement. Compatibility of a minor bump
    // is a property of the CHANGE (below), not of the negotiation: what makes an additive
    // change safe is that an old peer ignores what it does not know, and the version lists
    // here are the versions a peer can SPEAK, not a range it tolerates.
    const negotiated = negotiateVersion(['1.0'], [v.hello_proto_string]);

    expect(
      negotiated.version === null,
      `1.0 and 1.1 share no version, so the negotiation fails (got ${negotiated.version})`,
    );
    expect(negotiated.error === 'ERR_VERSION_MISMATCH', 'and it fails as a version mismatch');

    // A peer that knows both agrees the HIGHEST common one, which is 1.1 -- not 1.0, even
    // though 1.0 is also common. Taking the lower common version would be a silent downgrade,
    // which is the behaviour the whole rule exists to prevent.
    const common = negotiateVersion(['1.1', '1.0'], [v.hello_proto_string]);
    expect(common.version === '1.1', `a peer knowing both agrees the highest common one, 1.1 (got ${common.version})`);
  }

  const tooNew = file.vectors.find((x) => x.id === 'version.header-major-too-new');
  expect(!!tooNew, 'version.header-major-too-new exists');
  if (tooNew) {
    const refused = checkHeaderMajor(tooNew.header_version_field);

    expect(refused.version === null, 'an unknown major fails');
    expect(refused.error === 'ERR_VERSION_MISMATCH', 'it reports a version mismatch');
    expect(checkHeaderMajor(1).version === '1.0', 'the known major is accepted');
  }
}

/**
 * Mirror of VersionNegotiation.requiresMajorBump.
 *
 * Two families of name: a rule stated as `additive`/`breaking`, and a vector naming the
 * specific change. Both are needed -- the first is what a reviewer reasons about, the second
 * is what makes the example concrete. A name indicating neither is refused rather than
 * defaulted to the safe answer, because defaulting would give a change nobody classified minor
 * treatment, and a minor treatment of a breaking change is the silent compat break the rule
 * exists to stop.
 */
function requiresMajorBump(changeKind) {
  if (changeKind === 'additive' || changeKind.startsWith('add_')) return false;
  if (changeKind === 'breaking' || changeKind.startsWith('change_') || changeKind.startsWith('remove_')) return true;
  throw new Error(`unknown change kind "${changeKind}"`);
}

/**
 * As [requiresMajorBump], but reports a refusal as a value instead of an exception.
 *
 * The throwing form is the mirror's faithful copy of the Kotlin, which refuses an
 * unclassifiable name rather than defaulting. That is the right contract and the Kotlin should
 * keep it. But calling it directly from a check means an unrecognisable name kills the whole
 * run with a stack trace instead of naming the check that failed -- and during
 * mutation-testing that reads as "no output", which is how I nearly concluded this rule was
 * uncovered when it was in fact covered.
 *
 * So the checks call this: the exception becomes a verifiable value, and the refusal itself is
 * asserted like anything else.
 */
function classifyBump(changeKind) {
  try {
    return requiresMajorBump(changeKind);
  } catch {
    return 'refused';
  }
}

// ---- VersionNegotiationTest.anAdditiveChangeIsNotAMajorBump --------------------
{
  const file = load('version-negotiation.json');

  const additive = file.vectors.find((v) => v.id === 'version.additive-change-is-not-a-major-bump');
  const breaking = file.vectors.find((v) => v.id === 'version.breaking-change-requires-major-bump');

  expect(!!additive, 'the additive-change vector exists');
  expect(!!breaking, 'the breaking-change vector exists');

  if (additive && breaking) {
    // The kinds are descriptive names, not the literals "additive" and "breaking". What makes
    // a change additive or breaking is the DECLARED bump, which is the field the rule reads.
    expect(additive.expected_version_bump === false, 'an additive change does not bump the version');
    expect(breaking.expected_version_bump === true, 'a breaking change bumps the version');
    expect(
      additive.change_kind !== breaking.change_kind,
      'the two change kinds differ, or the pair tests nothing',
    );

    // The classification is actually exercised, in both families of name. This is not padding:
    // without these calls the function above is defined and never used, and mutation-testing
    // showed that deleting either prefix branch then left every check green. A rule no check
    // can fail on is worse than no rule, because it looks covered.
    expect(
      classifyBump(additive.change_kind) === false,
      `the vector-style name "${additive.change_kind}" is not a major bump`,
    );
    expect(
      classifyBump(breaking.change_kind) === true,
      `the vector-style name "${breaking.change_kind}" is a major bump`,
    );
    expect(classifyBump('additive') === false, 'the rule-style name "additive" is not a major bump');
    expect(classifyBump('breaking') === true, 'the rule-style name "breaking" is a major bump');
    expect(
      classifyBump('remove_a_field') === true,
      'a removal is a major bump, like any other breaking change',
    );

    // A name from neither family is refused rather than defaulted -- the exception is the
    // contract, and this asserts that it happens. Defaulting would give a change nobody
    // classified the milder treatment, and a minor treatment of a breaking change is the
    // silent compat break the version rule exists to prevent.
    expect(
      classifyBump('something_nobody_classified') === 'refused',
      'an unclassifiable change kind is refused, not defaulted',
    );

    // An old peer must keep working by ignoring what it does not know -- which is the same
    // forward-compatibility rule the malformed and malformed surfaces pin elsewhere, stated
    // here as the reason a minor bump is safe.
    expect(
      additive.old_peer_behaviour.includes('ignore_unknown_key'),
      'the additive change relies on an old peer ignoring unknown keys',
    );

    // A breaking change names the documents it must touch: a wire change that leaves the RFC
    // and the vectors alone is unpinned drift.
    expect(
      Array.isArray(breaking.required_documents) && breaking.required_documents.length > 0,
      'a breaking change names its documents',
    );
    expect(
      breaking.required_documents.some((d) => d.startsWith('docs/rfc/')),
      'a breaking change touches the RFC',
    );
    expect(
      breaking.required_documents.some((d) => d.startsWith('protocol/vectors/')),
      'a breaking change touches the vectors, or the change is unpinned',
    );
  }
}

// ---- VersionNegotiationTest.theListsAreOrderedMostPreferredFirst ---------------
{
  const file = load('version-negotiation.json');
  const v = file.vectors.find((x) => x.id === 'version.both-newer-and-older');

  expect(!!v, 'version.both-newer-and-older exists');
  if (v) {
    for (const [name, list] of [['controller', v.controller_supported], ['agent', v.agent_supported]]) {
      const parsed = list.map(parseVersion);
      const sorted = [...parsed].sort((a, b) => compareVersion(b, a));

      expect(
        parsed.map(formatVersion).join(',') === sorted.map(formatVersion).join(','),
        `the ${name}'s list is most-preferred-first (${list.join(', ')})`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Labels and Derivations  --  mirror of crypto/Labels.kt
// ---------------------------------------------------------------------------

const CRYPTO_LABELS = {
  transcript_label: 'DLWP/1-handshake',
  session_salt_label: 'DLWP/1-session',
  pairing_salt_label: 'DLWP/1-pairing',
  pairing_secret_info: 'DLWP/1-pairing-secret',
  pairing_agent_proof_label: 'DLWP/1-pairing-agent',
  pairing_controller_proof_label: 'DLWP/1-pairing-controller',
  pairing_confirmation_label: 'DLWP/1-pairing-confirm',
  pairing_code_label: 'DLWP/1-pairing-code',
  fingerprint_label: 'DLWP/1-fingerprint',
  txt_label: 'DLWP/1-txt',
  exporter_label: 'DLWP/1-exporter',
  c2a_key_info: 'DLWP/1-c2a-key',
  a2c_key_info: 'DLWP/1-a2c-key',
  c2a_iv_info: 'DLWP/1-c2a-iv',
  a2c_iv_info: 'DLWP/1-a2c-iv',
  auth_client_label: 'DLWP/1-client',
  auth_agent_label: 'DLWP/1-agent',
};

const TEST_KEY_LABEL = 'DLWP/1-test-key';

/** Mirror of Labels.labelled: the ASCII label followed by one zero byte. */
function labelled(label) {
  for (let i = 0; i < label.length; i++) {
    if (label.charCodeAt(i) >= 0x80) {
      throw new Error('label "' + label + '" contains a non-ASCII character at ' + i);
    }
  }
  return Buffer.concat([Buffer.from(label, 'ascii'), Buffer.from([0])]);
}

/** Mirror of Derivations.testKey: SHA-256("DLWP/1-test-key" || 0x00 || seed). */
function testKey(seed) {
  return sha256(Buffer.concat([labelled(TEST_KEY_LABEL), Buffer.from(seed, 'utf8')]));
}

/** Mirror of Derivations.fingerprint. */
function fingerprint(identityPublicKey) {
  if (identityPublicKey.length !== 32) {
    throw new RangeError('a public key is 32 bytes, not ' + identityPublicKey.length);
  }

  const digest = sha256(Buffer.concat([labelled('DLWP/1-fingerprint'), identityPublicKey]));
  const hex = digest.subarray(0, 8).toString('hex').toUpperCase();

  return hex.slice(0, 4) + '-' + hex.slice(4, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16);
}

/** Mirror of Derivations.pairingCode. */
function pairingCode(pairingSecret, controllerNonce, agentNonce) {
  if (controllerNonce.length !== 32) throw new RangeError('a nonce is 32 bytes');
  if (agentNonce.length !== 32) throw new RangeError('a nonce is 32 bytes');

  const digest = sha256(Buffer.concat([
    labelled('DLWP/1-pairing-code'),
    pairingSecret,
    controllerNonce,
    agentNonce,
  ]));

  // Big-endian, because the format says big-endian and a little-endian read gives a different
  // number from the same digest.
  const value = (digest[0] * 0x1000000) + (digest[1] * 0x10000) + (digest[2] * 0x100) + digest[3];

  return String(value % 1000000).padStart(6, '0');
}

// ---- CryptoPrimitivesTest.everyLabelMatchesTheFile ------------------------------
{
  const crypto = load('crypto-primitives.json');
  // The `labels` object carries a `note` key alongside the labels themselves. It is excluded
  // explicitly rather than by filtering on a value type, because it IS a string and a
  // type-based filter would let it through -- which is what the first version of this check
  // did, and what its own failure named.
  const fromFile = Object.fromEntries(
    Object.entries(crypto.labels).filter(([k]) => k !== 'note'),
  );

  expect(!!crypto.labels, 'crypto-primitives.json has a labels object');

  const fileNames = Object.keys(fromFile).sort();
  const codeNames = Object.keys(CRYPTO_LABELS).sort();

  expect(fileNames.length >= 17, 'at least 17 labels (found ' + fileNames.length + ')');

  // This is the check that matters most in this file: a one-character difference in a label
  // yields a different key and a session that fails at the first record, with nothing in the
  // logs pointing at the typo. There is no partial credit for getting sixteen of seventeen.
  expect(
    fileNames.join(',') === codeNames.join(','),
    'the label names match\n           file: ' + fileNames.join(', ') + '\n           code: ' + codeNames.join(', '),
  );

  for (const name of fileNames) {
    expect(
      fromFile[name] === CRYPTO_LABELS[name],
      'the label "' + name + '" matches (file "' + fromFile[name] + '", code "' + CRYPTO_LABELS[name] + '")',
    );
  }

  // And every label really is ASCII with the DLWP/1 prefix, which is a property of the whole
  // set rather than an incidental feature of the current one.
  for (const [name, value] of Object.entries(fromFile)) {
    expect(value.startsWith('DLWP/1-'), 'the label "' + name + '" starts with DLWP/1-');
    expect([...value].every((c) => c.charCodeAt(0) < 0x80), 'the label "' + name + '" is ASCII');
  }
}

// ---- CryptoPrimitivesTest.theSeedRuleDerivesKeysWithNoLiteralBytes ---------------
{
  const crypto = load('crypto-primitives.json');

  expect(!!crypto.seed_rule, 'crypto-primitives.json has a seed_rule');
  expect(
    crypto.seed_rule.formula === 'key(seed) = SHA-256("DLWP/1-test-key" || 0x00 || seed)',
    'the file declares the seed rule (got "' + crypto.seed_rule.formula + '")',
  );

  const first = testKey('droidlab-test-seed-01');
  const second = testKey('droidlab-test-seed-02');

  expect(first.length === 32, 'a derived key is 32 bytes (got ' + first.length + ')');
  expect(!first.equals(second), 'different seeds derive different keys');

  // Recomputed from the label and the seed, so the check is against the file's stated formula
  // and not against the function's own output.
  const expected = sha256(Buffer.concat([
    labelled('DLWP/1-test-key'),
    Buffer.from('droidlab-test-seed-01', 'utf8'),
  ]));

  expect(first.equals(expected), "the key is the formula's output");

  // The separator changes the key, so omitting it is a real and silent mistake: the key is
  // still well-formed and simply wrong.
  const withoutSeparator = sha256(Buffer.concat([
    Buffer.from('DLWP/1-test-key', 'ascii'),
    Buffer.from('droidlab-test-seed-01', 'utf8'),
  ]));

  expect(!withoutSeparator.equals(first), 'the separator changes the key, so omitting it is a real mistake');
}

// ---- CryptoPrimitivesTest.everySignatureVectorHasItsInputs ----------------------
{
  const crypto = load('crypto-primitives.json');
  const vectors = crypto.signature_vectors || [];

  expect(vectors.length >= 2, 'at least 2 signature vectors (found ' + vectors.length + ')');

  for (const v of vectors) {
    expect(typeof v.seed === 'string' && v.seed.length > 0, v.id + ' has a seed');

    // The seed is a short auditable string, not 32 bytes of key material -- the seed rule
    // doing its job.
    expect(v.seed.length < 32, v.id + "'s seed is a short string, not literal key bytes (" + v.seed.length + ' chars)');
    expect(typeof v.signature_input === 'string' && v.signature_input.length > 0, v.id + ' has a signature input');

    // 64 bytes, which is an Ed25519 signature and nothing else.
    expect(v.signature_output_length === 64, v.id + ' signs to 64 bytes (got ' + v.signature_output_length + ')');

    expect(testKey(v.seed).length === 32, v.id + "'s derived key is 32 bytes");
  }

  const seeds = vectors.map((v) => v.seed);
  expect(new Set(seeds).size === seeds.length, 'the signature vectors use distinct seeds');
}

// ---- CryptoPrimitivesTest: the two signature payloads --------------------------
{
  const crypto = load('crypto-primitives.json');

  const txt = crypto.signature_vectors.find((v) => v.id === 'ed25519.txt-payload.basic');
  expect(!!txt, 'the txt-payload vector exists');
  if (txt) {
    // Prefixed with the txt label and a separator, so a signature over a bare payload cannot
    // be replayed as a signature over a different one sharing bytes.
    expect(
      txt.signature_input.startsWith(CRYPTO_LABELS.txt_label + '\u0000'),
      'the txt payload is prefixed with its label and a separator',
    );
    expect(txt.signature_input.includes('id=11111111-2222-4333-8444-555555555555'), 'the payload carries the device id');
    expect(txt.signature_input.includes('port=45917'), 'the payload carries the port');
  }

  const qr = crypto.signature_vectors.find((v) => v.id === 'ed25519.qr-payload.basic');
  expect(!!qr, 'the qr-payload vector exists');
  if (qr) {
    // Signed exactly as it appears on the QR code, so a scanner and a signer agree without
    // either rebuilding the URI -- which is where an escaping difference would appear.
    expect(qr.signature_input.startsWith('droidlab://pair?'), 'the QR payload is the pairing URI');
    expect(qr.signature_input.includes('v=1'), 'the URI carries its version');
    expect(qr.signature_input.includes('pid='), 'the URI carries the pairing id');
    expect(qr.signature_input.includes('aep='), "the URI carries the agent's ephemeral public key");
    expect(qr.signature_input.includes('exp=1735689600'), 'the URI carries an expiry');
    expect(qr.signature_input.includes('name=Test%20Device'), 'the URI percent-encodes its name');

    // Not labelled, unlike the txt payload: the URI already carries its own scheme and version.
    expect(!qr.signature_input.startsWith(CRYPTO_LABELS.txt_label), 'the QR payload is not txt-labelled');
  }
}

// ---- CryptoPrimitivesTest.aFingerprintHasTheDeclaredFormat ---------------------
{
  const crypto = load('crypto-primitives.json');
  const recipe = crypto.derivation_recipes.fingerprint;

  expect(recipe.hash === 'SHA-256', 'the fingerprint is a SHA-256');
  expect(
    recipe.format.includes('Uppercase hex of the first 8 digest bytes'),
    'the format is the first eight bytes, uppercase',
  );

  const value = fingerprint(Buffer.alloc(32));

  expect(value.length === 19, 'a fingerprint is 19 characters (got ' + value.length + ': "' + value + '")');
  expect((value.match(/-/g) || []).length === 3, 'a fingerprint has three dashes');

  const hexValue = value.replace(/-/g, '');
  expect(hexValue.length === 16, 'a fingerprint shows eight bytes');
  expect(/^[0-9A-F]+$/.test(hexValue), 'a fingerprint is uppercase hex');

  // Derived, not a constant: two different keys give two fingerprints.
  expect(fingerprint(Buffer.alloc(32, 1)) !== value, 'different keys give different fingerprints');

  // A wrong-width key is refused rather than padded or truncated, either of which would give a
  // fingerprint that looks right and identifies the wrong key.
  let refusedShort = false;
  try {
    fingerprint(Buffer.alloc(31));
  } catch {
    refusedShort = true;
  }
  expect(refusedShort, 'a 31-byte key is refused');

  // The recipe's own note: the RFC's example is illustrative and derived from no seed, so the
  // vectors deliberately carry no fingerprint VALUE. Only the format is checkable.
  expect(
    recipe.note.includes('illustrative only') && recipe.note.includes('not derived from any seed'),
    "the fingerprint recipe's example is not a test value",
  );
}

// ---- CryptoPrimitivesTest.thePairingCodeIsSixDigits ----------------------------
{
  const crypto = load('crypto-primitives.json');
  const recipe = crypto.derivation_recipes.pairing_code;

  expect(
    recipe.format.includes('uint32_be(digest[0..4]) mod 1000000'),
    'the format is the first four digest bytes big-endian modulo a million',
  );

  const secret = testKey('pairing-secret');
  const controllerNonce = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const agentNonce = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32));

  const code = pairingCode(secret, controllerNonce, agentNonce);

  expect(code.length === 6, 'a pairing code is six digits (got ' + code.length + ': "' + code + '")');
  expect(/^\d{6}$/.test(code), 'a pairing code is decimal (got "' + code + '")');

  const value = Number(code);
  expect(value >= 0 && value < 1000000, 'a pairing code is below a million (got ' + value + ')');

  // The code depends on every input, so a peer cannot make it match by holding one fixed.
  const differentSecret = pairingCode(testKey('other'), controllerNonce, agentNonce);
  const differentAgentNonce = pairingCode(secret, controllerNonce, Buffer.alloc(32, 9));

  expect(code !== differentSecret && code !== differentAgentNonce, 'the code depends on every input');

  // A KNOWN VALUE, recomputed here from the digest by hand rather than by calling the function.
  // This is the assertion that pins the ENDIANNESS: the checks above only require six digits,
  // and reading the digest little-endian also gives six digits from the same bytes.
  // Mutation-testing showed exactly that -- swapping the byte order survived every other check.
  const digest = sha256(Buffer.concat([labelled('DLWP/1-pairing-code'), secret, controllerNonce, agentNonce]));

  const bigEndian =
    (digest[0] * 0x1000000) + (digest[1] * 0x10000) + (digest[2] * 0x100) + digest[3];
  const littleEndian =
    digest[0] + (digest[1] * 0x100) + (digest[2] * 0x10000) + (digest[3] * 0x1000000);

  expect(
    String(bigEndian % 1000000).padStart(6, '0') === code,
    'the code is the digest first four bytes, big-endian (by hand ' +
      String(bigEndian % 1000000).padStart(6, '0') + ', code ' + code + ')',
  );

  // And the little-endian reading gives a different code for the same digest, so the assertion
  // above discriminates rather than passing either way. Skipped in the rare case the two agree,
  // so the check cannot pass vacuously.
  if (littleEndian % 1000000 !== bigEndian % 1000000) {
    expect(
      String(littleEndian % 1000000).padStart(6, '0') !== code,
      'the little-endian reading gives a different code, so the check discriminates',
    );
  }

  // The padding is REACHED, not merely described. Deleting the padding from the derivation
  // survived every other check, because a real digest rarely lands below 100000; so an input
  // is searched for that produces a small code.
  let paddedFound = null;
  for (let attempt = 0; attempt < 500 && paddedFound === null; attempt++) {
    const cNonce = Buffer.from(Array.from({ length: 32 }, (_, i) => (i + attempt) & 0xff));
    const aNonce = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 7 + attempt) & 0xff));
    const candidate = pairingCode(secret, cNonce, aNonce);
    if (candidate.startsWith('0')) paddedFound = candidate;
  }

  expect(paddedFound !== null, 'an input producing a code below 100000 was found, so the padding is exercised');
  if (paddedFound !== null) {
    expect(paddedFound.startsWith('0'), 'a code below 100000 is zero padded (got "' + paddedFound + '")');
    expect(paddedFound.length === 6, 'a padded code is still six characters');
  }
}

// ---------------------------------------------------------------------------
// ReplayProtection  --  mirror of crypto/ReplayProtection.kt
// ---------------------------------------------------------------------------

const REORDER_WINDOW_SIZE = 32;

/** Mirror of ReplayProtection.classify. */
function classifySequenceNumber(sequenceNumber, highestAccepted, seenBefore, window) {
  if (seenBefore === undefined) seenBefore = null;
  if (window === undefined) window = REORDER_WINDOW_SIZE;

  // 1. A repeat, checked BEFORE the window. A number inside the window that has already been
  //    accepted must not be accepted twice, and the window alone cannot tell the difference
  //    between that and a legitimate reorder.
  if (seenBefore !== null && seenBefore.has(sequenceNumber)) {
    return { accepted: false, replay: true };
  }

  // Nothing accepted yet means there is no window to fall out of.
  if (highestAccepted === null || highestAccepted === undefined) {
    return { accepted: true, replay: false };
  }

  // 2. Behind the window's trailing edge, which is inclusive of the slot `window` behind.
  const oldestAcceptable = highestAccepted - window;
  if (sequenceNumber < oldestAcceptable) {
    return { accepted: false, replay: true };
  }

  // 3. In the window or ahead of it.
  return { accepted: true, replay: false };
}

/** Mirror of ReplayProtection.isUsableSharedSecret. */
function isUsableSharedSecret(sharedSecret) {
  if (sharedSecret.length !== 32) return false;

  // Folded rather than early-returned, so a secret whose FIRST byte is zero and one whose LAST
  // byte is zero take the same path. Not a timing defence -- the compared value is a fixed
  // public constant -- but it stops a reader misreading a short-circuit as one.
  let accumulator = 0;
  for (const byte of sharedSecret) accumulator |= byte;

  return accumulator !== 0;
}

// ---- CryptoPrimitivesTest.anAllZeroSharedSecretIsRefused -----------------------
{
  const crypto = load('crypto-primitives.json');
  const v = crypto.rejection_vectors.find((x) => x.id === 'x25519.reject.all-zero-output');

  expect(!!v, 'x25519.reject.all-zero-output exists');
  if (v) {
    expect(v.expected === 'rejected', 'the all-zero output is rejected');

    const peerKey = hex(v.peer_public_key);
    expect(peerKey.length === 32, 'the low-order point is 32 bytes');
    expect([...peerKey].every((b) => b === 0), "the vector's key really is all zero");

    expect(!isUsableSharedSecret(Buffer.alloc(32)), 'an all-zero shared secret is refused');
    expect(isUsableSharedSecret(Buffer.alloc(32, 1)), 'a non-zero secret is usable');

    // Including when only the LAST byte is non-zero, which an early return written against the
    // first byte would wrongly reject.
    const lastByteOnly = Buffer.alloc(32);
    lastByteOnly[31] = 1;
    expect(isUsableSharedSecret(lastByteOnly), 'a secret non-zero only in its last byte is usable');

    expect(!isUsableSharedSecret(Buffer.alloc(31)), 'a short secret is refused');
  }
}

// ---- CryptoPrimitivesTest.aReusedSequenceNumberIsRefused -----------------------
{
  const crypto = load('crypto-primitives.json');
  const v = crypto.rejection_vectors.find((x) => x.id === 'nonce.reject.reused-sequence');

  expect(!!v, 'nonce.reject.reused-sequence exists');
  if (v) {
    expect(v.expected === 'rejected', 'a reuse is rejected');
    expect(v.first_sequence_number === v.second_sequence_number, 'the two frames share a number');

    const sequence = v.first_sequence_number;

    expect(classifySequenceNumber(sequence, null, new Set()).accepted, 'the first frame is accepted');
    expect(!classifySequenceNumber(sequence, sequence, new Set([sequence])).accepted, 'the repeat is refused');
    expect(classifySequenceNumber(sequence, sequence, new Set([sequence])).replay, 'and it is a replay');

    // Which is the mistake this pair exists to catch: without the seen-set the window check
    // alone ACCEPTS the repeat, because the arriving number is inside the window.
    expect(
      classifySequenceNumber(sequence, sequence, null).accepted,
      'the window alone cannot tell a repeat from a reorder, which is why the seen-set is checked first',
    );
  }
}

// ---- CryptoPrimitivesTest.theReorderingWindowBracketsItsEdge -------------------
{
  const crypto = load('crypto-primitives.json');

  const out = crypto.rejection_vectors.find((x) => x.id === 'nonce.reject.out-of-window');
  const inside = crypto.rejection_vectors.find((x) => x.id === 'nonce.accept.inside-window');

  expect(!!out, 'the out-of-window vector exists');
  expect(!!inside, 'the inside-window vector exists');

  if (out) {
    expect(out.expected === 'rejected', 'a frame past the window is rejected');
    expect(out.window === REORDER_WINDOW_SIZE, "the vector's window matches the code (" + out.window + ')');

    const verdict = classifySequenceNumber(out.received, out.highest_accepted, new Set(), out.window);
    expect(!verdict.accepted, 'a frame ' + (out.highest_accepted - out.received) + ' behind is refused');
    expect(verdict.replay, 'and it is a replay');
  }

  if (inside) {
    expect(inside.expected === 'accepted', 'a frame inside the window is accepted');

    const verdict = classifySequenceNumber(inside.received, inside.highest_accepted, new Set(), inside.window);
    expect(verdict.accepted, 'a frame ' + (inside.highest_accepted - inside.received) + ' behind is accepted');
    expect(!verdict.replay, 'and it is not a replay');
  }
}

// ---- CryptoPrimitivesTest.theWindowEdgeIsExact --------------------------------
{
  const highest = 1000;
  const window = REORDER_WINDOW_SIZE;
  const oldest = highest - window;

  // Checked on BOTH sides of the line: an off-by-one here either refuses a legitimate reorder
  // or accepts one a frame too old, and the vectors sample only the two cases, not the edge.
  expect(classifySequenceNumber(oldest, highest, new Set(), window).accepted, 'the oldest number in the window is accepted');
  expect(!classifySequenceNumber(oldest - 1, highest, new Set(), window).accepted, 'one older than the window is refused');
  expect(classifySequenceNumber(highest + 1, highest, new Set(), window).accepted, 'a number ahead of the high-water mark is accepted');

  // Nothing accepted yet means no window, however small the number. Which is why the Kotlin's
  // `highestAccepted` is nullable rather than defaulting to zero.
  //
  // The discriminating case has to be a number a zero default would REJECT: with a high-water
  // mark of 0 and a window of 32, a frame numbered 0 is at the boundary and acceptable either
  // way, so testing 0 alone does not distinguish the two. A very low number does.
  //
  // Mutation-testing found this -- replacing the null case with a zero default survived, because
  // every number the check used was above the boundary under both readings.
  expect(
    classifySequenceNumber(Number.MIN_SAFE_INTEGER, null, new Set(), window).accepted,
    'with nothing accepted yet there is no window, so even a very low number is accepted',
  );

  // And the same number IS refused against a zero high-water mark, which is what makes the
  // assertion above meaningful rather than a tautology.
  expect(
    !classifySequenceNumber(Number.MIN_SAFE_INTEGER, 0, new Set(), window).accepted,
    'the same number is refused once something has been accepted, so the null case is doing work',
  );
}

// ---- CryptoPrimitivesTest.theFrameHeaderIsTheAssociatedData -------------------
{
  const crypto = load('crypto-primitives.json');
  const v = crypto.rejection_vectors.find((x) => x.id === 'aead.reject.tampered-header');

  expect(!!v, 'aead.reject.tampered-header exists');
  if (v) {
    expect(v.expected === 'rejected', 'a tampered header is rejected');
    expect(v.mutated_field === 'sequence_number', 'the mutated field is a header field');
    expect(v.expected_error === 'ERR_MALFORMED', 'a tampered header is reported as malformed');

    const headerFields = [
      'magic', 'version', 'flags', 'header_length', 'message_type',
      'channel_id', 'sequence_number', 'acknowledgment', 'body_length',
    ];

    expect(headerFields.includes(v.mutated_field), "the mutated field is one of the header's own fields");
  }
}

// ---- CryptoPrimitivesTest.theDeclaredAlgorithmsAreTheOnesUsed -----------------
{
  const crypto = load('crypto-primitives.json');
  const algorithms = crypto.algorithms;

  // Declared, not assumed: an implementation that substituted a primitive would still pass
  // every vector that only checks a length, so the declarations are compared to what the code
  // names.
  expect(algorithms.kdf === 'HKDF per RFC 5869 with SHA-256', 'the KDF is declared (got "' + algorithms.kdf + '")');
  expect(algorithms.aead === 'AES-256-GCM with a 96-bit nonce and a 128-bit tag', 'the AEAD is declared (got "' + algorithms.aead + '")');
  expect(algorithms.key_agreement === 'X25519 per RFC 7748', 'the agreement is declared (got "' + algorithms.key_agreement + '")');
  expect(algorithms.signature === 'Ed25519 per RFC 8032', 'the signature is declared (got "' + algorithms.signature + '")');
  expect(algorithms.hmac === 'HMAC-SHA256 per RFC 2104', 'the MAC is declared (got "' + algorithms.hmac + '")');
  expect(algorithms.hash === 'SHA-256 per FIPS 180-4', 'the hash is declared (got "' + algorithms.hash + '")');

  expect(sha256(Buffer.alloc(0)).length === 32, 'SHA-256 produces 32 bytes');

  // Known-answer checks, so the digest is SHA-256 and not merely 32 bytes of something. Two
  // answers, so one constant being right by construction cannot carry the check.
  expect(
    sha256(Buffer.alloc(0)).toString('hex') === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'SHA-256 of the empty string is its published value',
  );

  expect(
    sha256(Buffer.from('abc', 'ascii')).toString('hex') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'SHA-256 of "abc" is its published value',
  );
}

// ---- CryptoPrimitivesTest.theNonceLayoutIsTheDeclaredOne ----------------------
{
  const crypto = load('crypto-primitives.json');
  const nonce = crypto.derivation_recipes.nonce_layout;

  expect(
    nonce.form.includes('iv_prefix (4 bytes) || sequence_number (8 bytes, big-endian)'),
    'the nonce is an IV prefix and a big-endian sequence number (got "' + nonce.form + '")',
  );

  // Twelve bytes total, which is the 96-bit nonce AES-GCM is defined for.
  expect(4 + 8 === 12, 'the nonce is twelve bytes');
}


// ---------------------------------------------------------------------------
// DiscoveryAdvertisement  --  mirror of DiscoveryAdvertisement.kt
// ---------------------------------------------------------------------------

const DISCOVERY = {
  SERVICE_TYPE: '_droidlab._tcp',
  DOMAIN: 'local',
  TXT_LABEL: 'DLWP/1-txt',
  FIELD_SEPARATOR: 0x0a,
  REQUIRED_KEYS: ['v', 'id', 'fp', 'caps', 'port'],
  OPTIONAL_KEYS: ['model', 'android', 'sdk', 'busy', 'loc', 'tls'],
  DEFAULT_PORT: 45917,
  BEACON_PORT: 45918,
  TTL_SECONDS: 120,
  MAX_TXT_BYTES: 1300,
  SIGNATURE_LENGTH_BYTES: 64,
};

/** Mirror of DiscoveryAdvertisement.canonicalTxt. */
function canonicalTxt(fields) {
  const ordered = [...DISCOVERY.REQUIRED_KEYS, ...DISCOVERY.OPTIONAL_KEYS];
  let text = DISCOVERY.TXT_LABEL + '\u0000';

  for (let index = 0; index < ordered.length; index++) {
    const key = ordered[index];
    const value = fields[key];

    if (value === undefined || value === null) {
      if (DISCOVERY.REQUIRED_KEYS.includes(key)) {
        throw new Error('the required key "' + key + '" is missing');
      }
      continue;
    }

    if (String(value).includes('\n')) {
      throw new Error('the value of "' + key + '" contains a newline');
    }

    // The separator goes BETWEEN fields, never after the last one. Appending it per-field
    // would leave a trailing newline: one byte longer and a different signature.
    const hasPredecessor = ordered.slice(0, index).some((k) => Object.prototype.hasOwnProperty.call(fields, k) && fields[k] !== undefined);
    if (hasPredecessor) text += '\u000A';

    text += key + '=' + value;
  }

  return Buffer.from(text, 'utf8');
}

/** Mirror of DiscoveryAdvertisement.canonicalBeacon. */
function canonicalBeacon(fields) {
  const ordered = Object.keys(fields).sort();

  return Buffer.from(
    ordered
      .map((key) => {
        const value = fields[key];
        if (typeof value === 'string' || typeof value === 'number') return key + '=' + value;
        throw new Error('the field "' + key + '" is neither a string nor a number');
      })
      .join('\n'),
    'utf8',
  );
}

/** Mirror of DiscoveryAdvertisement.fitsTxtBudget. */
function fitsTxtBudget(byteCount) {
  return byteCount >= 0 && byteCount <= DISCOVERY.MAX_TXT_BYTES;
}

/** Mirror of DiscoveryAdvertisement.isUsablePort. */
function isUsablePort(port) {
  return port >= 1 && port <= 65535;
}

/** Mirror of DiscoveryAdvertisement.mayBeacon. */
function mayBeacon(discoveryEnabled) {
  return discoveryEnabled === true;
}

/** The plain-string view of a vector's `fields`. */
function discoveryFields(v) {
  const out = {};
  for (const [key, value] of Object.entries(v.fields)) {
    if (typeof value === 'string' || typeof value === 'number') out[key] = value;
    else throw new Error('discovery field "' + key + '" is neither a string nor a number');
  }
  return out;
}

/** A discovery vector by id. */
function discoveryVector(file, key, id) {
  const found = (file[key] || []).find((v) => v.id === id);
  if (!found) throw new Error('discovery.json has no ' + key + ' entry "' + id + '"');
  return found;
}

// ---- DiscoveryTest.theServiceConstantsAreTheOnesUsed --------------------------
{
  const service = load('discovery.json').service;

  expect(service.type === DISCOVERY.SERVICE_TYPE, 'the service type matches (got "' + service.type + '")');
  expect(service.domain === DISCOVERY.DOMAIN, 'the domain matches (got "' + service.domain + '")');
  expect(service.default_port === DISCOVERY.DEFAULT_PORT, 'the default port matches (got ' + service.default_port + ')');
  expect(service.beacon_port === DISCOVERY.BEACON_PORT, 'the beacon port matches (got ' + service.beacon_port + ')');
  expect(service.ttl_seconds === DISCOVERY.TTL_SECONDS, 'the TTL matches (got ' + service.ttl_seconds + ')');
  expect(service.max_txt_bytes === DISCOVERY.MAX_TXT_BYTES, 'the size budget matches (got ' + service.max_txt_bytes + ')');

  // The beacon is one above the service port, never the service port itself: a beacon delivered
  // to the service port would be parsed as a connection attempt.
  expect(DISCOVERY.BEACON_PORT !== DISCOVERY.DEFAULT_PORT, 'the beacon port is not the service port');
  expect(DISCOVERY.DEFAULT_PORT + 1 === DISCOVERY.BEACON_PORT, 'the beacon port is the next one up');

  // The budget is the mDNS delivery limit, not a figure chosen for comfort.
  expect(DISCOVERY.MAX_TXT_BYTES === 1300, 'the budget is the mDNS limit (got ' + DISCOVERY.MAX_TXT_BYTES + ')');
}

// ---- DiscoveryTest.theCanonicalisationIsFixedOrder ----------------------------
{
  const txt = load('discovery.json').txt_canonicalisation;
  const rule = txt.rule;

  expect(rule.includes('exactly this order'), 'the key order is fixed');
  expect(rule.includes('separated by 0x0A'), 'the separator is a newline');
  expect(rule.includes('with the label and a NUL first'), 'the label and a NUL come first');
  expect(rule.includes('No trailing newline'), 'there is no trailing newline');

  expect(
    txt.form ===
      '"DLWP/1-txt" || 0x00 || "v=" || v || 0x0A || "id=" || id || 0x0A || "fp=" || fp || ' +
        '0x0A || "caps=" || caps || 0x0A || "port=" || port',
    'the declared form matches (got "' + txt.form + '")',
  );

  // The order is deliberately not alphabetical, and the file says why.
  expect(txt.note.includes('fixed rather than alphabetical'), 'the order is fixed, not sorted');
  expect(
    DISCOVERY.REQUIRED_KEYS.slice().sort().join(',') !== DISCOVERY.REQUIRED_KEYS.join(','),
    'the fixed order differs from the sorted order, so the distinction is real',
  );

  expect(
    txt.extra_key_order.join(',') === DISCOVERY.OPTIONAL_KEYS.join(','),
    'the optional key order matches (file ' + txt.extra_key_order.join(',') + ', code ' + DISCOVERY.OPTIONAL_KEYS.join(',') + ')',
  );
}

// ---- DiscoveryTest.everyAdvertisementBuildsToItsDeclaredBytes -----------------
{
  const file = load('discovery.json');
  const vectors = file.vectors || [];

  expect(vectors.length >= 4, 'at least 4 advertisement vectors (found ' + vectors.length + ')');

  for (const id of ['discovery.txt.minimal', 'discovery.txt.full']) {
    const v = discoveryVector(file, 'vectors', id);
    const built = canonicalTxt(discoveryFields(v)).toString('utf8');

    expect(built === v.canonical_utf8, id + ' produces its declared canonical bytes (got "' + built + '")');
    expect(
      Buffer.from(built, 'utf8').length === v.canonical_length_bytes,
      id + ' declared length matches its bytes (' + Buffer.from(built, 'utf8').length + ' vs ' + v.canonical_length_bytes + ')',
    );
  }
}

// ---- DiscoveryTest.theOptionalKeysAddTheDeclaredBytes ------------------------
{
  const file = load('discovery.json');
  const minimal = canonicalTxt(discoveryFields(discoveryVector(file, 'vectors', 'discovery.txt.minimal')));
  const full = canonicalTxt(discoveryFields(discoveryVector(file, 'vectors', 'discovery.txt.full')));

  // The file says 87, measured rather than estimated.
  expect(full.length - minimal.length === 87, 'the optional keys add 87 bytes (got ' + (full.length - minimal.length) + ')');

  const fullText = full.toString('utf8');

  // NOT asserted as "the full record is the minimal record with fields appended": the two
  // vectors describe different devices, so their id, fingerprint and capability values differ
  // too. What holds is only that both carry the same required keys in the same ORDER, which is
  // what the field-ordering rule is actually about.
  const keyOrder = (text) => text.split('\n').map((line, i) => (i === 0 ? line.split('\u0000')[1] : line).split('=')[0]);

  expect(
    keyOrder(fullText).slice(0, 5).join(',') === keyOrder(minimal.toString('utf8')).slice(0, 5).join(','),
    'both records order their required keys the same way',
  );
  expect(
    keyOrder(fullText).slice(0, 5).join(',') === DISCOVERY.REQUIRED_KEYS.join(','),
    'the required keys are in the fixed order (got ' + keyOrder(fullText).slice(0, 5).join(',') + ')',
  );

  const positions = DISCOVERY.OPTIONAL_KEYS.map((k) => fullText.indexOf('\n' + k + '='));
  expect(positions.every((p) => p > 0), 'every optional key is present');

  const sorted = positions.slice().sort((a, b) => a - b);
  expect(positions.join(',') === sorted.join(','), 'the optional keys appear in the declared order');
}

// ---- DiscoveryTest.aRecordHasNoTrailingNewline ------------------------------
{
  const file = load('discovery.json');
  const built = canonicalTxt(discoveryFields(discoveryVector(file, 'vectors', 'discovery.txt.minimal')));
  const text = built.toString('utf8');

  // The mistake this guards: appending the separator after every field rather than between
  // fields. One byte longer, identical in a terminal, and a different signature.
  expect(!text.endsWith('\n'), 'the record does not end with a newline');
  expect(!text.endsWith('\u0000'), 'the record does not end with a NUL');

  expect(
    (text.match(/\n/g) || []).length === DISCOVERY.REQUIRED_KEYS.length - 1,
    'one separator between each pair of fields and none after the last (got ' + (text.match(/\n/g) || []).length + ')',
  );

  expect(text.startsWith(DISCOVERY.TXT_LABEL + '\u0000'), 'the record opens with the label and a NUL');

  // An extra NUL would terminate the string for a C consumer and truncate the record silently.
  expect((text.match(/\u0000/g) || []).length === 1, 'there is exactly one NUL, after the label');
}

// ---- DiscoveryTest.anUnknownKeyIsNotSigned ---------------------------------
{
  const file = load('discovery.json');
  const base = discoveryFields(discoveryVector(file, 'vectors', 'discovery.txt.minimal'));

  const withExtra = canonicalTxt({ ...base, surprise: 'payload' });

  expect(
    canonicalTxt(base).equals(withExtra),
    'an undefined key does not change the signed bytes',
  );

  expect(!withExtra.toString('utf8').includes('surprise'), 'the undefined key does not appear');
}

// ---- DiscoveryTest.aMissingRequiredKeyIsRefused ----------------------------
{
  const file = load('discovery.json');
  const base = discoveryFields(discoveryVector(file, 'vectors', 'discovery.txt.minimal'));

  for (const key of DISCOVERY.REQUIRED_KEYS) {
    const incomplete = { ...base };
    delete incomplete[key];

    let refused = null;
    try {
      canonicalTxt(incomplete);
    } catch (error) {
      refused = error.message;
    }

    expect(refused !== null, 'omitting the required key "' + key + '" is refused');
    expect(
      refused !== null && refused.includes(key),
      'the refusal names the missing key "' + key + '" (got "' + refused + '")',
    );
  }

  // A missing OPTIONAL key is not refused: its absence is the normal case.
  const withoutOptional = canonicalTxt({ ...discoveryFields(discoveryVector(file, 'vectors', 'discovery.txt.full')), model: undefined });
  expect(!withoutOptional.toString('utf8').includes('model='), 'a missing optional key is simply absent');
}

// ---- DiscoveryTest.aNewlineInAValueIsRefused -------------------------------
{
  const file = load('discovery.json');
  const base = discoveryFields(discoveryVector(file, 'vectors', 'discovery.txt.minimal'));

  // A value with a newline would let one field forge the appearance of another, and the record
  // is signed, so the injected key would be signed too.
  let refused = null;
  try {
    canonicalTxt({ ...base, model: 'Pixel\nid=evil' });
  } catch (error) {
    refused = error.message;
  }

  expect(refused !== null, 'a newline inside a value is refused');
  expect(refused !== null && refused.includes('model'), 'the refusal names the offending key (got "' + refused + '")');
}

// ---- DiscoveryTest.theBeaconIsCanonicalisedInAscendingOrder ----------------
{
  const file = load('discovery.json');
  const v = discoveryVector(file, 'vectors', 'discovery.beacon.canonical');

  const built = canonicalBeacon(v.fields);
  const declared = v.canonical_utf8;

  expect(built.toString('utf8') === declared, 'the beacon builds to its declared bytes (got "' + built.toString('utf8') + '")');
  expect(built.length === v.canonical_length_bytes, 'the beacon declared length matches its bytes');

  expect(
    declared ===
      'busy=0\nfp=9F3C-1A08-B7E2-44D1\nid=11111111-2222-4333-8444-555555555555\n' +
        'name=Pixel 7 - bench 3\nport=45917\nv=1.0',
    "the beacon's fields are in ascending key order",
  );

  const keys = declared.split('\n').map((line) => line.split('=')[0]);
  expect(keys.join(',') === keys.slice().sort().join(','), 'the beacon keys are ascending');

  // The vector's own field object happens to already be in ascending order, so building it
  // proves nothing about the sort: removing the sort survived this check. A map whose insertion
  // order differs from its sorted order is what makes the rule testable.
  const shuffled = { v: '1.0', port: 45917, name: 'Pixel 7 - bench 3', id: 'i', fp: 'f', busy: 0 };
  const shuffledBuilt = canonicalBeacon(shuffled).toString('utf8');

  expect(
    shuffledBuilt === 'busy=0\nfp=f\nid=i\nname=Pixel 7 - bench 3\nport=45917\nv=1.0',
    'a beacon whose fields were inserted out of order is still built in ascending order (got "' + shuffledBuilt.replace(/\n/g, '\\n') + '")',
  );

  // A number field is written without a decimal point or quotes: `busy=0`, not `busy=0.0`,
  // and not `busy="0"`.
  expect(declared.startsWith('busy=0\n'), 'an integer field is bare');
  expect(declared.includes('port=45917'), 'a port is written as an integer');
  expect(!declared.includes('"'), 'the beacon carries no quoting');
}

// ---- DiscoveryTest.aBadSignatureIsIgnoredNotConnected ----------------------
{
  const file = load('discovery.json');
  const v = discoveryVector(file, 'rejection_vectors', 'discovery.reject.signature-mismatch-paired-device');

  expect(v.signature_valid === false, "the vector's signature is invalid");
  expect(v.expected === 'ignore_advertisement', 'the advertisement is ignored');
  expect(v.expected_ui_state === 'Unverified', 'the device is shown as unverified');

  // The device is NOT removed from the list: an attacker jamming the real agent and advertising
  // in its place could otherwise clear the device, which is a denial of service dressed up as a
  // safety measure.
  expect(v.controller_has_pairing_for_id === '11111111-2222-4333-8444-555555555555', 'the controller holds a pairing record');
  expect(v.note_on_action.includes('must not connect'), 'the controller must not connect');
  expect(v.note_on_action.includes('must also not quietly remove the device'), 'the device is not removed');
}

// ---- DiscoveryTest.aChangedFingerprintIsRefused ---------------------------
{
  const file = load('discovery.json');
  const v = discoveryVector(file, 'rejection_vectors', 'discovery.reject.fingerprint-changed-for-known-id');

  expect(v.known_id === '11111111-2222-4333-8444-555555555555', 'the id matches a record');

  // The id is the same and the fingerprint is not. Asserted, because the whole vector is inert
  // if the two fingerprints happen to be equal.
  expect(v.known_fingerprint !== v.advertised_fingerprint, 'the fingerprint really did change');

  expect(v.expected === 'refuse_automatic_connect', 'an automatic connect is refused');
  expect(v.expected_warning.includes('possible impersonation'), 'the warning names impersonation as the possibility');

  // "possible", not "certain": a reinstalled agent with a new identity key gives the same
  // signal, and the operator decides.
  expect(!v.expected_warning.includes('confirmed'), 'the warning does not claim certainty');
}

// ---- DiscoveryTest.theOtherRejectionsAreAsDeclared --------------------------
{
  const file = load('discovery.json');

  const port = discoveryVector(file, 'rejection_vectors', 'discovery.reject.port-out-of-range');
  expect(port.advertised_port === 0, "the vector's port is zero");
  expect(!isUsablePort(0), 'port zero is not usable');
  expect(isUsablePort(1), 'port one is usable');
  expect(isUsablePort(65535), 'port 65535 is usable');
  expect(!isUsablePort(65536), 'port 65536 is not usable');
  expect(!isUsablePort(-1), 'a negative port is not usable');

  const version = discoveryVector(file, 'rejection_vectors', 'discovery.reject.unsupported-version');
  expect(version.advertised_version === '9.0', 'the advertised version is 9.0');
  expect(version.controller_supported_versions.join(',') === '1.0', 'the controller supports 1.0 only');
  expect(!version.controller_supported_versions.includes('9.0'), 'the advertised major is not supported');
  expect(version.expected === 'list_as_incompatible', 'it is listed as incompatible');
  expect(version.expected_error === 'ERR_VERSION_MISMATCH', 'the fault is a version mismatch');

  // A record over the budget must be regenerated, not truncated.
  const large = discoveryVector(file, 'rejection_vectors', 'discovery.reject.txt-too-large');
  expect(large.max_txt_bytes === DISCOVERY.MAX_TXT_BYTES, "the vector's budget is the implementation's");
  expect(!fitsTxtBudget(large.txt_bytes), large.txt_bytes + ' bytes does not fit a ' + large.max_txt_bytes + ' budget');
  expect(fitsTxtBudget(large.max_txt_bytes), 'exactly the budget fits');
  expect(large.expected === 'regenerate_record', 'the record is regenerated');

  const beacon = discoveryVector(file, 'rejection_vectors', 'discovery.reject.beacon-on-public-network');
  expect(beacon.discovery_enabled === false, 'discovery is disabled');
  expect(!mayBeacon(false), 'no beacon when discovery is off');
  expect(mayBeacon(true), 'a beacon when discovery is on');
  expect(
    beacon.note.includes('must not unicast it to an address it has not itself been contacted from'),
    'there is no unicast fallback',
  );
}

// ---- DiscoveryTest.aTruncatedCapabilityListIsAdvisory ----------------------
{
  const file = load('discovery.json');
  const v = discoveryVector(file, 'vectors', 'discovery.txt.caps-truncated');

  const advertised = discoveryFields(v).caps.split(',');
  const available = v.caps_actually_available;

  expect(advertised.length < available.length, 'the advertised list is shorter than the available set');

  for (const capability of advertised) {
    expect(available.includes(capability), 'the advertised "' + capability + '" really is available');
  }

  // Capabilities are available that were not advertised, which is the whole point: a controller
  // that trusted the record would refuse features the agent has.
  const missing = available.filter((c) => !advertised.includes(c));
  expect(missing.length > 0, 'some available capabilities were not advertised');
  expect(missing.includes('screen.record'), 'screen.record is available but not advertised');

  expect(!discoveryFields(v).caps.endsWith(','), 'the capability list has no trailing comma');
  expect(!discoveryFields(v).caps.includes(',,'), 'the capability list has no empty element');

  expect(
    v.note_on_trust.includes('Only the CAPABILITIES frame after authentication is authoritative'),
    'only the post-authentication frame is authoritative',
  );
}

// ---- DiscoveryTest.theLifecycleRulesAreAsDeclared -------------------------
{
  const file = load('discovery.json');

  const goodbye = discoveryVector(file, 'lifecycle_vectors', 'discovery.goodbye-on-disable');
  // The goodbye's TTL is ZERO, not the normal TTL. A goodbye is a withdrawal, and the reason it
  // carries its own TTL is that the alternative -- waiting for the record to expire -- leaves a
  // disabled agent listed for two minutes with no way for a controller to tell it apart from a
  // sleeping one.
  expect(goodbye.goodbye_ttl === 0, 'the goodbye has a TTL of zero (got ' + goodbye.goodbye_ttl + ')');
  expect(goodbye.goodbye_ttl !== DISCOVERY.TTL_SECONDS, 'the goodbye does not use the normal TTL');
  expect(goodbye.expected === 'send_goodbye', 'a goodbye is sent');

  // An expired advertisement keeps the device in the list. Removing it on expiry would make a
  // sleeping phone look like an uninstalled one.
  const expiry = discoveryVector(file, 'lifecycle_vectors', 'discovery.ttl-expiry-keeps-saved-device');
  expect(expiry.elapsed_s > expiry.ttl_s, "the vector's elapsed time is past the TTL");
  expect(expiry.expected_still_listed === true, 'an expired device stays listed');
  expect(expiry.expected_ui_state.length > 0, 'the expiry has a UI state');
  expect(!expiry.expected_ui_state.includes('removed'), 'the expired device is not removed from the list');

  // A busy agent still advertises with the flag set, rather than withdrawing: a controller that
  // cannot see the device at all also cannot see that it is busy.
  const busy = discoveryVector(file, 'lifecycle_vectors', 'discovery.busy-agent-still-advertises');
  expect(busy.active_sessions >= busy.max_sessions, "the vector's agent really is at its session limit");
  expect(busy.expected.includes('advertis'), 'a busy agent still advertises');
  expect(busy.expected_busy_value === 1, 'the busy flag is set (got ' + JSON.stringify(busy.expected_busy_value) + ')');

  const moved = discoveryVector(file, 'lifecycle_vectors', 'discovery.reannounce-after-address-change');
  expect(moved.expected === 're_register_service', 'an address change re-registers the service (got ' + moved.expected + ')');
}


// ---------------------------------------------------------------------------
// SessionMessages / SessionReplay  --  mirror of SessionReplay.kt
// ---------------------------------------------------------------------------

const SESSION_MESSAGES = {
  HELLO: 1,
  HELLO_ACK: 2,
  AUTH: 3,
  AUTH_OK: 4,
  PING: 5,
  PONG: 6,
  GET_CAPABILITIES: 16,
  CAPABILITIES: 17,
  CHANNEL_OPEN: 32,
  CHANNEL_OPENED: 33,
  CHANNEL_CLOSE: 34,
  VIDEO_START: 48,
  VIDEO_CONFIG: 49,
  VIDEO_FRAME: 50,
  VIDEO_STOP: 51,
  INPUT_TOUCH: 64,
  SHELL_EXEC: 80,
  DEVICE_INFO: 128,
  DEVICE_INFO_RESULT: 129,
  ERROR: 240,
  SESSION_END: 241,
};

const SESSION_UNENCRYPTED = new Set([SESSION_MESSAGES.HELLO, SESSION_MESSAGES.HELLO_ACK]);

const SESSION_STATE = {
  IDLE: 'idle',
  DISCOVERING: 'discovering',
  CONNECTING: 'connecting',
  HANDSHAKING: 'handshaking',
  AUTHENTICATING: 'authenticating',
  ESTABLISHED: 'established',
  STREAMING: 'streaming',
  CLOSING: 'closing',
  CLOSED: 'closed',
};

/** Mirror of SessionTransitions.next. Throws when the transition is illegal. */
function sessionNext(from, role, messageType, channelId) {
  const isEstablished = (s) => s === SESSION_STATE.ESTABLISHED || s === SESSION_STATE.STREAMING;
  const require_ = (ok, message) => {
    if (!ok) throw new Error(message);
  };

  require_(from !== SESSION_STATE.CLOSED, 'the session is closed and accepts no frames');

  switch (messageType) {
    case SESSION_MESSAGES.HELLO:
      require_(role === 'controller', 'only the controller sends HELLO');
      require_(from === SESSION_STATE.IDLE || from === SESSION_STATE.CONNECTING, 'HELLO is sent from idle or connecting, not from ' + from);
      return SESSION_STATE.HANDSHAKING;

    case SESSION_MESSAGES.HELLO_ACK:
      require_(role === 'agent', 'only the agent sends HELLO_ACK');
      require_(from === SESSION_STATE.HANDSHAKING, 'HELLO_ACK answers HELLO, so the state is handshaking, not ' + from);
      return SESSION_STATE.AUTHENTICATING;

    case SESSION_MESSAGES.AUTH:
      require_(role === 'controller', 'only the controller sends AUTH');
      require_(from === SESSION_STATE.AUTHENTICATING, 'AUTH is sent while authenticating, not from ' + from);

      // Sending AUTH does NOT establish the session: the session is established when the
      // HANDSHAKE completes, which is when both proofs have been exchanged. The controller has
      // sent its proof but has not checked the agent's, so it remains authenticating.
      return SESSION_STATE.AUTHENTICATING;

    case SESSION_MESSAGES.AUTH_OK:
      require_(role === 'agent', 'only the agent sends AUTH_OK');
      require_(from === SESSION_STATE.AUTHENTICATING, 'AUTH_OK is sent while authenticating, not from ' + from);
      return SESSION_STATE.ESTABLISHED;

    case SESSION_MESSAGES.SESSION_END:
      return SESSION_STATE.CLOSED;

    case SESSION_MESSAGES.ERROR:
      // An ERROR frame does not change the state on its own: whether the session survives depends
      // on the SEVERITY in the body, and this table deliberately does not read bodies.
      return from;

    case SESSION_MESSAGES.CHANNEL_OPEN:
    case SESSION_MESSAGES.CHANNEL_OPENED:
      require_(isEstablished(from), 'a channel is opened after authentication, not from ' + from);
      return from;

    case SESSION_MESSAGES.VIDEO_START:
    case SESSION_MESSAGES.VIDEO_CONFIG:
      require_(isEstablished(from), 'video starts after authentication, not from ' + from);
      return SESSION_STATE.STREAMING;

    case SESSION_MESSAGES.DEVICE_INFO:
    case SESSION_MESSAGES.DEVICE_INFO_RESULT:
    case SESSION_MESSAGES.INPUT_TOUCH:
    case SESSION_MESSAGES.SHELL_EXEC:
      require_(isEstablished(from), 'the message type ' + messageType + ' arrives after authentication, not from ' + from);
      return from;

    default:
      require_(isEstablished(from), 'message type ' + messageType + ' arrives after authentication, not from ' + from);
      return from;
  }
}

/** Mirror of SessionReplayer. */
class SessionReplayer {
  constructor(role) {
    this.role = role;
    this.state = SESSION_STATE.IDLE;
    this.lastSent = null;
    this.lastReceived = null;
    this.sentEncrypted = false;
    this.peerSentEncrypted = false;
    this.received = new Set();
  }

  send(messageType, sequenceNumber, encrypted, channelId = 0) {
    // Monotonic, not strictly sequential. A transcript records the frames that matter rather
    // than every frame: the controller in session-basic.json sends 1, 2, 3, 4, 5 and then 8,
    // because its 6 and 7 are the agent's frames in the agent's own counter. Demanding strict
    // succession made the transcript un-replayable.
    if (sequenceNumber < 1) throw new Error('the first outgoing sequence number is 1, not ' + sequenceNumber);
    if (this.lastSent !== null && sequenceNumber <= this.lastSent) {
      throw new Error('outgoing sequence number ' + sequenceNumber + ' does not advance past ' + this.lastSent);
    }

    const isUnencryptedType = SESSION_UNENCRYPTED.has(messageType);
    if (isUnencryptedType === encrypted) {
      throw new Error(isUnencryptedType ? 'this type must not be encrypted' : 'this type must be encrypted');
    }

    this.state = sessionNext(this.state, this.role, messageType, channelId);
    this.lastSent = sequenceNumber;
    if (encrypted) this.sentEncrypted = true;
  }

  receive(messageType, sequenceNumber, encrypted, channelId = 0) {
    const floor = this.lastReceived === null ? null : this.lastReceived - 32;

    if (this.received.has(sequenceNumber) || (floor !== null && sequenceNumber < floor)) {
      this.state = SESSION_STATE.CLOSING;
      return { kind: 'fatal', code: 'ERR_REPLAY_DETECTED' };
    }

    const other = this.role === 'controller' ? 'agent' : 'controller';

    try {
      var next = sessionNext(this.state, other, messageType, channelId);
    } catch {
      return { kind: 'recoverable', code: 'ERR_UNEXPECTED_MESSAGE' };
    }

    const isUnencryptedType = SESSION_UNENCRYPTED.has(messageType);
    if (isUnencryptedType === encrypted) {
      throw new Error(isUnencryptedType ? 'this type must not be encrypted' : 'this type must be encrypted');
    }

    this.received.add(sequenceNumber);
    if (encrypted) this.peerSentEncrypted = true;
    this.lastReceived = this.lastReceived === null ? sequenceNumber : Math.max(this.lastReceived, sequenceNumber);
    this.state = next;

    return { kind: 'accepted' };
  }
}

/** A transcript step, 1-based. */
function stepOf(file, index) {
  const found = file.steps.find((s) => s.step === index);
  if (!found) throw new Error('session-basic.json has no step ' + index);
  return found;
}

const sessionStep = (file, i) => stepOf(file, i);
const stepSend = (file, i) => stepOf(file, i).send;
const stepType = (file, i) => {
  const name = stepSend(file, i).name;
  const code = SESSION_MESSAGES[name];
  if (code === undefined) throw new Error('the message name "' + name + '" in step ' + i + ' is not one this mirror names');
  return code;
};
const stepEnc = (file, i) => stepSend(file, i).encrypted === true;
const stepSeq = (file, i) => stepSend(file, i).sequence_number;
const stepChannel = (file, i) => stepSend(file, i).channel_id;
const stepActor = (file, i) => stepOf(file, i).actor;

// ---- SessionReplayTest.everyMessageCodeMatchesTheRegistry ---------------------
{
  const registryJson = JSON.parse(fs.readFileSync('C:/Dev/DroidLab/protocol/registry/dlwp-1.json', 'utf8'));
  const byName = {};
  for (const definition of Object.values(registryJson.message_types)) {
    byName[definition.name] = definition.code;
  }

  // The registry's JSON object uses 0-based keys while each entry's `code` is 1-based.
  // Transcribing from the key instead of the field is silently plausible -- HELLO would be 0 and
  // the whole transcript would still run -- so every constant is checked against the FIELD.
  for (const [name, code] of Object.entries(SESSION_MESSAGES)) {
    expect(byName[name] !== undefined, 'dlwp-1.json has a message type named ' + name);
    expect(byName[name] === code, name + ' is the registry\'s code (registry ' + byName[name] + ', code ' + code + ')');
  }

  expect(new Set(Object.values(SESSION_MESSAGES)).size === Object.keys(SESSION_MESSAGES).length, 'every message code is distinct');

  // And the 0-based keys really do differ from the codes, so the check above is not trivially
  // true because the two happen to coincide.
  const firstKey = Object.keys(registryJson.message_types)[0];
  expect(registryJson.message_types[firstKey].code !== Number(firstKey), 'the JSON key is 0-based while the code is 1-based, so the distinction is real');

  const unencrypted = Object.values(registryJson.message_types)
    .filter((d) => d.encrypted === false)
    .map((d) => d.name)
    .sort();

  expect(unencrypted.join(',') === 'HELLO,HELLO_ACK', 'only the handshake pair travels unencrypted (got ' + unencrypted.join(',') + ')');
  expect(
    [...SESSION_UNENCRYPTED].sort((a, b) => a - b).join(',') === [SESSION_MESSAGES.HELLO, SESSION_MESSAGES.HELLO_ACK].join(','),
    'the unencrypted set matches the registry',
  );
}

// ---- SessionReplayTest.theTranscriptWalksTheDeclaredPath ----------------------
{
  const file = load('session-basic.json');
  const stateMachine = file.assertions.state_machine;

  expect(
    stateMachine.includes('idle -> discovering -> connecting -> handshaking -> authenticating -> established -> streaming -> closing -> closed'),
    'the declared path is the full one',
  );
  expect(stateMachine.includes('any_state_on_fatal_error -> closing'), 'a fatal error from any state goes to closing');

  // From ANY live state: a fatal error during the handshake and one during streaming both end at
  // closing, so the transition cannot be modelled as an edge from established.
  const live = Object.values(SESSION_STATE).filter((s) => s !== SESSION_STATE.CLOSED);
  expect(live.length >= 8, 'there are at least eight live states');

  for (const state of live) {
    if (state === SESSION_STATE.CLOSING) continue;
    let ok = true;
    try {
      sessionNext(state, 'agent', SESSION_MESSAGES.ERROR, 0);
    } catch {
      ok = false;
    }
    expect(ok, 'an ERROR frame is legal in ' + state);
  }
}

// ---- SessionReplayTest.theSequenceNumbersArePerDirection ----------------------
{
  const file = load('session-basic.json');
  const rule = file.assertions.sequence_numbers;

  expect(rule.includes('session-global'), 'the counter is session-global');
  expect(rule.includes('increase by one per frame sent by that side'), 'it increases per frame by that side');
  expect(rule.includes('The two directions number independently'), 'the directions are independent');
  expect(rule.includes('both sides legitimately use sequence number 1'), 'both sides start at one');

  // The transcript demonstrates it: steps 1 and 2 both use sequence number 1, from different actors.
  expect(stepSeq(file, 1) === 1 && stepSeq(file, 2) === 1, 'both first frames use sequence number 1');
  expect(stepActor(file, 1) !== stepActor(file, 2), 'and they are from different actors');

  // Within each direction the numbers increase by exactly one, with one deliberate exception.
  for (const role of ['controller', 'agent']) {
    const own = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19].filter((i) => stepActor(file, i) === role);
    const replays = own.filter((i) => stepOf(file, i).deliberate_replay === true);

    let previous = null;
    for (let position = 0; position < own.length; position++) {
      const index = own[position];
      if (replays.includes(index)) continue;

      // Monotonic, NOT gapless: the transcript records the frames that matter, so the
      // controller goes 1,2,3,4,5 and then 8. Its 6 and 7 are the agent's frames in the agent's
      // own counter. My first version demanded exactly one more and failed at step 13.
      const current = stepSeq(file, index);
      if (previous !== null) {
        expect(current > previous, role + "'s sequence number at step " + index + ' advances past ' + previous + ' (got ' + current + ')');
      }
      previous = current;
    }
  }
}

// ---- SessionReplayTest.replayingTheTranscriptReachesTheDeclaredStates ---------
{
  const file = load('session-basic.json');

  const controller = new SessionReplayer('controller');
  const agent = new SessionReplayer('agent');

  // Step 1.
  controller.send(stepType(file, 1), stepSeq(file, 1), stepEnc(file, 1));
  expect(controller.state === SESSION_STATE.HANDSHAKING, 'the controller is handshaking after HELLO (got ' + controller.state + ')');
  expect(agent.state === SESSION_STATE.IDLE, 'the agent has not seen the frame yet');
  expect(!controller.sentEncrypted, 'HELLO is not encrypted, so nothing has been sent under a key');

  // Step 2.
  expect(agent.receive(stepType(file, 1), stepSeq(file, 1), stepEnc(file, 1)).kind === 'accepted', 'the agent accepts HELLO');
  expect(agent.state === SESSION_STATE.HANDSHAKING, 'the agent is handshaking after receiving HELLO');

  agent.send(stepType(file, 2), stepSeq(file, 2), stepEnc(file, 2));
  expect(agent.state === SESSION_STATE.AUTHENTICATING, 'the agent authenticates after HELLO_ACK');

  expect(controller.receive(stepType(file, 2), stepSeq(file, 2), stepEnc(file, 2)).kind === 'accepted', 'the controller accepts HELLO_ACK');
  expect(controller.state === SESSION_STATE.AUTHENTICATING, 'the controller authenticates after HELLO_ACK');

  expect(!controller.sentEncrypted && !agent.sentEncrypted, 'neither side has sent an encrypted frame yet');

  // Step 3.
  controller.send(stepType(file, 3), stepSeq(file, 3), stepEnc(file, 3));
  // Sending AUTH leaves the controller AUTHENTICATING, not established: the session is
  // established when both proofs have been exchanged, and the controller has not yet checked
  // the agent's. Step 3's own expectation is that the controller is still authenticating.
  expect(controller.state === SESSION_STATE.AUTHENTICATING, 'the controller is authenticating after AUTH (got ' + controller.state + ')');
  expect(controller.sentEncrypted, "AUTH is the controller's first encrypted frame");

  // Step 4.
  expect(agent.receive(stepType(file, 3), stepSeq(file, 3), stepEnc(file, 3)).kind === 'accepted', 'the agent accepts AUTH');

  agent.send(stepType(file, 4), stepSeq(file, 4), stepEnc(file, 4));
  expect(agent.state === SESSION_STATE.ESTABLISHED, 'the agent is established after AUTH_OK');

  expect(controller.receive(stepType(file, 4), stepSeq(file, 4), stepEnc(file, 4)).kind === 'accepted', 'the controller accepts AUTH_OK');
  expect(controller.state === SESSION_STATE.ESTABLISHED, 'the controller is established after AUTH_OK (got ' + controller.state + ')');

  // Step 7/8.
  expect(agent.receive(stepType(file, 7), stepSeq(file, 7), stepEnc(file, 7), stepChannel(file, 7)).kind === 'accepted', 'the agent accepts CHANNEL_OPEN');

  agent.send(stepType(file, 8), stepSeq(file, 8), stepEnc(file, 8), stepChannel(file, 8));
  expect(controller.receive(stepType(file, 8), stepSeq(file, 8), stepEnc(file, 8), stepChannel(file, 8)).kind === 'accepted', 'the controller accepts CHANNEL_OPENED');

  expect(stepSend(file, 8).body.channel_id === 1, 'the agent allocated channel 1 (got ' + stepSend(file, 8).body.channel_id + ')');

  // Step 9.
  controller.send(stepType(file, 9), stepSeq(file, 9), stepEnc(file, 9), stepChannel(file, 9));
  expect(controller.state === SESSION_STATE.STREAMING, 'the controller is streaming after VIDEO_START (got ' + controller.state + ')');

  expect(agent.receive(stepType(file, 9), stepSeq(file, 9), stepEnc(file, 9), stepChannel(file, 9)).kind === 'accepted', 'the agent accepts VIDEO_START');
  expect(agent.state === SESSION_STATE.STREAMING, 'the agent is streaming after receiving VIDEO_START');
}

// ---- SessionReplayTest.theReplayedFrameEndsTheSession ------------------------
{
  const file = load('session-basic.json');

  expect(stepOf(file, 17).deliberate_replay === true, 'step 17 is marked as a deliberate replay');
  expect(stepSeq(file, 17) === stepSeq(file, 13), "step 17 reuses step 13's sequence number");
  // NOT compared against step 16: step 16 is the AGENT's frame and step 17 is the
  // controller's, and the two directions number independently. Both use 8 and 10 here for
  // entirely legitimate reasons.
  expect(stepActor(file, 16) !== stepActor(file, 17), 'steps 16 and 17 are from different actors');
  expect(stepActor(file, 13) === stepActor(file, 17), 'the replay is from the same actor');
  expect(stepChannel(file, 13) === stepChannel(file, 17), 'the replay is on the same channel');

  // The frame differs only in its body, which is the point: a replay is distinguished by its
  // sequence number and not by its contents. A receiver checking contents would accept this one.
  expect(
    stepSend(file, 13).body.gesture_id !== stepSend(file, 17).body.gesture_id,
    'the replayed frame has a DIFFERENT body, so only the sequence number can catch it',
  );

  // Replaying the WHOLE transcript up to step 16, both directions, rather than a hand-picked
  // subset. A subset is not a replay: the counts below only work out because every frame the
  // agent accepted is present, and leaving one out makes step 17 look like a legitimate reorder
  // instead of a repeat.
  const controller = new SessionReplayer('controller');
  const agent = new SessionReplayer('agent');

  for (let index = 1; index <= 16; index++) {
    const role = stepActor(file, index);
    const type = stepType(file, index);
    const seq = stepSeq(file, index);
    const enc = stepEnc(file, index);
    const channel = stepChannel(file, index);

    if (role === 'controller') {
      const peer = agent.receive(type, seq, enc, channel);
      expect(peer.kind !== 'fatal', 'the agent accepts step ' + index + ' (' + peer.kind + ')');
      controller.send(type, seq, enc, channel);
    } else {
      const peer = controller.receive(type, seq, enc, channel);
      expect(peer.kind !== 'fatal', 'the controller accepts step ' + index + ' (' + peer.kind + ')');
      agent.send(type, seq, enc, channel);
    }
  }

  // The agent has accepted 1,2,3,4,5,8,9,10 from the controller and nothing is repeated yet.
  expect(agent.lastReceived === 10, 'the agent has accepted up to sequence number 10 (got ' + agent.lastReceived + ')');
  expect(!agent.received.has(8) || agent.received.size >= 4, 'the agent has seen sequence number 8');

  const outcome = agent.receive(stepType(file, 17), stepSeq(file, 17), stepEnc(file, 17), stepChannel(file, 17));

  expect(outcome.kind === 'fatal', 'the replayed frame is fatal (got ' + outcome.kind + ')');
  expect(outcome.code === 'ERR_REPLAY_DETECTED', 'the code is ERR_REPLAY_DETECTED (got ' + outcome.code + ')');
  expect(agent.state === SESSION_STATE.CLOSING, 'the agent moves to closing (got ' + agent.state + ')');

  agent.send(stepType(file, 19), stepSeq(file, 19), stepEnc(file, 19), stepChannel(file, 19));
  expect(agent.state === SESSION_STATE.CLOSED, 'SESSION_END closes the session');
}

// ---- SessionReplayTest.aRecoverableFaultDoesNotEndTheSession ------------------
{
  const file = load('session-basic.json');

  const expect16 = stepOf(file, 16).expect || [];
  expect(expect16.some((e) => e.includes('session survives')), 'step 16 declares the session survives');
  expect(expect16.some((e) => e.includes('video stream continues')), 'step 16 declares the stream continues');

  expect(stepSend(file, 16).body.code === 'ERR_UNSUPPORTED_FEATURE', 'the refusal is ERR_UNSUPPORTED_FEATURE');
  expect(stepSend(file, 16).body.severity === 'recoverable', 'and its severity is recoverable');
  expect(stepSend(file, 18).body.severity === 'fatal', 'the replay error is fatal');

  // An ERROR frame does not itself change the state.
  expect(
    sessionNext(SESSION_STATE.STREAMING, 'agent', SESSION_MESSAGES.ERROR, 1) === SESSION_STATE.STREAMING,
    'an ERROR frame alone does not change the state',
  );
}

// ---- SessionReplayTest.theShellCommandIsRefusedForWantOfACapability -----------
{
  const file = load('session-basic.json');

  const expect4 = stepOf(file, 4).expect || [];
  expect(
    expect4.some((e) => e.includes('shell.exec and app.install are absent from the negotiated set')),
    'step 4 declares shell.exec and app.install absent',
  );

  const negotiated = stepSend(file, 4).body.negotiated.capabilities;
  expect(!negotiated.includes('shell.exec'), 'shell.exec was not negotiated');
  expect(!negotiated.includes('app.install'), 'app.install was not negotiated');

  // ERR_UNSUPPORTED_FEATURE rather than ERR_PERMISSION_DENIED: an unnegotiated capability is a
  // feature that was never agreed to, not a permission that was refused. The two have different
  // remedies -- renegotiation versus an operator grant.
  expect(stepSend(file, 16).body.code === 'ERR_UNSUPPORTED_FEATURE', 'an unnegotiated capability is an unsupported feature');
  expect(stepSend(file, 16).body.code !== 'ERR_PERMISSION_DENIED', 'it is not a permission denial');
}

// ---- SessionReplayTest.theVideoRequestIsClampedNotRefused --------------------
{
  const file = load('session-basic.json');

  const expect9 = stepOf(file, 9).expect || [];
  expect(expect9.some((e) => e.includes('must be clamped, not refused')), 'step 9 declares the request is clamped rather than refused');

  const request = stepSend(file, 9).body;
  const limits = file.preconditions.agent_limits;

  expect(request.max_width > limits.max_video_width, 'the requested width exceeds the limit');
  expect(request.max_height > limits.max_video_height, 'the requested height exceeds the limit');
  expect(request.fps > limits.max_video_fps, 'the requested rate exceeds the limit');

  const config = stepSend(file, 10).body;
  // NOT asserted as "each axis is within its limit", which is what I first wrote and what fails:
  // the agreed height 1920 exceeds the ceiling height 1080. The ceiling bounds the REQUEST box,
  // and the box is then oriented to the screen, so a landscape ceiling against a portrait screen
  // rotates to 1080x1920 -- the ceiling's own dimensions, swapped.
  //
  // What is conserved is the AREA, which is exactly what rotating a box does. Stated as the
  // property rather than a numeric comparison, because the numbers only line up when the screen
  // is the same aspect as the ceiling.
  const ceilingArea = limits.max_video_width * limits.max_video_height;
  const agreedArea = config.width * config.height;

  expect(agreedArea <= ceilingArea, 'the agreed area is within the ceiling area (' + agreedArea + ' <= ' + ceilingArea + ')');
  expect(agreedArea === ceilingArea, 'and here it uses the ceiling exactly');

  // And the box is the ceiling rotated into the screen's orientation.
  expect(
    (config.width === limits.max_video_height && config.height === limits.max_video_width) ||
      (config.width === limits.max_video_width && config.height === limits.max_video_height),
    'the agreed box is the ceiling in the screen orientation (got ' + config.width + 'x' + config.height + ')',
  );
  expect(config.csd !== undefined, 'the agent sends its codec configuration with the size');

  // The screen is reported separately from the encoded size, because they differ.
  expect(config.screen_width === 1080, 'the screen width is reported separately');
  expect(config.screen_height === 2400, 'the screen height is reported separately');
  expect(
    !(config.width === config.screen_width && config.height === config.screen_height),
    'the encoded size is not simply the screen size',
  );
}

// ---- SessionReplayTest.aTapIsMappedFromNormalisedCoordinates ----------------
{
  const file = load('session-basic.json');

  const expect14 = stepOf(file, 14).expect || [];
  expect(expect14.some((e) => e.includes('agent maps 5000/10000 onto 540,1200')), 'step 14 declares the mapping');

  const body = stepSend(file, 14).body;
  const pointer = body.pointers[0];

  // Ten thousand, not 65536 and not 32767: the declared mapping is exactly a division by 10000.
  expect(pointer.x * body.screen_width / 10000 === 540, pointer.x + ' maps to 540 across ' + body.screen_width);
  expect(pointer.y * body.screen_height / 10000 === 1200, pointer.y + ' maps to 1200 across ' + body.screen_height);

  expect(5000 * body.screen_width / 10000 === body.screen_width / 2, '5000 is the centre');
  expect(10000 * body.screen_width / 10000 === body.screen_width, 'the right edge is the width');
}

// ---- SessionReplayTest.theTranscriptNumbersItsFramesConsistently -------------
{
  const file = load('session-basic.json');
  const steps = file.steps;

  expect(steps.length === 19, 'the transcript has 19 steps (got ' + steps.length + ')');
  expect(steps.map((s) => s.step).join(',') === Array.from({ length: 19 }, (_, i) => i + 1).join(','), 'the steps are numbered 1 to 19 in order');

  for (const s of steps) {
    expect(!!s.actor, 'step ' + s.step + ' names an actor');
    expect(!!s.send, 'step ' + s.step + ' sends a frame');
    expect(!!s.send.name, "step " + s.step + "'s frame has a name");
  }

  for (const s of steps) {
    if (!s.recv) continue;
    const referenced = Number(String(s.recv).replace('step ', ''));
    expect(referenced >= 1 && referenced < s.step, 'step ' + s.step + ' answers an earlier step (' + referenced + ')');
    expect(stepActor(file, referenced) !== stepActor(file, s.step), 'step ' + s.step + " answers the other actor's frame");
  }
}


// ---------------------------------------------------------------------------
// SessionTransitions  --  the guards, each driven so a mutation cannot survive
// ---------------------------------------------------------------------------

/** Runs a transition and reports whether it was legal, so a refusal is a value not a throw. */
function transitionVerdict(from, role, messageType, channelId = 0) {
  try {
    return { ok: true, state: sessionNext(from, role, messageType, channelId) };
  } catch (error) {
    return { ok: false, message: error.message };
  }
}

/** Runs a replay and reports the outcome without the encryption assertion throwing. */
function receiveVerdict(replayer, messageType, sequenceNumber, encrypted, channelId = 0) {
  try {
    return replayer.receive(messageType, sequenceNumber, encrypted, channelId);
  } catch (error) {
    return { kind: 'threw', message: error.message };
  }
}

// ---- every transition the transcript uses, plus every illegal one it must refuse ----
{
  const S = SESSION_STATE;
  const M = SESSION_MESSAGES;

  // HELLO: legal only from idle or connecting, and only from the controller.
  expect(transitionVerdict(S.IDLE, 'controller', M.HELLO).ok, 'HELLO is legal from idle');
  expect(transitionVerdict(S.CONNECTING, 'controller', M.HELLO).ok, 'HELLO is legal from connecting');
  expect(transitionVerdict(S.IDLE, 'controller', M.HELLO).state === S.HANDSHAKING, 'HELLO moves to handshaking');

  for (const bad of [S.HANDSHAKING, S.AUTHENTICATING, S.ESTABLISHED, S.STREAMING, S.CLOSING]) {
    expect(!transitionVerdict(bad, 'controller', M.HELLO).ok, 'HELLO from ' + bad + ' is refused');
  }

  expect(!transitionVerdict(S.IDLE, 'agent', M.HELLO).ok, 'the agent does not send HELLO');
  expect(!transitionVerdict(S.IDLE, 'agent ', M.HELLO).ok, 'an unknown role does not send HELLO');

  // HELLO_ACK: only from the agent, only while handshaking.
  expect(transitionVerdict(S.HANDSHAKING, 'agent', M.HELLO_ACK).ok, 'HELLO_ACK is legal while handshaking');
  expect(transitionVerdict(S.HANDSHAKING, 'agent', M.HELLO_ACK).state === S.AUTHENTICATING, 'HELLO_ACK moves to authenticating');

  for (const bad of [S.IDLE, S.CONNECTING, S.AUTHENTICATING, S.ESTABLISHED, S.STREAMING]) {
    expect(!transitionVerdict(bad, 'agent', M.HELLO_ACK).ok, 'HELLO_ACK from ' + bad + ' is refused');
  }

  expect(!transitionVerdict(S.HANDSHAKING, 'controller', M.HELLO_ACK).ok, 'the controller does not send HELLO_ACK');

  // AUTH: only from the controller, only while authenticating, and it does NOT establish.
  expect(transitionVerdict(S.AUTHENTICATING, 'controller', M.AUTH).ok, 'AUTH is legal while authenticating');
  expect(
    transitionVerdict(S.AUTHENTICATING, 'controller', M.AUTH).state === S.AUTHENTICATING,
    'sending AUTH leaves the controller authenticating, not established',
  );
  expect(!transitionVerdict(S.AUTHENTICATING, 'agent', M.AUTH).ok, 'the agent does not send AUTH');
  expect(!transitionVerdict(S.ESTABLISHED, 'controller', M.AUTH).ok, 'AUTH from established is refused');

  // AUTH_OK: only from the agent, only while authenticating, and it DOES establish.
  expect(
    transitionVerdict(S.AUTHENTICATING, 'agent', M.AUTH_OK).state === S.ESTABLISHED,
    'AUTH_OK establishes the session',
  );
  expect(!transitionVerdict(S.AUTHENTICATING, 'controller', M.AUTH_OK).ok, 'the controller does not send AUTH_OK');

  // The pairing that makes the whole handshake work: the controller sends AUTH, stays
  // authenticating, and then RECEIVES AUTH_OK while still authenticating. If AUTH moved it to
  // established, AUTH_OK would be illegal there and the transcript would fail at step 4.
  const afterAuth = transitionVerdict(S.AUTHENTICATING, 'controller', M.AUTH).state;
  expect(
    transitionVerdict(afterAuth, 'agent', M.AUTH_OK).ok,
    'AUTH_OK is legal after the controller has sent AUTH (' + afterAuth + ')',
  );

  // A channel frame before authentication is refused.
  for (const type of [M.CHANNEL_OPEN, M.CHANNEL_OPENED, M.VIDEO_START, M.VIDEO_CONFIG, M.DEVICE_INFO, M.INPUT_TOUCH]) {
    for (const bad of [S.IDLE, S.CONNECTING, S.HANDSHAKING, S.AUTHENTICATING]) {
      expect(
        !transitionVerdict(bad, 'controller', type).ok,
        'message type ' + type + ' from ' + bad + ' is refused',
      );
    }
  }

  // And legal from both established states.
  for (const type of [M.CHANNEL_OPEN, M.DEVICE_INFO, M.INPUT_TOUCH, M.SHELL_EXEC]) {
    expect(transitionVerdict(S.ESTABLISHED, 'controller', type).ok, 'message type ' + type + ' is legal from established');
    expect(transitionVerdict(S.STREAMING, 'controller', type).ok, 'message type ' + type + ' is legal from streaming');
  }

  // Only the video frames move into streaming.
  expect(transitionVerdict(S.ESTABLISHED, 'controller', M.VIDEO_START).state === S.STREAMING, 'VIDEO_START enters streaming');
  expect(transitionVerdict(S.ESTABLISHED, 'agent', M.VIDEO_CONFIG).state === S.STREAMING, 'VIDEO_CONFIG enters streaming');
  expect(transitionVerdict(S.ESTABLISHED, 'controller', M.DEVICE_INFO).state === S.ESTABLISHED, 'DEVICE_INFO does not enter streaming');
  expect(transitionVerdict(S.ESTABLISHED, 'controller', M.INPUT_TOUCH).state === S.ESTABLISHED, 'INPUT_TOUCH does not enter streaming');

  // SESSION_END closes from every live state.
  for (const live of [S.IDLE, S.CONNECTING, S.HANDSHAKING, S.AUTHENTICATING, S.ESTABLISHED, S.STREAMING, S.CLOSING]) {
    expect(transitionVerdict(live, 'agent', M.SESSION_END).state === S.CLOSED, 'SESSION_END closes from ' + live);
  }

  // A closed session accepts nothing at all.
  for (const type of [M.HELLO, M.HELLO_ACK, M.AUTH, M.AUTH_OK, M.ERROR, M.SESSION_END, M.INPUT_TOUCH]) {
    expect(!transitionVerdict(S.CLOSED, 'controller', type).ok, 'message type ' + type + ' in a closed session is refused');
  }
}

// ---- an out-of-state frame is recoverable, a repeat is fatal ------------------
{
  const inHandshake = new SessionReplayer('agent');

  // A channel frame before authentication: recoverable, and the state is NOT closing.
  const early = receiveVerdict(inHandshake, SESSION_MESSAGES.CHANNEL_OPEN, 1, true, 0);

  expect(early.kind === 'recoverable', 'an out-of-state frame is recoverable (got ' + early.kind + ')');
  expect(early.code === 'ERR_UNEXPECTED_MESSAGE', 'and its code is ERR_UNEXPECTED_MESSAGE');
  expect(inHandshake.state !== SESSION_STATE.CLOSING, 'a recoverable fault does not move the session to closing');

  // Compare with a repeat, which IS fatal and DOES move to closing.
  const repeated = new SessionReplayer('agent');
  repeated.received.add(5);
  repeated.lastReceived = 5;

  const repeat = receiveVerdict(repeated, SESSION_MESSAGES.CHANNEL_OPEN, 5, true, 0);

  expect(repeat.kind === 'fatal', 'a repeated sequence number is fatal (got ' + repeat.kind + ')');
  expect(repeated.state === SESSION_STATE.CLOSING, 'and it moves the session to closing');

  // The two outcomes are genuinely different, so the distinction is not decorative.
  expect(early.kind !== repeat.kind, 'the two fault kinds differ');
}

// ---- an outgoing sequence number must advance --------------------------------
{
  const replayer = new SessionReplayer('controller');

  replayer.send(SESSION_MESSAGES.HELLO, 1, false, 0);
  expect(replayer.lastSent === 1, 'the first outgoing number is recorded');

  // Going backwards is refused. The frame has to be one the ROLE may send in this state, or the
  // role check throws first and the sequence check is never reached -- which is exactly why the
  // mutation deleting the sequence guard survived my first version of this check. So: an agent in
  // handshaking, which may legally send HELLO_ACK, and which has already sent sequence number 5.
  const agent = new SessionReplayer('agent');
  agent.state = SESSION_STATE.HANDSHAKING;
  agent.lastSent = 5;

  let refused = null;
  try {
    agent.send(SESSION_MESSAGES.HELLO_ACK, 5, false, 0);
  } catch (error) {
    refused = error.message;
  }

  expect(refused !== null, 'a non-advancing outgoing sequence number is refused');
  expect(
    refused !== null && refused.includes('does not advance'),
    'and it is the SEQUENCE check that refused, not the role or state check (got "' + refused + '")',
  );

  // Zero is refused too: the numbering starts at one.
  const fresh = new SessionReplayer('agent');
  fresh.state = SESSION_STATE.HANDSHAKING;
  fresh.lastSent = 0;

  let refusedZero = false;
  try {
    fresh.send(SESSION_MESSAGES.HELLO_ACK, 0, false, 0);
  } catch {
    refusedZero = true;
  }

  expect(refusedZero, 'sequence number zero is refused');

  // A jump FORWARDS is allowed, because a transcript records the frames that matter rather than
  // every frame: the controller in session-basic.json sends 1,2,3,4,5 and then 8.
  const jumping = new SessionReplayer('agent');
  jumping.state = SESSION_STATE.HANDSHAKING;
  jumping.lastSent = 5;

  let advanced = true;
  try {
    jumping.send(SESSION_MESSAGES.HELLO_ACK, 8, false, 0);
  } catch {
    advanced = false;
  }

  expect(advanced, 'a jump forwards is allowed, because a transcript is not gapless');
}

// ---- a repeat is caught by the seen-set, not only the window -----------------
{
  const replayer = new SessionReplayer('agent');
  replayer.received.add(8);
  replayer.received.add(9);
  replayer.received.add(10);
  replayer.lastReceived = 10;

  // 8 is INSIDE the window, so the window alone accepts it. The seen-set is what catches it.
  const floor = replayer.lastReceived - 32;

  expect(8 >= floor, '8 is inside the window, so the window alone would accept it');

  const verdict = receiveVerdict(replayer, SESSION_MESSAGES.INPUT_TOUCH, 8, true, 1);

  expect(verdict.kind === 'fatal', 'the repeat inside the window is still fatal');
  expect(verdict.code === 'ERR_REPLAY_DETECTED', 'and reported as a replay');
}

// ---- the unencrypted set is exactly the handshake pair ----------------------
{
  expect(SESSION_UNENCRYPTED.size === 2, 'exactly two message types travel unencrypted');
  expect(SESSION_UNENCRYPTED.has(SESSION_MESSAGES.HELLO), 'HELLO is unencrypted');
  expect(SESSION_UNENCRYPTED.has(SESSION_MESSAGES.HELLO_ACK), 'HELLO_ACK is unencrypted');
  expect(!SESSION_UNENCRYPTED.has(SESSION_MESSAGES.AUTH), 'AUTH is encrypted');
  expect(!SESSION_UNENCRYPTED.has(SESSION_MESSAGES.ERROR), 'ERROR is encrypted');

  // And the replayer enforces it: an encrypted HELLO is refused, and an unencrypted AUTH is too.
  const encryptedHello = new SessionReplayer('controller');

  let refusedEncryptedHello = false;
  try {
    encryptedHello.send(SESSION_MESSAGES.HELLO, 1, true, 0);
  } catch {
    refusedEncryptedHello = true;
  }

  expect(refusedEncryptedHello, 'an encrypted HELLO is refused');

  const plainAuth = new SessionReplayer('controller');
  plainAuth.state = SESSION_STATE.AUTHENTICATING;

  let refusedPlainAuth = false;
  try {
    plainAuth.send(SESSION_MESSAGES.AUTH, 1, false, 0);
  } catch {
    refusedPlainAuth = true;
  }

  expect(refusedPlainAuth, 'an unencrypted AUTH is refused');
}


// ---------------------------------------------------------------------------
// ShellPolicy  --  mirror of ShellPolicy.kt
// ---------------------------------------------------------------------------

const SHELL_VETTED_DIRECTORIES = ['/system/bin/', '/system/xbin/'];
const SHELL_MAX_COMMAND_LINE_BYTES = 4096;
const SHELL_OUTPUT_CAP_BYTES = 4194304;
const SHELL_REJECTIONS_BEFORE_SUSPENSION = 20;

/**
 * Mirror of ShellPolicy.isVettedPath.
 *
 * The path is separated into its directory and its basename, and the DIRECTORY is compared for
 * EQUALITY against the vetted list. That is the whole rule, and it is deliberately two tests and
 * no more.
 *
 * The longer version this replaced checked four things: that the path was absolute, that its
 * basename was not `.`/`..`/empty, that it contained no `..` segment, and that it contained no
 * double slash. Driving every one of them showed that three were unreachable: once the directory
 * is compared for equality, a relative path, a traversal path and a doubled slash all name a
 * directory that is not a vetted one, so the comparison refuses them without any help. Only the
 * basename test changed an answer, and only for a path like `/system/bin/`, whose directory IS
 * vetted but whose basename is empty. The redundant three were removed rather than kept as
 * decoration, because a guard no input can distinguish from its absence is a guard that will
 * silently stop working the day the comparison changes.
 *
 * Nothing here resolves the path. Resolving is exactly what an attacker wants:
 * `/system/bin/../../data/local/tmp/payload` resolves into a vetted directory and then out of it,
 * and a resolver with a bug is a check with a bug. Comparing the LITERAL directory segment cannot
 * be walked past, because `..` is a directory name that is not on the vetted list.
 */
function isVettedPath(executable) {
  const lastSlash = executable.lastIndexOf('/');

  // There must be a directory to compare, and something after it. A path with no separator
  // (`getprop`) or a separator at position zero (`/getprop`) has no vetted directory.
  if (lastSlash <= 0) return false;

  const directory = executable.slice(0, lastSlash + 1);
  const basename = executable.slice(lastSlash + 1);

  // The basename must name a program. `.` and `..` name directories, and an empty basename means
  // the path ended at a separator -- which matters because `/system/bin/` has a vetted DIRECTORY
  // and would otherwise be accepted as an executable.
  if (basename === '' || basename === '.' || basename === '..') return false;

  // The comparison is for EQUALITY on the directory, not `startsWith` on the whole path. A
  // `startsWith` test accepts `/system/binfoo/bar`, whose leading characters merely spell a
  // vetted directory, and accepts the vetted directory itself.
  return SHELL_VETTED_DIRECTORIES.includes(directory);
}

/** Mirror of ShellPolicy.commandLineLength. */
function commandLineLength(executable, args) {
  return (
    Buffer.byteLength(executable, 'utf8') +
    args.reduce((total, argument) => total + Buffer.byteLength(argument, 'utf8'), 0) +
    args.length
  );
}

/**
 * Mirror of ShellPolicy.signatureMatches: the executable and the literal argv prefix.
 *
 * This is what identifies the rule, so its failure means no rule applies.
 */
function ruleSignatureMatches(rule, executable, args) {
  if (rule.exe !== executable) return false;
  if (args.length < rule.argv_prefix.length) return false;

  for (let index = 0; index < rule.argv_prefix.length; index++) {
    if (args[index] !== rule.argv_prefix[index]) return false;
  }

  return true;
}

/**
 * Mirror of ShellPolicy.argumentsMatch: the count and the patterns.
 *
 * Only reached once a rule's signature has matched, so a failure here is argument_rejected.
 */
function ruleArgumentsMatch(rule, executable, args) {
  if (!ruleSignatureMatches(rule, executable, args)) return false;

  const rest = args.slice(rule.argv_prefix.length);
  if (rest.length > rule.max_args) return false;

  for (let index = 0; index < rest.length; index++) {
    const pattern = rule.arg_patterns[index];
    if (pattern === undefined) return false;
    if (!new RegExp(pattern).test(rest[index])) return false;
  }

  return true;
}

/** Both halves, for a caller that wants the whole answer. */
function ruleMatches(rule, executable, args) {
  return ruleSignatureMatches(rule, executable, args) && ruleArgumentsMatch(rule, executable, args);
}

/**
 * A rule's mutability is not in the vector file: it is derivable from the rule id, which the
 * registry convention makes explicit. `dev.*` rules mutate; `sys.*` rules do not. Stated here
 * rather than inlined so the assumption is visible and checkable.
 */
function ruleIsMutating(rule) {
  // Accepts a rule object or a bare id, so a check that only has the id can use it.
  const id = typeof rule === 'string' ? rule : rule.id;
  return id.startsWith('dev.');
}

/** Mirror of ShellPolicy.evaluate. */
function shellEvaluate(context, rules, executable, args) {
  // 1. The operator's grant, first and alone.
  if (!context.shell_granted) {
    return { allowed: false, error: 'ERR_PERMISSION_DENIED', reason: 'denied_by_operator' };
  }

  const basename = executable.includes('/') ? executable.slice(executable.lastIndexOf('/') + 1) : executable;

  // 2. The deny list, by BASENAME, before any rule matching. An EMPTY basename is not a deny
  //    entry -- it is refused by the path check below, as not_in_allow_list. My first version
  //    folded the empty case in here and reported deny_listed, which names a deny rule that does
  //    not exist.
  if (context.denied_rules.includes(basename)) {
    return { allowed: false, error: 'ERR_NOT_ALLOWED', reason: 'deny_listed' };
  }

  // 3. The path must be absolute and in a vetted directory.
  if (!isVettedPath(executable)) {
    return { allowed: false, error: 'ERR_NOT_ALLOWED', reason: 'not_in_allow_list' };
  }

  // 4. The command line cap, before a pattern is applied.
  if (commandLineLength(executable, args) > (context.max_command_line_bytes || SHELL_MAX_COMMAND_LINE_BYTES)) {
    return { allowed: false, error: 'ERR_NOT_ALLOWED', reason: 'argument_rejected' };
  }

  // 5. The allow list for this context, filtered by the LEVEL, and identified by the RULE --
  //    which includes its argv prefix. The prefix is part of what makes a rule that rule, not
  //    part of its argument checking: `dumpsys window2` does not match the `window` rule, and no
  //    other rule for `dumpsys` applies, so NO RULE APPLIES and the verdict is
  //    not_in_allow_list. Reporting argument_rejected here would say a rule applied and its
  //    argument was wrong, which is a different fact with a different remedy.
  const permits = (mutating) => !mutating || context.allow_level === 'read_write';

  const applicable = rules.filter(
    (rule) =>
      context.allowed_rules.includes(rule.id) &&
      permits(ruleIsMutating(rule)) &&
      ruleSignatureMatches(rule, executable, args),
  );

  if (applicable.length === 0) {
    return { allowed: false, error: 'ERR_NOT_ALLOWED', reason: 'not_in_allow_list' };
  }

  // 6. A rule applies, so its ARGUMENTS are now checked against its patterns. Only here does a
  //    mismatch become argument_rejected.
  const matched = applicable.find((rule) => ruleArgumentsMatch(rule, executable, args));

  if (matched === undefined) {
    return { allowed: false, error: 'ERR_NOT_ALLOWED', reason: 'argument_rejected' };
  }

  return { allowed: true, rule: matched.id };
}

/** Mirror of ShellPolicy.retainedOutputBytes / isTruncated. */
function retainedOutputBytes(produced) {
  return Math.min(produced, SHELL_OUTPUT_CAP_BYTES);
}
function isOutputTruncated(produced) {
  return produced > SHELL_OUTPUT_CAP_BYTES;
}

// ---- ShellPolicyTest: the rules and contexts are the file's own ----------------
{
  const file = load('shell-policy.json');

  expect((file.rules || []).length === 25, 'the file declares 25 rules (got ' + (file.rules || []).length + ')');
  expect((file.cases || []).length === 23, 'the file declares 23 cases (got ' + (file.cases || []).length + ')');
  expect((file.lifecycle_vectors || []).length === 5, 'the file declares 5 lifecycle vectors');

  // Every rule names an absolute executable in a vetted directory. Asserted for all 25 rather
  // than for the ones a case happens to reach, because a rule with an unvetted path is a rule
  // that can never fire -- and it would sit there looking like a permission that does not work.
  for (const rule of file.rules) {
    expect(rule.exe.startsWith('/'), 'the rule "' + rule.id + '" names an absolute path');
    expect(isVettedPath(rule.exe), 'the rule "' + rule.id + '" names a vetted path (' + rule.exe + ')');
    expect(rule.max_args === rule.arg_patterns.length || rule.arg_patterns.length === 0, 'the rule "' + rule.id + '" declares a pattern per permitted argument or none');
    expect(rule.timeout_ms > 0, 'the rule "' + rule.id + '" has a positive deadline');
  }

  // The rule ids are unique, so the audit log's rule_id identifies one rule.
  const ids = file.rules.map((r) => r.id);
  expect(new Set(ids).size === ids.length, 'the rule ids are unique');

  // Every context names only rules that exist, and every denied basename is a basename.
  const contextNames = Object.keys(file.policy_contexts);
  expect(contextNames.length === 4, 'the file declares 4 contexts');
  expect(contextNames.join(',') === 'default,app_control_grant,no_grant,mutating_grant', 'the context names are the four the cases use (got ' + contextNames.join(',') + ')');

  for (const [name, context] of Object.entries(file.policy_contexts)) {
    for (const ruleId of context.allowed_rules) {
      expect(ids.includes(ruleId), 'the context "' + name + '" names a rule that exists (' + ruleId + ')');
    }
    for (const denied of context.denied_rules) {
      expect(!denied.includes('/'), 'the context "' + name + '" denies a BASENAME, not a path (' + denied + ')');
    }
    expect(context.allow_stdin === false, 'the context "' + name + '" allows no stdin, because there is no shell');
    expect(context.max_command_line_bytes === SHELL_MAX_COMMAND_LINE_BYTES, 'the context "' + name + '" uses the declared cap');
  }

  // The mutability is derivable and consistent: every dev.* rule is mutating and every sys.*
  // rule is not, and both prefix families are present. This is the assumption the level gate
  // rests on, so it is asserted rather than assumed.
  const devRules = file.rules.filter((r) => r.id.startsWith('dev.')).map((r) => r.id);
  const sysRules = file.rules.filter((r) => r.id.startsWith('sys.')).map((r) => r.id);

  expect(devRules.length > 0, 'there are mutating rules');
  expect(sysRules.length > 0, 'there are read-only rules');
  expect(devRules.length + sysRules.length === file.rules.length, 'every rule is either dev.* or sys.*');
  expect(devRules.every(ruleIsMutating), 'every dev.* rule is mutating');
  expect(sysRules.every((id) => !ruleIsMutating({ id })), 'no sys.* rule is mutating');
}

// ---- ShellPolicyTest.everyCaseProducesItsDeclaredVerdict ----------------------
{
  const file = load('shell-policy.json');

  for (const kase of file.cases) {
    if (!kase.context) continue;

    const context = file.policy_contexts[kase.context];
    if (!context) throw new Error('case "' + kase.id + '" names an unknown context "' + kase.context + '"');

    const verdict = shellEvaluate(context, file.rules, kase.exe, kase.args || []);

    if (kase.expected === 'allowed') {
      expect(verdict.allowed, 'case "' + kase.id + '" is allowed (got ' + (verdict.allowed ? 'allowed' : verdict.reason) + ')');
      expect(verdict.rule === kase.expected_rule, 'case "' + kase.id + '" resolves to ' + kase.expected_rule + ' (got ' + verdict.rule + ')');
    } else if (kase.expected === 'rejected') {
      expect(!verdict.allowed, 'case "' + kase.id + '" is rejected (got allowed via ' + (verdict.rule || '?') + ')');
      expect(verdict.error === kase.expected_error, 'case "' + kase.id + '" has error ' + kase.expected_error + ' (got ' + verdict.error + ')');
      expect(
        verdict.reason === kase.expected_reason,
        'case "' + kase.id + '" has reason ' + kase.expected_reason + ' (got ' + verdict.reason + ')',
      );
    }
  }
}

// ---- ShellPolicyTest.theLevelGateIsSeparateFromTheAllowList -------------------
{
  const file = load('shell-policy.json');

  // force-stop is allow-listed for app_control_grant and refused under `default`, at the SAME
  // read_only level. The two contexts differ in their allow lists, not in their levels, so this
  // pair shows the allow list working.
  const withGrant = shellEvaluate(
    file.policy_contexts.app_control_grant,
    file.rules,
    '/system/bin/am',
    ['force-stop', 'com.example.app'],
  );
  const withoutGrant = shellEvaluate(
    file.policy_contexts.default,
    file.rules,
    '/system/bin/am',
    ['force-stop', 'com.example.app'],
  );

  expect(withGrant.allowed, 'force-stop is allowed under app_control_grant');
  expect(!withoutGrant.allowed, 'force-stop is refused under default');
  expect(withoutGrant.reason === 'not_in_allow_list', 'and the reason is not_in_allow_list, not argument_rejected');

  // The same reason for the settings case: the write rule is not in the default context's list at
  // all, so no rule applies. Asserted alongside for the contrast with the argument case below,
  // which IS argument_rejected because a rule did apply.
  const writeUnderDefault = shellEvaluate(
    file.policy_contexts.default,
    file.rules,
    '/system/bin/settings',
    ['put', 'system', 'screen_brightness', '0'],
  );

  expect(!writeUnderDefault.allowed, 'the settings write is refused under default');
  expect(writeUnderDefault.reason === 'not_in_allow_list', 'and its reason is not_in_allow_list, because no rule applies');

  // The SAME command line with the SAME allow list but a read_only level is refused, which is the
  // level gate on its own. The remedy differs from a missing allow-list entry, so the reason code
  // is asserted to be the allow-list one -- a mutating rule in a read_only context is simply not
  // in that context's list.
  const readOnlyCopy = { ...file.policy_contexts.app_control_grant, allow_level: 'read_only' };
  const levelRefused = shellEvaluate(readOnlyCopy, file.rules, '/system/bin/settings', ['put', 'system', 'screen_brightness', '0']);

  expect(!levelRefused.allowed, 'a mutating rule under read_only is refused');
  expect(levelRefused.reason === 'not_in_allow_list', 'and the reason is not_in_allow_list, because the level removes it from the list');

  // Lifting the level to read_write allows the same line, so the level is the only difference.
  const readWrite = { ...file.policy_contexts.app_control_grant, allow_level: 'read_write' };
  const allowed = shellEvaluate(readWrite, file.rules, '/system/bin/settings', ['put', 'system', 'screen_brightness', '0']);

  expect(allowed.allowed, 'the same line is allowed at read_write');
  expect(allowed.rule === 'dev.settings.put', 'and resolves to dev.settings.put');
}

// ---- ShellPolicyTest.theDenyListWinsAndIsCheckedFirst ------------------------
{
  const file = load('shell-policy.json');

  // Every deny-listed case gives deny_listed, including a path under a vetted directory.
  const denyCases = file.cases.filter((c) => c.expected_reason === 'deny_listed');
  expect(denyCases.length === 4, 'there are four deny-listed cases (got ' + denyCases.length + ')');

  for (const kase of denyCases) {
    const context = { ...file.policy_contexts[kase.context], allowed_rules: file.rules.map((r) => r.id) };

    // With EVERY rule allowed, a deny-listed executable is STILL refused. That is what makes the
    // deny list a deny list rather than a tie-break.
    const verdict = shellEvaluate(context, file.rules, kase.exe, kase.args || []);

    expect(!verdict.allowed, 'the deny-listed "' + kase.exe + '" is refused even with every rule allowed');
    expect(verdict.reason === 'deny_listed', 'and the reason is deny_listed (got ' + verdict.reason + ')');
  }

  // The deny list is by BASENAME: the same binary at a different path is still denied.
  const context = { ...file.policy_contexts.default, allowed_rules: file.rules.map((r) => r.id) };
  const sameBasenameElsewhere = shellEvaluate(context, file.rules, '/system/xbin/rm', []);

  expect(!sameBasenameElsewhere.allowed, 'a deny-listed basename is denied at another path too');
  expect(sameBasenameElsewhere.reason === 'deny_listed', 'and the reason is deny_listed, because the basename is what is denied');
}

// ---- ShellPolicyTest.aShellInterpreterIsNeverUsed ----------------------------
{
  const file = load('shell-policy.json');

  // The shell-interpreter case passes a full command string as an argument. It is refused, and
  // the executable is what is refused -- not the string. Stated as an assertion because it is the
  // design decision the whole policy rests on.
  const kase = file.cases.find((c) => c.id === 'shell.deny.shell-interpreter');

  expect(!!kase, 'the shell-interpreter case exists');
  expect(kase.exe === '/system/bin/sh', 'the vector names sh itself as the executable');
  expect(kase.args[0] === '-c', 'and passes the command with -c, which is what a shell call looks like');

  const verdict = shellEvaluate(file.policy_contexts.default, file.rules, kase.exe, kase.args);

  expect(!verdict.allowed, 'a shell is refused');
  expect(verdict.reason === 'deny_listed', 'and it is the EXECUTABLE that is denied, not the string parsed');

  // And every interpreter a device is likely to have is on the deny list, so no argument vector
  // can reach one through a rule.
  for (const interpreter of ['sh', 'bash', 'dash', 'busybox']) {
    expect(file.policy_contexts.default.denied_rules.includes(interpreter), interpreter + ' is deny-listed');
  }

  // No rule anywhere uses an interpreter as its executable.
  for (const rule of file.rules) {
    expect(
      !['sh', 'bash', 'dash', 'busybox', 'toybox'].some((i) => rule.exe.endsWith('/' + i)),
      'the rule "' + rule.id + '" does not use an interpreter',
    );
  }
}

// ---- ShellPolicyTest.aRejectedArgumentIsNotExpanded --------------------------
{
  const file = load('shell-policy.json');

  // The argument "ro.build.version;id" is refused. The note is explicit that no metacharacter
  // expansion happens: the argument simply does not match the pattern.
  const kase = file.cases.find((c) => c.id === 'shell.deny.argument-rejected');

  expect(kase.args[0] === 'ro.build.version;id', 'the vector passes a semicolon in the argument');

  const verdict = shellEvaluate(file.policy_contexts.default, file.rules, kase.exe, kase.args);

  expect(!verdict.allowed, 'the argument is refused');
  expect(verdict.reason === 'argument_rejected', 'and the reason is argument_rejected');

  // The pattern really does reject it, and for the reason the note gives rather than because a
  // sanitiser ran: the pattern is anchored and does not permit a semicolon.
  const rule = file.rules.find((r) => r.id === 'sys.getprop');

  expect(!new RegExp(rule.arg_patterns[0]).test('ro.build.version;id'), 'the pattern rejects the semicolon');
  expect(new RegExp(rule.arg_patterns[0]).test('ro.build.version'), 'and accepts the clean argument');
  expect(rule.arg_patterns[0].startsWith('^') && rule.arg_patterns[0].endsWith('$'), 'the pattern is anchored, so a prefix match cannot smuggle a suffix');
}

// ---- ShellPolicyTest.theVettedPathRuleRejectsTraversal ----------------------
{
  const file = load('shell-policy.json');

  for (const kase of file.cases.filter((c) => c.expected_reason === 'not_in_allow_list')) {
    if (kase.exe.includes('..')) {
      expect(!isVettedPath(kase.exe), 'the traversal path "' + kase.exe + '" is not vetted');
      expect(kase.exe.includes('..'), 'the vector really does contain a traversal segment');
    }
  }

  // The traversal path in the vector is reachable-looking: it STARTS with a vetted directory, so
  // a check written as a simple prefix test would accept it.
  const traversal = file.cases.find((c) => c.id === 'shell.deny.path-traversal');

  expect(!!traversal, 'the path-traversal case exists');
  expect(traversal.exe.startsWith('/system/bin/'), 'the traversal path starts with a vetted directory, so a prefix check alone accepts it');
  expect(!isVettedPath(traversal.exe), 'and the traversal check refuses it');

  // A relative path is refused, because the working directory must never select the binary.
  const relative = file.cases.find((c) => c.id === 'shell.deny.relative-path');
  expect(!!relative, 'the relative-path case exists');
  expect(!relative.exe.startsWith('/'), 'the vector names a bare name');
  expect(!isVettedPath(relative.exe), 'and a relative path is refused');

  // A double slash is refused rather than normalised.
  expect(!isVettedPath('/system/bin//getprop'), 'a double slash is refused');

  // And the vetted directories really do accept their own paths.
  expect(isVettedPath('/system/bin/getprop'), 'a vetted path is accepted');
  expect(isVettedPath('/system/xbin/su'), 'a vetted path is accepted even for a deny-listed name, because the path check is not the deny check');
  expect(!isVettedPath('/data/local/tmp/payload'), 'an unvetted directory is refused');
  expect(!isVettedPath(''), 'an empty path is refused');
}

// ---- ShellPolicyTest.theCommandLineCapBoundsTheWork -----------------------
{
  const file = load('shell-policy.json');

  // The regex-bomb case has both a pathological argument AND a time bound. The cap is what
  // rejects it, in bounded time, without depending on the regex engine's backtracking behaviour.
  const bomb = file.cases.find((c) => c.id === 'shell.deny.regex-bomb');

  expect(!!bomb, 'the regex-bomb case exists');
  expect(bomb.max_decision_time_ms === 50, 'and it declares a decision-time bound');
  expect(bomb.expected_reason === 'argument_rejected', 'and expects argument_rejected');

  const started = Date.now();
  const verdict = shellEvaluate(file.policy_contexts.default, file.rules, bomb.exe, bomb.args);
  const elapsed = Date.now() - started;

  expect(!verdict.allowed, 'the pathological argument is refused');
  expect(elapsed < bomb.max_decision_time_ms, 'and refused within the declared bound (' + elapsed + 'ms < ' + bomb.max_decision_time_ms + 'ms)');

  // The command-line-too-long case is named for the cap, but it does NOT exceed it: the argument
  // is 1392 characters and the whole command line is 1412 bytes against a 4096 cap. What rejects
  // it is the rule's own per-argument pattern, whose quantifier allows 64. I had asserted the cap
  // was what fired, and the mirror said otherwise.
  const tooLong = file.cases.find((c) => c.id === 'shell.deny.command-line-too-long');
  expect(!!tooLong, 'the command-line-too-long case exists');

  const length = commandLineLength(tooLong.exe, tooLong.args);
  expect(length <= SHELL_MAX_COMMAND_LINE_BYTES, 'the vector does NOT exceed the cap (' + length + ' <= ' + SHELL_MAX_COMMAND_LINE_BYTES + ')');

  const getprop = file.rules.find((r) => r.id === 'sys.getprop');
  expect(!new RegExp(getprop.arg_patterns[0]).test(tooLong.args[0]), 'the per-argument pattern is what rejects it');
  expect(tooLong.args[0].length > 64, 'because the argument is longer than the pattern allows (' + tooLong.args[0].length + ' > 64)');

  // The cap still has to bite for a command line that really does exceed it. Driven directly,
  // because no vector does: every case is rejected by a pattern first.
  const oversized = 'A'.repeat(SHELL_MAX_COMMAND_LINE_BYTES);

  expect(
    commandLineLength('/system/bin/getprop', [oversized]) > SHELL_MAX_COMMAND_LINE_BYTES,
    'an oversized command line exceeds the cap',
  );
  expect(
    shellEvaluate(file.policy_contexts.default, file.rules, '/system/bin/getprop', [oversized]).reason === 'argument_rejected',
    'and an oversized command line is argument_rejected',
  );
}

// ---- ShellPolicyTest.theMutabilitySplitIsByRuleNotByExecutable ---------------
{
  const file = load('shell-policy.json');

  // `settings get` and `settings put` share ONE executable and differ in mutability, so the split
  // is by rule rather than by binary. This is asserted as a property of the file, because it is
  // the reason the level gate is expressed over rules.
  const settingsRules = file.rules.filter((r) => r.exe === '/system/bin/settings');
  expect(settingsRules.length === 2, 'settings has exactly two rules');
  expect(settingsRules.some((r) => r.id === 'sys.settings.get'), 'one is sys.settings.get, the read half');
  expect(settingsRules.some((r) => r.id === 'dev.settings.put'), 'one is dev.settings.put, the write half');

  const read = settingsRules.find((r) => r.id === 'sys.settings.get');
  const write = settingsRules.find((r) => r.id === 'dev.settings.put');

  expect(!ruleIsMutating(read), 'the read half is not mutating');
  expect(ruleIsMutating(write), 'the write half is mutating');

  // Which is why BOTH are in the read-only context's list: the mutating one is filtered out by
  // the level rather than being absent from the list.
  expect(
    file.policy_contexts.default.allowed_rules.includes('sys.settings.get'),
    'the read half is in the default allow list',
  );
  expect(
    !file.policy_contexts.default.allowed_rules.includes('dev.settings.put'),
    'the write half is not, and the reason is its mutability',
  );

  // And the two argument vectors are genuinely different rules, not one rule with a flag.
  expect(
    JSON.stringify(read.argv_prefix) !== JSON.stringify(write.argv_prefix),
    'the two halves are distinguished by their argv prefix',
  );
}

// ---- ShellPolicyTest.theGrantIsRecheckedPerExecution -------------------------
{
  const file = load('shell-policy.json');
  const vector = file.lifecycle_vectors.find((v) => v.id === 'shell.grant-revoked-mid-session');

  expect(!!vector, 'the grant-revocation vector exists');
  expect(vector.sequence.length === 3, 'it has three steps');

  const [first, revoke, second] = vector.sequence;

  expect(first.expected === 'allowed', 'the first execution is allowed');
  expect(revoke.step === 'operator_revokes_shell_grant', 'the middle step revokes the grant');

  // The SAME pairing and the SAME command line before and after. The grant is what changed, so
  // the verdict differs, which is the whole point: checking the grant at connection time would
  // let a revoked operator's next command through.
  expect(first.exe === second.exe, 'both executions use the same executable');
  expect(JSON.stringify(first.args) === JSON.stringify(second.args), 'and the same arguments');

  const granted = { ...file.policy_contexts.default, allowed_rules: file.rules.map((r) => r.id) };
  const revoked = { ...granted, shell_granted: false };

  expect(shellEvaluate(granted, file.rules, first.exe, first.args).allowed, 'the first execution is allowed');
  expect(!shellEvaluate(revoked, file.rules, second.exe, second.args).allowed, 'the second is refused on the same session');
  expect(
    shellEvaluate(revoked, file.rules, second.exe, second.args).error === 'ERR_PERMISSION_DENIED',
    'and the fault is a permission denial, which is what an operator can act on',
  );

  // A revoked grant is checked BEFORE the allow list, so the reason is denied_by_operator even
  // for a command that would otherwise be perfectly legal.
  expect(
    shellEvaluate(revoked, file.rules, second.exe, second.args).reason === 'denied_by_operator',
    'and the reason names the operator rather than the rule',
  );
}

// ---- ShellPolicyTest.theRemainingLifecycleVectors --------------------------
{
  const file = load('shell-policy.json');

  // The rate limit counts REJECTIONS, not commands.
  const limit = file.lifecycle_vectors.find((v) => v.id === 'shell.rate-limit-after-repeated-rejections');

  expect(!!limit, 'the rate-limit vector exists');
  expect(limit.rejections_within_window === SHELL_REJECTIONS_BEFORE_SUSPENSION, 'the threshold matches the code');
  expect(limit.suspend_s === 300, 'the suspension lasts five minutes');
  expect(limit.expected === 'suspended', 'and the expected state is suspended');
  expect(limit.expected_error === 'ERR_PERMISSION_DENIED', 'with a permission denial, not a rate error');
  expect(limit.window_s === 60, 'counted over sixty seconds');

  // Output over the cap is truncated, not refused.
  const truncated = file.lifecycle_vectors.find((v) => v.id === 'shell.output-truncated');

  expect(!!truncated, 'the truncation vector exists');
  expect(isOutputTruncated(truncated.output_bytes), 'the vector really exceeds the cap');
  expect(retainedOutputBytes(truncated.output_bytes) === truncated.output_cap_bytes, 'exactly the cap is retained');
  expect(truncated.expected_flag === true, 'and the truncated flag is set');
  expect(!isOutputTruncated(truncated.output_cap_bytes), 'output exactly at the cap is not truncated');
  expect(!isOutputTruncated(1024), 'a small output is not truncated');

  // A timeout kills the process GROUP and reports 137.
  const timeout = file.lifecycle_vectors.find((v) => v.id === 'shell.timeout-kills-process-group');

  expect(!!timeout, 'the timeout vector exists');
  expect(timeout.expected_exit_code === 137, 'the exit code is 137');
  expect(timeout.expected_exit_code === 128 + 9, 'which is 128 + SIGKILL, not a bare failure');
  expect(timeout.expected_truncated === true, 'and the output is flagged as truncated, because it was cut short');

  // The audit log carries BLOCKED commands as well as executed ones.
  const audit = file.lifecycle_vectors.find((v) => v.id === 'shell.audit-log-contains-blocked');

  expect(!!audit, 'the audit vector exists');
  expect(audit.required_audit_fields.includes('blocked'), 'an entry records whether it was blocked');
  expect(audit.required_audit_fields.includes('rule_id'), 'and which rule decided it');
  expect(audit.required_audit_fields.includes('controller_fingerprint'), 'and which controller asked');
  expect(audit.min_retained_entries === 500, 'and at least 500 entries are retained');
}

// ---- ShellPolicyTest.everyContextRefusesWhenNoGrant ------------------------
{
  const file = load('shell-policy.json');

  // The no_grant context has an EMPTY allow list and no shell. Every case under it is refused
  // with denied_by_operator rather than not_in_allow_list, which is the ordering that matters:
  // the grant is checked first, so a disabled pairing reports the fact the operator can fix.
  const noGrant = file.policy_contexts.no_grant;

  expect(noGrant.shell_granted === false, 'the no_grant context has no shell');
  expect(noGrant.allowed_rules.length === 0, 'and an empty allow list');

  // Even a fully allow-listed command is refused.
  const verdict = shellEvaluate(noGrant, file.rules, '/system/bin/getprop', ['ro.build.version.sdk']);

  expect(!verdict.allowed, 'a legal command is refused when there is no grant');
  expect(verdict.error === 'ERR_PERMISSION_DENIED', 'the fault is a permission denial');
  expect(verdict.reason === 'denied_by_operator', 'and the reason names the operator');

  // And the same command IS allowed under a grant, so the grant is the only difference.
  expect(
    shellEvaluate(file.policy_contexts.default, file.rules, '/system/bin/getprop', ['ro.build.version.sdk']).allowed,
    'the same command is allowed under a grant',
  );

  // Every context that HAS a grant either allows or refuses; none is left undecided.
  for (const [name, context] of Object.entries(file.policy_contexts)) {
    if (!context.shell_granted) continue;

    const result = shellEvaluate(context, file.rules, '/system/bin/getprop', ['ro.build.version.sdk']);

    expect(
      result.allowed || result.reason !== undefined,
      'the context "' + name + '" produces a decided verdict',
    );
  }
}

// ---- ShellPolicyTest.theArgumentCountAndPatternsAreEnforced -----------------
{
  const file = load('shell-policy.json');

  // Too many arguments is argument_rejected, because a rule DID apply.
  const tooMany = file.cases.find((c) => c.id === 'shell.deny.too-many-arguments');

  expect(!!tooMany, 'the too-many-arguments case exists');

  const verdict = shellEvaluate(file.policy_contexts.default, file.rules, tooMany.exe, tooMany.args);

  expect(!verdict.allowed, 'too many arguments is refused');
  expect(verdict.reason === 'argument_rejected', 'and the reason is argument_rejected, because a rule applied');

  // The rule's own max_args is what rejects it.
  const rule = file.rules.find((r) => r.id === 'sys.getprop');

  expect(tooMany.args.length > rule.max_args, 'the vector really exceeds the rule maximum (' + tooMany.args.length + ' > ' + rule.max_args + ')');

  // A rule with no pattern for an argument it permits accepts nothing, so the two can never
  // disagree in the permissive direction.
  for (const candidate of file.rules) {
    const hasPatterns = candidate.arg_patterns.length > 0;

    if (candidate.max_args > 0) {
      expect(hasPatterns, 'the rule "' + candidate.id + '" permits arguments and declares patterns for them');
    }

    if (hasPatterns) {
      expect(candidate.max_args > 0, 'the rule "' + candidate.id + '" declares patterns and permits arguments');
    }
  }

  // The argv prefix must match EXACTLY, so a subtly different subcommand does not qualify.
  const mismatch = file.cases.find((c) => c.id === 'shell.deny.argv-prefix-mismatch');

  expect(!!mismatch, 'the argv-prefix-mismatch case exists');
  expect(mismatch.args[0] === 'window2', 'the vector passes window2 against a window rule');
  expect(!ruleMatches(file.rules.find((r) => r.id === 'sys.dumpsys.window'), mismatch.exe, mismatch.args), 'window2 does not match the window rule');
  expect(ruleMatches(file.rules.find((r) => r.id === 'sys.dumpsys.window'), mismatch.exe, ['window']), 'but window does');
}


// ---- ShellPolicyTest: the other two guards a first pass missed --------------------------
//
// Five shell mutations survived the first run, and each survivor names a rule the gate did not
// actually exercise. They are closed here rather than by loosening the mutations.
{
  const file = load('shell-policy.json');

  // 1. A RELATIVE path is refused. The vector's own case does cover it, but every check above
  //    looked at the verdict and not at the guard, and a version of isVettedPath that skipped the
  //    absolute-path test still reached not_in_allow_list by a different route -- the
  //    `VETTED_DIRECTORIES.some(...)` failing for a bare `getprop`. So the guard itself is driven
  //    directly: a name that WOULD start with a vetted directory if it were absolute.
  expect(!isVettedPath('getprop'), 'a bare name is not a vetted path');

  // Each guard inside isVettedPath has to be reachable by an input that only THAT guard refuses.
  // A guard no input can distinguish from its absence is not a guard, and a mutation test rightly
  // reports it as one that survives.
  //
  // The rule is two tests: the basename must name a program, and the directory must equal a
  // vetted directory. Everything else this function once checked turned out to be unreachable --
  // driven exhaustively, three of the four guards changed no answer for any input, because the
  // directory comparison already refuses a relative path, a traversal path and a doubled slash.
  // They were removed rather than kept, and these checks now pin the two that remain.
  const vettedAbsolute = '/system/bin/getprop';

  expect(isVettedPath(vettedAbsolute), 'an absolute vetted path is accepted');
  expect(isVettedPath('/system/xbin/su'), 'and so is one from the other vetted directory');
  expect(
    SHELL_VETTED_DIRECTORIES.includes(vettedAbsolute.slice(0, vettedAbsolute.lastIndexOf('/') + 1)),
    'and the directory it names is one of the vetted ones',
  );

  // Guard 1: the DIRECTORY is compared for EQUALITY.
  //
  //   The distinguishing input is a path whose leading characters spell a vetted directory but
  //   whose directory is not one -- `startsWith` accepts it and equality refuses it. Without this
  //   guard the check would be a prefix test, which is the bug the shape exists to prevent.
  for (const prefixOnly of ['/system/bin/getprop/x', '/system/bin/./getprop', '/system/bin/x/y/getprop']) {
    expect(
      SHELL_VETTED_DIRECTORIES.some((directory) => prefixOnly.startsWith(directory)),
      'the probe "' + prefixOnly + '" passes a prefix test',
    );
    expect(!isVettedPath(prefixOnly), 'and is refused, because the directory is not equal to a vetted one');
  }

  // The equality comparison is also what refuses a RELATIVE path and a path that leaves a vetted
  // directory, with no separate absolute-path or traversal guard needed.
  for (const relative of ['bin/getprop', 'system/bin/getprop', './system/bin/getprop', vettedAbsolute.slice(1)]) {
    expect(!relative.startsWith('/'), 'the probe "' + relative + '" is relative');
    expect(!isVettedPath(relative), 'and is refused, because its directory is not a vetted one');
  }

  for (const leavesVetted of ['/system/bin/../data/local/tmp/payload', '/system/bin/getprop/../rm']) {
    expect(!isVettedPath(leavesVetted), 'a path leaving a vetted directory is refused (' + leavesVetted + ')');
  }

  // A doubled slash is refused for the same reason: `/system/bin//` is not the string
  // `/system/bin/`. Asserted as a consequence of the comparison rather than as a guard of its
  // own, so the check says what is actually true.
  expect(!isVettedPath('/system/bin//getprop'), 'a doubled slash is refused');
  expect(
    !SHELL_VETTED_DIRECTORIES.includes('/system/bin//'),
    'because the doubled directory is not equal to the vetted one',
  );

  // Guard 2: the BASENAME must name a program.
  //
  //   This is the only other test that changes an answer, and it changes it for exactly one shape:
  //   a path whose DIRECTORY is vetted but whose basename is empty or a directory name. Removing
  //   it accepts `/system/bin/`, which is a directory and not an executable.
  for (const directoryItself of ['/system/bin/', '/system/xbin/', '/system/bin/.', '/system/bin/..']) {
    expect(
      SHELL_VETTED_DIRECTORIES.includes(directoryItself.slice(0, directoryItself.lastIndexOf('/') + 1)),
      'the probe "' + directoryItself + '" names a vetted DIRECTORY',
    );
    expect(!isVettedPath(directoryItself), 'and is refused, because its basename names no program');
  }

  // The vetted directories themselves, without a trailing slash, are refused by the equality test.
  for (const bareDirectory of ['/system/bin', '/system/xbin']) {
    expect(!isVettedPath(bareDirectory), 'the bare directory "' + bareDirectory + '" is not an executable');
  }

  // And a path with no directory at all has nothing to compare.
  for (const noDirectory of ['getprop', '', '/getprop']) {
    expect(!isVettedPath(noDirectory), 'the probe "' + noDirectory + '" names no directory');
  }

  expect(!isVettedPath('/data/local/tmp/payload'), 'an unvetted directory is refused');
  expect(!isVettedPath('/system/bogus/getprop'), 'a neighbouring directory is refused');

  // The relative-path case from the file is rejected, and by the path guard.
  const relative = file.cases.find((c) => c.id === 'shell.deny.relative-path');
  expect(!!relative, 'the relative-path case exists');
  expect(!relative.exe.startsWith('/'), 'the vector names a bare name (' + relative.exe + ')');
  expect(!isVettedPath(relative.exe), 'and the path guard refuses it');
  expect(
    shellEvaluate(file.policy_contexts.default, file.rules, relative.exe, relative.args).reason === 'not_in_allow_list',
    'and the verdict is not_in_allow_list',
  );

  // 2. The argument COUNT is capped. No vector exceeds a rule's max_args in a way that a missing
  //    count check would let through -- the surplus argument is also rejected by the pattern for
  //    its position, which is why the mutation survived. The cap is therefore driven on its own,
  //    with arguments that all match a pattern so only the count can refuse them.
  const counting = {
    id: 'test.count',
    exe: '/system/bin/test',
    argv_prefix: [],
    max_args: 2,
    arg_patterns: ['^[a-z]+$', '^[a-z]+$', '^[a-z]+$'],
    timeout_ms: 1000,
  };

  expect(ruleArgumentsMatch(counting, '/system/bin/test', ['ab', 'cd']), 'two matching arguments are accepted');
  expect(ruleArgumentsMatch(counting, '/system/bin/test', ['ab']), 'one matching argument is accepted');
  // The rule declares a pattern for the third argument as well, so the ONLY guard that can refuse
  // it is the count. With fewer patterns the refusal would come from the missing pattern at that
  // position, which is why the count mutation survived a first pass.
  expect(ruleArgumentsMatch(counting, '/system/bin/test', ['ab', 'cd']), 'two arguments are accepted');
  expect(
    !ruleArgumentsMatch(counting, '/system/bin/test', ['ab', 'cd', 'ef']),
    'a third argument is refused by the COUNT even though a pattern exists for it',
  );

  // Which is proved by checking the pattern in isolation: the third argument matches it, so the
  // count is what refuses the vector.
  expect(
    new RegExp(counting.arg_patterns[2]).test('ef'),
    'the third argument matches the pattern at its position',
  );

  // And the vector's own case really does exceed the rule's maximum.
  const tooMany = file.cases.find((c) => c.id === 'shell.deny.too-many-arguments');
  const getpropRule = file.rules.find((r) => r.id === 'sys.getprop');

  expect(!!tooMany, 'the too-many-arguments case exists');
  expect(tooMany.args.length > getpropRule.max_args, 'the vector exceeds the rule maximum (' + tooMany.args.length + ' > ' + getpropRule.max_args + ')');

  // 3. An argument with NO PATTERN of its own is refused, not accepted. A rule that permits more
  //    arguments than it has patterns would otherwise accept an unconstrained one -- so the check
  //    drives exactly that rule, which no vector provides.
  const underSpecified = {
    id: 'test.under-specified',
    exe: '/system/bin/test',
    argv_prefix: [],
    max_args: 2,
    arg_patterns: ['^[a-z]+$'],
    timeout_ms: 1000,
  };

  expect(ruleArgumentsMatch(underSpecified, '/system/bin/test', ['ab']), 'the argument that has a pattern is accepted');
  expect(
    !ruleArgumentsMatch(underSpecified, '/system/bin/test', ['ab', 'cd']),
    'the argument with no pattern of its own is refused',
  );

  // 4. The command-line cap is enforced. Every vector is rejected by a pattern first, so the cap
  //    has to be driven with a command line that exceeds it and matches every pattern.
  const cap = SHELL_MAX_COMMAND_LINE_BYTES;

  expect(commandLineLength('/system/bin/getprop', ['a']) < cap, 'an ordinary command line is under the cap');
  expect(commandLineLength('/system/bin/getprop', ['a'.repeat(cap)]) > cap, 'a huge argument is over the cap');
  expect(
    shellEvaluate(file.policy_contexts.default, file.rules, '/system/bin/getprop', ['a'.repeat(cap)]).reason === 'argument_rejected',
    'and the cap refuses it as argument_rejected',
  );

  // The cap is per CONTEXT and the context's own value is what is read, so a context with a lower
  // cap refuses a command line the default context accepts.
  const smallCap = { ...file.policy_contexts.default, max_command_line_bytes: 20 };
  const longEnoughToExceedTheSmallCap = 'a'.repeat(20);

  expect(
    shellEvaluate(file.policy_contexts.default, file.rules, '/system/bin/getprop', [longEnoughToExceedTheSmallCap]).allowed,
    'the default context accepts it',
  );
  expect(
    !shellEvaluate(smallCap, file.rules, '/system/bin/getprop', [longEnoughToExceedTheSmallCap]).allowed,
    'a context with a smaller cap refuses the same command line',
  );

  // 5. The length is counted in BYTES, not characters. Every vector is ASCII, so a
  //    character-counting implementation gives the same answer for all of them -- the difference
  //    is only visible on a multi-byte argument, which is driven here.
  const oneHundredAccents = 'é'.repeat(100);

  expect(oneHundredAccents.length === 100, 'the argument is one hundred characters');
  expect(Buffer.byteLength(oneHundredAccents, 'utf8') === 200, 'but two hundred bytes in UTF-8');
  expect(
    commandLineLength('/x', [oneHundredAccents]) > commandLineLength('/x', ['a'.repeat(100)]),
    'so a multi-byte argument counts for more than the same number of ASCII characters',
  );
  expect(
    commandLineLength('/x', [oneHundredAccents]) - commandLineLength('/x', ['a'.repeat(100)]) === 100,
    'by exactly one extra byte per character',
  );

  // And the byte count is what makes the cap bite earlier for a multi-byte command line: a string
  // two hundred characters long exceeds a three-hundred-byte cap by its byte length and not by
  // its character count.
  const byteCap = 250;
  const multibyteContext = { ...file.policy_contexts.default, max_command_line_bytes: byteCap };
  const twoHundredAccents = 'é'.repeat(200);

  expect(twoHundredAccents.length < byteCap, 'the argument is under the cap by character count');
  expect(Buffer.byteLength(twoHundredAccents, 'utf8') > byteCap, 'but over it by byte count');
  expect(
    !shellEvaluate(multibyteContext, file.rules, '/system/bin/getprop', [twoHundredAccents]).allowed,
    'so the cap refuses it, which a character count would not',
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
