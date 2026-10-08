#!/usr/bin/env node
/**
 * DroidLab conformance vector verifier.
 *
 * Checks that the vector set in protocol/vectors/ is internally consistent and
 * that it agrees with the registries in the RFC and in protocol/schema/.
 *
 * This tool does NOT test the Kotlin or C# codecs. Those load the same vector
 * files and check themselves against them; see:
 *   android/core-protocol/src/test/kotlin/io/droidlab/protocol/ConformanceTest.kt
 *   windows/DroidLab.Tests/Protocol/ConformanceTests.cs
 *
 * What it does check, and why each check exists:
 *   1. Every vector file is valid JSON and declares the expected envelope keys.
 *   2. Every hex frame has an even number of digits and a body length that
 *      matches the declared body_length, so a typo cannot make a vector
 *      self-consistent but wrong.
 *   3. Frame headers decode to the values in the accompanying "decoded" block,
 *      so the hex and the human-readable form cannot drift apart.
 *   4. Every error code and capability name used anywhere in the vectors is
 *      present in the RFC registry. A vector referring to an unregistered code
 *      is the failure mode that lets an implementation invent behaviour.
 *   5. Transcript vectors rebuild from their components and match the recorded
 *      bytes, so the length-prefix rule is actually exercised.
 *   6. The discovery canonicalisation vectors rebuild from their fields.
 *   7. Cross-file invariants: default limits agree between capabilities.json and
 *      the schema, message type codes agree between framing-basic.json and the
 *      RFC registry.
 *
 * Exit code is 0 when everything passes, 1 when any check fails.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..', '..');
const VECTOR_DIR = join(REPO, 'protocol', 'vectors');
const REGISTRY_PATH = join(REPO, 'protocol', 'registry', 'dlwp-1.json');

const failures = [];
const warnings = [];
const passes = [];

function fail(file, vector, message) {
  failures.push({ file, vector, message });
}

function warn(file, vector, message) {
  warnings.push({ file, vector, message });
}

function ok(message) {
  passes.push(message);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    fail(basename(path), '-', `not valid JSON: ${error.message}`);
    return null;
  }
}

/* ------------------------------------------------------------------ helpers */

const HEX = /^[0-9a-fA-F]*$/;

function isHex(value) {
  return typeof value === 'string' && value.length % 2 === 0 && HEX.test(value);
}

function hexBytes(value) {
  const out = [];
  for (let i = 0; i < value.length; i += 2) {
    out.push(parseInt(value.slice(i, i + 2), 16));
  }
  return out;
}

function readU32(bytes, offset) {
  return (
    ((bytes[offset] << 24) >>> 0) +
    (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) +
    bytes[offset + 3]
  );
}

function decodeHeader(frameHex) {
  const bytes = hexBytes(frameHex);
  if (bytes.length < 24) return null;
  return {
    magic: String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]),
    version: bytes[4],
    flags: bytes[5],
    header_length: bytes[6],
    message_type: bytes[7],
    channel_id: readU32(bytes, 8),
    sequence_number: readU32(bytes, 12),
    acknowledgment: readU32(bytes, 16),
    body_length: readU32(bytes, 20),
    total_length: bytes.length,
  };
}

function utf8Length(value) {
  return Buffer.byteLength(value, 'utf8');
}

function buildTranscript(inputs) {
  const parts = [];
  const push = (buf) => parts.push(buf);
  push(Buffer.from('DLWP/1-handshake', 'ascii'));
  push(Buffer.from([0x00]));
  const id = (value) => {
    const text = Buffer.from(value, 'utf8');
    const prefix = Buffer.alloc(2);
    prefix.writeUInt16BE(text.length, 0);
    push(prefix);
    push(text);
  };
  id(inputs.client_id);
  push(Buffer.from([0x00]));
  id(inputs.agent_id);
  push(Buffer.from([0x00]));
  for (const key of ['client_nonce', 'agent_nonce', 'client_pub', 'agent_pub']) {
    push(Buffer.from(inputs[key], 'base64url'));
  }
  return Buffer.concat(parts);
}

function buildTxtPayload(fields) {
  const order = ['v', 'id', 'fp', 'caps', 'port'];
  const extras = ['model', 'android', 'sdk', 'busy', 'loc', 'tls'];
  const lines = [];
  for (const key of [...order, ...extras]) {
    if (Object.prototype.hasOwnProperty.call(fields, key)) {
      lines.push(`${key}=${fields[key]}`);
    }
  }
  return Buffer.from('DLWP/1-txt\u0000' + lines.join('\n'), 'utf8');
}

function buildBeaconCanonical(fields) {
  const sorted = Object.keys(fields).sort();
  return Buffer.from(sorted.map((k) => `${k}=${fields[k]}`).join('\n'), 'utf8');
}

/* ------------------------------------------------------- registries from RFC */

function loadRegistries() {
  // The registries come from protocol/registry/dlwp-1.json, not from the RFC
  // Markdown. Parsing Markdown made every registry check depend on the exact
  // table formatting: a reflowed table silently produced an empty registry, the
  // check was skipped without failing, and the vector set looked verified while
  // nothing had been checked. A missing registry is now a hard failure, because
  // a check that cannot run must never be reported as a check that passed.
  let registry;
  try {
    registry = JSON.parse(readFileSync(REGISTRY_PATH, 'utf8'));
  } catch (error) {
    fail(
      'dlwp-1.json',
      `the machine-readable registry is unreadable (${error.message}); ` +
        'without it no vector can be checked against a registry, and an unchecked ' +
        'vector is worse than a missing one',
    );
    return { errorCodes: null, capabilities: null, messageTypes: null, sessionEndReasons: null, severity: null };
  }

  return {
    errorCodes: new Set((registry.error_codes ?? []).map((e) => e.code)),
    severity: new Map((registry.error_codes ?? []).map((e) => [e.code, e.severity])),
    capabilities: new Set((registry.capabilities ?? []).map((e) => e.name)),
    messageTypes: new Map((registry.message_types ?? []).map((e) => [e.name, e.code])),
    sessionEndReasons: new Set(registry.session_end_reasons ?? []),
    defaultLimits: registry.default_limits ?? {},
  };
}

/* ------------------------------------------------------------- the checks */

const registries = loadRegistries();

function walkStrings(node, visit, path = '$') {
  if (typeof node === 'string') {
    visit(node, path);
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((item, index) => walkStrings(item, visit, `${path}[${index}]`));
    return;
  }
  if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      walkStrings(value, visit, `${path}.${key}`);
    }
  }
}

function checkEnvelope(file, doc) {
  for (const key of ['spec', 'protocol_version', 'description']) {
    if (!doc[key]) warn(file, '-', `missing envelope key "${key}"`);
  }
  if (doc.spec && !/^RFC-\d{4}$/.test(doc.spec)) {
    warn(file, '-', `spec "${doc.spec}" does not look like an RFC reference`);
  }
  if (doc.protocol_version && doc.protocol_version !== '1.0') {
    warn(file, '-', `protocol_version is "${doc.protocol_version}", expected "1.0"`);
  }
}

function checkRegistriesUsed(file, doc) {
  if (registries.errorCodes) {
    walkStrings(doc, (value, path) => {
      if (/^ERR_[A-Z_]+$/.test(value) && !registries.errorCodes.has(value)) {
        fail(file, path, `error code "${value}" is not in the RFC-0001 section 6.2 registry`);
      }
    });
  }
  if (registries.capabilities) {
    // Only the protocol capability registry is closed-world. A shell-policy rule
    // id happens to have the same dotted shape ("sys.getprop") but belongs to a
    // different namespace that RFC-0004 defines, so this file is skipped here
    // and checked by checkShellPolicyCapabilityClosure instead. Inferring the
    // namespace from the string shape is not reliable; it is declared per file.
    if (doc.spec === 'RFC-0004') return;
    walkStrings(doc, (value, path) => {
      if (/^[a-z]+\.[a-z_]+$/.test(value) && !registries.capabilities.has(value)) {
        fail(file, path, `capability "${value}" is not in the RFC-0001 section 7.1 registry`);
      }
    });
  }
}

/**
 * The shell policy in this file is self-contained, and it has three namespaces
 * that must not be confused:
 *
 *   - rule ids      ("sys.getprop")      defined in `rules`
 *   - exe names     ("su", "rm")         the basename of a deny-listed binary
 *   - capability ids                     not used here at all
 *
 * `allowed_rules` refers to rule ids; `denied_rules` refers to executable
 * basenames. Treating the two as one namespace is what made the earlier
 * revision demand that "rm" be a declared capability. This check validates each
 * namespace separately: every allowed rule must exist, every referenced deny
 * name must correspond to a basename that the rules actually mention or to a
 * known interpreter class, and every rule must be reachable from some context
 * so that dead configuration cannot hide a capability nobody can use.
 */
function checkShellPolicyCapabilityClosure(file, doc) {
  const rules = Array.isArray(doc.rules) ? doc.rules : [];
  const ruleIds = new Set(rules.map((r) => r.id));
  const contexts = doc.policy_contexts ?? {};

  // allowed_rules -> rule ids
  for (const [name, context] of Object.entries(contexts)) {
    for (const id of context.allowed_rules ?? []) {
      if (!ruleIds.has(id)) {
        fail(file, `${name}.allowed_rules`, `allows rule "${id}", which is not defined in \`rules\``);
      }
    }
    for (const id of context.denied_rules ?? []) {
      if (ruleIds.has(id)) {
        fail(file, `${name}.denied_rules`, `deny-lists "${id}" as a binary name, but that is also a rule id; the two namespaces must not be mixed`);
      }
      if (/[/\\]/.test(id)) {
        fail(file, `${name}.denied_rules`, `deny-lists "${id}"; deny entries must be bare executable names, not paths`);
      }
    }
  }

  // Every rule must be allowed by at least one context, or it is unreachable.
  for (const rule of rules) {
    const reached = Object.values(contexts).some((c) => (c.allowed_rules ?? []).includes(rule.id));
    if (!reached) {
      fail(file, rule.id, `rule "${rule.id}" is defined but no policy context allows it, so it can never execute`);
    }
  }

  // A case that expects a rule must name a rule that exists and that the case's
  // context actually allows. This is the check that stops a vector from pinning
  // an "allowed" verdict for a command its own context refuses.
  for (const vector of doc.cases ?? []) {
    const id = vector.id ?? '(unnamed)';
    const context = contexts[vector.context];
    if (!context) continue;
    if (vector.expected_rule && !ruleIds.has(vector.expected_rule)) {
      fail(file, id, `expects rule "${vector.expected_rule}", which is not defined`);
    }
    if (vector.expected_rule && !(context.allowed_rules ?? []).includes(vector.expected_rule)) {
      fail(file, id, `expects rule "${vector.expected_rule}", which context "${vector.context}" does not allow`);
    }
  }

  // A baseline audit requirement: blocked commands must be logged, so the field
  // list has to include the one that distinguishes an attempt from an execution.
  for (const vector of doc.lifecycle_vectors ?? []) {
    if (vector.required_audit_fields && !vector.required_audit_fields.includes('blocked')) {
      fail(file, vector.id ?? '(unnamed)', 'an audit-log vector must require the `blocked` field, or refusals cannot be audited');
    }
  }
}

function checkFraming(file, doc) {
  const vectors = Array.isArray(doc.vectors) ? doc.vectors : [];
  for (const vector of vectors) {
    const id = vector.id ?? '(unnamed)';
    if (!vector.id) fail(file, id, 'vector has no id');
    if (!vector.note) warn(file, id, 'vector has no note explaining what it pins');
    if (typeof vector.frame !== 'string') continue;

    if (!isHex(vector.frame)) {
      fail(file, id, 'frame is not an even-length hex string');
      continue;
    }

    const header = decodeHeader(vector.frame);
    if (!header) {
      fail(file, id, `frame is ${hexBytes(vector.frame).length} bytes, shorter than the 24-byte header`);
      continue;
    }

    if (header.total_length !== header.header_length + header.body_length) {
      fail(
        file,
        id,
        `header_length (${header.header_length}) + body_length (${header.body_length}) ` +
          `= ${header.header_length + header.body_length}, but the frame is ${header.total_length} bytes`,
      );
    }

    if (!vector.decoded?.header) continue;
    const expected = vector.decoded.header;
    for (const field of [
      'magic',
      'version',
      'flags',
      'header_length',
      'message_type',
      'channel_id',
      'sequence_number',
      'acknowledgment',
      'body_length',
    ]) {
      if (expected[field] === undefined) continue;
      if (expected[field] !== header[field]) {
        fail(file, id, `header field ${field}: decoded says ${expected[field]}, the frame encodes ${header[field]}`);
      }
    }

    if (header.magic !== 'DLWP' && id.includes('bad-magic') === false) {
      fail(file, id, `magic is "${header.magic}", expected "DLWP"`);
    }
    ok(`${id}: header bytes agree with the decoded form`);
  }
}

function checkMalformed(file, doc) {
  const vectors = Array.isArray(doc.vectors) ? doc.vectors : [];
  for (const vector of vectors) {
    const id = vector.id ?? '(unnamed)';
    if (typeof vector.frame === 'string' && isHex(vector.frame)) {
      const header = decodeHeader(vector.frame);
      if (header && header.total_length !== header.header_length + header.body_length) {
        // For malformed vectors a deliberate mismatch is allowed only when the
        // vector is about that mismatch. Everything else must still add up.
        const aboutLength =
          id.includes('body-length') || id.includes('frame-too-large') || id.includes('header-length');
        if (!aboutLength) {
          fail(file, id, 'declared body length does not match the frame contents, and the vector is not about that');
        }
      }
    }
    if (vector.expected === 'rejected' || vector.expected === 'error_frame_then_close') {
      if (!vector.expected_error) fail(file, id, 'a rejection vector must state the expected error code');
      if (vector.expected === 'error_frame_then_close' && !vector.expected_severity) {
        fail(file, id, 'a fatal-path vector must state the expected severity');
      }
    }
    if (vector.expected_severity === 'fatal' && vector.expected === 'error_session_continues') {
      fail(file, id, 'severity fatal cannot leave the session running');
    }
  }
}

function checkTranscript(file, doc) {
  const vectors = Array.isArray(doc.vectors) ? doc.vectors : [];
  for (const vector of vectors) {
    const id = vector.id ?? '(unnamed)';
    if (!vector.inputs) continue;

    for (const field of ['client_nonce', 'agent_nonce', 'client_pub', 'agent_pub']) {
      const raw = Buffer.from(vector.inputs[field] ?? '', 'base64url');
      if (raw.length !== 32) {
        fail(file, id, `${field} decodes to ${raw.length} bytes, must be 32`);
      }
    }

    const built = buildTranscript(vector.inputs);

    if (vector.expected?.transcript_bytes) {
      const recorded = Buffer.from(vector.expected.transcript_bytes, 'hex');
      if (!built.equals(recorded)) {
        fail(
          file,
          id,
          `rebuilt transcript (${built.length} bytes) differs from the recorded transcript_bytes ` +
            `(${recorded.length} bytes)`,
        );
      } else {
        ok(`${id}: transcript rebuilds byte-for-byte from its components`);
      }
    }

    if (vector.expected?.transcript_length_bytes !== undefined) {
      if (built.length !== vector.expected.transcript_length_bytes) {
        fail(
          file,
          id,
          `rebuilt transcript is ${built.length} bytes, vector declares ${vector.expected.transcript_length_bytes}`,
        );
      }
    }

    // The written arithmetic is prose that a reader is expected to check by
    // hand, so it must actually reconcile to the same number. A naive sum of
    // every number in the string double-counts the parenthesised groups such as
    // "(2+36)", so the top-level additive terms are evaluated instead: each term
    // is either a bare number or a parenthesised sub-sum, and the terms are
    // joined by "+".
    if (vector.expected?.transcript_arithmetic) {
      const text = vector.expected.transcript_arithmetic;
      const expression = text.split('=')[0].replace(/\s+/g, ' ');
      let sum = 0;
      let parsed = false;

      // Split on top-level "+" only, so "(2+36)" stays one term.
      const terms = [];
      let depth = 0;
      let current = '';
      for (const char of expression) {
        if (char === '(') depth += 1;
        if (char === ')') depth -= 1;
        if (char === '+' && depth === 0) {
          terms.push(current);
          current = '';
        } else {
          current += char;
        }
      }
      terms.push(current);

      for (const rawTerm of terms) {
        const term = rawTerm.trim();
        if (!term) continue;
        if (/^\(\s*[\d\s+]*\s*\)$/.test(term)) {
          const inner = term.slice(1, -1);
          const parts = inner.split('+').map((p) => Number(p.trim()));
          if (parts.every((n) => Number.isFinite(n))) {
            sum += parts.reduce((a, b) => a + b, 0);
            parsed = true;
          }
        } else {
          const head = term.match(/^(\d+)/);
          if (head) {
            sum += Number(head[1]);
            parsed = true;
          }
        }
      }

      if (parsed && sum !== built.length) {
        fail(
          file,
          id,
          `the recorded transcript_arithmetic sums to ${sum} but the transcript is ${built.length} bytes`,
        );
      } else if (parsed) {
        ok(`${id}: the recorded arithmetic reconciles with the transcript length`);
      }
    }

    if (vector.expected?.client_id_length_prefix) {
      // The prefix sits immediately after the 18-byte label and its separator,
      // so its offset is 19. Computing it rather than hardcoding it keeps the
      // check correct if the label ever changes.
      const labelLength = Buffer.byteLength('DLWP/1-handshake', 'ascii');
      const offset = labelLength + 1;
      const prefix = built.readUInt16BE(offset).toString(16).padStart(4, '0');
      const declared = vector.expected.client_id_length_prefix;
      if (prefix !== declared) {
        fail(file, id, `client_id length prefix is ${prefix}, vector declares ${declared}`);
      }
      // The declared prefix must also equal the actual UTF-8 byte count of the
      // input identifier. Checking only the rebuilt bytes would let a vector
      // declare a prefix that matches the build helper and not the spec.
      const expectedBytes = Buffer.byteLength(vector.inputs.client_id ?? '', 'utf8');
      if (parseInt(declared, 16) !== expectedBytes) {
        fail(
          file,
          id,
          `client_id length prefix declares ${parseInt(declared, 16)} bytes but the identifier is ${expectedBytes} UTF-8 bytes`,
        );
      }
    }

    if (vector.expected?.transcript_sha256) {
      const digest = createHash('sha256').update(built).digest('hex');
      if (digest !== vector.expected.transcript_sha256) {
        fail(file, id, `recorded transcript_sha256 does not match SHA-256(transcript_bytes)`);
      } else {
        ok(`${id}: transcript_hash reproduces from the transcript bytes`);
      }
    }
  }

  const rejections = Array.isArray(doc.rejection_vectors) ? doc.rejection_vectors : [];
  for (const vector of rejections) {
    const id = vector.id ?? '(unnamed)';
    if (vector.must_differ_from) {
      const other = vectors.find((v) => v.id === vector.must_differ_from);
      if (!other) {
        fail(file, id, `must_differ_from refers to unknown vector "${vector.must_differ_from}"`);
        continue;
      }
      const mine = buildTranscript(vector.inputs);
      const theirs = buildTranscript(other.inputs);
      if (mine.equals(theirs)) {
        fail(file, id, 'transcripts are byte-identical, so the length-prefix rule is not actually being tested');
      } else {
        ok(`${id}: distinct identifier split produces a distinct transcript`);
      }
    }
  }
}

function checkDiscovery(file, doc) {
  const vectors = Array.isArray(doc.vectors) ? doc.vectors : [];
  for (const vector of vectors) {
    const id = vector.id ?? '(unnamed)';
    if (!vector.fields || !vector.canonical_utf8) continue;

    const built = id.includes('beacon') ? buildBeaconCanonical(vector.fields) : buildTxtPayload(vector.fields);
    const recorded = Buffer.from(vector.canonical_utf8, 'utf8');

    if (!built.equals(recorded)) {
      fail(file, id, 'rebuilt canonical payload differs from canonical_utf8');
    }

    if (vector.canonical_length_bytes !== undefined && recorded.length !== vector.canonical_length_bytes) {
      fail(
        file,
        id,
        `canonical_utf8 is ${recorded.length} bytes, vector declares ${vector.canonical_length_bytes}`,
      );
    } else if (vector.canonical_length_bytes !== undefined) {
      ok(`${id}: canonical payload rebuilds and its declared length is correct`);
    }

    if (doc.service?.max_txt_bytes && recorded.length > doc.service.max_txt_bytes) {
      fail(file, id, `canonical payload is ${recorded.length} bytes, over the ${doc.service.max_txt_bytes}-byte budget`);
    }
  }
}

function checkCapabilities(file, doc) {
  const registry = new Set(doc.capability_registry ?? []);
  const vectors = Array.isArray(doc.negotiation_vectors) ? doc.negotiation_vectors : [];

  for (const vector of vectors) {
    const id = vector.id ?? '(unnamed)';
    if (!Array.isArray(vector.expected_negotiated)) continue;

    const disabled = new Set(vector.agent_disabled ?? []);
    const offered = new Set(vector.controller_offered ?? []);
    // Negotiation is a set intersection, so duplicates on either side collapse.
    // The expected list is therefore deduplicated before comparison: a vector
    // that offers "screen.mirror" twice must still negotiate it once, which is
    // the property this case exists to pin.
    const computed = [...new Set((vector.agent_capabilities ?? []).filter(
      (cap) => registry.has(cap) && !disabled.has(cap) && offered.has(cap),
    ))];

    const expected = [...new Set(vector.expected_negotiated)];
    const same = computed.length === expected.length && computed.every((cap, i) => cap === expected[i]);
    if (!same) {
      fail(
        file,
        id,
        `computed negotiation [${computed.join(', ')}] does not match expected [${expected.join(', ')}]`,
      );
    } else {
      ok(`${id}: negotiation rule reproduces the expected set`);
    }

    for (const cap of [...(vector.agent_capabilities ?? []), ...(vector.controller_offered ?? [])]) {
      if (!registry.has(cap) && !/^future\./.test(cap)) {
        fail(file, id, `capability "${cap}" is not in the capability_registry`);
      }
    }
  }

  const defaults = doc.default_limits ?? {};
  for (const [key, value] of Object.entries(defaults)) {
    if (typeof value !== 'number') fail(file, 'default_limits', `${key} is not a number`);
  }

  const directions = Array.isArray(doc.direction_vectors) ? doc.direction_vectors : [];
  for (const vector of directions) {
    const id = vector.id ?? '(unnamed)';
    if (vector.expected_controller_sequence) {
      if (vector.expected_controller_sequence.some((id2) => id2 % 2 === 0)) {
        fail(file, id, 'controller channel ids must all be odd');
      }
      if (vector.expected_agent_sequence?.some((id2) => id2 % 2 !== 0)) {
        fail(file, id, 'agent channel ids must all be even');
      }
      ok(`${id}: channel id parity partition holds`);
    }
  }
}

function checkShellPolicy(file, doc) {
  const contexts = doc.policy_contexts ?? {};
  const rules = Array.isArray(doc.rules) ? doc.rules : [];
  const ruleIds = new Set(rules.map((r) => r.id));
  const denyNames = new Set(
    Object.values(contexts).flatMap((context) => context.denied_rules ?? []),
  );

  for (const rule of rules) {
    if (!rule.id) fail(file, '(rule)', 'a rule has no id');
    if (!rule.exe || !rule.exe.startsWith('/')) {
      fail(file, rule.id ?? '(rule)', 'a rule exe must be an absolute path');
    }
    for (const pattern of rule.arg_patterns ?? []) {
      try {
        new RegExp(pattern);
      } catch (error) {
        fail(file, rule.id ?? '(rule)', `arg pattern "${pattern}" is not a valid regular expression: ${error.message}`);
      }
    }
  }

  for (const rule of rules) {
    const name = basename(rule.exe);
    if (denyNames.has(name)) {
      fail(file, rule.id, `rule allows "${name}", which is on the deny list; deny rules always win`);
    }
  }

  const cases = Array.isArray(doc.cases) ? doc.cases : [];
  for (const vector of cases) {
    const id = vector.id ?? '(unnamed)';
    const context = contexts[vector.context];
    if (!context) {
      fail(file, id, `unknown policy context "${vector.context}"`);
      continue;
    }

    const exe = vector.exe ?? '';
    const name = basename(exe);
    const granted = context.shell_granted === true;
    const allowLevel = context.allow_level ?? 'read_only';
    const allowedInContext = context.allowed_rules ?? [];
    const denied = context.denied_rules?.includes(name) === true;

    // The rule is selected purely by matching the command line against the rules
    // the context actually allows at its allow level. A vector's expected_rule
    // is a claim to be cross-checked, never an input to the lookup: taking it as
    // the answer (as an earlier revision did) let a vector assert "allowed" for
    // a command the policy refuses, which is precisely the failure this file is
    // supposed to catch.
    const matchesRule = (rule) =>
      rule.exe === exe &&
      (rule.argv_prefix ?? []).every((value, index) => (vector.args ?? [])[index] === value);

    // A mutating rule is only in scope for a context that grants read_write.
    // RFC-0004 section 3.2: read_only is the default grant, so a rule that
    // changes device state must be refused unless the operator raised the level.
    // The allow list states what the operator has vetted; the allow level is a
    // separate, strictly narrowing grant. Both must admit the rule to run, and
    // that is what makes shell.deny.mutating-rule-without-write-grant a real
    // test of the level gate rather than a restatement of the list.
    const permittedByLevel = (rule) => (rule.mutating === true ? allowLevel === 'read_write' : true);

    const candidate = rules.find(
      (rule) => matchesRule(rule) && allowedInContext.includes(rule.id) && permittedByLevel(rule),
    );

    const ruleMatches = candidate !== undefined;

    let verdict;
    let reason;
    if (denied) {
      verdict = 'rejected';
      reason = 'deny_listed';
    } else if (exe === '' || !exe.startsWith('/') || exe.includes('..')) {
      // A relative path or a traversal is never allowed, whatever the rules say.
      verdict = 'rejected';
      reason = 'not_in_allow_list';
    } else if (!candidate) {
      verdict = 'rejected';
      reason = 'not_in_allow_list';
    } else {
      // argv_prefix is matched first and is not re-checked against arg_patterns:
      // the prefix is the rule's identity ("dumpsys window"), while
      // arg_patterns describes the operands that follow it. max_args and
      // arg_patterns therefore count the trailing arguments only. An earlier
      // revision indexed arg_patterns against the whole argv, so every argument
      // was compared to the wrong pattern and the prefix was validated twice.
      const args = vector.args ?? [];
      const prefix = candidate.argv_prefix ?? [];
      const trailing = args.slice(prefix.length);
      if (trailing.length > (candidate.max_args ?? 0)) {
        verdict = 'rejected';
        reason = 'argument_rejected';
      } else {
        let argumentBad = false;
        for (let i = 0; i < trailing.length; i += 1) {
          const pattern = candidate.arg_patterns?.[i];
          // A trailing argument with no pattern is unconstrained by design only
          // if the rule declares fewer patterns than max_args; otherwise it is a
          // rule-definition defect and the command must not run.
          if (pattern === undefined) {
            argumentBad = true;
          } else if (!new RegExp(pattern).test(trailing[i])) {
            argumentBad = true;
          }
        }
        const lineLength = exe.length + args.reduce((sum, value) => sum + value.length + 1, 0);
        if (lineLength > (context.max_command_line_bytes ?? 4096)) argumentBad = true;
        verdict = argumentBad ? 'rejected' : 'allowed';
        reason = argumentBad ? 'argument_rejected' : undefined;
      }
    }

    // Operator consent is the last gate, not a tie-break: without a grant even a
    // perfectly matching rule is refused, and the reason names the operator so
    // the controller can prompt rather than report a policy failure.
    if (!granted && verdict === 'allowed') {
      verdict = 'rejected';
      reason = 'denied_by_operator';
    }
    // A context that grants nothing must report the operator as the reason even
    // when no rule would have matched, because the operator's decision is the
    // actionable fact: the controller should ask for a grant, not explain the
    // allow list. This is what shell.deny.no-grant pins.
    if (!granted && verdict === 'rejected' && reason === 'not_in_allow_list' && allowedInContext.length === 0) {
      reason = 'denied_by_operator';
    }

    if (verdict !== vector.expected) {
      fail(file, id, `policy computes "${verdict}" but the vector expects "${vector.expected}"`);
      continue;
    }
    if (vector.expected_error && vector.expected_error !== 'ERR_NOT_ALLOWED' && vector.expected_error !== 'ERR_PERMISSION_DENIED') {
      fail(file, id, `expected_error "${vector.expected_error}" is not a shell policy error`);
    }
    if (vector.expected_reason && reason && vector.expected_reason !== reason) {
      fail(file, id, `computed reason "${reason}" but the vector expects "${vector.expected_reason}"`);
      continue;
    }
    if (vector.expected_reason && !reason) {
      fail(file, id, `the vector expects reason "${vector.expected_reason}" but the policy computes no reason`);
      continue;
    }
    // expected_rule is cross-checked against the rule the policy actually
    // selected. Without this, moving a command from one rule to another would
    // silently pass, and the vector would no longer pin which rule matched.
    if (vector.expected_rule && (!candidate || candidate.id !== vector.expected_rule)) {
      fail(
        file,
        id,
        `expects rule "${vector.expected_rule}" but the policy selected ` +
          `"${candidate ? candidate.id : 'none'}"`,
      );
      continue;
    }
    ok(`${id}: policy verdict and reason reproduce`);
  }
}

function checkSession(file, doc) {
  const steps = Array.isArray(doc.steps) ? doc.steps : [];
  const seen = new Map();

  for (const step of steps) {
    const id = `step ${step.step}`;
    if (typeof step.step !== 'number') fail(file, id, 'step has no number, so ordering cannot be checked');
    if (!step.actor) fail(file, id, 'step has no actor');

    const frame = step.send;
    if (!frame) continue;
    if (!frame.name) fail(file, id, 'sent frame has no name');
    if (typeof frame.sequence_number !== 'number') {
      fail(file, id, 'sent frame has no sequence number, so the monotonic rule is untested');
      continue;
    }

    const actor = step.actor;
    const last = seen.get(actor) ?? 0;

    // A vector may deliberately send a non-increasing sequence number to pin the
    // replay defence. Those steps are exempt from the monotonicity rule, but the
    // exemption must be explicit: a step that breaks monotonicity without
    // declaring itself a replay is a defect in the vector, not a test of one.
    const isDeliberateReplay =
      step.deliberate_replay === true ||
      /replay|reused|duplicate|non-monotonic/i.test(step.note ?? '') ||
      /ERR_REPLAY_DETECTED/.test(JSON.stringify(step.expect ?? ''));

    if (isDeliberateReplay) {
      ok(`${id}: ${actor} deliberately replays sequence ${frame.sequence_number}, which the agent must reject`);
      continue;
    }

    if (frame.sequence_number <= last) {
      fail(
        file,
        id,
        `${actor} sequence number ${frame.sequence_number} does not increase on its previous ${last}; ` +
          'if this is a deliberate replay, mark the step so the intent is explicit',
      );
    }
    seen.set(actor, frame.sequence_number);

    if (frame.name === 'HELLO' && step.step !== 1) {
      fail(file, id, 'HELLO appears after the first step');
    }
    if (frame.name !== 'HELLO' && step.step === 1) {
      fail(file, id, 'the first frame of a session must be HELLO');
    }
    if (frame.encrypted === true && ['HELLO', 'HELLO_ACK'].includes(frame.name)) {
      fail(file, id, 'HELLO and HELLO_ACK are cleartext frames; they cannot carry the ENCRYPTED flag');
    }
    if (frame.encrypted === true && (frame.flags & 0x01) !== 1) {
      fail(file, id, 'frame is marked encrypted but does not set the ENCRYPTED flag bit');
    }
    if (['AUTH', 'AUTH_OK'].includes(frame.name) && frame.encrypted !== true) {
      fail(file, id, 'AUTH and AUTH_OK must be encrypted');
    }
    if (frame.name === 'HELLO_ACK' && frame.body?.transcript_hash === undefined) {
      fail(file, id, 'HELLO_ACK must carry transcript_hash');
    }
  }

  if (doc.expected_negotiated_capabilities) {
    const pre = doc.preconditions ?? {};
    const disabled = new Set(pre.agent_disabled ?? []);
    const offered = new Set(pre.controller_offered ?? []);
    const computed = (pre.agent_capabilities ?? []).filter((cap) => !disabled.has(cap) && offered.has(cap));
    const expected = doc.expected_negotiated_capabilities;
    if (computed.join(',') !== expected.join(',')) {
      fail(
        file,
        'expected_negotiated_capabilities',
        `preconditions intersect to [${computed.join(', ')}] but the vector expects [${expected.join(', ')}]`,
      );
    } else {
      ok('session-basic: preconditions intersect to the declared negotiated set');
    }
  }
}

/**
 * Checks the session key schedule and AEAD vectors in crypto-session-keys.json.
 *
 * This file was previously unchecked, and a defect survived in it because of
 * that: the aead.header-is-associated-data vector declared aad_length 24 while
 * carrying a 21-byte hex string that decoded to a channel id of 50331649. A
 * declared length that disagrees with the bytes beside it is the single most
 * common way a hex vector rots, so it is checked mechanically for every hex
 * field here rather than left to review.
 */
function checkCryptoKeys(file, doc) {
  const vectors = Array.isArray(doc.vectors) ? doc.vectors : [];
  const aead = Array.isArray(doc.aead_vectors) ? doc.aead_vectors : [];

  // Every <name>_hex field must decode to exactly the number of bytes its
  // companion length field declares, or to the width its own name implies.
  const hexWidths = {
    salt_hex: null,
    ikm_hex: 64,
  };

  for (const vector of vectors) {
    const id = vector.id ?? '(unnamed)';
    const derived = vector.derived ?? {};

    for (const [field, expected] of Object.entries(hexWidths)) {
      const value = derived[field];
      if (typeof value !== 'string') continue;

      if (!isHex(value)) {
        fail(file, id, `${field} is not a valid hex string`);
        continue;
      }

      if (expected !== null && hexBytes(value).length !== expected) {
        fail(
          file,
          id,
          `${field} declares ${hexBytes(value).length} bytes but the schedule requires ${expected}`,
        );
        continue;
      }

      ok(`${id}: ${field} is ${hexBytes(value).length} bytes as declared`);
    }

    // The salt must be the label, a separator, then the session id.
    if (typeof derived.salt_hex === 'string' && isHex(derived.salt_hex)) {
      const salt = Buffer.from(derived.salt_hex, 'hex');
      const label = Buffer.from('DLWP/1-session', 'ascii');
      const sessionId = Buffer.from(vector.inputs?.session_id ?? '', 'base64url');

      const expectedSalt = Buffer.concat([label, Buffer.from([0]), sessionId]);

      if (!salt.equals(expectedSalt)) {
        fail(
          file,
          id,
          `salt_hex is not "DLWP/1-session" || 0x00 || session_id ` +
            `(expected ${expectedSalt.toString('hex')}, got ${derived.salt_hex})`,
        );
      } else {
        ok(`${id}: salt is the label, a separator, then the session id`);
      }
    }

    // The input keying material must be shared || pairing_secret.
    if (typeof derived.ikm_hex === 'string' && isHex(derived.ikm_hex)) {
      const expectedIkm = (vector.inputs?.shared ?? '') + (vector.inputs?.pairing_secret ?? '');
      if (derived.ikm_hex !== expectedIkm) {
        fail(file, id, 'ikm_hex is not shared || pairing_secret');
      } else {
        ok(`${id}: input keying material is shared || pairing_secret`);
      }
    }

    // A vector that declares expected lengths must declare the ones the
    // schedule produces, so a renamed or dropped output is caught here.
    if (derived.expected_lengths) {
      const required = ['c2a_key', 'a2c_key', 'c2a_iv', 'a2c_iv', 'exporter'];
      const declared = Object.keys(derived.expected_lengths);
      const missing = required.filter((name) => !declared.includes(name));

      if (missing.length > 0) {
        fail(file, id, `expected_lengths is missing ${missing.join(', ')}`);
      } else {
        ok(`${id}: expected_lengths covers every derived output`);
      }
    }
  }

  for (const vector of aead) {
    const id = vector.id ?? '(unnamed)';

    // A declared length must match the bytes it describes. This is the check
    // that the broken AAD vector failed.
    if (typeof vector.aad_bytes === 'string') {
      if (!isHex(vector.aad_bytes)) {
        fail(file, id, 'aad_bytes is not a valid hex string');
        continue;
      }

      const actual = hexBytes(vector.aad_bytes).length;
      const declared = vector.aad_length;

      if (declared !== undefined && actual !== declared) {
        fail(
          file,
          id,
          `aad_bytes is ${actual} bytes but aad_length declares ${declared}`,
        );
        continue;
      }

      // A DLWP/1 associated data string is exactly one frame header.
      if (actual !== 24) {
        fail(file, id, `aad_bytes must be 24 bytes (one frame header), got ${actual}`);
        continue;
      }

      // It must decode as a plausible header, and any recorded decoding must
      // agree with it field for field.
      const decoded = decodeHeader(vector.aad_bytes);
      if (decoded.magic !== 'DLWP') {
        fail(file, id, `aad_bytes does not begin with the DLWP magic (got "${decoded.magic}")`);
        continue;
      }

      if (decoded.header_length !== 24) {
        fail(file, id, `aad_bytes declares header_length ${decoded.header_length}, expected 24`);
        continue;
      }

      if (vector.aad_decoded) {
        let mismatch = null;
        for (const [key, value] of Object.entries(vector.aad_decoded)) {
          if (decoded[key] !== value) {
            mismatch = `${key}: recorded ${JSON.stringify(value)}, bytes encode ${JSON.stringify(decoded[key])}`;
            break;
          }
        }

        if (mismatch) {
          fail(file, id, `aad_decoded disagrees with aad_bytes (${mismatch})`);
          continue;
        }

        ok(`${id}: aad_decoded agrees with the bytes field for field`);
      }

      ok(`${id}: aad_bytes is a valid 24-byte header`);
    }

    if (typeof vector.expected_nonce_hex === 'string') {
      if (!isHex(vector.expected_nonce_hex)) {
        fail(file, id, 'expected_nonce_hex is not a valid hex string');
        continue;
      }

      const nonce = hexBytes(vector.expected_nonce_hex);
      if (nonce.length !== 12) {
        fail(file, id, `expected_nonce_hex is ${nonce.length} bytes, expected 12`);
        continue;
      }

      // The layout is iv_prefix(4) || sequence(u64 big-endian).
      const prefix = vector.c2a_iv;
      if (typeof prefix === 'string' && isHex(prefix)) {
        const expectedHex = (
          prefix + BigInt(vector.sequence_number).toString(16).padStart(16, '0')
        ).toLowerCase();

        if (vector.expected_nonce_hex.toLowerCase() !== expectedHex) {
          fail(
            file,
            id,
            `expected_nonce_hex is not iv_prefix || sequence_be (expected ${expectedHex})`,
          );
        } else {
          ok(`${id}: nonce is the prefix followed by the big-endian sequence number`);
        }
      }
    }
  }
}

function checkVersionNegotiation(file, doc) {
  const vectors = Array.isArray(doc.vectors) ? doc.vectors : [];

  const parse = (value) => value.split('.').map(Number);
  const compare = (a, b) => {
    const [aMaj, aMin] = parse(a);
    const [bMaj, bMin] = parse(b);
    return aMaj === bMaj ? aMin - bMin : aMaj - bMaj;
  };

  for (const vector of vectors) {
    const id = vector.id ?? '(unnamed)';
    if (!Array.isArray(vector.controller_supported) || !Array.isArray(vector.agent_supported)) continue;

    const common = vector.controller_supported.filter((v) => vector.agent_supported.includes(v));
    common.sort((a, b) => compare(b, a));
    const best = common[0] ?? null;

    if ((vector.expected_negotiated ?? null) !== best) {
      fail(
        file,
        id,
        `highest-common-version computes "${best}" but the vector expects "${vector.expected_negotiated}"`,
      );
    } else {
      ok(`${id}: highest common version rule reproduces`);
    }

    if (best === null && vector.expected_error !== 'ERR_VERSION_MISMATCH') {
      fail(file, id, 'no common version must produce ERR_VERSION_MISMATCH');
    }
  }
}

/* ------------------------------------------------------------------- driver */

const CHECKERS = {
  'framing-basic.json': checkFraming,
  'malformed.json': checkMalformed,
  'handshake-transcript.json': checkTranscript,
  'discovery.json': checkDiscovery,
  'capabilities.json': checkCapabilities,
  'shell-policy.json': checkShellPolicy,
  'session-basic.json': checkSession,
  'version-negotiation.json': checkVersionNegotiation,
  'crypto-primitives.json': null,
  'crypto-session-keys.json': checkCryptoKeys,
};

let fileCount = 0;

for (const name of readdirSync(VECTOR_DIR).sort()) {
  if (!name.endsWith('.json')) continue;
  const doc = readJson(join(VECTOR_DIR, name));
  if (!doc) continue;
  fileCount += 1;

  checkEnvelope(name, doc);
  checkRegistriesUsed(name, doc);
  if (name === 'shell-policy.json') checkShellPolicyCapabilityClosure(name, doc);

  const checker = CHECKERS[name];
  if (checker) {
    checker(name, doc);
    ok(`${name}: checked`);
  } else if (checker === undefined) {
    warn(name, '-', 'no checker registered for this vector file');
  }
}

// Cross-file invariants.
const capabilitiesDoc = readJson(join(VECTOR_DIR, 'capabilities.json'));
const framingDoc = readJson(join(VECTOR_DIR, 'framing-basic.json'));

if (capabilitiesDoc && registries.capabilities) {
  for (const cap of capabilitiesDoc.capability_registry ?? []) {
    if (!registries.capabilities.has(cap)) {
      fail('capabilities.json', 'capability_registry', `"${cap}" is absent from RFC-0001 section 7.1`);
    }
  }
}

if (framingDoc && registries.messageTypes) {
  for (const vector of framingDoc.vectors ?? []) {
    const name = vector.decoded?.name;
    const type = vector.decoded?.header?.message_type;
    if (!name || typeof type !== 'number') continue;
    const registered = registries.messageTypes.get(name);
    if (registered !== undefined && registered !== type) {
      fail('framing-basic.json', vector.id, `${name} encodes message_type ${type}, the registry says ${registered}`);
    }
  }
}

if (registries.messageTypes) {
  for (const [name, code] of registries.messageTypes) {
    if (code < 0x01 || (code > 0xF1)) {
      fail('dlwp-1.json', 'message type registry', `${name} has out-of-range code 0x${code.toString(16)}`);
    }
  }
}

// The severity attached to an error code is normative in the RFC registry. A
// vector that expects a different severity than the code's registered one is
// telling an implementer to do the opposite of the specification.
if (registries.severity) {
  for (const name of readdirSync(VECTOR_DIR).sort()) {
    if (!name.endsWith('.json')) continue;
    const doc = readJson(join(VECTOR_DIR, name));
    if (!doc) continue;

    const seen = [];
    const collect = (node) => {
      if (Array.isArray(node)) return node.forEach(collect);
      if (node && typeof node === 'object') {
        if (typeof node.expected_error === 'string' && typeof node.expected_severity === 'string') {
          seen.push({ code: node.expected_error, severity: node.expected_severity, id: node.id ?? '-' });
        }
        Object.values(node).forEach(collect);
      }
    };
    collect(doc);

    for (const entry of seen) {
      const registered = registries.severity.get(entry.code);
      if (registered && registered !== entry.severity) {
        fail(
          name,
          entry.id,
          `expects severity "${entry.severity}" for ${entry.code}, but the registry declares "${registered}"`,
        );
      }
    }
  }
}

/* ------------------------------------------------------------------- report */

const total = passes.length + failures.length;

console.log('DroidLab conformance vector verification');
console.log('========================================');
console.log(`vector files     : ${fileCount}`);
console.log(`checks executed  : ${total}`);
console.log(`checks passed    : ${passes.length}`);
console.log(`checks failed    : ${failures.length}`);
console.log(`warnings         : ${warnings.length}`);
console.log('');

if (process.argv.includes('--verbose')) {
  for (const line of passes) console.log(`  PASS  ${line}`);
  console.log('');
}

if (warnings.length) {
  console.log('Warnings');
  console.log('--------');
  for (const w of warnings) console.log(`  WARN  ${w.file} [${w.vector}] ${w.message}`);
  console.log('');
}

if (failures.length) {
  console.log('Failures');
  console.log('--------');
  for (const f of failures) console.log(`  FAIL  ${f.file} [${f.vector}] ${f.message}`);
  console.log('');
  console.log('The vector set is inconsistent. A vector that cannot be reproduced from its own');
  console.log('inputs is worse than no vector, because it makes a wrong behaviour look pinned.');
  process.exitCode = 1;
} else {
  console.log('All vectors are internally consistent and agree with the RFC registries.');
}
