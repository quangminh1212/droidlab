#!/usr/bin/env node
/**
 * DroidLab registry drift checker.
 *
 * RFC-0001 section 11 declares the message-type, error-code and capability
 * registries normative, and docs/rfc/RFC-0001-wire-protocol.md is the source of
 * truth. protocol/registry/dlwp-1.json is the machine-readable encoding of the
 * same registries, so that code and tooling never parse Markdown tables.
 *
 * Two encodings of one registry drift. That drift is the highest-severity class
 * of documentation defect in this project: an implementer reads a capability
 * name out of the RFC, writes it into code, and the conformance vectors reject
 * it — or worse, accept it while a peer that read the other copy does not.
 *
 * So this tool parses the RFC and compares it against the JSON registry in both
 * directions, and fails on any asymmetry. It is deliberately strict:
 *   - a name only in the RFC           -> failure (the JSON registry is stale)
 *   - a name only in the JSON          -> failure (the JSON invented a name)
 *   - a code that disagrees on value   -> failure
 *   - a severity that disagrees        -> failure
 *
 * Exit code is 0 when the two encodings agree exactly, 1 otherwise.
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const RFC_PATH = join(REPO, 'docs', 'rfc', 'RFC-0001-wire-protocol.md');
const REGISTRY_PATH = join(REPO, 'protocol', 'registry', 'dlwp-1.json');

const failures = [];

function fail(what, detail) {
  failures.push(`${what}: ${detail}`);
}

const rfc = readFileSync(RFC_PATH, 'utf8');
const registry = JSON.parse(readFileSync(REGISTRY_PATH, 'utf8'));

/* ------------------------------------------------------------------ RFC side */

function section(startMarker, endMarker) {
  const after = rfc.split(startMarker)[1];
  if (after === undefined) {
    fail('RFC parse', `could not find section starting at "${startMarker}"`);
    return '';
  }
  return after.split(endMarker)[0] ?? '';
}

// Section 4 message types: | `0x01` | `HELLO` | C -> A | 0 | No | ... |
const rfcMessageTypes = new Map();
for (const m of section('## 4. Message types', '## 5.').matchAll(
  /\|\s*`0x([0-9A-Fa-f]{2})`\s*\|\s*`([A-Z_]+)`/g,
)) {
  rfcMessageTypes.set(m[2], parseInt(m[1], 16));
}

// Section 6.2 error codes: | `ERR_MALFORMED` | fatal | ... |
const rfcErrorCodes = new Map();
for (const m of section('### 6.2 Error codes', '### 6.3').matchAll(
  /\|\s*`(ERR_[A-Z_]+)`\s*\|\s*`?([a-z]+)`?\s*\|/g,
)) {
  rfcErrorCodes.set(m[1], m[2]);
}

// Section 7.1 capability names: | `screen.mirror` | Video capture ... |
const rfcCapabilities = new Set();
for (const m of section('### 7.1 Capability names', '### 7.2').matchAll(
  /\|\s*`([a-z][a-z0-9]*\.[a-z0-9_]+)`\s*\|/g,
)) {
  rfcCapabilities.add(m[1]);
}

// Section 7.3 default limits: | `max_frame_bytes` | int | `16777216` | ... |
const rfcLimits = new Map();
for (const m of section('### 7.3 `limits`', '### 7.4').matchAll(
  /\|\s*`(max_[a-z_]+|shell_timeout_ms)`\s*\|\s*int\s*\|\s*`(\d+)`/g,
)) {
  rfcLimits.set(m[1], parseInt(m[2], 10));
}

/* ------------------------------------------------------------- registry side */

const regMessageTypes = new Map(registry.message_types.map((e) => [e.name, e.code]));
const regErrorCodes = new Map(registry.error_codes.map((e) => [e.code, e.severity]));
const regCapabilities = new Set(registry.capabilities.map((e) => e.name));
const regLimits = new Map(Object.entries(registry.default_limits));

/* ----------------------------------------------------------- both directions */

function compareMaps(label, rfcSide, regSide, describe) {
  for (const [key, value] of rfcSide) {
    if (!regSide.has(key)) {
      fail(label, `"${key}" is in the RFC but missing from the JSON registry`);
    } else if (regSide.get(key) !== value) {
      fail(label, `"${key}" is ${describe(value)} in the RFC but ${describe(regSide.get(key))} in the JSON registry`);
    }
  }
  for (const key of regSide.keys()) {
    if (!rfcSide.has(key)) {
      fail(label, `"${key}" is in the JSON registry but absent from the RFC`);
    }
  }
}

function compareSets(label, rfcSide, regSide) {
  for (const name of rfcSide) {
    if (!regSide.has(name)) fail(label, `"${name}" is in the RFC but missing from the JSON registry`);
  }
  for (const name of regSide) {
    if (!rfcSide.has(name)) fail(label, `"${name}" is in the JSON registry but absent from the RFC`);
  }
}

compareMaps('message type registry', rfcMessageTypes, regMessageTypes, (v) => `0x${v.toString(16)}`);
compareMaps('error code registry', rfcErrorCodes, regErrorCodes, (v) => `"${v}"`);
compareSets('capability registry', rfcCapabilities, regCapabilities);
compareMaps('default limits', rfcLimits, regLimits, (v) => String(v));

/* --------------------------------------------- internal consistency of JSON */

const declaredNames = new Set(registry.message_types.map((e) => e.name));
const declaredCodes = new Set(registry.message_types.map((e) => e.code));
if (declaredNames.size !== registry.message_types.length) {
  fail('message type registry', 'duplicate message type names');
}
if (declaredCodes.size !== registry.message_types.length) {
  fail('message type registry', 'duplicate message type codes');
}
for (const { code, name } of registry.message_types) {
  if (code < 0x01 || code > 0xf1) {
    fail('message type registry', `${name} has an out-of-range code 0x${code.toString(16)}`);
  }
}

for (const { message_type: type, capability } of registry.message_type_capability) {
  const entry = registry.message_types.find((e) => e.code === type);
  if (!entry) {
    fail('message_type_capability', `maps message type ${type} to a capability, but that type is not registered`);
  }
  if (!regCapabilities.has(capability)) {
    fail('message_type_capability', `${entry?.name ?? type} requires capability "${capability}", which is not registered`);
  }
}

for (const rule of registry.severity_rules ?? []) {
  if (!/fatal|recoverable|warning/.test(rule)) {
    fail('severity_rules', `entry does not mention a severity: "${rule}"`);
  }
}

// Every fatal error code must be covered by the fatal severity rule, because the
// rule is what tells an implementer it must also close the connection.
const fatalCodes = registry.error_codes.filter((e) => e.severity === 'fatal');
if (fatalCodes.length === 0) {
  fail('error code registry', 'no fatal error codes are declared, which cannot be right');
}
if (!(registry.severity_rules ?? []).some((r) => /fatal/.test(r) && /close/i.test(r))) {
  fail('severity_rules', 'no rule states that a fatal error closes the connection');
}

/* ------------------------------------------------------------------- report */

console.log('DroidLab registry drift check');
console.log('=============================');
console.log(`source of truth  : docs/rfc/RFC-0001-wire-protocol.md`);
console.log(`machine registry : protocol/registry/dlwp-1.json`);
console.log('');
console.log(`message types    : RFC ${rfcMessageTypes.size} / registry ${regMessageTypes.size}`);
console.log(`error codes      : RFC ${rfcErrorCodes.size} / registry ${regErrorCodes.size}`);
console.log(`capability names : RFC ${rfcCapabilities.size} / registry ${regCapabilities.size}`);
console.log(`default limits   : RFC ${rfcLimits.size} / registry ${regLimits.size}`);
console.log('');

if (failures.length) {
  console.log('Failures');
  console.log('--------');
  for (const f of failures) console.log(`  FAIL  ${f}`);
  console.log('');
  console.log('The two encodings of the registries disagree. Fix the RFC and the JSON');
  console.log('registry together; a disagreement means one of them is lying to an');
  console.log('implementer who trusted it.');
  process.exitCode = 1;
} else {
  console.log('The RFC and the machine-readable registry agree exactly, in both directions.');
}
