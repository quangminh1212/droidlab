// Generates android/core-protocol/src/main/kotlin/dev/droidlab/protocol/ErrorCodes.kt
// from protocol/registry/dlwp-1.json, so the Kotlin constants cannot drift from the
// registry. The C# side has an equivalent file whose values are checked by a test;
// this side is generated because the two implementations are siblings and a generated
// table cannot disagree with its source.
//
// Run from the repository root:  node protocol/tools/generate-kotlin-error-codes.cjs
const fs = require('fs');
const path = require('path');

const registryPath = path.join(__dirname, '..', 'registry', 'dlwp-1.json');
const outPath = path.join(
  __dirname,
  '..',
  '..',
  'android',
  'core-protocol',
  'src',
  'main',
  'kotlin',
  'dev',
  'droidlab',
  'protocol',
  'ErrorCodes.kt',
);

const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));

// The Kotlin property name for a code: ERR_FRAME_TOO_LARGE becomes FRAME_TOO_LARGE,
// because the object is already named ErrorCodes and repeating the prefix in every
// member reads as noise at the call site.
const propertyName = (code) => code.replace(/^ERR_/, '');

const seen = new Set();
for (const entry of registry.error_codes) {
  const name = propertyName(entry.code);
  if (seen.has(name)) {
    throw new Error(`duplicate Kotlin property ${name} from ${entry.code}`);
  }
  seen.add(name);
  if (!['warning', 'recoverable', 'fatal'].includes(entry.severity)) {
    throw new Error(`${entry.code} has unknown severity ${entry.severity}`);
  }
}

const lines = [];
lines.push('package dev.droidlab.protocol');
lines.push('');
lines.push('// GENERATED FROM protocol/registry/dlwp-1.json -- DO NOT EDIT BY HAND.');
lines.push('//');
lines.push('// Regenerate with:  node protocol/tools/generate-kotlin-error-codes.cjs');
lines.push('//');
lines.push('// The registry is normative and this file is derived from it, so a change to an');
lines.push('// error code is a change to the registry and then a regeneration. Hand-editing');
lines.push('// here would create a second source of truth, and the copy that is not checked is');
lines.push('// the one that drifts.');
lines.push('');
lines.push('/**');
lines.push(' * The DLWP/1 error codes (RFC-0001 section 6).');
lines.push(' */');
lines.push('enum class ErrorCode(val wireName: String, val severity: Severity) {');

for (const entry of registry.error_codes) {
  const severity = entry.severity.charAt(0).toUpperCase() + entry.severity.slice(1);
  lines.push(`    /** \`${entry.code}\` -- ${entry.severity}. */`);
  lines.push(`    ${propertyName(entry.code)}("${entry.code}", Severity.${severity}),`);
  lines.push('');
}

// Drop the trailing blank line inside the enum body.
if (lines[lines.length - 1] === '') lines.pop();

lines.push('    ;');
lines.push('');
lines.push('    /**');
lines.push('     * Whether this error ends the session.');
lines.push('     *');
lines.push('     * Fatal errors must be followed by SESSION_END and the connection must close.');
lines.push('     * A recoverable one aborts only the affected operation or channel, and the');
lines.push('     * session continues, which is what makes the difference worth modelling rather');
lines.push('     * than leaving to each call site to decide.');
lines.push('     */');
lines.push('    val isFatal: Boolean get() = severity == Severity.Fatal');
lines.push('');
lines.push('    companion object {');
lines.push('        private val byWireName: Map<String, ErrorCode> = entries.associateBy { it.wireName }');
lines.push('');
lines.push('        /**');
lines.push('         * Finds a code by its wire name.');
lines.push('         *');
lines.push('         * @param wireName the name, as it appears on the wire and in the registry.');
lines.push('         * @return the code, or null when it is not one this version knows.');
lines.push('         */');
lines.push('        fun fromWireName(wireName: String): ErrorCode? = byWireName[wireName]');
lines.push('    }');
lines.push('}');
lines.push('');
lines.push('/**');
lines.push(' * The three severities the registry defines.');
lines.push(' */');
lines.push('enum class Severity {');
lines.push('    /** Informational; the session continues. */');
lines.push('    Warning,');
lines.push('');
lines.push('    /** Aborts only the affected operation or channel; the session continues. */');
lines.push('    Recoverable,');
lines.push('');
lines.push('    /** Must be followed by SESSION_END, and the sender must close the connection. */');
lines.push('    Fatal,');
lines.push('}');
lines.push('');

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, lines.join('\n'), 'utf8');

console.log(`wrote ${registry.error_codes.length} error codes to ${path.relative(process.cwd(), outPath)}`);
