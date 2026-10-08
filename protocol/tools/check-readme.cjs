/**
 * Verifies that every file path and internal anchor referenced by README.md
 * exists, and that the counts the README quotes match the repository.
 *
 * A README is documentation that rots silently. The two failure modes that
 * matter most are a link to a file that was renamed, and a quoted number that
 * no longer holds. Both are checked here so the README cannot drift.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');

let failures = 0;
let checked = 0;

function fail(msg) {
  console.log('  FAIL  ' + msg);
  failures += 1;
}
function pass(msg) {
  console.log('  ok    ' + msg);
  checked += 1;
}

console.log('README link check');
console.log('-----------------');

// 1. Every markdown link whose target is a repository-relative path.
const links = [...readme.matchAll(/\]\(([^)#]+)(#[^)]*)?\)/g)].map((m) => m[1]);
const external = (t) => /^https?:\/\//.test(t) || t.startsWith('mailto:');
const unique = [...new Set(links)];

for (const target of unique) {
  if (external(target)) continue;
  const resolved = path.join(ROOT, target);
  if (fs.existsSync(resolved)) {
    pass(target);
  } else {
    fail(`README links to "${target}", which does not exist`);
  }
}

// 2. Anchor links of the form (#heading) must resolve to a heading in README.
const anchors = [...readme.matchAll(/\]\(#([^)]+)\)/g)].map((m) => m[1]);
const headings = [...readme.matchAll(/^#{1,6}\s+(.+)$/gm)].map((m) =>
  m[1]
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-'),
);
for (const anchor of new Set(anchors)) {
  if (headings.includes(anchor)) {
    pass('#' + anchor);
  } else {
    fail(`README links to "#${anchor}", which is not a heading in README.md`);
  }
}

console.log('\nQuoted-fact check');
console.log('-----------------');

// 3. The conformance numbers quoted in the README must match reality.
const summary = require('child_process').execSync(
  'node protocol/tools/test-vectors/verify.mjs',
  { cwd: ROOT, encoding: 'utf8' },
);
const passed = summary.match(/checks passed\s+:\s+(\d+)/)?.[1];
const failed = summary.match(/checks failed\s+:\s+(\d+)/)?.[1];
const files = summary.match(/vector files\s+:\s+(\d+)/)?.[1];
const warnings = summary.match(/warnings\s+:\s+(\d+)/)?.[1];

// The expected values are read out of the README rather than written here. A
// hardcoded expectation checks the README against a stale copy of itself: it
// cannot notice the README drifting, and it fails as soon as the real count
// changes for a good reason. Reading the README means this compares the two
// documents to each other, which is the thing that can actually be wrong.
const readmeNumbers = (label) => {
  const match = readme.match(new RegExp(`${label}\\s*:\\s*(\\d+)`));
  return match?.[1] ?? null;
};

const expectations = [
  ['checks passed', passed, readmeNumbers('checks passed')],
  ['checks failed', failed, readmeNumbers('checks failed')],
  ['vector files', files, readmeNumbers('vector files')],
  ['warnings', warnings, readmeNumbers('warnings')],
];
for (const [label, actual, want] of expectations) {
  if (want === null) fail(`the README does not quote a "${label}" count`);
  else if (actual === want) pass(`${label} = ${actual} (README and the run agree)`);
  else fail(`${label} is ${actual}, README says ${want}`);
}

// The README also quotes the check total in prose, so the badge and the body
// cannot disagree with each other or with the run.
const badge = readme.match(/conformance-(\d+)%2F(\d+)%20checks/);
if (badge) {
  if (badge[1] === passed && badge[2] === passed) {
    pass(`the conformance badge quotes ${passed}`);
  } else {
    fail(`the conformance badge says ${badge[1]}/${badge[2]} but the run passed ${passed}`);
  }
}

// 4. Registry counts quoted in the README.
const registry = JSON.parse(fs.readFileSync(path.join(ROOT, 'protocol/registry/dlwp-1.json'), 'utf8'));

// Each label's expected count comes from the README's own registry-drift block,
// so a genuine change to the registry fails here only when the README was not
// updated with it.
const readmeRegistryCount = (label) => {
  const match = readme.match(new RegExp(`${label}\\s*:\\s*RFC\\s*\\d+\\s*\\/\\s*registry\\s*(\\d+)`));
  return match?.[1] ?? null;
};

const counts = [
  ['message types', registry.message_types.length, readmeRegistryCount('message types')],
  ['error codes', registry.error_codes.length, readmeRegistryCount('error codes')],
  ['capability names', registry.capabilities.length, readmeRegistryCount('capability names')],
  ['limits', Object.keys(registry.default_limits).length, readmeRegistryCount('limits')],
];
for (const [label, actual, want] of counts) {
  if (want === null) fail(`the README does not quote a registry count for "${label}"`);
  else if (actual === Number(want)) pass(`${label} = ${actual} (registry and README agree)`);
  else fail(`${label} is ${actual}, README quotes ${want}`);
}

// 5. Vector file names listed in the README must all exist.
const listed = [...readme.matchAll(/`([a-z-]+\.json)`/g)].map((m) => m[1]);
for (const name of new Set(listed)) {
  const inVectors = fs.existsSync(path.join(ROOT, 'protocol/vectors', name));
  const inRegistry = fs.existsSync(path.join(ROOT, 'protocol/registry', name));
  if (inVectors || inRegistry) pass(`vectors/${name}`);
  else fail(`README names \`${name}\`, which is not a vector or registry file`);
}

// 6. RFC and ADR documents referenced by name must exist.
for (const rfc of ['RFC-0001', 'RFC-0002', 'RFC-0003', 'RFC-0004']) {
  const found = fs
    .readdirSync(path.join(ROOT, 'docs/rfc'))
    .some((f) => f.startsWith(rfc));
  if (found) pass(rfc);
  else fail(`README references ${rfc}, which is missing from docs/rfc/`);
}

console.log('');
if (failures) {
  console.log(`${failures} problem(s) found; ${checked} checks passed.`);
  process.exitCode = 1;
} else {
  console.log(`All ${checked} README checks passed.`);
}
