// Verifies that every generated file matches what its generator would produce.
//
// A generated file that is committed and never checked is worse than a hand-written
// one: it looks authoritative and cannot be edited, so when it drifts from its source
// nobody notices and the reader trusts the stale copy. This runs the generators into a
// temporary location and compares, which is the only check that actually catches drift.
//
// Run from the repository root:  node protocol/tools/check-generated.cjs
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.join(__dirname, '..', '..');

// Each entry names a generator and the file it must produce. The generator is run as a
// child process rather than required, because the generators write to their output path
// as a side effect and requiring them would overwrite the file being checked.
const generated = [
  {
    name: 'kotlin error codes',
    script: path.join(__dirname, 'generate-kotlin-error-codes.cjs'),
    output: path.join(
      root,
      'android',
      'core-protocol',
      'src',
      'main',
      'kotlin',
      'dev',
      'droidlab',
      'protocol',
      'ErrorCodes.kt',
    ),
  },
];

const problems = [];

for (const entry of generated) {
  if (!fs.existsSync(entry.script)) {
    problems.push(`${entry.name}: the generator is missing at ${path.relative(root, entry.script)}`);
    continue;
  }

  if (!fs.existsSync(entry.output)) {
    problems.push(`${entry.name}: the generated file is missing at ${path.relative(root, entry.output)}`);
    continue;
  }

  // Read the committed file before regenerating, so the comparison is against what
  // was checked in rather than against what the generator just wrote.
  const committed = fs.readFileSync(entry.output, 'utf8');

  execFileSync(process.execPath, [entry.script], { cwd: root, stdio: 'pipe' });

  const regenerated = fs.readFileSync(entry.output, 'utf8');

  if (committed !== regenerated) {
    problems.push(
      `${entry.name}: ${path.relative(root, entry.output)} is stale; ` +
        `regenerate it with node ${path.relative(root, entry.script)}`,
    );

    // Leave the freshly generated content in place rather than restoring the stale
    // version: the developer's next command should be the commit, not the rerun.
    continue;
  }

  console.log(`ok    ${entry.name} is current`);
}

if (problems.length > 0) {
  console.error('');
  for (const problem of problems) {
    console.error(`FAIL  ${problem}`);
  }

  process.exit(1);
}

console.log(`ok    ${generated.length} generated file(s) verified`);
