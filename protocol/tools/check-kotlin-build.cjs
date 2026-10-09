#!/usr/bin/env node
'use strict';
// Compile and test the Kotlin protocol core.
//
// This gate exists because its absence was the project's largest blind spot. The Kotlin sibling
// was described as "wired to the same vectors" while nothing built it, and the module shipped
// with 1111 compile errors and 10 failing tests. The JavaScript mirror in
// `check-kotlin-vectors.cjs` checks the *arithmetic*, and it could not see any of that: a missing
// import, an ambiguous overload and a wrong argument count are not failures JavaScript has.
// See docs/findings/kotlin-never-compiled.md.
//
// The two gates are complementary and both are wanted:
//
//   check:kotlin        ports the arithmetic to JS and runs it against the real vectors.
//                       Catches a wrong rule even when nothing compiles.
//   check:kotlin-build  compiles and runs the actual Kotlin. Catches everything else.
//
// This one is not in `npm run check`, because it needs a JDK and a Gradle download and
// `npm run check` is documented as running with Node alone. It runs in CI, and
// `npm run check:all` runs both locally.
//
// Usage:
//   node protocol/tools/check-kotlin-build.cjs           # compile + test
//   node protocol/tools/check-kotlin-build.cjs --quick    # compile only

const { spawnSync } = require('node:child_process');
const { existsSync } = require('node:fs');
const { join, dirname } = require('node:path');

const here = __dirname;
const repoRoot = join(here, '..', '..');
const androidDir = join(repoRoot, 'android');

const quick = process.argv.includes('--quick');

/** Windows uses gradlew.bat; everything else uses gradlew. */
const wrapper = process.platform === 'win32' ? 'gradlew.bat' : './gradlew';

function findJavaHome() {
    if (process.env.JAVA_HOME && existsSync(process.env.JAVA_HOME)) {
        return process.env.JAVA_HOME;
    }

    return null;
}

function run(label, args) {
    process.stdout.write(`\n> ${label}\n`);

    const result = spawnSync(wrapper, args, {
        cwd: androidDir,
        stdio: 'inherit',
        shell: process.platform === 'win32',
        env: {
            ...process.env,
            ...(findJavaHome() ? { JAVA_HOME: findJavaHome() } : {}),
            // The wrapper must not phone home for a different version than the one pinned in
            // gradle-wrapper.properties: a gate that silently upgrades its own toolchain is a
            // gate whose result cannot be reproduced from the repository.
            GRADLE_OPTS: '-Dorg.gradle.daemon=false',
        },
    });

    return result.status === 0;
}

function main() {
    console.log('DroidLab Kotlin build check');
    console.log('============================');
    console.log(`module     : android/core-protocol`);
    console.log(`wrapper    : ${wrapper}`);
    console.log(`mode       : ${quick ? 'compile only' : 'compile and test'}`);
    console.log('');

    if (!existsSync(join(androidDir, wrapper))) {
        console.error(`FAIL  the Gradle wrapper is missing from ${androidDir}.`);
        console.error('      Run `gradle wrapper` in android/ and commit the result.');
        process.exit(1);
    }

    const javaHome = findJavaHome();

    if (!javaHome) {
        console.error('FAIL  JAVA_HOME is not set to an existing directory, and the Kotlin');
        console.error('      toolchain is resolved from it. Set JAVA_HOME to a JDK 17 or newer.');
        process.exit(1);
    }

    console.log(`JAVA_HOME  : ${javaHome}`);

    // `--console=plain` so CI logs are readable and the output is diffable. `--no-daemon`
    // because a gate that leaves a background process behind on a build agent is a gate that
    // eventually fails for a reason unrelated to the code.
    const base = ['--no-daemon', '--console=plain', '--stacktrace'];

    const tasks = quick
        ? [':core-protocol:compileKotlin', ':core-protocol:compileTestKotlin']
        : [':core-protocol:test'];

    if (!run(`gradle ${tasks.join(' ')}`, [...tasks, ...base])) {
        console.error('');
        console.error('FAIL  the Kotlin protocol core does not build or does not pass its tests.');
        console.error('      This is the check that was missing while the module shipped with');
        console.error('      1111 compile errors. Do not weaken it: a source file that nothing');
        console.error('      builds is a file that rots in the way that is hardest to see.');
        process.exit(1);
    }

    console.log('');
    console.log('ok    the Kotlin protocol core compiles');

    if (!quick) {
        console.log('ok    every Kotlin test passes against the shared vectors');
        console.log('');
        console.log('NOTE  Compiling is evidence that the code exists and runs. It is not evidence');
        console.log('      that its rules agree with the Rust core or the C# codec -- the vectors');
        console.log('      are that evidence, and `npm run check:kotlin` is where they are applied.');
    }
}

main();
