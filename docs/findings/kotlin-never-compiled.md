# Finding: the Kotlin protocol core has never been compiled

**Status:** open, verified by compiling it. Reproduces on the first `gradle compileKotlin`.

## Summary

`android/core-protocol` is described in the README, the changelog and ADR-0008 as an
implementation that exists, is wired to the shared conformance vectors, and whose *logic* is
proven by the JavaScript mirror in `protocol/tools/check-kotlin-vectors.cjs`. It is not
compiled by anything, anywhere.

That was believed to be an environment limitation: "this project has no Android SDK or Gradle".
It is not. The module is a **plain Kotlin/JVM module with no Android dependency** — its own
`build.gradle.kts` says so — and this machine has JDK 17, Visual Studio, and a full Android SDK
at `C:\Users\GHC\AndroidSdk` (platform `android-34`, build-tools `34.0.0`, cmdline-tools, an
emulator and an AVD). The missing piece was Gradle, and the missing piece after that was
`ANDROID_HOME` being unset, which made every check for an SDK come back negative.

The moment it was compiled, it did not compile.

## Evidence

Compiling the **library** target produced four errors:

```text
core-protocol/build.gradle.kts:60:5
    Type mismatch: inferred type is Directory! but Provider<Directory> was expected

CapabilityNegotiation.kt:87:8
    Unresolved reference 'SortedSet'

FrameHeaderCodec.kt:148:41
    Argument type mismatch: actual type is 'kotlin.Pair<ErrorCode, String>',
    but 'ErrorCode' was expected
FrameHeaderCodec.kt:148:41
    No value passed for parameter 'reason'
```

Compiling the **test** target produced 1111 errors, and they are not all the same mistake. The
first few, from the file that everything else depends on:

```text
Vectors.kt:64:25   No 'get' operator method providing array access.
Vectors.kt:103:37  Function 'component1()' is ambiguous for this expression
Vectors.kt:103:67  Unresolved reference 'asObject'
Vectors.kt:104:32  Unresolved reference 'require'
```

## Why the JavaScript mirror could not see this

The mirror is the right idea for the problem it was built for, and it should stay until this
module compiles in CI. But its blind spot is exactly the class of defect above:

* `operator fun get` is declared on `JsonValue.Obj`, not on `JsonValue`, so `file[property]`
  where `file: JsonValue` does not resolve. **A type error.**
* `EncodeResult.Failure` takes two parameters and is handed one `Pair`. **A type error.**
* `SortedSet` is `java.util.SortedSet`, never imported. **A resolution error.**

The mirror ports arithmetic to JavaScript and checks that the arithmetic holds. It cannot see a
missing import, an ambiguous overload, or a wrong argument count, because JavaScript has none of
those failures. Every check it reports is true and none of them is evidence that the Kotlin
exists as a program.

The README already says this in the abstract — "this validates the Kotlin logic, NOT that the
Kotlin compiles" — and the finding is that the distinction was doing more work than anyone had
measured. The honest reading of "wired to the same vectors" was: *written against them*, never
*run against them*.

## Consequence

Until this module compiles:

* `android/core-protocol` is **not** an implementation. It is a draft.
* The three-sibling model of ADR-0007 has **two** members in practice, not three.
* Any claim that the Kotlin is "wired to the vectors" must be qualified as "written against
  them".
* The mirror must not be retired on the grounds that the Kotlin now compiles — the mirror and
  the compiler check different things, and both are wanted. It may be retired once the Kotlin's
  own tests run in CI and pass, which is a stronger statement than compilation alone.

## What is being done

1. Fix the library errors (four) — done first, because the test target cannot compile until the
   library does.
2. Fix the test errors, which are many but fall into a small number of root causes.
3. **Compile and test the module in CI**, which is the only lasting fix. A source file that
   nothing builds is a file that rots, and this one rotted in the way that is hardest to see:
   it still reads as correct.
4. Correct the README, the changelog and ADR-0008 to state the actual state, with the number of
   errors found, and then to state the new state once they are gone.

The last point is not bookkeeping. The repository's central claim is that it does not assert
things it has not checked, and "the Kotlin is written and wired to the vectors" was one it had
not checked.
