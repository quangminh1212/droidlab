// DroidLab -- DLWP/1 protocol core, Kotlin implementation.
//
// This module is the Android side's implementation of DLWP/1 (RFC-0001) and the
// supporting specifications. It is deliberately a plain Kotlin/JVM module with no
// Android dependency: the protocol core has to be usable from a unit test on a
// developer machine and from an instrumented test on a device, and the wire format
// has nothing to do with Android.
//
// It is a sibling of windows/DroidLab.Protocol, not a binding to it. ADR-0007 makes
// the conformance vectors the only interop contract between the two, and R3 of the
// layer model keeps them independent: neither language may be the reference for the
// other, because a bug in one would otherwise be copied into the other by
// translation. The two are checked against protocol/vectors/, and that is all.

plugins {
    kotlin("jvm") version "2.0.21"
    `java-library`
}

group = "dev.droidlab"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    // The only test dependency. The protocol core itself has none: it uses the JDK's
    // own crypto and Bouncy Castle is deliberately not required, because a protocol
    // library that pulls a cryptography provider into every consumer is a decision
    // that belongs to the application and not to the wire format.
    testImplementation(kotlin("test"))
}

kotlin {
    // Java 17, matching the JDK the Windows side requires and the oldest that is
    // still supported for Android tooling.
    jvmToolchain(17)

    compilerOptions {
        // A warning in protocol code is a defect, as it is on the C# side where
        // TreatWarningsAsErrors is set for the same reason.
        allWarningsAsErrors.set(true)
    }
}

tasks.test {
    useJUnitPlatform()

    testLogging {
        events("passed", "skipped", "failed")
    }
}

// The vectors live at the repository root and are shared by both implementations.
// Resolving them here rather than copying them is the point of ADR-0007: a copy
// would be a second source of truth, and the copy that is not checked is the one
// that drifts.
val vectorsDirectory: Provider<Directory> =
    layout.projectDirectory.dir("../../protocol/vectors")

tasks.test {
    systemProperty("droidlab.vectors", vectorsDirectory.get().asFile.absolutePath)
}
