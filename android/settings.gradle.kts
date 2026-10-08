pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

// The protocol core is the only module here so far. A second module, the app, will
// depend on it rather than the other way round: the wire format must not be able to
// reach into the application, which is what keeps it testable on a developer machine
// without a device.
rootProject.name = "droidlab-android"
include(":core-protocol")
project(":core-protocol").projectDir = file("core-protocol")
