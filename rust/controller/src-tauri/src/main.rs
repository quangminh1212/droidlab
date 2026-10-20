//! The controller binary's entry point.
//!
//! Deliberately thin. It configures logging and hands control to Tauri; every module with
//! behaviour in it is in the library next to this file, so that the tests can reach it without
//! linking a window.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]

use droidlab_controller::commands;

fn main() {
    // Logging first, so that a failure during startup is itself logged. A panic in the expect below
    // is the one place in this crate where panicking is the right answer: there is no UI to report
    // to yet, and continuing without a window would leave a process with no way to be quit.
    commands::install_logging();

    // `expect` is denied by the lint above, and the deny is overridden here on purpose. Tauri's
    // `run` returns a `Result`, and the only way it fails is that the window could not be created —
    // a dotfile being unreadable, a WebView2 runtime that is missing. There is nothing to degrade
    // to and nothing to show the user, so the honest thing is to fail loudly with the reason.
    #[allow(clippy::expect_used)]
    commands::run().expect("the controller window failed to start");
}
