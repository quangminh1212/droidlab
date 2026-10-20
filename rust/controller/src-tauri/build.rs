//! Build script: generates Tauri's context (the capability manifest and window config) from
//! `tauri.conf.json` at compile time.
//!
//! The only thing worth knowing about it is why it cannot be replaced by a hand-written module:
//! Tauri's ACL and the window definition are derived from the config file, so the config is the
//! source of truth and this reads it. A hand-written equivalent would be a second copy of the
//! config in a different language.
//!
//! Not `#![forbid(unsafe_code)]`: `tauri_build::build()` pulls in code-generation macros that this
//! crate does not control.

#![deny(missing_docs)]

/// Runs Tauri's build steps.
fn main() {
    tauri_build::build()
}
