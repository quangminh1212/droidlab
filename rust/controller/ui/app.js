// The controller's UI. It renders state and calls commands; it holds no session state of its own,
// because the session lives in Rust and a second copy here would be a copy that can disagree.
//
// `app.js` rather than a framework, and deliberately: the surface is a device list, a session
// panel and a status line. A bundler and a component framework for that would be more build
// machinery than the UI it builds, and the CSP gets weaker as the toolchain gets larger.
//
// Everything goes through `window.__TAURI__.core.invoke`. There is no `fetch`, no dynamic script
// loading and no `innerHTML` of anything that came from a device.

/// `@type {typeof window.__TAURI__.core.invoke}` -- the task list's only bridge to Rust.
const invoke = window.__TAURI__.core.invoke;

/// Renders an error into a status line without ever putting device text into the DOM as markup.
///
/// `textContent`, never `innerHTML`. Every string this file displays can originate from a device
/// on the network, and a device is an untrusted input.
function setStatus(node, text, kind) {
  node.textContent = text;
  node.className = `status ${kind ?? ""}`.trim();
}

/// Loads the controller's identity and shows it.
async function loadIdentity() {
  const node = document.getElementById("identity");
  const status = document.getElementById("status");

  try {
    const info = await invoke("controller_info");
    const versions = info.supported_versions.join(", ");
    node.textContent =
      `controller ${info.controller_version} · DLWP/${info.protocol_version} ` +
      `(accepts ${versions})`;
    setStatus(status, "ready", "ok");
  } catch (error) {
    // A failure here means the IPC bridge itself is broken, which is the one thing the UI cannot
    // work around. Reported rather than swallowed.
    node.textContent = "could not read controller identity";
    setStatus(status, `IPC failure: ${String(error)}`, "bad");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadIdentity();
});
