# IOI OS Driver

The **IOI OS Driver** provides the Kernel with "Context Awareness" regarding the host operating system state. 

Unlike the GUI driver (which handles Input/Output), the OS driver focuses on **metadata and introspection**. Its primary role is to inform the **Agency Firewall** about the currently active context (e.g., "Which window is currently focused?"), allowing for context-aware security policies.

## Features

*   **Active Window Detection**: Retrieves the title of the currently focused application window.
*   **Non-Blocking Integration**: Automatically offloads platform-specific, synchronous OS calls to a blocking thread pool when running inside a Tokio runtime, preventing heartbeat starvation in the Orchestrator.
*   **Cross-Platform**: Built on top of `active-win-pos-rs`, supporting Windows, macOS, and Linux (X11).

## Architecture

The `NativeOsDriver` implements the `OsDriver` trait defined in the API.

### Context-Aware Security
This driver is a critical dependency for the **Policy Engine** (`crates/services/src/agentic/policy`). It enables rules such as:

*   *"Allow `gui::type` ONLY if the active window title contains 'Terminal' or 'VS Code'."*
*   *"Block `gui::click` if the active window is 'Password Manager'."*

This prevents "Context Confusion" attacks where an agent might accidentally (or maliciously) interact with the wrong application.

## Usage

This driver is typically injected into the `DesktopAgentService` and the `PolicyEngine` during node startup.

### Example

```rust
use ioi_drivers::os::NativeOsDriver;
use ioi_api::vm::drivers::os::OsDriver;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let driver = NativeOsDriver::new();

    // Retrieve the active window title
    match driver.get_active_window_title().await? {
        Some(title) => println!("Agent is currently looking at: '{}'", title),
        None => println!("Could not determine active window."),
    }

    Ok(())
}
```

## System Requirements

*   **Linux**: Requires X11 libraries (usually `libxcb`, `libx11`).
*   **macOS**: Requires Accessibility permissions to read window titles of other applications.
*   **Windows**: No special requirements.

## API Reference

### `get_active_window_title() -> Result<Option<String>, VmError>`

Fetches the title of the window currently holding the OS input focus.

*   **Returns `Ok(Some(String))`**: If the window title was successfully retrieved.
*   **Returns `Ok(None)`**: If the OS call failed or returned no data (fail-safe).
*   **Returns `Err(VmError)`**: If a thread joining error or critical failure occurs.