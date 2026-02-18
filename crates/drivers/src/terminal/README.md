# IOI Terminal Driver

The **IOI Terminal Driver** provides the interface for agents to execute system commands. It acts as the "Hands" of the agent for CLI-based tasks within the IOI Kernel.

It wraps Rust's native process execution with safety mechanisms to ensure that agent-triggered processes do not destabilize the Kernel or hang indefinitely.

## Features

*   **Command Execution**: Executes binaries available in the host system's PATH.
*   **Time-Bounded Execution**: Enforces a strict **5-second timeout** on all commands. If a process exceeds this limit, it is forcibly killed.
*   **Output Capture**: Captures and returns `stdout` for successful commands, or combines execution status and `stderr` for failures.

## Architecture

This driver supports both atomic command execution and persistent shell sessions.

*   `sys__exec`: one-off process execution (piped stdio)
*   `sys__exec_session`: a persistent shell session keyed by agent session (on unix this is PTY-backed so TTY-gated CLIs work)

It is primarily used by the `DesktopAgentService` to fulfill the `sys__exec` tool capability.

## Usage

```rust
use ioi_drivers::terminal::TerminalDriver;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let driver = TerminalDriver::new();

    // Execute a command
    let args = vec!["-la".to_string()];
    match driver.execute("ls", &args).await {
        Ok(output) => println!("Command output:\n{}", output),
        Err(e) => eprintln!("Command failed: {}", e),
    }

    Ok(())
}
```

## Security Model

**⚠️ Critical Warning:** This driver executes code on the host operating system.

Security is **NOT** enforced within this driver itself. It relies entirely on the upstream **Agency Firewall** (`ioi-services/src/agentic/policy`) to sanitize inputs and enforce allowlists before calling `driver.execute()`.

### Security Layers:
1.  **Policy Engine**: Inspects the `ActionRequest` target `sys::exec`.
2.  **Command Allowlist**: The Policy Engine ensures only safe binaries (e.g., `ls`, `whoami`, `ping`) are executed.
3.  **Argument Sanitization**: Checks for shell injection vectors (`;`, `|`, etc.) in the arguments.
4.  **Driver Timeout**: This driver enforces the 5-second hard limit to prevent Denial of Service via hanging processes.

## API Reference

### `execute(command: &str, args: &[String]) -> Result<String>`

Executes the specified binary with arguments.

*   **Returns `Ok(String)`**: If the process exits successfully (exit code 0), returns the content of `stdout`.
*   **Returns `Ok(String)` (Formatted Error)**: If the process exits with a non-zero code, returns a string containing "Command failed:" and the content of `stderr`.
*   **Returns `Err(anyhow::Error)`**: If the command cannot be spawned or times out.
