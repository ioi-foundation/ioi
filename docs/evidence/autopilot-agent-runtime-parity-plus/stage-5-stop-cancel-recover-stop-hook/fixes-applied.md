## Fixes Applied

- Added daemon-owned `stop_hook` runtime state with schema `ioi.runtime.stop_hook.v1`.
- Added bridge `control_thread` support for pause, cancel, resume/recover, and deny.
- Added `stop_hooks` to `inspect_thread` so GUI, CLI, and TUI can consume the same runtime contract.
- Blocked queued and direct terminal completion when the latest validation-like command failed.
- Recorded `StopHookBlocked` in the execution ledger for replay/debug distinction from generic missing-evidence gates.

This slice keeps deterministic code in the enforcement/observation role only. It does not author product answers.
