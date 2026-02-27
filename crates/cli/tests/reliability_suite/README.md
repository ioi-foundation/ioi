# Reliability Suite (E2E)

This suite organizes reliability-focused flows around:

- `browser__snapshot -> browser__click_element`
- `gui__snapshot -> gui__click_element`
- `sys__exec_session` continuity/reset/timeout+failure-class receipts
- `web__search -> web__read -> net__fetch` deterministic retrieval chain
- parity paths for browser/gui/computer/routing interaction tests

## Test Entry

- Integration entrypoint: `crates/cli/tests/reliability_suite_e2e.rs`
- Module root: `crates/cli/tests/reliability_suite/mod.rs`
- Parity module storage: `crates/cli/tests/reliability_suite/parity/`

Legacy integration test filenames in `crates/cli/tests/*.rs` are kept as
thin wrappers (`#[path = ...]`) so existing `cargo test --test ...` targets
do not change.

## Running

These tests are `#[ignore]` by default because they require local runtime dependencies.

Compile-only:

```bash
cargo test -p ioi-cli --test reliability_suite_e2e --no-run
```

Run ignored tests:

```bash
cargo test -p ioi-cli --test reliability_suite_e2e -- --ignored --nocapture
```

Run phase-0 hardening gate commands:

```bash
bash .github/scripts/run_phase0_reliability_gate.sh
```

Strict gate prerequisites:

- Browser flow needs either `xvfb-run` or an active `DISPLAY`/`WAYLAND_DISPLAY`.
- GUI flow needs `python3` with `tkinter` available (`python3-tk` on Ubuntu/Debian).
