# Reliability Suite (E2E)

This suite organizes reliability-focused flows around:

- `browser__inspect -> browser__click`
- `screen__inspect -> screen__click`
- `shell__start` continuity/reset/timeout+failure-class evidence
- `web__search -> web__read -> http__fetch` deterministic retrieval chain
- contract paths for browser/gui/computer/routing interaction tests

## Test Entry

- Integration entrypoint: `crates/cli/tests/reliability_suite_e2e.rs`
- Module root: `crates/cli/tests/reliability_suite/mod.rs`
- Contract module storage: `crates/cli/tests/reliability_suite/contracts/`

Contract-focused integration test entry files in `crates/cli/tests/*.rs` are
kept as thin wrappers (`#[path = ...]`) around this suite's module files.

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
