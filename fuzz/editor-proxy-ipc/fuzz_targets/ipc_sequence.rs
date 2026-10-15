//! Bidirectional OPERATION SEQUENCES over a daemon and a proxy session (up to 16384 operations per
//! input). Invariants: crate `ioi_editor_proxy_ipc::fuzz_support::run_sequence`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ioi_editor_proxy_ipc::fuzz_support::run_sequence(data);
});
