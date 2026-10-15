//! Raw P2D bytes into the stateless decoder and a daemon session (phase and receive flags from the
//! first byte). Invariants: crate `ioi_editor_proxy_ipc::fuzz_support::run_p2d_decode`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ioi_editor_proxy_ipc::fuzz_support::run_p2d_decode(data);
});
