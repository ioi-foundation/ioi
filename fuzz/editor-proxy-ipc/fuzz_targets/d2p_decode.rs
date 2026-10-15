//! Raw D2P bytes, with chosen descriptor facts and flags, into the stateless decoder and a proxy
//! session. Invariants: crate `ioi_editor_proxy_ipc::fuzz_support::run_d2p_decode`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ioi_editor_proxy_ipc::fuzz_support::run_d2p_decode(data);
});
