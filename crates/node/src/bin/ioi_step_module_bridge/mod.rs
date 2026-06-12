mod bridge_dispatch;

pub use bridge_dispatch::run_bridge_response_from_stdin;

#[cfg(test)]
mod proof_tests;
