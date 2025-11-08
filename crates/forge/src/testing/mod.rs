// Path: crates/forge/src/testing/mod.rs

//! Contains helper functions for building and running end-to-end tests.
//! These functions are exposed as a public library to allow users of the
//! SDK to write their own integration tests with the same tooling.

pub mod backend;
pub mod rpc;

// New, focused submodules
pub mod assert;
pub mod build;
pub mod cluster;
pub mod docker;
pub mod validator;

// Re-export public items to preserve the API and avoid breaking changes in tests.
pub use assert::{
    assert_log_contains, assert_log_contains_and_return_line, confirm_proposal_passed_state,
    wait_for, wait_for_contract_deployment, wait_for_evidence, wait_for_height,
    wait_for_oracle_data, wait_for_pending_oracle_request, wait_for_quarantine_status,
    wait_for_stake_to_be, wait_until,
};
pub use build::build_test_artifacts;
pub use cluster::{TestCluster, TestClusterBuilder};
pub use rpc::{submit_transaction, submit_transaction_no_wait};
pub use validator::TestValidator;