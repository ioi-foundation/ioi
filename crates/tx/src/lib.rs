// Path: crates/tx/src/lib.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

pub mod settlement;
pub mod system;
pub mod unified;

// [FIX] Re-export SettlementTransaction from types directly or via settlement module if public
// Since SettlementTransaction is in ioi_types, we can just re-export it here for convenience if desired,
// but the previous code tried to re-export from `settlement` mod where it wasn't pub.
// Let's just export SettlementModel from settlement, and let users get Transaction types from ioi_types.
// OR, make it pub use in settlement.
pub use ioi_types::app::SettlementTransaction;
pub use settlement::SettlementModel;

pub use unified::UnifiedTransactionModel;
