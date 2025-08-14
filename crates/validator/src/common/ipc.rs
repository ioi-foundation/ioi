// Path: crates/validator/src/common/ipc.rs

//! Defines the Inter-Process Communication (IPC) protocol between the
//! Orchestration and Workload containers.

use depin_sdk_api::vm::{ExecutionContext, ExecutionOutput};
use depin_sdk_types::app::ChainTransaction;
use depin_sdk_types::error::ValidatorError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Type aliases to simplify the response definitions and address clippy warnings.
type DeployResult = Result<(Vec<u8>, std::collections::HashMap<Vec<u8>, Vec<u8>>), String>;
type CallResult = Result<(ExecutionOutput, std::collections::HashMap<Vec<u8>, Vec<u8>>), String>;
type QueryResult = Result<ExecutionOutput, String>;
type TxResult = Result<(), String>;
type StakesResult = Result<BTreeMap<String, u64>, String>;

/// A command sent from the Orchestration container to the Workload container.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkloadRequest {
    ExecuteTransaction(ChainTransaction),
    DeployContract {
        code: Vec<u8>,
        sender: Vec<u8>,
    },
    CallContract {
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    },
    QueryContract {
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    },
    GetStakes,
}

/// A response sent from the Workload container back to the Orchestration container.
/// It wraps a `Result` to transport success or failure information across the wire.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkloadResponse {
    ExecuteTransaction(TxResult),
    DeployContract(DeployResult),
    CallContract(CallResult),
    QueryContract(QueryResult),
    GetStakes(StakesResult),
}

// Helper to convert ValidatorError to a serializable String for the response.
impl From<ValidatorError> for WorkloadResponse {
    fn from(e: ValidatorError) -> Self {
        WorkloadResponse::ExecuteTransaction(Err(e.to_string()))
    }
}
