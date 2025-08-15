// Path: crates/validator/src/common/ipc.rs

//! Defines the Inter-Process Communication (IPC) protocol between the
//! Orchestration and Workload containers.

use depin_sdk_api::vm::{ExecutionContext, ExecutionOutput};
// FIX: Add Block and ChainStatus to imports
use depin_sdk_types::app::{Block, ChainStatus, ChainTransaction};
use depin_sdk_types::error::ValidatorError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

type DeployResult = Result<(Vec<u8>, std::collections::HashMap<Vec<u8>, Vec<u8>>), String>;
type CallResult = Result<(ExecutionOutput, std::collections::HashMap<Vec<u8>, Vec<u8>>), String>;
type QueryResult = Result<ExecutionOutput, String>;
type TxResult = Result<(), String>;
type StakesResult = Result<BTreeMap<String, u64>, String>;
type VecVecResult = Result<Vec<Vec<u8>>, String>;
type StateRootResult = Result<Vec<u8>, String>;
// FIX: Add type aliases for new responses
type ProcessBlockResult = Result<Block<ChainTransaction>, String>;
type StatusResult = Result<ChainStatus, String>;

/// A command sent from the Orchestration container to the Workload container.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkloadRequest {
    // FIX: Add new request variants
    ProcessBlock(Block<ChainTransaction>),
    GetStatus,
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
    GetAuthoritySet,
    GetValidatorSet,
    GetStateRoot,
    /// A generic request to call a method on a runtime service.
    CallService {
        service_id: String,
        method_id: String,
        params: serde_json::Value,
    },
}

/// A response sent from the Workload container back to the Orchestration container.
/// It wraps a `Result` to transport success or failure information across the wire.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkloadResponse {
    // FIX: Add new response variants
    ProcessBlock(ProcessBlockResult),
    GetStatus(StatusResult),
    ExecuteTransaction(TxResult),
    DeployContract(DeployResult),
    CallContract(CallResult),
    QueryContract(QueryResult),
    GetStakes(StakesResult),
    GetAuthoritySet(VecVecResult),
    GetValidatorSet(VecVecResult),
    GetStateRoot(StateRootResult),
    /// The response from a generic service call.
    CallService(Result<serde_json::Value, String>),
}

impl From<ValidatorError> for WorkloadResponse {
    fn from(e: ValidatorError) -> Self {
        WorkloadResponse::ExecuteTransaction(Err(e.to_string()))
    }
}