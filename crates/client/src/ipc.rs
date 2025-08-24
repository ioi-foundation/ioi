// Path: crates/client/src/ipc.rs
//! Defines the Inter-Process Communication (IPC) protocol between the
//! Orchestration and Workload containers.

use depin_sdk_api::vm::{ExecutionContext, ExecutionOutput};
use depin_sdk_types::app::{Block, ChainStatus, ChainTransaction};
use depin_sdk_types::error::ValidatorError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

type DeployResult = Result<(Vec<u8>, std::collections::HashMap<Vec<u8>, Vec<u8>>), String>;
type CallResult = Result<(ExecutionOutput, std::collections::HashMap<Vec<u8>, Vec<u8>>), String>;
type QueryResult = Result<ExecutionOutput, String>;
type TxResult = Result<(), String>;
type ScanResult = Result<Vec<(Vec<u8>, Vec<u8>)>, String>;
type StakesResult = Result<BTreeMap<String, u64>, String>;
type VecVecResult = Result<Vec<Vec<u8>>, String>;
type StateRootResult = Result<Vec<u8>, String>;
type ProcessBlockResult = Result<(Block<ChainTransaction>, Vec<Vec<u8>>), String>;
type StatusResult = Result<ChainStatus, String>;
type BlockHashResult = Result<Vec<u8>, String>;
type TallyResult = Result<Vec<String>, String>;

/// A command sent from the Orchestration container to the Workload container.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkloadRequest {
    ProcessBlock(Block<ChainTransaction>),
    GetStatus,
    GetExpectedModelHash,
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
    GetNextStakes,
    GetAuthoritySet,
    GetValidatorSet,
    GetStateRoot,
    GetLastBlockHash,
    CheckAndTallyProposals {
        current_height: u64,
    },
    CallService {
        service_id: String,
        method_id: String,
        params: serde_json::Value,
    },
    PrefixScan(Vec<u8>),
}

/// A response sent from the Workload container back to the Orchestration container.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkloadResponse {
    ProcessBlock(ProcessBlockResult),
    GetStatus(StatusResult),
    GetExpectedModelHash(Result<Vec<u8>, String>),
    ExecuteTransaction(TxResult),
    DeployContract(DeployResult),
    CallContract(CallResult),
    QueryContract(QueryResult),
    GetStakes(StakesResult),
    GetNextStakes(StakesResult),
    GetAuthoritySet(VecVecResult),
    GetValidatorSet(VecVecResult),
    GetStateRoot(StateRootResult),
    GetLastBlockHash(BlockHashResult),
    CheckAndTallyProposals(TallyResult),
    CallService(Result<serde_json::Value, String>),
    PrefixScan(ScanResult),
}

impl From<ValidatorError> for WorkloadResponse {
    fn from(e: ValidatorError) -> Self {
        WorkloadResponse::ExecuteTransaction(Err(e.to_string()))
    }
}
