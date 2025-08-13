// Path: crates/validator/src/standard/workload_client.rs
use crate::common::{
    ipc::{WorkloadRequest, WorkloadResponse},
    security::SecurityChannel,
};
use anyhow::Result;
use depin_sdk_api::vm::{ExecutionContext, ExecutionOutput};
use std::collections::HashMap;

/// A client-side proxy for communicating with the remote Workload container.
#[derive(Debug, Clone)]
pub struct WorkloadClient {
    channel: SecurityChannel,
}

impl WorkloadClient {
    pub fn new(workload_addr: &str) -> Result<Self> {
        let channel = SecurityChannel::new("orchestration", "workload");
        // We establish the connection here, but in a real-world scenario,
        // this might be lazy or have retry logic.
        tokio::spawn({
            let channel = channel.clone();
            let workload_addr = workload_addr.to_string();
            async move {
                channel
                    .establish_client(&workload_addr, "workload")
                    .await
                    .expect("Failed to connect to Workload container");
            }
        });

        Ok(Self { channel })
    }

    async fn send_and_receive(
        &self,
        request: WorkloadRequest,
    ) -> Result<WorkloadResponse> {
        let request_bytes = serde_json::to_vec(&request)?;
        self.channel.send(&request_bytes).await?;
        let response_bytes = self.channel.receive().await?;
        let response = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        sender: Vec<u8>,
    ) -> Result<(Vec<u8>, HashMap<Vec<u8>, Vec<u8>>)> {
        let request = WorkloadRequest::DeployContract { code, sender };
        match self.send_and_receive(request).await? {
            WorkloadResponse::DeployContract(res) => res.map_err(|e| anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Invalid response type from workload")),
        }
    }

    pub async fn call_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<(ExecutionOutput, HashMap<Vec<u8>, Vec<u8>>)> {
        let request = WorkloadRequest::CallContract {
            address,
            input_data,
            context,
        };
        match self.send_and_receive(request).await? {
            WorkloadResponse::CallContract(res) => res.map_err(|e| anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Invalid response type from workload")),
        }
    }
}