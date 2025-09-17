// Path: crates/validator/src/rpc.rs
//! The JSON-RPC server for the Orchestration container.

use crate::config::OrchestrationConfig;
use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_client::WorkloadClient;
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_types::app::ChainTransaction;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

#[derive(Deserialize, Debug, Clone, Serialize, Default)]
#[serde(untagged)]
enum JsonId {
    Num(u64),
    Str(String),
    #[default]
    Null,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(untagged)]
enum Params {
    Array(Vec<serde_json::Value>),
    Object(serde_json::Map<String, serde_json::Value>),
    #[default]
    None,
}

#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    method: String,
    #[serde(default)]
    params: Params,
    #[serde(default)]
    id: JsonId,
}

struct RpcAppState {
    tx_pool: Arc<Mutex<VecDeque<ChainTransaction>>>,
    workload_client: Arc<WorkloadClient>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    // [+] Add a channel to kick the consensus ticker when a new tx arrives.
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    config: OrchestrationConfig,
}

fn extract_tx_param(params: &Params) -> Option<serde_json::Value> {
    match params {
        Params::Array(v) => v.first().cloned(),
        Params::Object(m) => m
            .get("tx")
            .cloned()
            .or_else(|| m.get("transaction").cloned()),
        Params::None => None,
    }
}

async fn rpc_handler(
    State(app_state): State<Arc<RpcAppState>>,
    Json(payload): Json<JsonRpcRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let make_ok = |id: &JsonId, result: serde_json::Value| {
        Json(serde_json::json!({"jsonrpc":"2.0","id": id, "result": result}))
    };
    let make_err = |id: &JsonId, code: i64, msg: String| {
        Json(serde_json::json!({"jsonrpc":"2.0","id": id, "error": {"code": code, "message": msg}}))
    };

    match payload.method.as_str() {
        "system.getStatus.v1" => match app_state.workload_client.get_status().await {
            Ok(status) => (
                StatusCode::OK,
                make_ok(&payload.id, serde_json::to_value(status).unwrap()),
            ),
            Err(e) => (
                StatusCode::OK,
                make_err(&payload.id, -32000, format!("Failed to get status: {}", e)),
            ),
        },
        "submit_transaction" | "submit_tx" | "broadcast_tx" | "sendTransaction" => {
            let Some(tx_val) = extract_tx_param(&payload.params) else {
                return (
                    StatusCode::OK,
                    make_err(&payload.id, -32602, "Missing transaction parameter".into()),
                );
            };

            let tx: ChainTransaction = match tx_val {
                serde_json::Value::String(s) => {
                    let bytes = match hex::decode(&s) {
                        Ok(b) => b,
                        Err(_) => BASE64_STANDARD
                            .decode(&s)
                            .unwrap_or_else(|_| s.into_bytes()),
                    };

                    match serde_json::from_slice::<ChainTransaction>(&bytes) {
                        Ok(t) => t,
                        Err(e) => {
                            return (
                                StatusCode::OK,
                                make_err(
                                    &payload.id,
                                    -32602,
                                    format!("Failed to deserialize transaction from string: {}", e),
                                ),
                            );
                        }
                    }
                }
                other_json => match serde_json::from_value(other_json) {
                    Ok(t) => t,
                    Err(e) => {
                        return (
                            StatusCode::OK,
                            make_err(
                                &payload.id,
                                -32602,
                                format!("Failed to deserialize transaction object: {}", e),
                            ),
                        );
                    }
                },
            };

            // Local admission to mempool
            let new_size = {
                let mut pool = app_state.tx_pool.lock().await;
                pool.push_back(tx.clone());
                pool.len()
            };
            log::info!(
                "[RPC] Locally admitted tx to mempool (size now: {}).",
                new_size
            );

            // [+] Kick the consensus ticker to let it know there's new work.
            let _ = app_state.consensus_kick_tx.send(());

            // Gossip to peers
            let wire = serde_json::to_vec(&tx).unwrap();
            if let Err(e) = app_state
                .swarm_command_sender
                .send(SwarmCommand::PublishTransaction(wire))
                .await
            {
                log::warn!("[RPC] Failed to publish tx via gossip: {}", e);
            } else {
                log::info!("[RPC] Published transaction via gossip.");
            }
            (
                StatusCode::OK,
                make_ok(&payload.id, serde_json::json!("Transaction accepted")),
            )
        }
        "query_contract" => {
            let (address_opt, input_opt) = match &payload.params {
                Params::Array(v) => (
                    v.first()
                        .and_then(|x| x.as_str())
                        .and_then(|s| hex::decode(s).ok()),
                    v.get(1)
                        .and_then(|x| x.as_str())
                        .and_then(|s| hex::decode(s).ok()),
                ),
                _ => (None, None),
            };
            match (address_opt, input_opt) {
                (Some(address), Some(input_data)) => {
                    let context = depin_sdk_api::vm::ExecutionContext {
                        caller: vec![],
                        block_height: 0,
                        gas_limit: app_state.config.default_query_gas_limit,
                        contract_address: vec![],
                    };
                    match app_state
                        .workload_client
                        .query_contract(address, input_data, context)
                        .await
                    {
                        Ok(output) => (
                            StatusCode::OK,
                            make_ok(
                                &payload.id,
                                serde_json::json!(hex::encode(output.return_data)),
                            ),
                        ),
                        Err(e) => (
                            StatusCode::OK,
                            make_err(&payload.id, -32000, format!("Contract query failed: {}", e)),
                        ),
                    }
                }
                _ => (
                    StatusCode::OK,
                    make_err(
                        &payload.id,
                        -32602,
                        "Failed to decode hex parameters".into(),
                    ),
                ),
            }
        }
        "query_state" => {
            let key_hex_opt = match &payload.params {
                Params::Array(v) => v.first().and_then(|x| x.as_str()),
                _ => None,
            };

            if let Some(key_hex) = key_hex_opt {
                match hex::decode(key_hex) {
                    Ok(key) => match app_state.workload_client.query_raw_state(&key).await {
                        Ok(Some(value_bytes)) => (
                            StatusCode::OK,
                            make_ok(&payload.id, serde_json::json!(hex::encode(value_bytes))),
                        ),
                        Ok(None) => (
                            StatusCode::OK,
                            make_ok(&payload.id, serde_json::Value::Null),
                        ),
                        Err(e) => (
                            StatusCode::OK,
                            make_err(&payload.id, -32000, format!("State query failed: {}", e)),
                        ),
                    },
                    Err(_) => (
                        StatusCode::OK,
                        make_err(&payload.id, -32602, "Failed to decode hex key".into()),
                    ),
                }
            } else {
                (
                    StatusCode::OK,
                    make_err(&payload.id, -32602, "Missing key parameter".into()),
                )
            }
        }
        _ => (
            StatusCode::OK,
            make_err(
                &payload.id,
                -32601,
                format!("Method '{}' not found", payload.method),
            ),
        ),
    }
}

pub async fn run_rpc_server(
    listen_address: &str,
    tx_pool: Arc<Mutex<VecDeque<ChainTransaction>>>,
    workload_client: Arc<WorkloadClient>,
    swarm_commander: mpsc::Sender<SwarmCommand>,
    // [+] Add a channel to kick the consensus ticker.
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    config: OrchestrationConfig,
) -> Result<JoinHandle<()>> {
    let app_state = Arc::new(RpcAppState {
        tx_pool,
        workload_client,
        swarm_command_sender: swarm_commander,
        consensus_kick_tx,
        config,
    });

    let app = Router::new()
        .route("/", post(rpc_handler))
        .route("/rpc", post(rpc_handler))
        .with_state(app_state);

    let addr: std::net::SocketAddr = listen_address.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("ORCHESTRATION_RPC_LISTENING_ON_{}", listen_address);
    log::info!("RPC server listening on {}", listen_address);

    let handle = tokio::spawn(async move {
        axum::Server::from_tcp(listener.into_std().unwrap())
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    Ok(handle)
}
