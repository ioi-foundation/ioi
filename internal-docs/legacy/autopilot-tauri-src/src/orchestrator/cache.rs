use crate::execution::ExecutionResult;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::MemoryRuntime;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

static GLOBAL_EXECUTION_CACHE: Lazy<Mutex<HashMap<String, ExecutionResult>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn compute_cache_key(node_id: &str, config: &Value, input_str: &str) -> [u8; 32] {
    let config_str = serde_json::to_string(config).unwrap_or_default();
    let preimage = format!("{}|{}|{}", node_id, config_str, input_str);

    match sha256(preimage.as_bytes()) {
        Ok(digest) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(digest.as_ref());
            arr
        }
        Err(_) => [0u8; 32],
    }
}

fn fetch_cached_result(
    memory_runtime: &Arc<MemoryRuntime>,
    cache_key: [u8; 32],
) -> Option<ExecutionResult> {
    let payload_json = memory_runtime.load_execution_cache_json(cache_key).ok()??;
    serde_json::from_str::<ExecutionResult>(&payload_json).ok()
}

fn persist_execution_result(
    memory_runtime: &Arc<MemoryRuntime>,
    cache_key: [u8; 32],
    result: &ExecutionResult,
) {
    let Ok(payload_json) = serde_json::to_string(result) else {
        return;
    };

    let _ = memory_runtime.upsert_execution_cache_json(cache_key, &payload_json);
}

pub fn query_cache(
    memory_runtime: &Arc<MemoryRuntime>,
    node_id: String,
    config: Value,
    input_str: String,
) -> Option<ExecutionResult> {
    let key_bytes = compute_cache_key(&node_id, &config, &input_str);
    let key_hex = hex::encode(key_bytes);

    if let Ok(cache) = GLOBAL_EXECUTION_CACHE.lock() {
        if let Some(res) = cache.get(&key_hex) {
            return Some(res.clone());
        }
    }

    let res = fetch_cached_result(memory_runtime, key_bytes);
    if let Some(r) = &res {
        if let Ok(mut cache) = GLOBAL_EXECUTION_CACHE.lock() {
            cache.insert(key_hex, r.clone());
        }
    }

    res
}

pub fn inject_execution_result(
    memory_runtime: &Arc<MemoryRuntime>,
    node_id: String,
    config: Value,
    input_str: String,
    result: ExecutionResult,
) {
    let key_bytes = compute_cache_key(&node_id, &config, &input_str);
    let key_hex = hex::encode(key_bytes);

    if let Ok(mut cache) = GLOBAL_EXECUTION_CACHE.lock() {
        cache.insert(key_hex, result.clone());
    }

    persist_execution_result(memory_runtime, key_bytes, &result);
}
