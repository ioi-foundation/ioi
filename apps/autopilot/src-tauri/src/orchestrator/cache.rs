use crate::execution::ExecutionResult;
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, RetentionClass, SovereignContextStore};
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
    scs: &Arc<Mutex<SovereignContextStore>>,
    cache_key: [u8; 32],
) -> Option<ExecutionResult> {
    let store = scs.lock().ok()?;
    let frame_ids = store.session_index.get(&cache_key)?;
    let last_id = *frame_ids.last()?;
    let payload = store.read_frame_payload(last_id).ok()?;
    serde_json::from_slice::<ExecutionResult>(&payload).ok()
}

fn persist_execution_result(
    scs: &Arc<Mutex<SovereignContextStore>>,
    cache_key: [u8; 32],
    result: &ExecutionResult,
) {
    let Ok(mut store) = scs.lock() else {
        return;
    };
    let Ok(bytes) = serde_json::to_vec(result) else {
        return;
    };

    let _ = store.append_frame(
        FrameType::System,
        &bytes,
        0,
        [0u8; 32],
        cache_key,
        RetentionClass::Ephemeral,
    );
}

pub fn query_cache(
    scs: &Arc<Mutex<SovereignContextStore>>,
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

    let res = fetch_cached_result(scs, key_bytes);
    if let Some(r) = &res {
        if let Ok(mut cache) = GLOBAL_EXECUTION_CACHE.lock() {
            cache.insert(key_hex, r.clone());
        }
    }

    res
}

pub fn inject_execution_result(
    scs: &Arc<Mutex<SovereignContextStore>>,
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

    persist_execution_result(scs, key_bytes, &result);
}
