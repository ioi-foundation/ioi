// crates/test_utils/src/agentic_mock.rs
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde_json::{json, Value};

/// Simulates a real LLM by returning a structurally identical but
/// byte-for-byte different JSON string on each call.
pub fn mock_llm(_canonical_prompt: &str) -> String {
    // A simple mock that always returns the same structure but with randomized elements.
    let mut params = vec![("to", json!("0xabcde12345")), ("amount", json!(50))];

    // **The key to simulating non-determinism**: Shuffle the keys.
    params.shuffle(&mut thread_rng());
    let params_map: serde_json::Map<String, Value> = params
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let output_value = json!({
        "operation_id": "token_transfer",
        "params": Value::Object(params_map),
        "gas_ceiling": 100000,
    });

    // **Another non-deterministic element**: Randomly choose between minified and pretty-printed.
    if rand::random() {
        serde_json::to_string_pretty(&output_value).unwrap()
    } else {
        serde_json::to_string(&output_value).unwrap()
    }
}
