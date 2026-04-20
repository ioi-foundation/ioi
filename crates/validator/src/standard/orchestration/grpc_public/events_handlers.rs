use super::*;
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, BlockCommitted, ChainEvent, SubscribeEventsRequest,
};

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn should_log_raw_kernel_event_payloads() -> bool {
    env_truthy("IOI_LOG_RAW_KERNEL_EVENTS") || env_truthy("IOI_LOG_RAW_PROMPTS")
}

fn prefix_hex_4(bytes: &[u8; 32]) -> String {
    hex::encode(&bytes[..4])
}

fn text_fingerprint(text: &str) -> String {
    let hash_hex = sha256(text.as_bytes())
        .map(|digest| hex::encode(digest.as_ref()))
        .unwrap_or_else(|_| "sha256_error".to_string());
    format!(
        "chars={} lines={} hash={}",
        text.chars().count(),
        text.lines().count(),
        hash_hex
    )
}

include!("events_handlers/kernel_summary.rs");

include!("events_handlers/kernel_mapping.rs");

include!("events_handlers/subscription.rs");

#[cfg(test)]
#[path = "events_handlers/workload_event_mapping_tests.rs"]
mod workload_event_mapping_tests;
