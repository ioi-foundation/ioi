use crate::wallet_network::support::hash_bytes;
use ioi_types::error::TransactionError;

pub(super) fn bound_text(input: &str, max_len: usize) -> String {
    let collapsed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(max_len).collect()
}

pub(super) fn deterministic_mock_id(parts: &[&[u8]]) -> Result<String, TransactionError> {
    let mut material = Vec::new();
    for part in parts {
        material.extend_from_slice(part);
        material.extend_from_slice(b"|");
    }
    let digest = hash_bytes(&material)?;
    Ok(format!("msg-{}", hex::encode(&digest[..8])))
}
