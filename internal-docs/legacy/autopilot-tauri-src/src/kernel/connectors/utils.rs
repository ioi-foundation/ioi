pub(crate) fn decode_hex_32(label: &str, value: &str) -> Result<[u8; 32], String> {
    let normalized = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(normalized).map_err(|e| format!("Invalid {} hex: {}", label, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Invalid {} length: expected 32 bytes, got {}",
            label,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn generate_operation_id() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    out
}

pub(crate) fn generate_op_nonce() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    if out == [0u8; 32] {
        out[0] = 1;
    }
    out
}
