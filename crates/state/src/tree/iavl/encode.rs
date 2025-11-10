// Path: crates/state/src/tree/iavl/encode.rs

use super::node::IAVLNode;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::error::StateError;

/// Encodes a leaf node using ICS-23 VarProto length prefixes.
/// MODIFICATION: Aligned with the common Cosmos SDK IAVL profile. The value is
/// pre-hashed with SHA-256 before being included in the final preimage. The prefix
/// is simplified to just the leaf tag `0x00`.
#[inline]
fn encode_leaf_canonical(n: &IAVLNode) -> Result<Vec<u8>, StateError> {
    let key = &n.key;
    // Pre-hash the value to align with the new LeafOp profile.
    let value_hash =
        sha256(&n.value).map_err(|e| StateError::Backend(format!("pre-hash value failed: {e}")))?;

    let mut buf = Vec::with_capacity(
        1 // prefix
        + prost::length_delimiter_len(key.len()) + key.len()
        + prost::length_delimiter_len(value_hash.len()) + value_hash.len(),
    );

    // Simplified leaf prefix (0x00).
    buf.push(0x00);

    // ICS-23: LengthOp::VarProto for key and the pre-hashed value.
    prost::encode_length_delimiter(key.len(), &mut buf)
        .map_err(|e| StateError::Backend(format!("encode varint(key_len): {e}")))?;
    buf.extend_from_slice(key);

    prost::encode_length_delimiter(value_hash.len(), &mut buf)
        .map_err(|e| StateError::Backend(format!("encode varint(value_hash_len): {e}")))?;
    buf.extend_from_slice(&value_hash);

    Ok(buf)
}

/// Encodes an inner node using the established format.
#[inline]
fn encode_inner_canonical(n: &IAVLNode) -> Vec<u8> {
    // This format remains unchanged:
    // 0x01 | version | height | size | u32LE(len(split_key)) | split_key | left_hash | right_hash
    let mut buf = Vec::with_capacity(1 + 8 + 4 + 8 + 4 + n.key.len() + 32 + 32);
    buf.push(0x01);
    buf.extend_from_slice(&n.version.to_le_bytes());
    buf.extend_from_slice(&n.height.to_le_bytes());
    buf.extend_from_slice(&n.size.to_le_bytes());
    buf.extend_from_slice(&(n.key.len() as u32).to_le_bytes());
    buf.extend_from_slice(&n.key);
    let left = n
        .left
        .as_ref()
        .map(|x| x.hash.clone())
        .unwrap_or_else(IAVLNode::empty_hash);
    let right = n
        .right
        .as_ref()
        .map(|x| x.hash.clone())
        .unwrap_or_else(IAVLNode::empty_hash);
    buf.extend_from_slice(&left);
    buf.extend_from_slice(&right);
    buf
}

/// Encodes an `IAVLNode` into its canonical byte format, which is the preimage for its hash.
pub(super) fn encode_node_canonical(n: &IAVLNode) -> Result<Vec<u8>, StateError> {
    if n.is_leaf() {
        encode_leaf_canonical(n)
    } else {
        Ok(encode_inner_canonical(n))
    }
}

// A parsed inner/leaf view (no allocations beyond what's necessary)
#[derive(Clone)]
pub(super) struct DecodedNode {
    pub(super) is_leaf: bool,
    pub(super) version: u64,
    pub(super) height: i32,
    pub(super) size: u64,
    pub(super) split_key: Vec<u8>,   // for inner
    pub(super) key: Vec<u8>,         // for leaf
    pub(super) value: Vec<u8>,       // for leaf
    pub(super) left_hash: [u8; 32],  // for inner
    pub(super) right_hash: [u8; 32], // for inner
}

/// Helper to advance a slice cursor by `n` bytes, returning the advanced part.
fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cursor.len() < n {
        return None;
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Some(head)
}

// minimal decoder matching `encode_node_canonical`
pub(super) fn decode_node(bytes: &[u8]) -> Option<DecodedNode> {
    let mut cursor = bytes;

    let tag = *take(&mut cursor, 1)?.first()?;
    let ver = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?);

    if tag == 0x00 {
        // Leaf node with VarProto lengths
        let _height = i32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?); // 0
        let _size = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?); // 1

        // Use prost to decode varint lengths from the mutable cursor
        let key_len = prost::decode_length_delimiter(&mut cursor).ok()?;
        let key = take(&mut cursor, key_len)?.to_vec();
        let val_len = prost::decode_length_delimiter(&mut cursor).ok()?;
        let value = take(&mut cursor, val_len)?.to_vec();

        if !cursor.is_empty() {
            return None;
        } // Ensure all bytes are consumed

        Some(DecodedNode {
            is_leaf: true,
            version: ver,
            height: 0,
            size: 1,
            split_key: Vec::new(),
            key,
            value,
            left_hash: [0u8; 32],
            right_hash: [0u8; 32],
        })
    } else {
        // Inner node logic is unchanged
        let h = i32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?);
        let sz = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?);
        let klen = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?) as usize;
        let split = take(&mut cursor, klen)?.to_vec();
        let mut lh = [0u8; 32];
        lh.copy_from_slice(take(&mut cursor, 32)?);
        let mut rh = [0u8; 32];
        rh.copy_from_slice(take(&mut cursor, 32)?);
        Some(DecodedNode {
            is_leaf: false,
            version: ver,
            height: h,
            size: sz,
            split_key: split,
            key: Vec::new(),
            value: Vec::new(),
            left_hash: lh,
            right_hash: rh,
        })
    }
}