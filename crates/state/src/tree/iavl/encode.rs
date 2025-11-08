// Path: crates/state/src/tree/iavl/encode.rs

use super::node::IAVLNode;
use ioi_types::error::StateError;

/// Encodes an `IAVLNode` into its canonical byte format, which is the preimage for its hash.
pub(super) fn encode_node_canonical(n: &IAVLNode) -> Result<Vec<u8>, StateError> {
    let mut data = Vec::new();
    if n.is_leaf() {
        data.push(0x00);
        data.extend_from_slice(&n.version.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // height
        data.extend_from_slice(&1u64.to_le_bytes()); // size
        data.extend_from_slice(&(n.key.len() as u32).to_le_bytes());
        data.extend_from_slice(&n.key);
        data.extend_from_slice(&(n.value.len() as u32).to_le_bytes());
        data.extend_from_slice(&n.value);
    } else {
        data.push(0x01);
        data.extend_from_slice(&n.version.to_le_bytes());
        data.extend_from_slice(&n.height.to_le_bytes());
        data.extend_from_slice(&n.size.to_le_bytes());
        data.extend_from_slice(&(n.key.len() as u32).to_le_bytes());
        data.extend_from_slice(&n.key);
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
        data.extend_from_slice(&left);
        data.extend_from_slice(&right);
    }
    Ok(data)
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

// minimal decoder matching `encode_node_canonical`
pub(super) fn decode_node(bytes: &[u8]) -> Option<DecodedNode> {
    let mut rd = bytes;
    let mut take = |n: usize| -> Option<&[u8]> {
        if rd.len() < n {
            return None;
        }
        let (a, b) = rd.split_at(n);
        rd = b;
        Some(a)
    };
    let tag = *take(1)?.get(0)?;
    let ver = u64::from_le_bytes(take(8)?.try_into().ok()?);
    if tag == 0x00 {
        let _height = i32::from_le_bytes(take(4)?.try_into().ok()?); // 0
        let _size = u64::from_le_bytes(take(8)?.try_into().ok()?); // 1
        let klen = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let key = take(klen)?.to_vec();
        let vlen = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let value = take(vlen)?.to_vec();
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
        let h = i32::from_le_bytes(take(4)?.try_into().ok()?);
        let sz = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let klen = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let split = take(klen)?.to_vec();
        let mut lh = [0u8; 32];
        lh.copy_from_slice(take(32)?);
        let mut rh = [0u8; 32];
        rh.copy_from_slice(take(32)?);
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