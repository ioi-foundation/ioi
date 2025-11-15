// Path: crates/state/src/tree/iavl/node.rs

use super::encode;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::error::StateError;

/// A hash representing a child node.
pub(crate) type NodeHash = [u8; 32];
/// A canonical hash for an empty/nil child node.
pub(crate) const EMPTY_HASH: NodeHash = [0; 32];

/// IAVL tree node with immutable structure. Now references children by hash.
#[derive(Debug, Clone)]
pub(crate) struct IAVLNode {
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) version: u64,
    pub(crate) height: i32,
    pub(crate) size: u64,
    /// The hash of this node's canonical representation.
    pub hash: NodeHash,
    /// The hash of the left child, if it exists.
    pub left_hash: Option<NodeHash>,
    /// The hash of the right child, if it exists.
    pub right_hash: Option<NodeHash>,
}

impl IAVLNode {
    /// Create a new leaf node and compute its hash.
    pub(crate) fn new_leaf(key: Vec<u8>, value: Vec<u8>, version: u64) -> Result<Self, StateError> {
        let mut node = Self {
            key,
            value,
            version,
            height: 0,
            size: 1,
            hash: EMPTY_HASH, // Temp value, will be computed next.
            left_hash: None,
            right_hash: None,
        };
        node.hash = node.compute_hash()?;
        Ok(node)
    }

    /// Compute the hash of this node according to the canonical specification.
    pub(crate) fn compute_hash(&self) -> Result<NodeHash, StateError> {
        if self.is_leaf() {
            // Build the ICS-23 compliant preimage for hashing.
            // HASH THE VALUE here, for the preimage only.
            let value_hash = sha256(&self.value).map_err(|e| StateError::Backend(e.to_string()))?;

            let mut preimage = vec![0x00]; // Leaf prefix

            // Key Preimage (VarProto length prefixed)
            prost::encode_length_delimiter(self.key.len(), &mut preimage)
                .map_err(|e| StateError::Backend(format!("encode key len: {e}")))?;
            preimage.extend_from_slice(&self.key);

            // Value Preimage (VarProto length prefixed HASH of the value)
            prost::encode_length_delimiter(value_hash.len(), &mut preimage)
                .map_err(|e| StateError::Backend(format!("encode value_hash len: {e}")))?;
            preimage.extend_from_slice(&value_hash);

            return sha256(&preimage).map_err(|e| StateError::Backend(e.to_string()));
        } else {
            // Inner node logic remains unchanged, using the persistence encoding for its preimage.
            let data = encode::encode_node_canonical(self)?;
            sha256(&data).map_err(|e| StateError::Backend(e.to_string()))
        }
    }

    /// Check if this is a leaf node.
    pub(crate) fn is_leaf(&self) -> bool {
        self.left_hash.is_none() && self.right_hash.is_none()
    }

    /// Reconstructs an `IAVLNode` from the raw parts provided by the decoder.
    pub(crate) fn from_decoded(decoded: encode::DecodedNode) -> Result<Self, StateError> {
        let mut node = IAVLNode {
            key: if decoded.is_leaf {
                decoded.key
            } else {
                decoded.split_key
            },
            value: decoded.value,
            version: decoded.version,
            height: decoded.height,
            size: decoded.size,
            hash: EMPTY_HASH, // Will be recomputed and validated.
            left_hash: (decoded.left_hash != EMPTY_HASH).then_some(decoded.left_hash),
            right_hash: (decoded.right_hash != EMPTY_HASH).then_some(decoded.right_hash),
        };
        node.hash = node.compute_hash()?;
        Ok(node)
    }
}
