// Path: crates/state/src/tree/iavl/node.rs
use super::encode;
use ioi_types::error::StateError;
use ioi_types::prelude::OptionExt;
use std::cmp::max;
use std::sync::Arc;

/// IAVL tree node with immutable structure
#[derive(Debug, Clone)]
pub(crate) struct IAVLNode {
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) version: u64,
    pub(crate) height: i32,
    pub(crate) size: u64,
    pub(crate) hash: Vec<u8>,
    pub(crate) left: Option<Arc<IAVLNode>>,
    pub(crate) right: Option<Arc<IAVLNode>>,
}

impl IAVLNode {
    /// Create a new leaf node
    pub(crate) fn new_leaf(
        key: Vec<u8>,
        value: Vec<u8>,
        version: u64,
    ) -> Result<Self, StateError> {
        let mut node = Self {
            key,
            value,
            version,
            height: 0,
            size: 1,
            hash: Vec::new(),
            left: None,
            right: None,
        };
        node.hash = node.compute_hash()?;
        Ok(node)
    }

    /// Compute the hash of this node according to the canonical specification.
    fn compute_hash(&self) -> Result<Vec<u8>, StateError> {
        let data = encode::encode_node_canonical(self)?;
        ioi_crypto::algorithms::hash::sha256(&data)
            .map(|h| h.to_vec())
            .map_err(|e| StateError::Backend(e.to_string()))
    }

    /// Provides the canonical hash of an empty/nil child node.
    pub(crate) fn empty_hash() -> Vec<u8> {
        ioi_crypto::algorithms::hash::sha256([])
            .unwrap_or_else(|e| {
                log::error!("CRITICAL: SHA256 of empty slice should not fail: {}", e);
                [0u8; 32]
            })
            .to_vec()
    }

    /// Check if this is a leaf node
    pub(crate) fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    /// Get the height of a node (None is -1)
    fn node_height(node: &Option<Arc<IAVLNode>>) -> i32 {
        node.as_ref().map_or(-1, |n| n.height)
    }

    /// Get the size of a node (None is 0)
    fn node_size(node: &Option<Arc<IAVLNode>>) -> u64 {
        node.as_ref().map_or(0, |n| n.size)
    }

    /// Create a new node with updated children, recomputing the split key.
    pub(crate) fn with_children(
        _key: Vec<u8>, // Key is ignored and recomputed from left subtree
        value: Vec<u8>,
        version: u64,
        left: Option<Arc<IAVLNode>>,
        right: Option<Arc<IAVLNode>>,
    ) -> Result<Self, StateError> {
        let key = if let Some(l) = &left {
            Self::find_max(l).key.clone()
        } else {
            Vec::new()
        };
        let height = 1 + max(Self::node_height(&left), Self::node_height(&right));
        let size = 1 + Self::node_size(&left) + Self::node_size(&right);

        let mut node = Self {
            key,
            value,
            version,
            height,
            size,
            hash: Vec::new(),
            left,
            right,
        };
        node.hash = node.compute_hash()?;
        Ok(node)
    }

    /// Balance factor (right height - left height)
    fn balance_factor(&self) -> i32 {
        Self::node_height(&self.right) - Self::node_height(&self.left)
    }

    /// Single left rotation (RR case around `node`)
    pub(crate) fn rotate_left(
        node: Arc<IAVLNode>,
        version: u64,
    ) -> Result<Arc<IAVLNode>, StateError> {
        let r = node
            .right
            .as_ref()
            .required(StateError::Validation(
                "rotate_left requires right child".into(),
            ))?
            .clone();

        let new_left = Arc::new(Self::with_children(
            Vec::new(),
            Vec::new(),
            version,
            node.left.clone(),
            r.left.clone(),
        )?);

        Ok(Arc::new(Self::with_children(
            Vec::new(),
            Vec::new(),
            version,
            Some(new_left),
            r.right.clone(),
        )?))
    }

    /// Single right rotation (LL case around `node`)
    pub(crate) fn rotate_right(
        node: Arc<IAVLNode>,
        version: u64,
    ) -> Result<Arc<IAVLNode>, StateError> {
        let l = node
            .left
            .as_ref()
            .required(StateError::Validation(
                "rotate_right requires left child".into(),
            ))?
            .clone();

        let new_right = Arc::new(Self::with_children(
            Vec::new(),
            Vec::new(),
            version,
            l.right.clone(),
            node.right.clone(),
        )?);

        Ok(Arc::new(Self::with_children(
            Vec::new(),
            Vec::new(),
            version,
            l.left.clone(),
            Some(new_right),
        )?))
    }

    /// AVL rebalancing
    pub(crate) fn balance(
        mut node: Arc<IAVLNode>,
        version: u64,
    ) -> Result<Arc<IAVLNode>, StateError> {
        let bf = node.balance_factor();

        if bf > 1 {
            if let Some(r) = &node.right {
                if r.balance_factor() < 0 {
                    let rotated_right = Self::rotate_right(r.clone(), version)?;
                    node = Arc::new(Self::with_children(
                        Vec::new(),
                        Vec::new(),
                        version,
                        node.left.clone(),
                        Some(rotated_right),
                    )?);
                }
            }
            return Self::rotate_left(node, version);
        }

        if bf < -1 {
            if let Some(l) = &node.left {
                if l.balance_factor() > 0 {
                    let rotated_left = Self::rotate_left(l.clone(), version)?;
                    node = Arc::new(Self::with_children(
                        Vec::new(),
                        Vec::new(),
                        version,
                        Some(rotated_left),
                        node.right.clone(),
                    )?);
                }
            }
            return Self::rotate_right(node, version);
        }

        Ok(node)
    }

    /// Find the minimum node in a subtree
    pub(crate) fn find_min(node: &Arc<IAVLNode>) -> Arc<IAVLNode> {
        node.left
            .as_ref()
            .map_or_else(|| node.clone(), Self::find_min)
    }

    /// Find the maximum node in a subtree
    pub(crate) fn find_max(node: &Arc<IAVLNode>) -> Arc<IAVLNode> {
        node.right
            .as_ref()
            .map_or_else(|| node.clone(), Self::find_max)
    }

    /// Get a value by key
    pub(crate) fn get(node: &Option<Arc<IAVLNode>>, key: &[u8]) -> Option<Vec<u8>> {
        node.as_ref().and_then(|n| {
            if n.is_leaf() {
                if key == n.key.as_slice() {
                    Some(n.value.clone())
                } else {
                    None
                }
            } else if key <= n.key.as_slice() {
                Self::get(&n.left, key)
            } else {
                Self::get(&n.right, key)
            }
        })
    }

    /// Recursively scan the tree for keys matching a prefix.
    pub(crate) fn range_scan(
        node: &Option<Arc<IAVLNode>>,
        prefix: &[u8],
        results: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) {
        if let Some(n) = node {
            if n.is_leaf() {
                if n.key.starts_with(prefix) {
                    results.push((n.key.clone(), n.value.clone()));
                }
            } else {
                if prefix <= n.key.as_slice() {
                    Self::range_scan(&n.left, prefix, results);
                }
                if prefix > n.key.as_slice() || n.key.starts_with(prefix) {
                    Self::range_scan(&n.right, prefix, results);
                }
            }
        }
    }
}