// Path: crates/state/src/tree/iavl/ops.rs
use super::node::IAVLNode;
use ioi_types::error::StateError;
use std::cmp::Ordering;
use std::sync::Arc;

/// Insert a key-value pair into the tree
pub(crate) fn insert(
    node: Option<Arc<IAVLNode>>,
    key: Vec<u8>,
    value: Vec<u8>,
    version: u64,
) -> Result<Arc<IAVLNode>, StateError> {
    match node {
        None => Ok(Arc::new(IAVLNode::new_leaf(key, value, version)?)),
        Some(n) => {
            if n.is_leaf() {
                match key.cmp(&n.key) {
                    Ordering::Less => {
                        let new_leaf = Arc::new(IAVLNode::new_leaf(key, value, version)?);
                        Ok(Arc::new(IAVLNode::with_children(
                            Vec::new(),
                            Vec::new(),
                            version,
                            Some(new_leaf),
                            Some(n),
                        )?))
                    }
                    Ordering::Greater => {
                        let new_leaf = Arc::new(IAVLNode::new_leaf(key, value, version)?);
                        Ok(Arc::new(IAVLNode::with_children(
                            Vec::new(),
                            Vec::new(),
                            version,
                            Some(n),
                            Some(new_leaf),
                        )?))
                    }
                    Ordering::Equal => {
                        Ok(Arc::new(IAVLNode::new_leaf(n.key.clone(), value, version)?))
                    }
                }
            } else {
                let (new_left, new_right) = if key <= n.key {
                    (
                        Some(insert(n.left.clone(), key, value, version)?),
                        n.right.clone(),
                    )
                } else {
                    (
                        n.left.clone(),
                        Some(insert(n.right.clone(), key, value, version)?),
                    )
                };
                let new_node =
                    IAVLNode::with_children(Vec::new(), Vec::new(), version, new_left, new_right)?;
                IAVLNode::balance(Arc::new(new_node), version)
            }
        }
    }
}

/// Remove a key from the tree
pub(crate) fn remove(
    node: Option<Arc<IAVLNode>>,
    key: &[u8],
    version: u64,
) -> Result<Option<Arc<IAVLNode>>, StateError> {
    match node {
        None => Ok(None),
        Some(n) => match key.cmp(&n.key) {
            Ordering::Less => {
                let new_left = remove(n.left.clone(), key, version)?;
                let new_node = IAVLNode::with_children(
                    n.key.clone(),
                    n.value.clone(),
                    version,
                    new_left,
                    n.right.clone(),
                )?;
                IAVLNode::balance(Arc::new(new_node), version).map(Some)
            }
            Ordering::Greater => {
                let new_right = remove(n.right.clone(), key, version)?;
                let new_node = IAVLNode::with_children(
                    n.key.clone(),
                    n.value.clone(),
                    version,
                    n.left.clone(),
                    new_right,
                )?;
                IAVLNode::balance(Arc::new(new_node), version).map(Some)
            }
            Ordering::Equal => match (n.left.clone(), n.right.clone()) {
                (None, None) => Ok(None),
                (Some(left), None) => Ok(Some(left)),
                (None, Some(right)) => Ok(Some(right)),
                (Some(left), Some(right)) => {
                    let min_right = IAVLNode::find_min(&right);
                    let new_right = remove(Some(right), &min_right.key, version)?;
                    let new_node = IAVLNode::with_children(
                        min_right.key.clone(),
                        min_right.value.clone(),
                        version,
                        Some(left),
                        new_right,
                    )?;
                    IAVLNode::balance(Arc::new(new_node), version).map(Some)
                }
            },
        },
    }
}