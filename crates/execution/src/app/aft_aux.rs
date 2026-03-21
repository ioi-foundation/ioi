use ioi_api::app::{Block, ChainTransaction};
use ioi_api::storage::NodeStore;
use ioi_types::app::{
    derive_canonical_collapse_object_with_previous, CanonicalCollapseObject,
    AFT_COLLAPSE_OBJECT_PREFIX,
};
use ioi_types::codec;
use ioi_types::error::ChainError;
use std::collections::BTreeMap;

fn parse_aft_canonical_collapse_height_key(key: &[u8]) -> Option<u64> {
    if !key.starts_with(AFT_COLLAPSE_OBJECT_PREFIX) {
        return None;
    }
    let suffix = &key[AFT_COLLAPSE_OBJECT_PREFIX.len()..];
    let bytes: [u8; 8] = suffix.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn derive_canonical_collapse_for_block_chain(
    store: &dyn NodeStore,
    height: u64,
    cache: &mut BTreeMap<u64, CanonicalCollapseObject>,
) -> Result<Option<CanonicalCollapseObject>, ChainError> {
    if height == 0 {
        return Ok(None);
    }
    if let Some(cached) = cache.get(&height) {
        return Ok(Some(cached.clone()));
    }

    let Some(block) = store.get_block_by_height(height).map_err(|error| {
        ChainError::ExecutionClient(format!(
            "failed to load committed block {height} for AFT auxiliary state: {error}"
        ))
    })?
    else {
        return Ok(None);
    };

    let previous = if height <= 1 {
        None
    } else {
        derive_canonical_collapse_for_block_chain(store, height - 1, cache)?
    };
    let collapse = derive_canonical_collapse_for_block(&block, previous.as_ref())?;
    cache.insert(height, collapse.clone());
    Ok(Some(collapse))
}

pub fn derive_canonical_collapse_for_block(
    block: &Block<ChainTransaction>,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<CanonicalCollapseObject, ChainError> {
    derive_canonical_collapse_object_with_previous(&block.header, &block.transactions, previous)
        .map_err(|error| {
            ChainError::Transaction(format!(
                "failed to derive canonical collapse object for committed AFT block {}: {error}",
                block.header.height
            ))
        })
}

pub fn derive_canonical_collapse_for_height(
    store: &dyn NodeStore,
    height: u64,
) -> Result<Option<CanonicalCollapseObject>, ChainError> {
    let mut cache = BTreeMap::new();
    derive_canonical_collapse_for_block_chain(store, height, &mut cache)
}

pub fn load_aft_auxiliary_raw_state_value(
    store: &dyn NodeStore,
    key: &[u8],
) -> Result<Option<Vec<u8>>, ChainError> {
    let Some(height) = parse_aft_canonical_collapse_height_key(key) else {
        return Ok(None);
    };
    let Some(collapse) = derive_canonical_collapse_for_height(store, height)? else {
        return Ok(None);
    };
    codec::to_bytes_canonical(&collapse)
        .map(Some)
        .map_err(ChainError::Transaction)
}
