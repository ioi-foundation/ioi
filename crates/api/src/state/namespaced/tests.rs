use super::{service_namespace_prefix, NamespacedStateAccess};
use crate::state::{StateAccess, StateError, StateKVPair, StateScanIter};
use ioi_types::keys::{active_service_key, UPGRADE_ACTIVE_SERVICE_PREFIX};
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Default)]
struct MemState {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl StateAccess for MemState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.map.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.map.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.map.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.map.insert(key.clone(), value.clone());
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        Ok(keys
            .iter()
            .map(|key| self.map.get(key).cloned())
            .collect::<Vec<_>>())
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for (key, value) in inserts {
            self.map.insert(key.clone(), value.clone());
        }
        for key in deletes {
            self.map.remove(key);
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let items: Vec<Result<StateKVPair, StateError>> = self
            .map
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| {
                Ok((
                    Arc::from(key.clone().into_boxed_slice()),
                    Arc::from(value.clone().into_boxed_slice()),
                ))
            })
            .collect();
        Ok(Box::new(items.into_iter()))
    }
}

fn desktop_meta() -> ActiveServiceMeta {
    let mut methods = BTreeMap::new();
    methods.insert("step@v1".to_string(), MethodPermission::User);
    ActiveServiceMeta {
        id: "desktop_agent".to_string(),
        abi_version: 1,
        state_schema: "desktop_agent.v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods,
        allowed_system_prefixes: vec![],
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    }
}

#[test]
fn namespaced_reads_can_access_upgrade_active_registry_without_allowlist() {
    let mut state = MemState::default();
    let global_key = active_service_key("wallet_network");
    state
        .insert(&global_key, b"wallet-meta")
        .expect("insert global active service key");

    let meta = desktop_meta();
    let prefix = service_namespace_prefix("desktop_agent");
    let namespaced = NamespacedStateAccess::new(&mut state, prefix, &meta);

    let value = namespaced
        .get(&global_key)
        .expect("read should succeed")
        .expect("global key should be visible");
    assert_eq!(value, b"wallet-meta");

    let scanned = namespaced
        .prefix_scan(UPGRADE_ACTIVE_SERVICE_PREFIX)
        .expect("scan should succeed")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect scan");
    assert_eq!(scanned.len(), 1);
}

#[test]
fn namespaced_writes_to_upgrade_active_registry_remain_namespaced() {
    let mut state = MemState::default();
    let meta = desktop_meta();
    let ns_prefix = service_namespace_prefix("desktop_agent");
    let global_key = active_service_key("wallet_network");

    {
        let mut namespaced = NamespacedStateAccess::new(&mut state, ns_prefix.clone(), &meta);
        namespaced
            .insert(&global_key, b"scoped")
            .expect("write should succeed");
    }

    assert!(
        state.get(&global_key).expect("global read").is_none(),
        "global key must not be mutated by non-allowlisted write"
    );

    let namespaced_key = [ns_prefix.as_slice(), global_key.as_slice()].concat();
    let scoped = state
        .get(&namespaced_key)
        .expect("namespaced read")
        .expect("namespaced key should exist");
    assert_eq!(scoped, b"scoped");
}
