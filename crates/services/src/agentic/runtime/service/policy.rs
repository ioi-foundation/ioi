use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::keys::AGENT_POLICY_PREFIX;
use crate::agentic::runtime::service::decision_loop::helpers::default_safe_policy;
use ioi_api::state::StateAccess;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub(crate) const GLOBAL_POLICY_SESSION_ID: [u8; 32] = [0u8; 32];

pub(crate) fn action_policy_key(session_id: &[u8; 32]) -> Vec<u8> {
    [AGENT_POLICY_PREFIX, session_id.as_slice()].concat()
}

fn decode_action_rules(bytes: &[u8]) -> Option<ActionRules> {
    codec::from_bytes_canonical::<ActionRules>(bytes).ok()
}

pub(crate) fn load_action_rules_for_session(
    state: &dyn StateAccess,
    session_id: [u8; 32],
) -> Result<ActionRules, TransactionError> {
    let session_key = action_policy_key(&session_id);
    if let Some(rules) = state
        .get(&session_key)?
        .and_then(|bytes| decode_action_rules(&bytes))
    {
        return Ok(rules);
    }

    if session_id != GLOBAL_POLICY_SESSION_ID {
        let global_key = action_policy_key(&GLOBAL_POLICY_SESSION_ID);
        if let Some(rules) = state
            .get(&global_key)?
            .and_then(|bytes| decode_action_rules(&bytes))
        {
            return Ok(rules);
        }
    }

    Ok(default_safe_policy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::rules::{DefaultPolicy, Rule, Verdict};
    use ioi_api::state::namespaced::NamespacedStateAccess;
    use ioi_api::state::{service_namespace_prefix, StateKVPair, StateScanIter};
    use ioi_types::error::StateError;
    use ioi_types::service_configs::{ActiveServiceMeta, Capabilities};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[derive(Default)]
    struct MemoryState {
        values: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl MemoryState {
        fn put_rules(&mut self, session_id: [u8; 32], rules: &ActionRules) {
            self.values.insert(
                action_policy_key(&session_id),
                codec::to_bytes_canonical(rules).expect("encode rules"),
            );
        }
    }

    impl StateAccess for MemoryState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.values.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.values.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.values.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            self.batch_set(inserts)
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let items: Vec<Result<StateKVPair, StateError>> = self
                .values
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.clone()), Arc::from(value.clone()))))
                .collect();
            Ok(Box::new(items.into_iter()))
        }
    }

    fn policy(policy_id: &str, defaults: DefaultPolicy) -> ActionRules {
        ActionRules {
            policy_id: policy_id.to_string(),
            defaults,
            ontology_policy: Default::default(),
            pii_controls: Default::default(),
            rules: vec![Rule {
                rule_id: Some(format!("{policy_id}-allow-complete")),
                target: "agent__complete".to_string(),
                conditions: Default::default(),
                action: Verdict::Allow,
            }],
        }
    }

    #[test]
    fn policy_lookup_falls_back_to_global_policy_for_new_sessions() {
        let mut state = MemoryState::default();
        let global = policy("global-local-runtime", DefaultPolicy::AllowAll);
        state.put_rules(GLOBAL_POLICY_SESSION_ID, &global);

        let loaded = load_action_rules_for_session(&state, [4u8; 32]).expect("load rules");

        assert_eq!(loaded.policy_id, "global-local-runtime");
        assert_eq!(loaded.defaults, DefaultPolicy::AllowAll);
    }

    #[test]
    fn policy_lookup_prefers_session_policy_over_global_policy() {
        let mut state = MemoryState::default();
        let session_id = [9u8; 32];
        state.put_rules(
            GLOBAL_POLICY_SESSION_ID,
            &policy("global-local-runtime", DefaultPolicy::AllowAll),
        );
        state.put_rules(
            session_id,
            &policy("session-specific-runtime", DefaultPolicy::RequireApproval),
        );

        let loaded = load_action_rules_for_session(&state, session_id).expect("load rules");

        assert_eq!(loaded.policy_id, "session-specific-runtime");
        assert_eq!(loaded.defaults, DefaultPolicy::RequireApproval);
    }

    #[test]
    fn policy_lookup_works_through_desktop_agent_namespaced_state() {
        let mut root = MemoryState::default();
        let global = policy("global-local-runtime", DefaultPolicy::AllowAll);
        let namespaced_global_key = [
            service_namespace_prefix("desktop_agent").as_slice(),
            action_policy_key(&GLOBAL_POLICY_SESSION_ID).as_slice(),
        ]
        .concat();
        root.insert(
            &namespaced_global_key,
            &codec::to_bytes_canonical(&global).expect("encode rules"),
        )
        .expect("insert namespaced rules");
        let meta = ActiveServiceMeta {
            id: "desktop_agent".to_string(),
            abi_version: 1,
            state_schema: "v1".to_string(),
            caps: Capabilities::empty(),
            artifact_hash: [0u8; 32],
            activated_at: 0,
            methods: BTreeMap::new(),
            allowed_system_prefixes: Vec::new(),
            generation_id: 0,
            parent_hash: None,
            author: None,
            context_filter: None,
        };
        let namespaced_prefix = service_namespace_prefix("desktop_agent");
        let namespaced_state = NamespacedStateAccess::new(&mut root, namespaced_prefix, &meta);

        let loaded =
            load_action_rules_for_session(&namespaced_state, [4u8; 32]).expect("load rules");

        assert_eq!(loaded.policy_id, "global-local-runtime");
        assert_eq!(loaded.defaults, DefaultPolicy::AllowAll);
    }
}
