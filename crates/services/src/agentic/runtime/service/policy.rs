use crate::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
use crate::agentic::runtime::keys::AGENT_POLICY_PREFIX;
use crate::agentic::runtime::service::decision_loop::helpers::default_safe_policy;
use ioi_api::state::StateAccess;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub(crate) const GLOBAL_POLICY_SESSION_ID: [u8; 32] = [0u8; 32];

pub(crate) fn action_policy_key(session_id: &[u8; 32]) -> Vec<u8> {
    [AGENT_POLICY_PREFIX, session_id.as_slice()].concat()
}

/// The lifecycle meta-tools a constrained host session must always allow so the agent
/// can conclude the step (every other capability stays under the default gate).
fn constrained_lifecycle_rules() -> Vec<Rule> {
    let allow = |rule_id: &str, target: &str| Rule {
        rule_id: Some(rule_id.to_string()),
        target: target.to_string(),
        conditions: Default::default(),
        action: Verdict::Allow,
    };
    vec![
        allow("allow-complete", "agent__complete"),
        allow("allow-pause", "agent__pause"),
        allow("allow-chat-reply", "chat__reply"),
    ]
}

/// Persist a constrained session policy: the supplied `consequential_rules` are the
/// only allowed consequential capabilities, the lifecycle meta-tools are allowed so
/// the agent can conclude, and every OTHER capability falls through to the default
/// `RequireApproval` gate.
///
/// This is the runtime POLICY DECISION (an `Allow` verdict), not an approval-token
/// bypass: the firewall executes the action because the persisted policy permits the
/// constrained capability, and the per-capability hard guards (workspace boundary for
/// `fs::write`, command allowlist + bwrap sandbox for `sys::exec`) still apply. Callers
/// are expected to have already established the user's authority at their own admission
/// boundary (e.g. the Hypervisor daemon's wallet execution-authority gate) first.
fn install_constrained_session_policy(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    policy_id: &str,
    consequential_rules: Vec<Rule>,
) -> Result<(), TransactionError> {
    let mut rules = consequential_rules;
    rules.extend(constrained_lifecycle_rules());
    let action_rules = ActionRules {
        policy_id: policy_id.to_string(),
        defaults: DefaultPolicy::RequireApproval,
        rules,
        ontology_policy: Default::default(),
        pii_controls: Default::default(),
    };
    let key = action_policy_key(&session_id);
    let bytes = codec::to_bytes_canonical(&action_rules)?;
    state
        .insert(&key, &bytes)
        .map_err(TransactionError::State)?;
    Ok(())
}

/// Constrained session policy whose only consequential allowance is a workspace-scoped
/// file write (`fs::write`). The workspace-boundary check still hard-guards the path.
pub fn install_constrained_workspace_write_policy(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    install_constrained_session_policy(
        state,
        session_id,
        "hypervisor-runtime-host-workspace-write",
        vec![Rule {
            rule_id: Some("allow-fs-write".to_string()),
            target: "fs::write".to_string(),
            conditions: Default::default(),
            action: Verdict::Allow,
        }],
    )
}

/// Constrained session policy whose only consequential allowance is a single shell
/// command (`sys::exec` limited to `command` via the policy command allowlist). The
/// policy engine still hard-denies interpreter/shell binaries (sh/bash/…) regardless,
/// and the bwrap sandbox (network-unshared, workspace-bound) still confines execution.
pub fn install_constrained_shell_exec_policy(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    command: &str,
) -> Result<(), TransactionError> {
    install_constrained_session_policy(
        state,
        session_id,
        "hypervisor-runtime-host-shell-exec",
        vec![Rule {
            rule_id: Some("allow-sys-exec".to_string()),
            target: "sys::exec".to_string(),
            conditions: RuleConditions {
                allow_commands: Some(vec![command.to_string()]),
                ..Default::default()
            },
            action: Verdict::Allow,
        }],
    )
}

/// Constrained session policy whose only consequential allowance is browser navigation
/// (`browser::interact`). The PII egress firewall still inspects the navigated URL (a
/// URL carrying PII is intercepted regardless), and a `file://`/localhost URL is treated
/// as local processing.
pub fn install_constrained_browser_navigation_policy(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    install_constrained_session_policy(
        state,
        session_id,
        "hypervisor-runtime-host-browser-navigation",
        vec![Rule {
            rule_id: Some("allow-browser-interact".to_string()),
            target: "browser::interact".to_string(),
            conditions: Default::default(),
            action: Verdict::Allow,
        }],
    )
}

fn decode_action_rules(bytes: &[u8]) -> Option<ActionRules> {
    codec::from_bytes_canonical::<ActionRules>(bytes).ok()
}

pub(crate) fn load_action_rules_for_session(
    state: &dyn StateAccess,
    session_id: [u8; 32],
) -> Result<ActionRules, TransactionError> {
    let session_key = action_policy_key(&session_id);
    let rules = if let Some(rules) = state
        .get(&session_key)?
        .and_then(|bytes| decode_action_rules(&bytes))
    {
        rules
    } else if session_id != GLOBAL_POLICY_SESSION_ID {
        let global_key = action_policy_key(&GLOBAL_POLICY_SESSION_ID);
        if let Some(rules) = state
            .get(&global_key)?
            .and_then(|bytes| decode_action_rules(&bytes))
        {
            rules
        } else {
            default_safe_policy()
        }
    } else {
        default_safe_policy()
    };

    Ok(rules)
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
