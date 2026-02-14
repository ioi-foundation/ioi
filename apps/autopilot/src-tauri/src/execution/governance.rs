use super::*;

// Governance Logic: Synthesize ActionRules from UI Config
pub(super) fn synthesize_node_policy(node_type: &str, law_config: &Value) -> ActionRules {
    let mut rules = Vec::new();
    let mut conditions = RuleConditions::default();

    if let Some(budget) = law_config.get("budgetCap").and_then(|v| v.as_f64()) {
        if budget > 0.0 {
            conditions.max_spend = Some((budget * 1000.0) as u64);
        }
    }

    if let Some(allowlist) = law_config
        .get("networkAllowlist")
        .and_then(|v| v.as_array())
    {
        let domains: Vec<String> = allowlist
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if !domains.is_empty() {
            conditions.allow_domains = Some(domains);
        }
    }

    let target = match node_type {
        "browser" => "browser::navigate",
        "tool" => "net::fetch",
        "model" => "model::inference",
        "gate" => "gov::gate",
        "code" => "sys::exec",
        _ => "*",
    };

    let require_human = law_config
        .get("requireHumanGate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let action = if require_human {
        Verdict::RequireApproval
    } else {
        Verdict::Allow
    };

    rules.push(Rule {
        rule_id: Some("studio-rule-1".into()),
        target: target.to_string(),
        conditions,
        action,
    });

    ActionRules {
        policy_id: "studio-simulation".into(),
        defaults: DefaultPolicy::DenyAll,
        rules,
        ontology_policy: Default::default(),
    }
}

// Governance Logic: Construct canonical ActionRequest with Session Context
pub(super) fn map_to_action_request(
    node_type: &str,
    logic_config: &Value,
    input_json: &str,
    session_id: Option<String>,
) -> ActionRequest {
    let target = match node_type {
        "browser" => ActionTarget::BrowserNavigateHermetic,
        "tool" => {
            if let Some(endpoint) = logic_config.get("endpoint").and_then(|s| s.as_str()) {
                if endpoint.starts_with("http") {
                    ActionTarget::NetFetch
                } else {
                    ActionTarget::Custom("tool:generic".into())
                }
            } else {
                ActionTarget::Custom("tool:generic".into())
            }
        }
        _ => ActionTarget::Custom(format!("node:{}", node_type)),
    };

    let mut params_obj = json!({});
    let input_ctx: Value = serde_json::from_str(input_json).unwrap_or(json!({}));

    if let Some(url_template) = logic_config
        .get("url")
        .or_else(|| logic_config.get("endpoint"))
        .and_then(|s| s.as_str())
    {
        let final_url = interpolate_template(url_template, &input_ctx);
        params_obj["url"] = json!(final_url);
    }

    if let Some(budget) = logic_config.get("cost").and_then(|v| v.as_u64()) {
        params_obj["total_amount"] = json!(budget);
    }

    let params_bytes = serde_json::to_vec(&params_obj).unwrap_or_default();

    let session_id_bytes: Option<[u8; 32]> = session_id.and_then(|s| {
        let vec = hex::decode(s).ok()?;
        if vec.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&vec);
            Some(arr)
        } else {
            None
        }
    });

    ActionRequest {
        target,
        params: params_bytes,
        context: ActionContext {
            agent_id: "studio-simulator".into(),
            session_id: session_id_bytes,
            window_id: None,
        },
        nonce: 0,
    }
}

/// The Governance Layer
pub(super) async fn check_governance(
    node_type: &str,
    config: &Value,
    input_context: &str,
    session_id: Option<String>,
    tier: GovernanceTier, // [NEW] Accept Tier
) -> Result<(), String> {
    if tier == GovernanceTier::None {
        return Ok(());
    }

    let default_val = serde_json::json!({});
    let law_config = config.get("law").unwrap_or(&default_val);
    let logic_config = config.get("logic").unwrap_or(&default_val);

    let policy = synthesize_node_policy(node_type, law_config);
    let request = map_to_action_request(node_type, logic_config, input_context, session_id);

    // Evaluate against policy + current OS state
    let verdict =
        PolicyEngine::evaluate(&policy, &request, &*SAFETY_MODEL, &*OS_DRIVER, None).await;

    match verdict {
        Verdict::Allow => Ok(()),
        Verdict::Block => {
            // 2. Silent Mode: Only block if it's a "Hard" violation (e.g. key access),
            // otherwise allow but log warning.
            // For MVP, we treat Block as Block, but in production this would differ.
            Err("🛡️ BLOCKED: Policy violation (e.g., Domain not in allowlist)".into())
        }
        Verdict::RequireApproval => {
            // 3. Silent Mode: Auto-approve "Soft" gates
            if tier == GovernanceTier::Silent {
                // Log the bypass
                println!(
                    "[Governance] Auto-approving gate for {} (Silent Mode)",
                    node_type
                );
                Ok(())
            } else {
                Err("🛡️ PAUSED: Execution requires Human Approval (Gate)".into())
            }
        }
    }
}
