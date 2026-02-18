use super::*;

fn action_target_for_macro_step(target: &str, _params: &serde_json::Value) -> ActionTarget {
    match target {
        "web__search" | "web__read" => ActionTarget::WebRetrieve,
        "browser__snapshot" => ActionTarget::BrowserInspect,
        "gui__snapshot" => ActionTarget::GuiInspect,
        "browser__navigate"
        | "browser__click"
        | "browser__click_element"
        | "browser__synthetic_click"
        | "browser__scroll"
        | "browser__type"
        | "browser__key" => ActionTarget::BrowserInteract,
        "gui__type" => ActionTarget::GuiType,
        "gui__click" => ActionTarget::GuiClick,
        "sys__exec" | "sys__change_directory" => ActionTarget::SysExec,
        "sys__install_package" => ActionTarget::SysInstallPackage,
        _ => ActionTarget::Custom(target.to_string()),
    }
}

impl OptimizerService {
    /// [NEW] Helper to index a skill in the vector store for semantic retrieval.
    pub(crate) async fn index_skill(
        &self,
        frame_id: u64,
        definition: &LlmToolDefinition,
    ) -> Result<(), TransactionError> {
        let runtime = self.inference.as_ref().ok_or(TransactionError::Invalid(
            "Optimizer has no inference runtime for embedding".into(),
        ))?;

        let scs_mutex = self
            .scs
            .as_ref()
            .ok_or(TransactionError::Invalid("SCS not available".into()))?;

        // Create a semantic representation: "Name: Description"
        let text_to_embed = format!("{}: {}", definition.name, definition.description);

        // Generate embedding
        let vector = runtime
            .embed_text(&text_to_embed)
            .await
            .map_err(|e| TransactionError::Invalid(format!("Failed to embed skill: {}", e)))?;

        // Insert into mHNSW
        let store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock poisoned".into()))?;
        if let Ok(index_arc) = store.get_vector_index() {
            let mut index = index_arc
                .lock()
                .map_err(|_| TransactionError::Invalid("Index lock".into()))?;
            if let Some(idx) = index.as_mut() {
                idx.insert_with_metadata(frame_id, vector, FrameType::Skill, [0u8; 32])
                    .map_err(|e| {
                        TransactionError::Invalid(format!("Index insert failed: {}", e))
                    })?;
            }
        }

        Ok(())
    }
    /// [NEW] Generalizes a raw execution trace into a reusable skill macro.
    pub async fn synthesize_skill_from_trace(
        &self,
        trace: &[StepTrace],
        goal: &str,
    ) -> Result<AgentMacro, TransactionError> {
        let runtime = self
            .inference
            .as_ref()
            .ok_or(TransactionError::Invalid("Inference not available".into()))?;

        // 1. Format Trace
        let transcript = trace
            .iter()
            .map(|s| {
                format!(
                    "Step {}: Action={}\nOutput={}",
                    s.step_index, s.raw_output, s.raw_output
                )
            })
            .collect::<Vec<_>>()
            .join("\n---\n");

        // 2. Prompt Engineering
        let prompt = format!(
            "SYSTEM: You are a Skill Crystallizer. Convert this successful execution trace into a reusable, generalized JSON Macro.
            
            GOAL: {}
            
            TRACE:
            {}
            
            INSTRUCTIONS:
            1. Identify the generic pattern.
            2. Replace specific values (usernames, URLs, file paths) with parameters {{param_name}}.
            3. Generate a JSON schema for the parameters.
            4. Create a sequence of steps mapping inputs to tool calls.
            
            OUTPUT SCHEMA:
            {{
                \"name\": \"snake_case_skill_name\",
                \"description\": \"What this skill does\",
                \"parameters\": {{ \"type\": \"object\", \"properties\": {{ ... }} }},
                \"steps\": [
                    {{ \"target\": \"tool_name\", \"params\": {{ \"arg\": \"{{param_name}}\" }} }}
                ]
            }}
            RETURN JSON ONLY.",
            goal, transcript
        );

        let options = InferenceOptions {
            temperature: 0.1,
            json_mode: true,
            ..Default::default()
        };
        let output_bytes = runtime
            .execute_inference([0u8; 32], prompt.as_bytes(), options)
            .await
            .map_err(|e| TransactionError::Invalid(format!("Skill synthesis failed: {}", e)))?;

        let output_str = String::from_utf8(output_bytes).unwrap_or_default();

        // 3. Parse & Validate
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str
            .rfind('}')
            .map(|i| i + 1)
            .unwrap_or(output_str.len());
        let skill_json: serde_json::Value = serde_json::from_str(&output_str[json_start..json_end])
            .map_err(|e| TransactionError::Invalid(format!("JSON parse failed: {}", e)))?;

        // 4. Construct Macro
        let definition = LlmToolDefinition {
            name: skill_json["name"]
                .as_str()
                .unwrap_or("new_skill")
                .to_string(),
            description: skill_json["description"].as_str().unwrap_or("").to_string(),
            parameters: skill_json["parameters"].to_string(),
        };

        let mut steps = Vec::new();
        if let Some(steps_arr) = skill_json["steps"].as_array() {
            for s in steps_arr {
                let target_str = s["target"].as_str().unwrap_or("");
                let target = action_target_for_macro_step(target_str, &s["params"]);
                let params = serde_json::to_vec(&s["params"]).unwrap_or_default();

                steps.push(ActionRequest {
                    target,
                    params,
                    context: ActionContext {
                        agent_id: "macro".into(),
                        session_id: None,
                        window_id: None,
                    },
                    nonce: 0,
                });
            }
        }

        Ok(AgentMacro {
            definition,
            steps,
            source_trace_hash: [0u8; 32],
            fitness: 1.0,
        })
    }

    /// [NEW] Validates a synthesized skill (Static Analysis).
    pub fn validate_skill(&self, skill: &AgentMacro) -> Result<(), TransactionError> {
        if skill.steps.is_empty() {
            return Err(TransactionError::Invalid("Skill has no steps".into()));
        }
        // Future: Check policy violations in template strings
        Ok(())
    }
    /// Analyzes a failure trace and synthesizes a new Skill (Macro) to fix it.
    /// This is the "System 2" intervention.
    pub async fn synthesize_recovery_skill(
        &self,
        session_id: [u8; 32],
        trace: &StepTrace,
    ) -> Result<AgentMacro, TransactionError> {
        let scs_mutex = self
            .scs
            .as_ref()
            .ok_or(TransactionError::Invalid("SCS not available".into()))?;
        let runtime = self
            .inference
            .as_ref()
            .ok_or(TransactionError::Invalid("Inference not available".into()))?;

        // 1. Prompt Engineering for Repair
        let prompt = format!(
            "SYSTEM: You are the IOI Optimizer. An agent got stuck.
            
            FAILURE CONTEXT:
            Goal: (Infer from trace)
            Last Action: {}
            Error: {:?}
            
            TASK:
            Write a JSON Skill Macro that robustly solves this specific step.
            Use atomic tools (mouse_move, key, wait) or higher-level tools (browser__navigate) as needed.
            
            OUTPUT SCHEMA:
            {{
                \"name\": \"fix_<short_desc>\",
                \"description\": \"Recovered skill for <failure>\",
                \"parameters\": {{ \"type\": \"object\", \"properties\": {{}} }},
                \"steps\": [
                    {{ \"target\": \"tool_name\", \"params\": {{ ... }} }}
                ]
            }}
            RETURN JSON ONLY.",
            trace.raw_output,
            trace.error
        );

        let options = InferenceOptions {
            temperature: 0.2,
            json_mode: true,
            ..Default::default()
        };
        let output_bytes = runtime
            .execute_inference([0u8; 32], prompt.as_bytes(), options)
            .await
            .map_err(|e| {
                TransactionError::Invalid(format!("Optimization inference failed: {}", e))
            })?;

        let output_str = String::from_utf8(output_bytes).unwrap_or_default();

        // 2. Parse & Validate
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str
            .rfind('}')
            .map(|i| i + 1)
            .unwrap_or(output_str.len());
        let skill_json: serde_json::Value = serde_json::from_str(&output_str[json_start..json_end])
            .map_err(|e| TransactionError::Invalid(format!("Skill synthesis failed: {}", e)))?;

        // Construct Macro object
        let definition = LlmToolDefinition {
            name: skill_json["name"]
                .as_str()
                .unwrap_or("recovery_skill")
                .to_string(),
            description: skill_json["description"]
                .as_str()
                .unwrap_or("Auto-generated recovery")
                .to_string(),
            parameters: skill_json["parameters"].to_string(),
        };

        let mut steps = Vec::new();
        if let Some(steps_arr) = skill_json["steps"].as_array() {
            for s in steps_arr {
                let target_str = s["target"].as_str().unwrap_or("");
                let target = action_target_for_macro_step(target_str, &s["params"]);
                let params = serde_json::to_vec(&s["params"]).unwrap_or_default();

                steps.push(ActionRequest {
                    target,
                    params,
                    context: ActionContext {
                        agent_id: "macro".into(),
                        session_id: None,
                        window_id: None,
                    },
                    nonce: 0,
                });
            }
        }

        let skill = AgentMacro {
            definition,
            steps,
            source_trace_hash: [0u8; 32],
            fitness: 0.5, // Initial tentative score
        };

        // 3. Persist to SCS (Hotfix)
        let skill_bytes =
            codec::to_bytes_canonical(&skill).map_err(TransactionError::Serialization)?;
        let hash = sha256(&skill_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(hash.as_ref());

        // Scope the lock
        let frame_id = {
            let mut store = scs_mutex
                .lock()
                .map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
            store
                .append_frame(
                    FrameType::Skill,
                    &skill_bytes,
                    0,
                    [0u8; 32],
                    session_id,
                    // [FIX] Added retention policy (Archival for learned skills)
                    RetentionClass::Archival,
                )
                .map_err(|e| TransactionError::Invalid(e.to_string()))?
        };

        // 4. Index immediately so it's discoverable
        self.index_skill(frame_id, &skill.definition).await?;

        log::info!(
            "Optimizer: Synthesized Recovery Skill '{}' (Hash: {})",
            skill.definition.name,
            hex::encode(hash_arr)
        );

        Ok(skill)
    }
    pub async fn compile_trace(
        &self,
        trace_steps: Vec<StepTrace>,
    ) -> Result<ActionRules, TransactionError> {
        use crate::agentic::rules::{DefaultPolicy, Rule, RuleConditions, Verdict};
        use std::collections::HashSet;

        let mut allowed_domains = HashSet::new();
        let mut allowed_files = HashSet::new();

        for step in trace_steps {
            if !step.success {
                continue;
            }
            if let Ok(tool_call) = serde_json::from_str::<serde_json::Value>(&step.raw_output) {
                if let Some(name) = tool_call["name"].as_str() {
                    let args = &tool_call["arguments"];
                    match name {
                        "browser__navigate" | "net__fetch" => {
                            if let Some(url) = args["url"].as_str() {
                                if let Ok(u) = Url::parse(url) {
                                    if let Some(host) = u.host_str() {
                                        allowed_domains.insert(host.to_string());
                                    }
                                }
                            }
                        }
                        "filesystem__read_file" | "filesystem__write_file" => {
                            if let Some(path) = args["path"].as_str() {
                                allowed_files.insert(path.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let rules = vec![
            Rule {
                rule_id: Some("compiled-network-whitelist".into()),
                target: "net::fetch".into(),
                conditions: RuleConditions {
                    allow_domains: Some(allowed_domains.into_iter().collect()),
                    ..Default::default()
                },
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("compiled-fs-whitelist".into()),
                target: "fs::*".into(),
                conditions: RuleConditions {
                    allow_paths: Some(allowed_files.into_iter().collect()),
                    ..Default::default()
                },
                action: Verdict::Allow,
            },
        ];

        Ok(ActionRules {
            policy_id: format!(
                "frozen-skill-{}",
                hex::encode(ioi_crypto::algorithms::hash::sha256(b"trace").unwrap())
            ),
            defaults: DefaultPolicy::DenyAll,
            ontology_policy: Default::default(),
            pii_controls: Default::default(),
            rules,
        })
    }

    pub async fn crystallize_skill_internal(
        &self,
        session_id: [u8; 32],
        trace_hash: [u8; 32],
        // [NEW] Added optional trace injection for direct synthesis
        trace_data: Option<(&[StepTrace], &str)>,
    ) -> Result<AgentMacro, TransactionError> {
        let scs_mutex = self
            .scs
            .as_ref()
            .ok_or(TransactionError::Invalid("SCS not available".into()))?;

        // 1. Synthesize or Load
        let skill = if let Some((trace, goal)) = trace_data {
            let mut s = self.synthesize_skill_from_trace(trace, goal).await?;
            s.source_trace_hash = trace_hash;
            s
        } else {
            // Fallback for legacy calls (should use synthesize path)
            return Err(TransactionError::Invalid(
                "Direct crystallization requires trace data".into(),
            ));
        };

        // 2. Validate
        self.validate_skill(&skill)?;

        // 3. Persist to SCS
        let skill_bytes =
            codec::to_bytes_canonical(&skill).map_err(TransactionError::Serialization)?;
        let hash = sha256(&skill_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(hash.as_ref());

        let frame_id = {
            let mut store = scs_mutex
                .lock()
                .map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
            store
                .append_frame(
                    FrameType::Skill,
                    &skill_bytes,
                    0,
                    [0u8; 32],
                    session_id,
                    RetentionClass::Archival,
                )
                .map_err(|e| TransactionError::Invalid(e.to_string()))?
        };

        // 4. Index
        self.index_skill(frame_id, &skill.definition).await?;

        log::info!(
            "Optimizer: Crystallized skill '{}' (Hash: {})",
            skill.definition.name,
            hex::encode(hash_arr)
        );

        Ok(skill)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn macro_step_browser_navigate_maps_to_browser_interact_bucket() {
        let target = action_target_for_macro_step(
            "browser__navigate",
            &json!({"url": "https://example.com"}),
        );
        assert_eq!(target, ActionTarget::BrowserInteract);
    }
}
