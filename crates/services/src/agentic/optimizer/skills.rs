use super::*;
use crate::agentic::runtime::keys::get_skill_external_evidence_key;
use crate::agentic::skill_registry::{
    build_skill_archival_metadata_json, canonical_skill_hash, generate_published_skill_doc, now_ms,
    skill_archival_content, upsert_published_skill_doc, upsert_skill_record, SKILL_ARCHIVAL_KIND,
    SKILL_ARCHIVAL_SCOPE,
};
use ioi_api::state::StateAccess;
use ioi_memory::NewArchivalMemoryRecord;
use ioi_types::app::agentic::{
    ExternalSkillEvidence, SkillLifecycleState, SkillRecord, SkillSourceType,
};

fn action_target_for_macro_step(target: &str, _params: &serde_json::Value) -> ActionTarget {
    match target {
        "web__search" | "web__read" => ActionTarget::WebRetrieve,
        "media__extract_transcript" => ActionTarget::MediaExtractTranscript,
        "media__extract_evidence" => ActionTarget::MediaExtractMultimodalEvidence,
        "http__fetch" => ActionTarget::NetFetch,
        "browser__inspect" => ActionTarget::BrowserInspect,
        "screen__inspect" => ActionTarget::GuiInspect,
        "browser__navigate"
        | "browser__click"
        | "browser__hover"
        | "browser__move_pointer"
        | "browser__pointer_down"
        | "browser__pointer_up"
        | "browser__click_at"
        | "browser__scroll"
        | "browser__type"
        | "browser__select"
        | "browser__press_key"
        | "browser__copy"
        | "browser__paste"
        | "browser__find_text"
        | "browser__screenshot"
        | "browser__wait"
        | "browser__upload"
        | "browser__list_options"
        | "browser__select_option"
        | "browser__back"
        | "browser__list_tabs"
        | "browser__switch_tab"
        | "browser__close_tab" => ActionTarget::BrowserInteract,
        "screen__type" => ActionTarget::GuiType,
        "screen__click_at" => ActionTarget::GuiClick,
        // Element-targeted click variants should route as GUI clicks (policy/app isolation),
        // but require explicit tool-name preservation for queue replay.
        "screen__click" => ActionTarget::GuiClick,
        "math__eval" => ActionTarget::Custom("math::eval".to_string()),
        "shell__run" | "shell__start" | "shell__reset" | "shell__cd" => ActionTarget::SysExec,
        "package__install" => ActionTarget::SysInstallPackage,
        _ => ActionTarget::Custom(target.to_string()),
    }
}

// Keep this key in sync with queue execution (`crates/services/src/agentic/runtime/service/step/queue/support.rs`).
const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";
const GUI_CLICK_ELEMENT_TOOL_NAME: &str = "screen__click";

fn macro_step_params_with_queue_metadata(
    target_str: &str,
    params: &serde_json::Value,
) -> serde_json::Value {
    let mut out = params.clone();

    let tool_name_override = if matches!(target_str, "screen__click") {
        Some(GUI_CLICK_ELEMENT_TOOL_NAME.to_string())
    } else if target_str.starts_with("browser__")
        && matches!(
            action_target_for_macro_step(target_str, params),
            ActionTarget::BrowserInteract
        )
    {
        Some(target_str.to_string())
    } else if matches!(
        target_str,
        "media__extract_transcript" | "media__extract_evidence"
    ) {
        Some(target_str.to_string())
    } else if matches!(target_str, "shell__start" | "shell__reset") {
        Some(target_str.to_string())
    } else {
        None
    };

    if let Some(tool_name) = tool_name_override {
        match &mut out {
            serde_json::Value::Object(obj) => {
                obj.insert(
                    QUEUE_TOOL_NAME_KEY.to_string(),
                    serde_json::Value::String(tool_name),
                );
            }
            serde_json::Value::Null => {
                let mut obj = serde_json::Map::new();
                obj.insert(
                    QUEUE_TOOL_NAME_KEY.to_string(),
                    serde_json::Value::String(tool_name),
                );
                out = serde_json::Value::Object(obj);
            }
            _ => {}
        }
    }
    out
}

impl OptimizerService {
    /// Persists a skill to archival memory and indexes it for semantic retrieval.
    pub(crate) async fn archive_skill(
        &self,
        skill: &AgentMacro,
        definition: &LlmToolDefinition,
        skill_hash: [u8; 32],
    ) -> Result<i64, TransactionError> {
        let runtime = self.inference.as_ref().ok_or(TransactionError::Invalid(
            "Optimizer has no inference runtime for embedding".into(),
        ))?;
        let memory_runtime = self
            .memory_runtime
            .as_ref()
            .ok_or(TransactionError::Invalid(
                "Memory runtime not available".into(),
            ))?;

        let text_to_embed = skill_archival_content(definition);
        let vector = runtime
            .embed_text(&text_to_embed)
            .await
            .map_err(|e| TransactionError::Invalid(format!("Failed to embed skill: {}", e)))?;
        let metadata_json = build_skill_archival_metadata_json(skill_hash, skill)?;
        let archival_record_id = memory_runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: SKILL_ARCHIVAL_SCOPE.to_string(),
                thread_id: None,
                kind: SKILL_ARCHIVAL_KIND.to_string(),
                content: text_to_embed,
                metadata_json,
            })
            .map_err(|e| TransactionError::Invalid(format!("Skill archival insert failed: {}", e)))?
            .ok_or(TransactionError::Invalid(
                "Memory runtime archival store unavailable".into(),
            ))?;
        memory_runtime
            .upsert_archival_embedding(archival_record_id, &vector)
            .map_err(|e| {
                TransactionError::Invalid(format!("Skill archival index failed: {}", e))
            })?;

        Ok(archival_record_id)
    }

    pub(crate) async fn persist_skill_record(
        &self,
        state: &mut dyn StateAccess,
        source_session_id: Option<[u8; 32]>,
        source_evidence_hash: Option<[u8; 32]>,
        skill: AgentMacro,
        source_type: SkillSourceType,
        lifecycle_state: SkillLifecycleState,
    ) -> Result<SkillRecord, TransactionError> {
        self.validate_skill(&skill)?;

        let skill_hash = canonical_skill_hash(&skill)?;
        let archival_record_id = self
            .archive_skill(&skill, &skill.definition, skill_hash)
            .await?;

        let timestamp = now_ms();
        let mut record = SkillRecord {
            skill_hash,
            archival_record_id,
            macro_body: skill,
            lifecycle_state,
            source_type,
            source_session_id,
            source_evidence_hash,
            benchmark: None,
            publication: None,
            created_at: timestamp,
            updated_at: timestamp,
        };

        if lifecycle_state == SkillLifecycleState::Promoted {
            let (doc, publication) = generate_published_skill_doc(&record)?;
            record.publication = Some(publication);
            upsert_published_skill_doc(state, &doc)?;
        }

        upsert_skill_record(state, &record)?;
        Ok(record)
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
                let args = macro_step_params_with_queue_metadata(target_str, &s["params"]);
                let params = serde_json::to_vec(&args).unwrap_or_default();

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
        state: &mut dyn StateAccess,
        session_id: [u8; 32],
        trace: &StepTrace,
    ) -> Result<SkillRecord, TransactionError> {
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
                let args = macro_step_params_with_queue_metadata(target_str, &s["params"]);
                let params = serde_json::to_vec(&args).unwrap_or_default();

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

        let trace_hash = sha256(&codec::to_bytes_canonical(trace)?)
            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
        let mut source_trace_hash = [0u8; 32];
        source_trace_hash.copy_from_slice(trace_hash.as_ref());

        let skill = AgentMacro {
            definition,
            steps,
            source_trace_hash,
            fitness: 0.5, // Initial tentative score
        };

        let record = self
            .persist_skill_record(
                state,
                Some(session_id),
                None,
                skill,
                SkillSourceType::Recovery,
                SkillLifecycleState::Candidate,
            )
            .await?;

        log::info!(
            "Optimizer: Synthesized Recovery Skill '{}' (Hash: {})",
            record.macro_body.definition.name,
            hex::encode(record.skill_hash)
        );

        Ok(record)
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
                        "browser__navigate" | "http__fetch" => {
                            if let Some(url) = args["url"].as_str() {
                                if let Ok(u) = Url::parse(url) {
                                    if let Some(host) = u.host_str() {
                                        allowed_domains.insert(host.to_string());
                                    }
                                }
                            }
                        }
                        "file__read" | "file__write" => {
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
        state: &mut dyn StateAccess,
        session_id: [u8; 32],
        trace_hash: [u8; 32],
        // [NEW] Added optional trace injection for direct synthesis
        trace_data: Option<(&[StepTrace], &str)>,
    ) -> Result<SkillRecord, TransactionError> {
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

        let record = self
            .persist_skill_record(
                state,
                Some(session_id),
                None,
                skill,
                SkillSourceType::Trace,
                SkillLifecycleState::Candidate,
            )
            .await?;

        log::info!(
            "Optimizer: Crystallized skill '{}' (Hash: {})",
            record.macro_body.definition.name,
            hex::encode(record.skill_hash)
        );

        Ok(record)
    }

    pub async fn synthesize_skill_from_evidence(
        &self,
        evidence: &ExternalSkillEvidence,
    ) -> Result<AgentMacro, TransactionError> {
        let runtime = self
            .inference
            .as_ref()
            .ok_or(TransactionError::Invalid("Inference not available".into()))?;

        let prompt = format!(
            "SYSTEM: You are the IOI Skill Extractor.

SOURCE TYPE: {:?}
SOURCE URI: {}
TITLE: {}

NORMALIZED PROCEDURE:
{}

STRUCTURED HINTS:
{}

TASK:
Convert the normalized procedure into a reusable JSON skill macro.
- Preserve only actions that can be executed by IOI tools.
- Generalize concrete values into parameters.
- Prefer the highest-level safe tool that preserves determinism.
- Return JSON only.

OUTPUT SCHEMA:
{{
  \"name\": \"snake_case_skill_name\",
  \"description\": \"What this skill does\",
  \"parameters\": {{ \"type\": \"object\", \"properties\": {{ }} }},
  \"steps\": [
    {{ \"target\": \"tool_name\", \"params\": {{ }} }}
  ]
}}",
            evidence.source_type,
            evidence.source_uri.as_deref().unwrap_or(""),
            evidence.title.as_deref().unwrap_or(""),
            evidence.normalized_procedure,
            evidence.structured_hints_json.as_deref().unwrap_or("{}"),
        );

        let options = InferenceOptions {
            temperature: 0.1,
            json_mode: true,
            ..Default::default()
        };
        let output_bytes = runtime
            .execute_inference([0u8; 32], prompt.as_bytes(), options)
            .await
            .map_err(|e| {
                TransactionError::Invalid(format!("External skill synthesis failed: {}", e))
            })?;
        let output_str = String::from_utf8(output_bytes).unwrap_or_default();
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str
            .rfind('}')
            .map(|i| i + 1)
            .unwrap_or(output_str.len());
        let skill_json: serde_json::Value = serde_json::from_str(&output_str[json_start..json_end])
            .map_err(|e| TransactionError::Invalid(format!("Skill synthesis failed: {}", e)))?;

        let definition = LlmToolDefinition {
            name: skill_json["name"]
                .as_str()
                .unwrap_or("external_skill")
                .to_string(),
            description: skill_json["description"]
                .as_str()
                .unwrap_or("External evidence skill")
                .to_string(),
            parameters: skill_json["parameters"].to_string(),
        };

        let mut steps = Vec::new();
        if let Some(steps_arr) = skill_json["steps"].as_array() {
            for s in steps_arr {
                let target_str = s["target"].as_str().unwrap_or("");
                let target = action_target_for_macro_step(target_str, &s["params"]);
                let args = macro_step_params_with_queue_metadata(target_str, &s["params"]);
                let params = serde_json::to_vec(&args).unwrap_or_default();
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
            source_trace_hash: evidence.source_trace_hash.unwrap_or([0u8; 32]),
            fitness: 0.5,
        })
    }

    pub async fn ingest_external_skill_evidence_internal(
        &self,
        state: &mut dyn StateAccess,
        evidence: ExternalSkillEvidence,
    ) -> Result<SkillRecord, TransactionError> {
        let evidence_hash_bytes = sha256(&codec::to_bytes_canonical(&evidence)?)
            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
        let mut evidence_hash = [0u8; 32];
        evidence_hash.copy_from_slice(evidence_hash_bytes.as_ref());
        let evidence_key = get_skill_external_evidence_key(&evidence_hash);
        state.insert(&evidence_key, &codec::to_bytes_canonical(&evidence)?)?;

        let skill = self.synthesize_skill_from_evidence(&evidence).await?;
        self.persist_skill_record(
            state,
            evidence.source_session_id,
            Some(evidence_hash),
            skill,
            evidence.source_type,
            SkillLifecycleState::Candidate,
        )
        .await
    }
}

#[cfg(test)]
#[path = "skills/tests.rs"]
mod tests;
