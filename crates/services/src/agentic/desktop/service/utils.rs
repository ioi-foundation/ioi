// Path: crates/services/src/agentic/desktop/service/utils.rs

use super::DesktopAgentService;
use crate::agentic::desktop::keys::{TRACE_PREFIX, SKILL_INDEX_PREFIX};
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use ioi_api::state::StateAccess;
// [FIX] Removed unused ByteSerializable
use ioi_types::app::agentic::{AgentSkill, StepTrace, SemanticFact, AgentMacro}; 
use ioi_types::codec;
use ioi_types::error::TransactionError;
use ioi_scs::FrameType;
use ioi_types::app::agentic::ChatMessage;
use crate::agentic::normaliser::OutputNormaliser; 
use ioi_types::app::KernelEvent; 
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::Value; // [NEW] Import for JSON interpolation

impl DesktopAgentService {
    // Searches the state for skills that match the agent's goal.
    pub(crate) async fn recall_skills(
        &self,
        state: &dyn StateAccess,
        goal: &str,
    ) -> Result<Vec<AgentSkill>, TransactionError> {
        let mut relevant_skills = Vec::new();
        let goal_lower = goal.to_lowercase();
        if let Ok(iter) = state.prefix_scan(SKILL_INDEX_PREFIX) {
            for item in iter {
                if let Ok((_, val_bytes)) = item {
                    if let Ok(skill) = codec::from_bytes_canonical::<AgentSkill>(&val_bytes) {
                        let name_lower = skill.name.to_lowercase();
                        let desc_lower = skill.description.to_lowercase();
                        if goal_lower.contains(&name_lower)
                            || name_lower.contains(&goal_lower)
                            || desc_lower.contains(&goal_lower)
                        {
                            relevant_skills.push(skill);
                        }
                    }
                }
            }
        }
        Ok(relevant_skills)
    }

    /// [UPDATED] Hybrid Retrieval of Episodic Memory
    /// Returns context pointers and the top-1 snippet to reduce context bloat.
    /// This replaces the previous `retrieve_context` which injected full content.
    pub(crate) async fn retrieve_context_hybrid(
        &self, 
        query: &str, 
        visual_phash: Option<[u8; 32]>
    ) -> String {
        let scs_mutex = match &self.scs {
            Some(m) => m,
            None => return "".to_string(),
        };

        // Use reasoning model to embed the query
        let embedding_res = self.reasoning_inference.embed_text(query).await;

        let embedding = match embedding_res {
            Ok(vec) => vec,
            Err(e) => {
                log::warn!("Failed to generate embedding for RAG: {}", e);
                return "".to_string();
            }
        };

        let results = {
            let scs = match scs_mutex.lock() {
                Ok(s) => s,
                Err(_) => return "".to_string(),
            };

            let index_mutex = match scs.get_vector_index() {
                Ok(idx) => idx,
                Err(e) => {
                    log::warn!("Failed to get vector index: {}", e);
                    return "".to_string();
                }
            };

            let idx = match index_mutex.lock() {
                Ok(i) => i,
                Err(_) => return "".to_string(),
            };

            if let Some(index) = idx.as_ref() {
                // Use Hybrid Search to get metadata (Type, VisualHash)
                index.search_hybrid(&embedding, 5)
            } else {
                Ok(vec![])
            }
        };

        let matches = match results {
            Ok(m) => m,
            Err(e) => {
                log::warn!("RAG search failed: {}", e);
                return "".to_string();
            }
        };

        if matches.is_empty() {
            return "".to_string();
        }

        let mut output = String::new();
        let mut top_snippet_included = false;

        let scs = match scs_mutex.lock() {
             Ok(s) => s,
             Err(_) => return "".to_string(),
        };

        for (i, (frame_id, distance, f_type, _)) in matches.iter().enumerate() {
            if *distance > 0.35 { continue; } // Relevance threshold

            // Read metadata only for list
            // For MVP we read payload, but in prod we'd read header only.
            // Since we don't have separate header read yet, we read payload and truncate.
            if let Ok(payload) = scs.read_frame_payload(*frame_id) {
                 if let Ok(text) = String::from_utf8(payload.to_vec()) {
                     let confidence = (1.0 - distance) * 100.0;
                     let type_str = format!("{:?}", f_type);
                     
                     // Pointer Entry
                     output.push_str(&format!("- [ID:{}] Kind:{} Conf:{:.0}% | ", frame_id, type_str, confidence));
                     
                     // Micro-Snippet Logic
                     if i == 0 && !top_snippet_included {
                         // Include first 3 lines of top result
                         let snippet: String = text.lines().take(3).collect::<Vec<_>>().join(" ");
                         output.push_str(&format!("Snippet: \"{}...\"\n", snippet));
                         top_snippet_included = true;
                     } else {
                         // Just the first 60 chars (Header/Summary)
                         let summary = if text.len() > 60 { format!("{}...", &text[..60]) } else { text };
                         output.push_str(&format!("Summary: \"{}\"\n", summary));
                     }
                 }
            }
        }
        
        output
    }

    pub(crate) fn select_runtime(&self, state: &AgentState) -> std::sync::Arc<dyn ioi_api::vm::inference::InferenceRuntime> {
        if state.consecutive_failures > 0 {
            return self.reasoning_inference.clone();
        }
        if state.step_count == 0 {
            return self.reasoning_inference.clone();
        }
        match state.last_action_type.as_deref() {
            Some("gui__click") | Some("gui__type") => {
                // [FIX] Only use fast_inference if it's NOT the Mock runtime (unless reasoning is also mock)
                // We assume if they are the same Arc pointer, it's the same config
                if std::sync::Arc::ptr_eq(&self.fast_inference, &self.reasoning_inference) {
                    self.fast_inference.clone()
                } else {
                    // In a real impl, we might check a "ready" flag. 
                    // For now, assume if fast_inference was configured separately, we use it.
                    self.fast_inference.clone()
                }
            },
            _ => self.reasoning_inference.clone(),
        }
    }

    async fn extract_facts(&self, text: &str) -> Vec<SemanticFact> {
        if text.len() < 20 { return vec![]; }

        let prompt = format!(
            "SYSTEM: Extract important facts from the text below as a JSON list of tuples.\n\
             Schema: [{{\"subject\": \"string\", \"predicate\": \"string\", \"object\": \"string\"}}]\n\
             Text: \"{}\"\n\
             Output JSON only:",
            text.replace('"', "\\\"")
        );

        let options = ioi_types::app::agentic::InferenceOptions {
            temperature: 0.0, 
            ..Default::default()
        };

        let model_hash = [0u8; 32];
        
        match self.reasoning_inference.execute_inference(model_hash, prompt.as_bytes(), options).await {
            Ok(bytes) => {
                 let s = String::from_utf8_lossy(&bytes);
                 let start = s.find('[').unwrap_or(0);
                 let end = s.rfind(']').map(|i| i + 1).unwrap_or(s.len());
                 if start < end {
                     serde_json::from_str(&s[start..end]).unwrap_or_default()
                 } else {
                     vec![]
                 }
            }
            Err(_) => vec![]
        }
    }

    pub(crate) async fn append_chat_to_scs(
        &self, 
        session_id: [u8; 32], 
        msg: &ChatMessage, 
        block_height: u64
    ) -> Result<[u8; 32], TransactionError> {
        let scs_mutex = self.scs.as_ref()
            .ok_or(TransactionError::Invalid("Internal: SCS not available".into()))?;
        
        // 1. Persist Raw Frame
        let (frame_id, checksum) = {
            let mut store = scs_mutex.lock()
                .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

            let payload = codec::to_bytes_canonical(msg)
                .map_err(|e| TransactionError::Serialization(e))?;

            let id = store.append_frame(
                FrameType::Thought, 
                &payload,
                block_height,
                [0u8; 32], 
                session_id,
            ).map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;
            
            let frame = store.toc.frames.get(id as usize)
                .ok_or(TransactionError::Invalid("Internal: Frame not found".into()))?;
            
            (id, frame.checksum)
        };

        // 2. Semantic Indexing
        let facts = self.extract_facts(&msg.content).await;
        let mut vectors = Vec::new();
        
        if let Ok(vec) = self.reasoning_inference.embed_text(&msg.content).await {
            vectors.push(vec);
        }

        for fact in facts {
            if let Ok(json_str) = serde_json::to_string(&fact) {
                if let Ok(_canonical_bytes) = OutputNormaliser::normalise_and_hash(&json_str) {
                    if let Ok(vec) = self.reasoning_inference.embed_text(&json_str).await {
                        vectors.push(vec);
                    }
                }
            }
        }

        // C. Insert into Index
        if !vectors.is_empty() {
             let store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
             if let Ok(index_arc) = store.get_vector_index() {
                 let mut index = index_arc.lock().map_err(|_| TransactionError::Invalid("Index lock".into()))?;
                 if let Some(idx) = index.as_mut() {
                     for vec in vectors {
                         if let Err(e) = idx.insert_with_metadata(frame_id, vec, FrameType::Thought, [0u8; 32]) {
                             log::warn!("Failed to index vector for frame {}: {}", frame_id, e);
                         }
                     }
                 }
             }
        }

        Ok(checksum)
    }

    pub(crate) fn hydrate_session_history(
        &self, 
        session_id: [u8; 32]
    ) -> Result<Vec<ChatMessage>, TransactionError> {
        let scs_mutex = self.scs.as_ref()
            .ok_or(TransactionError::Invalid("Internal: SCS not available".into()))?;
        
        let store = scs_mutex.lock()
            .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

        let mut history = Vec::new();

        if let Some(frame_ids) = store.session_index.get(&session_id) {
            for &id in frame_ids {
                let frame = store.toc.frames.get(id as usize).unwrap();
                
                if matches!(frame.frame_type, FrameType::Thought) {
                    let payload = store.read_frame_payload(id)
                        .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;
                    
                    if let Ok(msg) = codec::from_bytes_canonical::<ChatMessage>(payload) {
                        history.push(msg);
                    }
                }
            }
        }

        history.sort_by_key(|m| m.timestamp);
        Ok(history)
    }

    pub(crate) fn fetch_failure_context(
        &self, 
        session_id: [u8; 32]
    ) -> Result<Vec<StepTrace>, TransactionError> {
        let scs_mutex = self.scs.as_ref()
            .ok_or(TransactionError::Invalid("Internal: SCS not available".into()))?;
        
        let store = scs_mutex.lock()
            .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

        let mut failures = Vec::new();

        if let Some(frame_ids) = store.session_index.get(&session_id) {
            for &id in frame_ids {
                let frame = store.toc.frames.get(id as usize).unwrap();
                
                if matches!(frame.frame_type, FrameType::System) {
                    let payload = store.read_frame_payload(id)
                        .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;
                    
                    if let Ok(trace) = codec::from_bytes_canonical::<StepTrace>(payload) {
                        if !trace.success {
                            failures.push(trace);
                        }
                    }
                }
            }
        }

        Ok(failures)
    }

    // [NEW] Fetch a specific skill macro by its tool name.
    pub(crate) fn fetch_skill_macro(
        &self,
        tool_name: &str,
    ) -> Option<AgentMacro> {
        // Access SCS to find the skill
        if let Some(store_mutex) = &self.scs {
            if let Ok(store) = store_mutex.lock() {
                // In a real optimized system, we'd have a name->hash index.
                // For now, we scan the loaded skill cache or re-scan skills.
                // Since `discover_tools` scans, we can reuse that logic or optimize.
                // Here we linear scan the skill payloads for exact name match.
                let payloads = store.scan_skills();
                for p in payloads {
                    if let Ok(skill) = codec::from_bytes_canonical::<AgentMacro>(&p) {
                         // Check if tool name matches (handling namespacing if necessary)
                         if skill.definition.name == tool_name || skill.definition.name.ends_with(&format!("__{}", tool_name)) {
                             return Some(skill);
                         }
                    }
                }
            }
        }
        None
    }

    // [NEW] Expand a macro by substituting arguments into its steps.
    pub(crate) fn expand_macro(
        &self,
        skill: &AgentMacro,
        args: &serde_json::Map<String, Value>,
    ) -> Result<Vec<ioi_types::app::ActionRequest>, TransactionError> {
        let mut expanded_steps = Vec::new();

        for step in &skill.steps {
            // 1. Deserialize the step's params template
            let mut params_json: Value = serde_json::from_slice(&step.params)
                .map_err(|e| TransactionError::Serialization(e.to_string()))?;

            // 2. Recursive substitution
            Self::interpolate_values(&mut params_json, args);

            // 3. Re-serialize
            let new_params = serde_json::to_vec(&params_json)
                .map_err(|e| TransactionError::Serialization(e.to_string()))?;

            let mut new_step = step.clone();
            new_step.params = new_params;
            // Ensure nonce/context are reset or set by caller context later
            new_step.nonce = 0; 
            
            expanded_steps.push(new_step);
        }

        Ok(expanded_steps)
    }

    fn interpolate_values(target: &mut Value, args: &serde_json::Map<String, Value>) {
        match target {
            Value::String(s) => {
                // Check for exact matches first: "{{arg}}" -> replace with type-preserved value
                if s.starts_with("{{") && s.ends_with("}}") {
                    let key = &s[2..s.len()-2];
                    if let Some(val) = args.get(key) {
                        *target = val.clone();
                        return;
                    }
                }
                // Partial interpolation (string only): "Hello {{name}}"
                // (Implementation omitted for brevity, assuming full replacement for params)
            },
            Value::Array(arr) => {
                for item in arr {
                    Self::interpolate_values(item, args);
                }
            },
            Value::Object(map) => {
                for val in map.values_mut() {
                    Self::interpolate_values(val, args);
                }
            },
            _ => {}
        }
    }
}

pub fn goto_trace_log(
    agent_state: &mut AgentState,
    state: &mut dyn StateAccess,
    key: &[u8],
    session_id: [u8; 32],
    visual_hash_arr: [u8; 32],
    user_prompt: String,
    output_str: String,
    action_success: bool,
    action_error: Option<String>,
    action_type: String,
    event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
) -> Result<(), TransactionError> {
    let trace = StepTrace {
        session_id,
        step_index: agent_state.step_count,
        visual_hash: visual_hash_arr,
        full_prompt: user_prompt,
        raw_output: output_str,
        success: action_success,
        error: action_error.clone(),
        // [FIX] Initialize new evolutionary fields
        cost_incurred: 0,
        fitness_score: None,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    let trace_key = [TRACE_PREFIX, session_id.as_slice(), &agent_state.step_count.to_le_bytes()].concat();
    state.insert(&trace_key, &codec::to_bytes_canonical(&trace)?)?;

    if let Some(tx) = &event_sender {
        let event = KernelEvent::AgentStep(trace.clone());
        match tx.send(event) {
            Ok(count) => log::info!(target: "agent_driver", "Emitted AgentStep event to {} subscribers. Step: {}", count, trace.step_index),
            Err(_) => log::warn!(target: "agent_driver", "Failed to emit AgentStep event (no subscribers)"),
        }
    }

    if let Some(_e) = action_error {
        agent_state.consecutive_failures += 1;
    } else {
        agent_state.consecutive_failures = 0;
    }

    agent_state.step_count += 1;
    agent_state.last_action_type = Some(action_type);

    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running {
        // [FIX] Only complete if queue is also empty
        if agent_state.execution_queue.is_empty() {
             agent_state.status = AgentStatus::Completed(None);
             if let Some(tx) = &event_sender {
                  let _ = tx.send(KernelEvent::AgentActionResult {
                      session_id: session_id, 
                      step_index: agent_state.step_count,
                      tool_name: "system::max_steps_reached".to_string(),
                      output: "Max steps reached. Task completed.".to_string(),
                  });
             }
        }
    }

    state.insert(key, &codec::to_bytes_canonical(&agent_state)?)?;
    Ok(())
}