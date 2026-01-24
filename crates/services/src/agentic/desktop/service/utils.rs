// Path: crates/services/src/agentic/desktop/service/utils.rs

use super::DesktopAgentService;
use crate::agentic::desktop::keys::{TRACE_PREFIX, SKILL_INDEX_PREFIX};
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{AgentSkill, LlmToolDefinition, StepTrace, SemanticFact, InferenceOptions}; // Added SemanticFact, InferenceOptions
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::sync::Arc;
use ioi_scs::FrameType;
use ioi_types::app::agentic::ChatMessage;
use crate::agentic::normaliser::OutputNormaliser; // Import Normaliser

impl DesktopAgentService {
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

    pub(crate) async fn retrieve_memory(&self, query: &str) -> String {
        let scs_mutex = match &self.scs {
            Some(m) => m,
            None => return "".to_string(),
        };

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
                index.search(&embedding, 3)
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

        let mut context_str = String::new();
        context_str.push_str("\n### Relevant Memories\n");

        {
            let scs = match scs_mutex.lock() {
                Ok(s) => s,
                Err(_) => return "".to_string(),
            };

            for (frame_id, dist) in matches {
                if let Ok(payload) = scs.read_frame_payload(frame_id) {
                    if let Ok(text) = String::from_utf8(payload.to_vec()) {
                        let snippet = if text.len() > 200 {
                            format!("{}...", &text[..200])
                        } else {
                            text
                        };
                        context_str
                            .push_str(&format!("- (Sim: {:.2}) {}\n", 1.0 - dist, snippet));
                    }
                }
            }
        }
        context_str
    }

    pub(crate) fn select_runtime(&self, state: &AgentState) -> Arc<dyn InferenceRuntime> {
        if state.consecutive_failures > 0 {
            return self.reasoning_inference.clone();
        }
        if state.step_count == 0 {
            return self.reasoning_inference.clone();
        }
        match state.last_action_type.as_deref() {
            Some("gui__click") | Some("gui__type") => self.fast_inference.clone(),
            _ => self.reasoning_inference.clone(),
        }
    }

    /// Internal helper to extract semantic facts from text using the reasoning model.
    async fn extract_facts(&self, text: &str) -> Vec<SemanticFact> {
        // Skip extraction for short messages to save compute
        if text.len() < 20 { return vec![]; }

        let prompt = format!(
            "SYSTEM: Extract important facts from the text below as a JSON list of tuples.\n\
             Schema: [{{\"subject\": \"string\", \"predicate\": \"string\", \"object\": \"string\"}}]\n\
             Text: \"{}\"\n\
             Output JSON only:",
            text.replace('"', "\\\"")
        );

        let options = InferenceOptions {
            temperature: 0.0, // Strict determinism for fact extraction
            ..Default::default()
        };

        // Use reasoning model for high-quality extraction
        // Use a zero hash for model_id (default)
        let model_hash = [0u8; 32];
        
        match self.reasoning_inference.execute_inference(model_hash, prompt.as_bytes(), options).await {
            Ok(bytes) => {
                 let s = String::from_utf8_lossy(&bytes);
                 // Robust JSON extraction (find first [ and last ])
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

    /// Appends a chat message to the SCS and indexes its semantic content.
    /// Returns the new Frame Hash (Transcript Root).
    pub(crate) async fn append_chat_to_scs(
        &self, 
        session_id: [u8; 32], 
        msg: &ChatMessage, 
        block_height: u64
    ) -> Result<[u8; 32], TransactionError> {
        let scs_mutex = self.scs.as_ref()
            .ok_or(TransactionError::Invalid("Internal: SCS not available".into()))?;
        
        // 1. Persist Raw Frame (The "Book of Record")
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

        // 2. Semantic Indexing (The "Reasoning-to-Vector" Bridge)
        // We do this *outside* the store lock to allow parallelism (inference is slow)
        
        // A. Extract Facts
        let facts = self.extract_facts(&msg.content).await;
        
        // B. Canonicalize & Embed
        let mut vectors = Vec::new();
        
        // Always index the raw text too (hybrid approach)
        if let Ok(vec) = self.reasoning_inference.embed_text(&msg.content).await {
            vectors.push(vec);
        }

        for fact in facts {
            // Canonicalize the fact tuple into a deterministic string
            // e.g. {"object":"50_USD","predicate":"is_limit","subject":"budget"}
            if let Ok(json_str) = serde_json::to_string(&fact) {
                if let Ok(_canonical_bytes) = OutputNormaliser::normalise_and_hash(&json_str) {
                    // Embed the CANONICAL string representation
                    // This ensures "budget is 50" and "50 budget" (if extracted to same fact) collide in vector space
                    // or at least cluster very tightly.
                    if let Ok(vec) = self.reasoning_inference.embed_text(&json_str).await {
                        vectors.push(vec);
                    }
                }
            }
        }

        // C. Insert into Index
        // Re-acquire lock to write to index
        if !vectors.is_empty() {
             // We need to lock the store to access the lazy-loaded index
             let store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
             if let Ok(index_arc) = store.get_vector_index() {
                 let mut index = index_arc.lock().map_err(|_| TransactionError::Invalid("Index lock".into()))?;
                 if let Some(idx) = index.as_mut() {
                     for vec in vectors {
                         // Insert into mHNSW
                         if let Err(e) = idx.insert(frame_id, vec) {
                             log::warn!("Failed to index vector for frame {}: {}", frame_id, e);
                         }
                     }
                 }
             }
        }

        Ok(checksum)
    }

    /// Reconstructs the full chat history from the SCS.
    pub(crate) fn hydrate_session_history(
        &self, 
        session_id: [u8; 32]
    ) -> Result<Vec<ChatMessage>, TransactionError> {
        let scs_mutex = self.scs.as_ref()
            .ok_or(TransactionError::Invalid("Internal: SCS not available".into()))?;
        
        let store = scs_mutex.lock()
            .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

        let mut history = Vec::new();

        // Use the new O(1) session index
        if let Some(frame_ids) = store.session_index.get(&session_id) {
            for &id in frame_ids {
                let frame = store.toc.frames.get(id as usize).unwrap();
                
                // Filter for Thought/Chat frames
                if matches!(frame.frame_type, FrameType::Thought) {
                    let payload = store.read_frame_payload(id)
                        .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;
                    
                    if let Ok(msg) = codec::from_bytes_canonical::<ChatMessage>(payload) {
                        history.push(msg);
                    }
                }
            }
        }

        // Ensure chronological order
        history.sort_by_key(|m| m.timestamp);
        Ok(history)
    }

    // -------------------------------------------------------------------------
    // [NEW] Evolutionary Support
    // -------------------------------------------------------------------------

    /// Fetches all failure traces for a given session from the SCS.
    /// Used by the Optimizer Service to diagnose recurring errors.
    pub(crate) fn fetch_failure_context(
        &self, 
        session_id: [u8; 32]
    ) -> Result<Vec<StepTrace>, TransactionError> {
        let scs_mutex = self.scs.as_ref()
            .ok_or(TransactionError::Invalid("Internal: SCS not available".into()))?;
        
        let store = scs_mutex.lock()
            .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

        let mut failures = Vec::new();

        // 1. Get all frames for session
        if let Some(frame_ids) = store.session_index.get(&session_id) {
            for &id in frame_ids {
                let frame = store.toc.frames.get(id as usize).unwrap();
                
                // 2. Scan for System Frames which contain the canonical StepTrace logs
                // Note: StepTraces are written as FrameType::System in step.rs to separate them from thoughts/observations.
                if matches!(frame.frame_type, FrameType::System) {
                    let payload = store.read_frame_payload(id)
                        .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;
                    
                    // Attempt to decode as StepTrace
                    if let Ok(trace) = codec::from_bytes_canonical::<StepTrace>(payload) {
                        // Filter for failed steps only
                        if !trace.success {
                            failures.push(trace);
                        }
                    }
                }
            }
        }

        Ok(failures)
    }
}

pub(crate) fn merge_tools(
    base: Vec<LlmToolDefinition>,
    extra: Vec<LlmToolDefinition>,
) -> Vec<LlmToolDefinition> {
    let mut map = std::collections::HashMap::new();
    for t in base {
        map.insert(t.name.clone(), t);
    }
    for t in extra {
        map.insert(t.name.clone(), t);
    }
    map.into_values().collect()
}