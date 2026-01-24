// Path: crates/services/src/agentic/desktop/service/utils.rs

use super::DesktopAgentService;
use crate::agentic::desktop::keys::SKILL_INDEX_PREFIX;
// [FIX] Removed unused SessionSummary import
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{AgentSkill, LlmToolDefinition};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::sync::Arc;
use ioi_scs::FrameType;
use ioi_types::app::agentic::ChatMessage;
// [FIX] Removed unused imports: SystemTime, UNIX_EPOCH

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

    /// Appends a chat message to the SCS and returns the new Frame Hash (Transcript Root).
    pub(crate) fn append_chat_to_scs(
        &self, 
        session_id: [u8; 32], 
        msg: &ChatMessage, 
        block_height: u64
    ) -> Result<[u8; 32], TransactionError> {
        let scs_mutex = self.scs.as_ref()
            // [FIX] Map internal error to TransactionError::Invalid
            .ok_or(TransactionError::Invalid("Internal: SCS not available".into()))?;
        
        let mut store = scs_mutex.lock()
            .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

        let payload = codec::to_bytes_canonical(msg)
            .map_err(|e| TransactionError::Serialization(e))?;

        // Append to store
        // Note: You must update store.append_frame signature to accept session_id
        let frame_id = store.append_frame(
            FrameType::Thought, 
            &payload,
            block_height,
            [0u8; 32], 
            session_id, // Link to session
        ).map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

        // Return checksum as new root
        let frame = store.toc.frames.get(frame_id as usize)
            .ok_or(TransactionError::Invalid("Internal: Frame not found after write".into()))?;
        
        Ok(frame.checksum)
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