// Path: crates/api/src/vm/inference/mock.rs

use crate::vm::inference::InferenceRuntime;
use async_trait::async_trait;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct MockInferenceRuntime;

#[async_trait]
impl InferenceRuntime for MockInferenceRuntime {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // Log the execution request
        log::info!(
            "MockInference: Executing on model {} with input len {}",
            hex::encode(model_hash),
            input_context.len()
        );

        let input_str = String::from_utf8_lossy(input_context);

        // [DEBUG]
        // println!("[MockBrain] Input: {}", input_str);

        if input_str.contains("classifying a structural web retrieval contract") {
            let lower = input_str.to_ascii_lowercase();
            let restaurants = lower.contains("restaurant");
            let weather = lower.contains("weather");
            let bitcoin = lower.contains("bitcoin") || lower.contains("btc");
            let headlines = lower.contains("headline") || lower.contains("top news");
            let compare = lower.contains("compare") || lower.contains("comparison");
            let near_me = lower.contains("near me") || lower.contains("nearby");
            let currentness = lower.contains("current")
                || lower.contains("right now")
                || lower.contains("today")
                || lower.contains("latest");
            let scalar_measure = weather || bitcoin;

            let response = if restaurants {
                json!({
                    "contract_version": "web_retrieval_contract.v1",
                    "entity_cardinality_min": 3,
                    "comparison_required": true,
                    "currentness_required": false,
                    "runtime_locality_required": near_me,
                    "source_independence_min": 3,
                    "citation_count_min": 1,
                    "structured_record_preferred": false,
                    "ordered_collection_preferred": false,
                    "link_collection_preferred": true,
                    "canonical_link_out_preferred": true,
                    "geo_scoped_detail_required": near_me,
                    "discovery_surface_required": true,
                    "entity_diversity_required": true,
                    "scalar_measure_required": false,
                    "browser_fallback_allowed": true
                })
            } else if headlines {
                json!({
                    "contract_version": "web_retrieval_contract.v1",
                    "entity_cardinality_min": 3,
                    "comparison_required": compare,
                    "currentness_required": true,
                    "runtime_locality_required": false,
                    "source_independence_min": 3,
                    "citation_count_min": 2,
                    "structured_record_preferred": false,
                    "ordered_collection_preferred": true,
                    "link_collection_preferred": false,
                    "canonical_link_out_preferred": false,
                    "geo_scoped_detail_required": false,
                    "discovery_surface_required": true,
                    "entity_diversity_required": false,
                    "scalar_measure_required": false,
                    "browser_fallback_allowed": true
                })
            } else if weather {
                json!({
                    "contract_version": "web_retrieval_contract.v1",
                    "entity_cardinality_min": 1,
                    "comparison_required": false,
                    "currentness_required": true,
                    "runtime_locality_required": near_me || lower.contains(" in "),
                    "source_independence_min": 2,
                    "citation_count_min": 1,
                    "structured_record_preferred": true,
                    "ordered_collection_preferred": false,
                    "link_collection_preferred": false,
                    "canonical_link_out_preferred": false,
                    "geo_scoped_detail_required": near_me || lower.contains(" in "),
                    "discovery_surface_required": false,
                    "entity_diversity_required": false,
                    "scalar_measure_required": true,
                    "browser_fallback_allowed": true
                })
            } else if bitcoin {
                json!({
                    "contract_version": "web_retrieval_contract.v1",
                    "entity_cardinality_min": 1,
                    "comparison_required": false,
                    "currentness_required": currentness,
                    "runtime_locality_required": false,
                    "source_independence_min": 2,
                    "citation_count_min": 1,
                    "structured_record_preferred": true,
                    "ordered_collection_preferred": false,
                    "link_collection_preferred": false,
                    "canonical_link_out_preferred": false,
                    "geo_scoped_detail_required": false,
                    "discovery_surface_required": true,
                    "entity_diversity_required": false,
                    "scalar_measure_required": true,
                    "browser_fallback_allowed": true
                })
            } else {
                json!({
                    "contract_version": "web_retrieval_contract.v1",
                    "entity_cardinality_min": if compare { 3 } else { 1 },
                    "comparison_required": compare,
                    "currentness_required": currentness,
                    "runtime_locality_required": near_me,
                    "source_independence_min": if compare || currentness { 2 } else { 1 },
                    "citation_count_min": 1,
                    "structured_record_preferred": scalar_measure && !compare,
                    "ordered_collection_preferred": false,
                    "link_collection_preferred": compare && near_me,
                    "canonical_link_out_preferred": compare && near_me,
                    "geo_scoped_detail_required": near_me,
                    "discovery_surface_required": compare || !scalar_measure,
                    "entity_diversity_required": compare && near_me,
                    "scalar_measure_required": scalar_measure,
                    "browser_fallback_allowed": true
                })
            };
            return Ok(response.to_string().into_bytes());
        }

        if input_str.contains("Extract a connector-agnostic instruction contract") {
            let lower = input_str.to_ascii_lowercase();
            let side_effect_mode =
                if lower.contains("do not send") || lower.contains("draft an email") {
                    "draft_only"
                } else if lower.contains("send an email") || lower.contains("send email") {
                    "send"
                } else {
                    "unknown"
                };
            let operation = if lower.contains("email") {
                "mail.reply"
            } else {
                "unknown"
            };

            let subject = input_str
                .split("subject \"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default();
            let body = input_str
                .split("Body: \"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default();

            let to_binding = if lower.contains("connected google address")
                || lower.contains("connected google email")
                || lower.contains("connected gmail address")
                || lower.contains("connected address")
                || lower.contains("connected email")
            {
                json!({
                    "slot": "to",
                    "bindingKind": "symbolic_ref",
                    "value": "connected_account.email",
                    "origin": "state_ref",
                    "protectedSlotKind": "email_address"
                })
            } else {
                json!({
                    "slot": "to",
                    "bindingKind": "unresolved",
                    "value": null,
                    "origin": "model_inferred",
                    "protectedSlotKind": "email_address"
                })
            };

            let response = json!({
                "operation": operation,
                "sideEffectMode": side_effect_mode,
                "slotBindings": [
                    to_binding,
                    {
                        "slot": "subject",
                        "bindingKind": "user_literal",
                        "value": subject,
                        "origin": "user_span",
                        "protectedSlotKind": "unknown"
                    },
                    {
                        "slot": "body",
                        "bindingKind": "user_literal",
                        "value": body,
                        "origin": "user_span",
                        "protectedSlotKind": "unknown"
                    }
                ],
                "negativeConstraints": if side_effect_mode == "draft_only" {
                    json!(["do_not_send"])
                } else {
                    json!([])
                },
                "successCriteria": if operation == "mail.reply" {
                    json!(["mail.reply.completed"])
                } else {
                    json!([])
                }
            });
            return Ok(response.to_string().into_bytes());
        }

        // 1. Intent Resolver Logic (Control Plane)
        // Detect if this is a request to map Natural Language -> Transaction.
        // We look for keywords from the System Prompt or specific user intent triggers.
        if (input_str.contains("intent resolver")
            || input_str.contains("User Input:")
            || input_str.contains("<user_intent>"))
            && (input_str.contains("Analyze network traffic") || input_str.contains("example.com"))
        {
            // Return Intent Plan JSON matching the schema expected by IntentResolver
            let mock_intent_json = json!({
                "operation_id": "start_agent",
                "params": {
                    "goal": "Analyze network traffic on example.com"
                },
                "gas_ceiling": 5000000
            });
            return Ok(mock_intent_json.to_string().into_bytes());
        }

        // 2. Agent Execution Logic (Data Plane)
        // If not intent resolution, it's the agent loop asking for the next tool action.
        let response = if input_str.contains("browser")
            || (input_str.contains("network") && !input_str.contains("start_agent"))
            || input_str.contains("example.com")
        {
            json!({
                "name": "browser__navigate",
                "arguments": { "url": "https://example.com" }
            })
        } else if input_str.contains("click") {
            json!({
                "name": "gui__click",
                "arguments": { "x": 500, "y": 500, "button": "left" }
            })
        } else {
            // Default thought/action
            json!({
                "name": "sys__exec",
                "arguments": { "command": "echo", "args": ["Mock Brain Thinking..."] }
            })
        };

        Ok(response.to_string().into_bytes())
    }

    // [NEW] Implement embed_text
    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        // Deterministic embedding: Hash the text, seed a PRNG (or just cycle the bytes),
        // and generate a float vector.

        let digest =
            Sha256::digest(text.as_bytes()).map_err(|e| VmError::HostError(e.to_string()))?;

        let seed = digest.as_ref();
        let mut embedding = Vec::with_capacity(384);
        let seed_len = seed.len();

        for i in 0..384 {
            // Simple chaotic mapping to get floats in [-1.0, 1.0]
            let byte = seed.get(i % seed_len).copied().unwrap_or_default();
            let modifier = (i * 7) as u8;
            let val = byte.wrapping_add(modifier);
            let float_val = (val as f32 / 255.0) * 2.0 - 1.0;
            embedding.push(float_val);
        }

        // Normalize vector
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut embedding {
                *x /= norm;
            }
        }

        Ok(embedding)
    }

    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError> {
        if !path.exists() {
            // In mock mode, we don't strictly require the file to exist on disk unless testing hydration.
            // But we log it.
            log::warn!(
                "MockInference: Model file not found at {:?} (proceeding anyway for mock)",
                path
            );
        } else {
            log::info!(
                "MockInference: Loaded model {} from {:?}",
                hex::encode(model_hash),
                path
            );
        }
        Ok(())
    }

    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError> {
        log::info!("MockInference: Unloaded model {}", hex::encode(model_hash));
        Ok(())
    }
}
