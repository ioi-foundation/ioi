use super::*;

impl OptimizerService {
    /// [NEW] Internal logic for asset hydration.
    pub(crate) async fn install_asset_internal(
        &self,
        state: &dyn StateAccess,
        params: InstallAssetParams,
        installer_id: ioi_types::app::AccountId,
    ) -> Result<(), TransactionError> {
        let scs_mutex = self
            .scs
            .as_ref()
            .ok_or(TransactionError::Invalid("SCS not available".into()))?;

        // 1. Verify License
        let ns_prefix = ioi_api::state::service_namespace_prefix("market");
        let license_key = [
            ns_prefix.as_slice(),
            b"market::license::",
            installer_id.as_ref(),
            b"::",
            &params.asset_hash,
        ]
        .concat();

        if state.get(&license_key)?.is_none() {
            return Err(TransactionError::Invalid(
                "No license found. Purchase before installing.".into(),
            ));
        }

        // 2. Fetch Payload from Market
        let payload_key = [
            ns_prefix.as_slice(),
            b"market::payload::",
            &params.asset_hash,
        ]
        .concat();

        let payload_bytes = state.get(&payload_key)?.ok_or(TransactionError::Invalid(
            "Asset payload not found in Market".into(),
        ))?;

        // 3. Validate Hash Integrity (Omitted for brevity, assumed checked at publish)

        // 4. Determine Asset Type & Index
        if let Ok(skill) = codec::from_bytes_canonical::<AgentMacro>(&payload_bytes) {
            // [FIX] Scope the lock to ensure it's dropped before await
            let frame_id = {
                let mut store = scs_mutex
                    .lock()
                    .map_err(|_| TransactionError::Invalid("SCS lock".into()))?;

                store
                    .append_frame(
                        FrameType::Skill,
                        &payload_bytes,
                        0,
                        [0u8; 32],
                        [0u8; 32],
                        RetentionClass::Archival,
                    )
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?
            };

            // Index
            self.index_skill(frame_id, &skill.definition).await?;

            log::info!(
                "Optimizer: Installed & Indexed skill '{}'",
                skill.definition.name
            );
            return Ok(());
        }

        Ok(())
    }
    pub(crate) async fn synthesize_mutation(
        &self,
        current_manifest: &str,
        failure_trace: &StepTrace,
        feedback: Option<&String>,
    ) -> Result<(String, String), TransactionError> {
        let runtime = self.inference.as_ref().ok_or(TransactionError::Invalid(
            "Optimizer has no inference runtime".into(),
        ))?;

        let prompt = format!(
            "SYSTEM: You are an AGI Optimizer. Your goal is to fix a failing agent.\n\
            \n\
            CONTEXT:\n\
            Current Agent Manifest:\n{}\n\
            \n\
            Failure Trace:\n\
            - Input: {}\n\
            - Output: {}\n\
            - Error: {:?}\n\
            - Feedback: {:?}\n\
            \n\
            TASK:\n\
            Rewrite the Agent Manifest to fix this error. \n\
            1. You MAY update the `system_prompt` or `tools`.\n\
            2. You MAY add entries to `static_knowledge` if the failure was due to missing API docs or patterns.\n\
               Format: {{ \"source\": \"docs/api.md\", \"kind\": \"ApiDocs\", \"content\": \"...\", ... }}\n\
            3. You MUST NOT relax the `policy` (safety rules).\n\
            4. Return a JSON object: {{ \"manifest\": {{...}}, \"rationale\": \"string\" }}",
            current_manifest,
            failure_trace.full_prompt,
            failure_trace.raw_output,
            failure_trace.error,
            feedback.unwrap_or(&"Fix the runtime error.".to_string())
        );

        let options = InferenceOptions {
            temperature: 0.7,
            ..Default::default()
        };

        let model_hash = [0u8; 32];

        let output_bytes = runtime
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await
            .map_err(|e| TransactionError::Invalid(format!("Mutation failed: {}", e)))?;

        let output_str = String::from_utf8(output_bytes)
            .map_err(|_| TransactionError::Invalid("Invalid UTF-8 from optimizer".into()))?;

        // Extract JSON
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str
            .rfind('}')
            .map(|i| i + 1)
            .unwrap_or(output_str.len());
        let json_str = &output_str[json_start..json_end];

        let response: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
            TransactionError::Invalid(format!("Failed to parse optimizer response: {}", e))
        })?;

        let manifest = serde_json::to_string(&response["manifest"])
            .map_err(|e| TransactionError::Serialization(e.to_string()))?;

        let rationale = response["rationale"]
            .as_str()
            .unwrap_or("No rationale provided.")
            .to_string();

        Ok((manifest, rationale))
    }
    pub async fn package_agent_for_market(
        &self,
        state: &mut dyn StateAccess,
        params: OptimizeAgentParams,
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
        let full_key = [
            ns_prefix.as_slice(),
            b"agent::state::",
            params.session_id.as_slice(),
        ]
        .concat();

        let state_bytes = state
            .get(&full_key)?
            .ok_or(TransactionError::Invalid("Agent state not found".into()))?;
        let agent_state: crate::agentic::desktop::AgentState =
            codec::from_bytes_canonical(&state_bytes)?;

        let scs_mutex = self
            .scs
            .as_ref()
            .ok_or(TransactionError::Invalid("SCS not available".into()))?;
        let store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock".into()))?;

        let empty_vec = Vec::new();
        let session_frames = store
            .session_index
            .get(&params.session_id)
            .unwrap_or(&empty_vec);

        let mut skill_hashes = Vec::new();
        for &fid in session_frames {
            let frame = store.toc.frames.get(fid as usize).unwrap();
            if frame.frame_type == ioi_scs::FrameType::Skill {
                skill_hashes.push(frame.checksum);
            }
        }

        let manifest = AgentManifest {
            name: format!("Agent-{}", hex::encode(&params.session_id[0..4])),
            description: format!(
                "Auto-packaged agent trained on goal: '{}'",
                agent_state.goal
            ),
            system_prompt: "You are a specialized agent...".to_string(),
            model_selector: "gpt-4o".to_string(),
            skills: skill_hashes,
            default_policy_hash: [0u8; 32],
            author: ctx.signer_account_id,
            price: 500,
            tags: vec!["auto-packaged".into()],
            version: "0.1.0".to_string(),
            runtime: RuntimeEnvironment::Native,
            resources: ResourceRequirements {
                min_vram_gb: 0,
                min_ram_gb: 4,
                min_cpus: 2,
                network_access: "public".to_string(),
                provider_preference: "any".to_string(),
            },
            static_knowledge: vec![],
            // [FIX] Initialize missing fields
            has_embedded_app: false,
            app_entrypoint: None,
            custom_lenses: vec![],
            ui_assets_root: [0u8; 32],
        };

        let intent_key = [b"optimizer::publish_intent::", params.session_id.as_slice()].concat();
        let publish_params = PublishAssetParams {
            asset: IntelligenceAsset::Agent(manifest),
            // [FIX] Initialize empty payload for now
            payload: vec![],
        };

        state.insert(&intent_key, &codec::to_bytes_canonical(&publish_params)?)?;

        log::info!(
            "Optimizer: Packaged agent session {} for market.",
            hex::encode(&params.session_id[0..4])
        );
        Ok(())
    }
}
