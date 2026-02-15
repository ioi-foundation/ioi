use super::*;

#[allow(dead_code)]
struct SafetyModelAsInference {
    model: Arc<dyn LocalSafetyModel>,
}

#[async_trait::async_trait]
impl InferenceRuntime for SafetyModelAsInference {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let input_str = String::from_utf8_lossy(input_context);

        let mock_json = format!(
            r#"{{
            "operation_id": "start_agent",
            "params": {{ 
                "goal": "{}" 
            }},
            "gas_ceiling": 5000000
        }}"#,
            input_str.trim().escape_debug()
        );

        Ok(mock_json.into_bytes())
    }

    async fn load_model(&self, _hash: [u8; 32], _path: &std::path::Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}
