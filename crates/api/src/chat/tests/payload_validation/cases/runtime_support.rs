#[derive(Clone)]
struct ChatTestRuntime {
    provenance: ChatRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

impl ChatTestRuntime {
    fn new(
        kind: ChatRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            provenance: ChatRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some(model.to_string()),
                endpoint: Some(endpoint.to_string()),
            },
            role,
            calls,
        }
    }
}

#[async_trait]
impl InferenceRuntime for ChatTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_chat_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
        } else if prompt.contains("typed artifact validation") {
            "validation"
        } else {
            "unknown"
        };
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:{stage}", self.role));

        let response = match stage {
            "brief" => serde_json::json!({
                "audience": "operators",
                "jobToBeDone": "explain the rollout",
                "subjectDomain": "rollout planning",
                "artifactThesis": "show the launch plan clearly",
                "requiredConcepts": ["rollout timeline", "launch owners", "readiness checkpoints"],
                "requiredInteractions": ["chart toggle", "detail comparison"],
                "visualTone": ["confident"],
                "factualAnchors": ["launch checkpoint review"],
                "styleDirectives": [],
                "referenceHints": []
            }),
            "materialize" => {
                if prompt.contains("\"renderer\": \"markdown\"")
                    || prompt.contains("\"renderer\":\"markdown\"")
                {
                    serde_json::json!({
                        "summary": "Prepared a rollout artifact",
                        "notes": ["request-grounded candidate"],
                        "files": [{
                            "path": "release-checklist.md",
                            "mime": "text/markdown",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "# Release checklist\n\n- Finalize branch\n- Run QA\n- Tag release"
                        }]
                    })
                } else {
                    serde_json::json!({
                        "summary": "Prepared a rollout artifact",
                        "notes": ["request-grounded candidate"],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "<!doctype html><html><body><main><section><h1>Rollout</h1></section><article><p>Timeline and owners.</p></article><footer>Ready for review.</footer></main></body></html>"
                        }]
                    })
                }
            }
            "validation" => serde_json::json!({
                "classification": "pass",
                "requestFaithfulness": 5,
                "conceptCoverage": 4,
                "interactionRelevance": 4,
                "layoutCoherence": 4,
                "visualHierarchy": 4,
                "completeness": 4,
                "genericShellDetected": false,
                "trivialShellDetected": false,
                "deservesPrimaryArtifactView": true,
                "patchedExistingArtifact": null,
                "continuityRevisionUx": null,
                "strongestContradiction": null,
                "rationale": format!("validated by {}", self.role)
            }),
            _ => return Err(VmError::HostError("unexpected Chat prompt".to_string())),
        };
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
        self.provenance.clone()
    }
}
