#[tokio::test]
async fn local_html_work_graph_strategy_repairs_and_passes_quantum_artifact_regression() {
    #[derive(Clone)]
    struct QuantumWorkGraphRegressionRuntime {
        provenance: ChatRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for QuantumWorkGraphRegressionRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief"
            } else if prompt.contains("typed work_graph Skeleton worker") {
                "skeleton"
            } else if prompt.contains("typed work_graph SectionContent worker") {
                "section"
            } else if prompt.contains("typed work_graph StyleSystem worker") {
                "style"
            } else if prompt.contains("typed work_graph Interaction worker") {
                "interaction"
            } else if prompt.contains("typed work_graph Repair worker") {
                "repair"
            } else if prompt.contains("typed work_graph Integrator worker") {
                "integrator"
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
                "brief" => {
                    serde_json::to_value(sample_quantum_explainer_brief()).expect("quantum brief")
                }
                "skeleton" => serde_json::json!({
                    "summary": "Quantum computers interactive draft",
                    "notes": ["Created the bounded quantum explainer skeleton."],
                    "operations": [{
                        "kind": "create_file",
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><meta charset=\"utf-8\"><title>Quantum computers interactive explainer</title></head><body><main><section><h1>Quantum computers, step by step</h1><p>Compare classical bits with quantum states, then inspect how measurement changes the outcome.</p><div class=\"mode-switch\"><button type=\"button\" data-mode=\"classical\" aria-selected=\"true\">Classical Bit</button><button type=\"button\" data-mode=\"quantum\" aria-selected=\"false\">Quantum State</button></div></section><section><article><h2>State comparison</h2><p id=\"mode-summary\">Classical bits stay in one definite state at a time.</p></article></section><aside><h2>Inspector</h2><p id=\"detail-copy\">Select a mode to inspect the difference.</p></aside></main></body></html>"
                    }]
                }),
                "section" => serde_json::json!({
                    "summary": "Extended the bounded quantum section.",
                    "notes": ["Added a scoped comparison section patch."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<section class=\"comparison-band\"><article><h2>Probability intuition</h2><p>Quantum systems distribute likelihood across outcomes before measurement.</p></article></section>"
                    }]
                }),
                "style" => serde_json::json!({
                    "summary": "Applied the slate quantum style system.",
                    "notes": ["Added restrained slate styling for the explainer."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<style>:root{color-scheme:dark;--bg:#13171d;--panel:#1b222c;--panel-border:#2b3644;--text:#e6ebf2;--muted:#97a5b8;--accent:#7dd3fc;}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);}main{display:grid;gap:18px;padding:24px;max-width:960px;margin:0 auto;}section,aside{background:var(--panel);border:1px solid var(--panel-border);border-radius:18px;padding:18px;}button{border:1px solid #36506a;background:#1d2a38;color:var(--text);border-radius:999px;padding:10px 14px;cursor:pointer;}button[aria-selected=\"true\"]{border-color:var(--accent);box-shadow:0 0 0 1px rgba(125,211,252,.35) inset;}p{color:var(--muted);}h1,h2{margin:0 0 10px;}svg{width:100%;height:auto;display:block;}</style>"
                    }]
                }),
                "interaction" => serde_json::json!({
                    "summary": "Wired the bounded quantum interaction loop.",
                    "notes": ["Added button-driven explanation updates."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<script>const summary=document.getElementById('mode-summary');const detail=document.getElementById('detail-copy');const controls=document.querySelectorAll('[data-mode]');controls.forEach((button)=>button.addEventListener('click',()=>{controls.forEach((control)=>control.setAttribute('aria-selected', String(control===button)));if(button.dataset.mode==='quantum'){summary.textContent='Quantum states can spread amplitude across multiple outcomes before measurement.';detail.textContent='Quantum state selected. Inspect how probabilities differ from a classical bit.';}else{summary.textContent='Classical bits stay in one definite state at a time.';detail.textContent='Classical mode selected. A bit resolves to one state immediately.';}}));</script>"
                    }]
                }),
                "repair" => serde_json::json!({
                    "summary": "Repair completed with a stronger quantum comparison.",
                    "notes": ["Added the missing qubit-focused comparison module."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<section data-verified-repair=\"quantum-state-compare\"><article><h2>Measurement comparison</h2><p>Quantum Qubit views show a weighted set of possible outcomes before measurement collapses the state.</p><div class=\"repair-switch\"><button type=\"button\">Classical Bit</button><button type=\"button\">Quantum Qubit</button></div><svg viewBox=\"0 0 320 160\" role=\"img\" aria-label=\"Classical versus quantum measurement distribution\"><rect x=\"34\" y=\"42\" width=\"54\" height=\"88\"></rect><rect x=\"132\" y=\"64\" width=\"54\" height=\"66\"></rect><rect x=\"230\" y=\"28\" width=\"54\" height=\"102\"></rect><text x=\"28\" y=\"148\">0</text><text x=\"126\" y=\"148\">0 / 1</text><text x=\"224\" y=\"148\">1</text></svg></article></section>"
                    }]
                }),
                "integrator" => serde_json::json!({
                    "summary": "No extra integrator pass was required.",
                    "notes": ["The local HTML work_graph keeps the integrator in reserve."],
                    "operations": []
                }),
                "validation" => {
                    if prompt.contains("Repair completed with a stronger quantum comparison.")
                        || prompt.contains("qubit-focused comparison module")
                        || (prompt.contains("Measurement comparison")
                            && prompt.contains("Quantum Qubit"))
                    {
                        serde_json::json!({
                            "classification": "pass",
                            "requestFaithfulness": 5,
                            "conceptCoverage": 5,
                            "interactionRelevance": 5,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 5,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": null,
                            "rationale": "Acceptance cleared the repaired quantum explainer."
                        })
                    } else {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 4,
                            "conceptCoverage": 4,
                            "interactionRelevance": 4,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 3,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": "The explainer still needs a visible qubit measurement comparison.",
                            "rationale": "Acceptance wants a stronger qubit-focused comparison before primary view."
                        })
                    }
                }
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

    #[derive(Default)]
    struct QuantumWorkGraphRegressionRenderEvaluator;

    #[async_trait]
    impl ChatArtifactRenderEvaluator for QuantumWorkGraphRegressionRenderEvaluator {
        async fn evaluate_candidate_render(
            &self,
            _request: &ChatOutcomeArtifactRequest,
            _brief: &ChatArtifactBrief,
            _blueprint: Option<&ChatArtifactBlueprint>,
            _artifact_ir: Option<&ChatArtifactIR>,
            _edit_intent: Option<&ChatArtifactEditIntent>,
            candidate: &ChatGeneratedArtifactPayload,
        ) -> Result<Option<ChatArtifactRenderEvaluation>, String> {
            let repaired = candidate
                .files
                .iter()
                .find(|file| file.path == "index.html")
                .map(|file| {
                    file.body
                        .contains("data-verified-repair=\"quantum-state-compare\"")
                })
                .unwrap_or(false);

            Ok(Some(chat_test_render_evaluation(
                if repaired { 24 } else { 17 },
                true,
                if repaired {
                    Vec::new()
                } else {
                    vec![ChatArtifactRenderFinding {
                        code: "comparison_depth_thin".to_string(),
                        severity: ChatArtifactRenderFindingSeverity::Warning,
                        summary: "The first render still needs a stronger qubit comparison module."
                            .to_string(),
                    }]
                },
                vec![
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Desktop,
                        if repaired { 46 } else { 28 },
                        if repaired { 540 } else { 320 },
                        if repaired { 7 } else { 4 },
                    ),
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Mobile,
                        if repaired { 42 } else { 24 },
                        if repaired { 482 } else { 274 },
                        if repaired { 7 } else { 4 },
                    ),
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Interaction,
                        if repaired { 45 } else { 22 },
                        if repaired { 498 } else { 248 },
                        if repaired { 8 } else { 4 },
                    ),
                ],
            )))
        }
    }

    with_modal_first_html_env_async(|| async {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(QuantumWorkGraphRegressionRuntime {
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                },
                role: "production",
                calls: calls.clone(),
            });
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(QuantumWorkGraphRegressionRuntime {
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some(
                        "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance"
                            .to_string(),
                    ),
                },
                role: "acceptance",
                calls: calls.clone(),
            });
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let runtime_plan = resolve_chat_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            ChatArtifactRuntimePolicyProfile::FullyLocal,
        );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            "Quantum computers interactive explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            None,
        )
        .await;
        let evaluator = QuantumWorkGraphRegressionRenderEvaluator;

        let bundle =
            generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                "Quantum computers interactive explainer",
                "Create an interactive HTML artifact that explains quantum computers",
                &request,
                None,
                &planning_context,
                ChatExecutionStrategy::AdaptiveWorkGraph,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("quantum work_graph bundle should generate");

        assert!(bundle.candidate_summaries.is_empty());
        assert_eq!(
            bundle
                .work_graph_plan
                .as_ref()
                .map(|plan| plan.execution_domain.as_str()),
            Some("chat_artifact")
        );
        assert_eq!(
            bundle
                .work_graph_execution
                .as_ref()
                .map(|execution| execution.verification_status.as_str()),
            Some("pass")
        );
        assert_eq!(
            bundle
                .work_graph_execution
                .as_ref()
                .map(|execution| execution.current_stage.as_str()),
            Some("ready")
        );
        assert_eq!(
            bundle.validation.classification,
            ChatArtifactValidationStatus::Pass
        );
        assert!(bundle
            .work_graph_worker_receipts
            .iter()
            .any(|receipt| receipt.role == ChatArtifactWorkerRole::Repair
                && receipt.status == ChatArtifactWorkItemStatus::Succeeded));
        assert!(bundle
            .work_graph_plan
            .as_ref()
            .is_some_and(|plan| plan
                .work_items
                .iter()
                .any(|item| item.id == "repair-pass-1"
                    && item.spawned_from_id.as_deref() == Some("repair"))));
        assert!(bundle
            .work_graph_change_receipts
            .iter()
            .any(|receipt| receipt.work_item_id == "repair-pass-1" && receipt.operation_count > 0));
        assert!(bundle
            .work_graph_merge_receipts
            .iter()
            .any(|receipt| receipt.work_item_id == "repair-pass-1"));
        assert!(bundle
            .work_graph_verification_receipts
            .iter()
            .any(|receipt| receipt.kind == "artifact_validation"));
        assert!(bundle
            .execution_envelope
            .as_ref()
            .is_some_and(|envelope| envelope
                .graph_mutation_receipts
                .iter()
                .any(|receipt| receipt.mutation_kind == "subtask_spawned")));
        assert!(bundle
            .execution_envelope
            .as_ref()
            .is_some_and(|envelope| envelope
                .dispatch_batches
                .iter()
                .any(|batch| {
                    batch.status != "blocked"
                        && batch
                            .work_item_ids
                            .iter()
                            .filter(|id| id.starts_with("section-"))
                            .count()
                            >= 2
                })));
        assert!(bundle
            .render_evaluation
            .as_ref()
            .is_some_and(|evaluation| evaluation.captures.iter().any(|capture| {
                capture.viewport == ChatArtifactRenderCaptureViewport::Interaction
                    && capture.interactive_element_count >= 8
            })));
        assert!(bundle.winner.files.iter().any(|file| {
            file.path == "index.html"
                && file.body.contains("data-verified-repair=\"quantum-state-compare\"")
                && file.body.contains("Quantum Qubit")
        }));

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|call| call == "production:brief"));
        assert!(recorded_calls.iter().any(|call| call == "production:skeleton"));
        assert!(recorded_calls.iter().any(|call| call == "production:style"));
        assert!(recorded_calls.iter().any(|call| call == "production:interaction"));
        assert!(recorded_calls.iter().any(|call| call == "production:repair"));
        assert!(!recorded_calls
            .iter()
            .any(|call| call.starts_with("acceptance:")));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.ends_with(":validation"))
                .count(),
            0
        );
    })
    .await;
}

#[tokio::test]
async fn local_html_work_graph_strategy_breaks_complex_mission_control_query_into_iterative_waves() {
    #[derive(Clone)]
    struct ComplexMissionControlRuntime {
        provenance: ChatRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        section_regions: Vec<String>,
        repair_region: String,
    }

    fn section_region_from_prompt(prompt: &str, section_regions: &[String]) -> Option<String> {
        let candidate = [
            "\"targetRegion\":\"",
            "\"targetRegion\": \"",
            "targetRegion\":\"",
            "targetRegion\": \"",
        ]
        .into_iter()
        .find_map(|needle| {
            let start = prompt.find(needle)? + needle.len();
            let rest = &prompt[start..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        });

        candidate.filter(|region| section_regions.iter().any(|entry| entry == region))
    }

    #[async_trait]
    impl InferenceRuntime for ComplexMissionControlRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief".to_string()
            } else if prompt.contains("typed work_graph Skeleton worker") {
                "skeleton".to_string()
            } else if prompt.contains("typed work_graph SectionContent worker") {
                let region = section_region_from_prompt(&prompt, &self.section_regions)
                    .unwrap_or_else(|| "section:unknown".to_string());
                format!("section:{region}")
            } else if prompt.contains("typed work_graph StyleSystem worker") {
                "style".to_string()
            } else if prompt.contains("typed work_graph Interaction worker") {
                "interaction".to_string()
            } else if prompt.contains("typed work_graph Repair worker") {
                "repair".to_string()
            } else if prompt.contains("typed work_graph Integrator worker") {
                "integrator".to_string()
            } else if prompt.contains("typed artifact validation") {
                "validation".to_string()
            } else {
                "unknown".to_string()
            };

            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("{}:{stage}", self.role));

            let response = if stage == "brief" {
                serde_json::to_value(sample_complex_mission_control_brief()).expect("complex brief")
            } else if stage == "skeleton" {
                serde_json::json!({
                    "summary": "Mission control workbook shell",
                    "notes": ["Created the canonical mission-control HTML shell."],
                    "operations": [{
                        "kind": "create_file",
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><meta charset=\"utf-8\"><title>Post-quantum migration mission control</title></head><body><main><header><h1>Post-quantum migration mission control</h1><p>Track rollout phases, inspect risk posture, compare owner handoffs, and test cutover readiness from one control room artifact.</p><div class=\"mode-switch\"><button type=\"button\" data-panel=\"phases\" aria-selected=\"true\">Phases</button><button type=\"button\" data-panel=\"risk\" aria-selected=\"false\">Risk</button><button type=\"button\" data-panel=\"handoffs\" aria-selected=\"false\">Handoffs</button></div></header><aside class=\"detail-rail\"><h2>Operator detail</h2><p id=\"detail-copy\">Phases panel is selected with fleet rollout evidence visible on first paint.</p></aside></main></body></html>"
                    }]
                })
            } else if let Some(region) = stage.strip_prefix("section:") {
                let section_markup = if region == self.section_regions[0] {
                    "<section data-panel=\"phases\" class=\"mission-panel\"><article><h2>Fleet rollout phases</h2><p>Wave 1 upgrades signing infrastructure, Wave 2 rotates edge services, and Wave 3 retires the legacy fallback lane after verification clears.</p><ol><li><strong>Pilot:</strong> five canary regions with manual approval.</li><li><strong>Expansion:</strong> regional fleet rollout with live latency watch.</li><li><strong>Retire:</strong> remove the legacy signing path after rollback confidence stays green.</li></ol><div class=\"evidence-strip\"><button type=\"button\" data-detail=\"Pilot phase focuses on low-blast-radius rollout across five regions.\">Pilot focus</button><button type=\"button\" data-detail=\"Expansion phase compares readiness, latency, and rollback tolerance.\">Expansion focus</button></div></article></section>"
                } else if region == self.section_regions[1] {
                    "<section data-panel=\"risk\" class=\"mission-panel\"><article><h2>Cryptography risk drilldown</h2><p>Inspect signing libraries, vendor readiness, and support exposure before each cutover decision.</p><table><tr><th>Surface</th><th>Status</th><th>Risk</th></tr><tr><td>Identity signing</td><td>Library patched</td><td>Low</td></tr><tr><td>Mobile SDK</td><td>Vendor awaiting rollout</td><td>Medium</td></tr><tr><td>Support scripts</td><td>Legacy fallback active</td><td>High</td></tr></table><div class=\"risk-toggles\"><button type=\"button\" data-risk=\"identity\">Identity</button><button type=\"button\" data-risk=\"mobile\">Mobile</button><button type=\"button\" data-risk=\"support\">Support</button></div></article></section>"
                } else {
                    "<section data-panel=\"handoffs\" class=\"mission-panel\"><article><h2>Owner handoffs and cutover simulation</h2><p>Compare who owns preflight, cutover, and rollback, then simulate whether the current readiness state permits launch.</p><div class=\"ownership-grid\"><div><h3>Infrastructure</h3><p>Owns certificate rotation, cutover execution, and rollback thresholds.</p></div><div><h3>Product</h3><p>Owns rollout messaging, customer sequencing, and regional launch approval.</p></div><div><h3>Support</h3><p>Owns incident intake, escalation templates, and customer-safe fallback guidance.</p></div></div><div class=\"simulator\"><button type=\"button\" data-sim=\"hold\">Hold rollout</button><button type=\"button\" data-sim=\"launch\">Launch rollout</button></div><p id=\"sim-status\">Simulation idle. Review ownership signals before launch.</p></article></section>"
                };

                serde_json::json!({
                    "summary": format!("Filled {region} with request-grounded mission-control content."),
                    "notes": [format!("Patched scoped region {region}.")],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": region,
                        "body": section_markup
                    }]
                })
            } else if stage == "style" {
                serde_json::json!({
                    "summary": "Applied the mission-control style system.",
                    "notes": ["Added the shared slate hierarchy and compact chrome."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": "style-system",
                        "body": "<style>:root{color-scheme:dark;--bg:#11161c;--panel:#1a212b;--panel-alt:#151b24;--border:#2c3948;--text:#e8eef6;--muted:#94a3b8;--accent:#7dd3fc;--warn:#f59e0b;}*{box-sizing:border-box;}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);}main{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:18px;padding:22px;max-width:1200px;margin:0 auto;}header,section,aside{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:18px;}header{grid-column:1 / span 2;display:grid;gap:14px;}h1,h2,h3,p,ol{margin:0;}p,li,td,th{color:var(--muted);line-height:1.5;}table{width:100%;border-collapse:collapse;margin-top:12px;}th,td{padding:10px 12px;border-bottom:1px solid var(--border);text-align:left;}button{border:1px solid #31506d;background:#182635;color:var(--text);border-radius:999px;padding:9px 13px;font:inherit;cursor:pointer;}button[aria-selected=\"true\"],button[data-active=\"true\"]{border-color:var(--accent);box-shadow:0 0 0 1px rgba(125,211,252,.34) inset;}header .mode-switch,.evidence-strip,.risk-toggles,.simulator{display:flex;gap:10px;flex-wrap:wrap;}.mission-panel{display:grid;gap:14px;}.ownership-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;}.ownership-grid>div{background:var(--panel-alt);border:1px solid var(--border);border-radius:14px;padding:12px;}.detail-rail{position:sticky;top:18px;height:max-content;}#sim-status{padding:12px 14px;border-radius:14px;background:rgba(125,211,252,.08);border:1px solid rgba(125,211,252,.22);color:var(--text);}strong{color:var(--text);}</style>"
                    }]
                })
            } else if stage == "interaction" {
                serde_json::json!({
                    "summary": "Wired the mission-control interaction grammar.",
                    "notes": ["Bound the control bar, detail rail, risk drilldown, and cutover simulator."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": "interaction",
                        "body": "<script>const detail=document.getElementById('detail-copy');const panels=[...document.querySelectorAll('.mission-panel')];const tabButtons=[...document.querySelectorAll('button[data-panel]')];tabButtons.forEach((button)=>button.addEventListener('click',()=>{const target=button.dataset.panel;tabButtons.forEach((control)=>control.setAttribute('aria-selected',String(control===button)));panels.forEach((panel)=>panel.dataset.active=String(panel.dataset.panel===target));detail.textContent=target==='phases'?'Phases panel selected. Inspect the rollout wave timing and the readiness evidence strip.':target==='risk'?'Risk panel selected. Compare surface readiness and vendor exposure before cutover.':'Handoffs panel selected. Compare owners and simulate whether launch can proceed.';}));document.querySelectorAll('[data-detail]').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=button.dataset.detail;}));document.querySelectorAll('[data-risk]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-risk]').forEach((control)=>control.dataset.active=String(control===button));detail.textContent=button.dataset.risk==='identity'?'Identity path is patched and ready for early rollout.':button.dataset.risk==='mobile'?'Mobile path is blocked on vendor rollout timing.':'Support path still depends on the legacy fallback lane.';}));const simStatus=document.getElementById('sim-status');document.querySelectorAll('[data-sim]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-sim]').forEach((control)=>control.dataset.active=String(control===button));if(button.dataset.sim==='launch'){simStatus.textContent='Launch simulation: proceed only if vendor readiness and rollback staffing both stay green.';detail.textContent='Launch simulation selected. Confirm support staffing and vendor readiness before go-live.';}else{simStatus.textContent='Hold simulation: keep the rollout paused until support scripts leave the legacy lane.';detail.textContent='Hold simulation selected. Remediate the support fallback dependency before launch.';}}));</script>"
                    }]
                })
            } else if stage == "repair" {
                serde_json::json!({
                    "summary": "Added the missing rollback playbook detail.",
                    "notes": ["Repair added the cited fallback playbook depth."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": self.repair_region,
                        "body": "<section data-panel=\"handoffs\" class=\"mission-panel\" data-repaired=\"rollback-playbook\"><article><h2>Owner handoffs and cutover simulation</h2><p>Compare who owns preflight, cutover, and rollback, then simulate whether the current readiness state permits launch.</p><div class=\"ownership-grid\"><div><h3>Infrastructure</h3><p>Owns certificate rotation, cutover execution, and rollback thresholds.</p></div><div><h3>Product</h3><p>Owns rollout messaging, customer sequencing, and regional launch approval.</p></div><div><h3>Support</h3><p>Owns incident intake, escalation templates, and customer-safe fallback guidance.</p></div></div><section class=\"rollback-playbook\"><h3>Rollback playbook</h3><p>If vendor readiness drops or support fallback remains red, freeze launch, return traffic to the legacy signer, and page the owning leads in the order shown above.</p></section><div class=\"simulator\"><button type=\"button\" data-sim=\"hold\">Hold rollout</button><button type=\"button\" data-sim=\"launch\">Launch rollout</button></div><p id=\"sim-status\">Simulation idle. Review ownership signals before launch.</p></article></section>"
                    }]
                })
            } else if stage == "integrator" {
                serde_json::json!({
                    "summary": "Integrator stayed in reserve.",
                    "notes": ["Local HTML path keeps the integrator as a reserve seam."],
                    "operations": []
                })
            } else if stage == "validation" {
                let repaired_already = self
                    .calls
                    .lock()
                    .expect("calls lock")
                    .iter()
                    .any(|call| call == "production:repair")
                    || prompt.contains("data-repaired=\"rollback-playbook\"")
                    || prompt.contains("Rollback playbook");
                if repaired_already {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 5,
                        "conceptCoverage": 5,
                        "interactionRelevance": 5,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 5,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "The repaired mission-control artifact now covers rollout, risk, ownership, and rollback decisions with visible interactions."
                    })
                } else {
                    serde_json::json!({
                        "classification": "repairable",
                        "requestFaithfulness": 4,
                        "conceptCoverage": 4,
                        "interactionRelevance": 4,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 3,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": "The artifact still needs an explicit rollback playbook inside the owner handoff surface.",
                        "rationale": "The control room is strong, but the launch decision loop is incomplete without a visible rollback playbook."
                    })
                }
            } else {
                return Err(VmError::HostError("unexpected Chat prompt".to_string()));
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

    #[derive(Default)]
    struct ComplexMissionControlRenderEvaluator;

    #[async_trait]
    impl ChatArtifactRenderEvaluator for ComplexMissionControlRenderEvaluator {
        async fn evaluate_candidate_render(
            &self,
            _request: &ChatOutcomeArtifactRequest,
            _brief: &ChatArtifactBrief,
            _blueprint: Option<&ChatArtifactBlueprint>,
            _artifact_ir: Option<&ChatArtifactIR>,
            _edit_intent: Option<&ChatArtifactEditIntent>,
            candidate: &ChatGeneratedArtifactPayload,
        ) -> Result<Option<ChatArtifactRenderEvaluation>, String> {
            let repaired = candidate
                .files
                .iter()
                .find(|file| file.path == "index.html")
                .map(|file| file.body.contains("data-repaired=\"rollback-playbook\""))
                .unwrap_or(false);

            Ok(Some(chat_test_render_evaluation(
                if repaired { 32 } else { 24 },
                true,
                if repaired {
                    Vec::new()
                } else {
                    vec![ChatArtifactRenderFinding {
                        code: "rollback_playbook_missing".to_string(),
                        severity: ChatArtifactRenderFindingSeverity::Warning,
                        summary: "The first render still needs an explicit rollback playbook in the handoff surface.".to_string(),
                    }]
                },
                vec![
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Desktop,
                        if repaired { 58 } else { 42 },
                        if repaired { 910 } else { 680 },
                        if repaired { 12 } else { 8 },
                    ),
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Mobile,
                        if repaired { 51 } else { 36 },
                        if repaired { 840 } else { 590 },
                        if repaired { 11 } else { 7 },
                    ),
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Interaction,
                        if repaired { 56 } else { 40 },
                        if repaired { 876 } else { 622 },
                        if repaired { 13 } else { 8 },
                    ),
                ],
            )))
        }
    }

    with_modal_first_html_env_async(|| async {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_complex_mission_control_brief();
        let blueprint = derive_chat_artifact_blueprint(&request, &brief);
        let work_graph_plan = super::generation::build_chat_artifact_work_graph_plan(
            &request,
            Some(&blueprint),
            &brief,
            ChatExecutionStrategy::AdaptiveWorkGraph,
        );
        let section_regions = work_graph_plan
            .work_items
            .iter()
            .filter(|item| item.role == ChatArtifactWorkerRole::SectionContent)
            .flat_map(|item| item.write_regions.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            section_regions.len(),
            3,
            "complex HTML briefs should coalesce into three bounded section workers"
        );
        let repair_region = section_regions
            .last()
            .cloned()
            .expect("repair region should exist");

        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(ComplexMissionControlRuntime {
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                },
                role: "production",
                calls: calls.clone(),
                section_regions: section_regions.clone(),
                repair_region: repair_region.clone(),
            });
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(ComplexMissionControlRuntime {
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some(
                        "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance"
                            .to_string(),
                    ),
                },
                role: "acceptance",
                calls: calls.clone(),
                section_regions: section_regions.clone(),
                repair_region: repair_region.clone(),
            });
        let runtime_plan = resolve_chat_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            ChatArtifactRuntimePolicyProfile::FullyLocal,
        );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            "Post-quantum migration mission control",
            "Create an interactive HTML mission control artifact for a post-quantum migration program that lets operators compare rollout phases, inspect cryptography risk, simulate cutover decisions, and review owner handoffs with a visible rollback playbook.",
            &request,
            None,
        )
        .await;
        let evaluator = ComplexMissionControlRenderEvaluator;

        let bundle =
            generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                "Post-quantum migration mission control",
                "Create an interactive HTML mission control artifact for a post-quantum migration program that lets operators compare rollout phases, inspect cryptography risk, simulate cutover decisions, and review owner handoffs with a visible rollback playbook.",
                &request,
                None,
                &planning_context,
                ChatExecutionStrategy::AdaptiveWorkGraph,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("complex mission-control work_graph bundle should generate");

        assert!(bundle.candidate_summaries.is_empty());
        assert_eq!(
            bundle.validation.classification,
            ChatArtifactValidationStatus::Pass
        );

        let envelope = bundle
            .execution_envelope
            .as_ref()
            .expect("execution envelope");
        assert_eq!(
            envelope.execution_summary.as_ref().map(|summary| summary.current_stage.as_str()),
            Some("ready")
        );
        assert_eq!(
            envelope.execution_summary.as_ref().map(|summary| summary.verification_status.as_str()),
            Some("pass")
        );
        assert!(
            envelope.dispatch_batches.len() >= 5,
            "complex local HTML should require several iterative dispatch waves"
        );
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().filter(|id| id.starts_with("section-")).count() == 2
                && !batch.deferred_work_item_ids.is_empty()
        }));
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().filter(|id| id.starts_with("section-")).count() == 1
                && batch.deferred_work_item_ids.is_empty()
        }));
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().any(|id| id == "style-system")
                && batch.work_item_ids.iter().any(|id| id == "interaction")
        }));
        assert!(envelope
            .graph_mutation_receipts
            .iter()
            .any(|receipt| receipt.mutation_kind == "subtask_spawned"));
        assert!(envelope
            .repair_receipts
            .iter()
            .any(|receipt| receipt.status == "pass"
                && receipt
                    .work_item_ids
                    .iter()
                    .any(|id| id == "repair-pass-1")));
        assert!(
            envelope
                .budget_summary
                .as_ref()
                .and_then(|summary| summary.token_budget)
                .unwrap_or_default()
                > 0
        );
        assert!(
            envelope
                .budget_summary
                .as_ref()
                .and_then(|summary| summary.dispatched_worker_count)
                .unwrap_or_default()
                >= 7
        );

        let section_receipts = bundle
            .work_graph_worker_receipts
            .iter()
            .filter(|receipt| receipt.role == ChatArtifactWorkerRole::SectionContent)
            .collect::<Vec<_>>();
        assert_eq!(section_receipts.len(), 3);
        assert!(section_receipts.iter().all(|receipt| {
            receipt.status == ChatArtifactWorkItemStatus::Succeeded
                && receipt.write_regions.len() == 1
        }));
        assert!(bundle
            .work_graph_change_receipts
            .iter()
            .filter(|receipt| receipt.work_item_id.starts_with("section-"))
            .all(|receipt| receipt.operation_count == 1 && receipt.touched_regions.len() == 1));
        assert!(bundle
            .work_graph_verification_receipts
            .iter()
            .any(|receipt| receipt.kind == "artifact_validation"));
        assert!(bundle.winner.files.iter().any(|file| {
            file.path == "index.html"
                && file.body.contains("Fleet rollout phases")
                && file.body.contains("Cryptography risk drilldown")
                && file.body.contains("Owner handoffs and cutover simulation")
                && file.body.contains("Rollback playbook")
                && file.body.contains("data-repaired=\"rollback-playbook\"")
        }));
        assert!(bundle
            .render_evaluation
            .as_ref()
            .is_some_and(|evaluation| evaluation.captures.iter().any(|capture| {
                capture.viewport == ChatArtifactRenderCaptureViewport::Interaction
                    && capture.interactive_element_count >= 13
            })));

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|call| call == "production:brief"));
        assert!(recorded_calls.iter().any(|call| call == "production:skeleton"));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.starts_with("production:section:section:"))
                .count(),
            3
        );
        assert!(recorded_calls.iter().any(|call| call == "production:style"));
        assert!(recorded_calls.iter().any(|call| call == "production:interaction"));
        assert!(recorded_calls.iter().any(|call| call == "production:repair"));
        assert!(!recorded_calls
            .iter()
            .any(|call| call.starts_with("acceptance:")));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.ends_with(":validation"))
                .count(),
            0
        );
    })
    .await;
}
