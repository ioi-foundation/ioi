use super::*;

#[test]
fn studio_authoritative_status_preserves_completed_inline_reply() {
    let mut task = empty_task("What is the capital of Spain?");
    let outcome_request = StudioOutcomeRequest {
        request_id: "conversation-inline".to_string(),
        raw_prompt: "What is the capital of Spain?".to_string(),
        active_artifact_id: None,
        outcome_kind: StudioOutcomeKind::Conversation,
        execution_strategy: StudioExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.99,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["no_persistent_artifact_requested".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_studio_session(
        &mut task,
        "What is the capital of Spain?",
        crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );
    task.phase = AgentPhase::Complete;
    task.current_step = "Ready for input".to_string();
    task.history.push(ChatMessage {
        role: "agent".to_string(),
        text: "The capital of Spain is Madrid.".to_string(),
        timestamp: crate::kernel::state::now(),
    });

    apply_studio_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(task.current_step, "Ready for input");
    assert_eq!(
        task.history.last().map(|entry| entry.text.as_str()),
        Some("The capital of Spain is Madrid."),
    );
}

#[test]
fn partial_nonworkspace_artifact_marks_task_complete() {
    let mut task = test_task(StudioArtifactVerificationStatus::Partial);

    apply_studio_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(
        task.current_step,
        "Studio partially materialized the requested artifact and needs follow-up verification."
    );
}

#[test]
fn weak_html_artifact_is_downgraded_to_blocked() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
            &request,
            &[MaterializedArtifactQualityFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                renderable: true,
                downloadable: true,
                text_content: Some(
                    "<!doctype html><html><body><main><section><h1>Placeholder</h1><p>Coming soon.</p></section></main></body></html>"
                        .to_string(),
                ),
            }],
        );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert!(assessment.summary.contains("blocked"));
}

#[test]
fn acceptance_judge_promotes_soft_html_prefilter_findings_to_ready() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
            &request,
            &[MaterializedArtifactQualityFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                renderable: true,
                downloadable: true,
                text_content: Some(
                    "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Launch sequencing, adoption by channel, partner enablement, and retailer milestones stay visible in this interactive rollout page.</p></section><section><h2>Why now</h2><p>The story focuses on channel readiness, store education, and repeat-purchase lift without falling back to a generic shell.</p></section></main></body></html>"
                        .to_string(),
                ),
            }],
        );
    let promoted = finalize_presentation_assessment(
        &request,
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Pass,
            request_faithfulness: 5,
            concept_coverage: 4,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness: 4,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths: vec!["Acceptance cleared the artifact for primary presentation.".to_string()],
            blocked_reasons: Vec::new(),
            file_findings: Vec::new(),
            aesthetic_verdict: "clear_hierarchy_and_density".to_string(),
            interaction_verdict: "request_aligned".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: None,
            strongest_contradiction: None,
            rationale: "acceptance cleared the artifact".to_string(),
        },
        None,
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Ready
    );
    assert!(promoted.summary.contains("acceptance judging cleared"));
}

#[test]
fn render_eval_warning_keeps_html_out_of_ready_state_even_when_acceptance_passes() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "<!doctype html><html><head><style>body { font-family: 'Avenir Next', sans-serif; background: #f6f1e7; color: #1b1a17; } main { display: grid; gap: 1.5rem; padding: 2rem; } .hero, .grid, .evidence, footer { background: #fffdf8; border: 1px solid #d5c7ad; border-radius: 20px; padding: 1.25rem; } .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; } .metric { background: #f0e2c8; border-radius: 14px; padding: 0.85rem; }</style></head><body><main><section class=\"hero\"><h1>Dog shampoo rollout command center</h1><p>The launch page keeps merchandisers, veterinary advisers, and regional channel leads aligned on the first four weeks of the dog shampoo launch. A compact narrative explains the gentle skin positioning, fragrance-free formula, and retail education plan so the first visible artifact already feels like a real launch surface instead of a placeholder shell.</p><p>Operators can compare mass retail, ecommerce, and boutique pet-store readiness without leaving the page, then use the follow-up refinement pass to deepen ingredient and pH evidence.</p></section><section class=\"grid\"><article class=\"metric\"><h2>Mass Retail</h2><p>Floor sets complete in 81% of target doors, with sampling carts scheduled for the highest-volume weekend windows.</p></article><article class=\"metric\"><h2>Ecommerce</h2><p>Subscription attach is pacing above plan because the bundle pairs the shampoo with a coat brush and refill reminder.</p></article><article class=\"metric\"><h2>Boutique</h2><p>Independent stores are asking for more shelf talkers and a clearer ingredient story before launch week.</p></article></section><article class=\"evidence\"><h2>Launch evidence rail</h2><p>Retail readiness notes, customer language, and merchandising checkpoints stay visible together so the surface can support real refinement decisions. Teams can inspect the copy, compare channels, and extend the page with more charts in the next judged revision.</p><button type=\"button\">Inspect rollout detail</button></article><aside><p>Readiness evidence remains visible beside the command surface so approval notes do not drift away from the rendered artifact.</p></aside><footer><p>Current gap: ingredient and pH comparison charts still need a dedicated visual treatment.</p></footer></main></body></html>"
                    .to_string(),
            ),
        }],
    );
    let render_evaluation = StudioArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: true,
        captures: vec![
            StudioArtifactRenderCapture {
                viewport: StudioArtifactRenderCaptureViewport::Desktop,
                width: 1440,
                height: 960,
                screenshot_sha256: "desktop".to_string(),
                screenshot_byte_count: 4096,
                visible_element_count: 26,
                visible_text_chars: 380,
                interactive_element_count: 2,
                screenshot_changed_from_previous: false,
            },
            StudioArtifactRenderCapture {
                viewport: StudioArtifactRenderCaptureViewport::Mobile,
                width: 390,
                height: 844,
                screenshot_sha256: "mobile".to_string(),
                screenshot_byte_count: 3980,
                visible_element_count: 24,
                visible_text_chars: 352,
                interactive_element_count: 2,
                screenshot_changed_from_previous: true,
            },
        ],
        layout_density_score: 3,
        spacing_alignment_score: 3,
        typography_contrast_score: 4,
        visual_hierarchy_score: 3,
        blueprint_consistency_score: 3,
        overall_score: 16,
        findings: vec![StudioArtifactRenderFinding {
            code: "visual_hierarchy_flat".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Warning,
            summary: "The capture reads as visually flat instead of establishing a clear first-paint hierarchy."
                .to_string(),
        }],
        acceptance_obligations: Vec::new(),
        execution_witnesses: Vec::new(),
        summary:
            "Render evaluation found repairable desktop/mobile issues with an overall score of 16/25."
                .to_string(),
    observation: None,
    acceptance_policy: None,
};
    let promoted = finalize_presentation_assessment(
        &request,
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Pass,
            request_faithfulness: 5,
            concept_coverage: 4,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness: 4,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths: vec!["Acceptance cleared the artifact for primary presentation.".to_string()],
            blocked_reasons: Vec::new(),
            file_findings: Vec::new(),
            aesthetic_verdict: "clear_hierarchy_and_density".to_string(),
            interaction_verdict: "request_aligned".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: None,
            strongest_contradiction: None,
            rationale: "acceptance cleared the artifact".to_string(),
        },
        Some(&render_evaluation),
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
    assert!(promoted
        .summary
        .contains("render evaluation kept it provisional"));
    assert!(promoted
        .findings
        .iter()
        .any(|finding| finding.contains("visually flat")));
}

#[test]
fn render_eval_blocker_overrides_acceptance_pass_for_html_artifacts() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Launch sequencing, adoption by channel, partner enablement, and retailer milestones stay visible in this interactive rollout page.</p></section><section><h2>Why now</h2><p>The story focuses on channel readiness, store education, and repeat-purchase lift without falling back to a generic shell.</p></section></main></body></html>"
                    .to_string(),
            ),
        }],
    );
    let render_evaluation = StudioArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: false,
        interaction_capture_attempted: false,
        captures: vec![StudioArtifactRenderCapture {
            viewport: StudioArtifactRenderCaptureViewport::Desktop,
            width: 1440,
            height: 960,
            screenshot_sha256: "desktop".to_string(),
            screenshot_byte_count: 0,
            visible_element_count: 0,
            visible_text_chars: 0,
            interactive_element_count: 0,
            screenshot_changed_from_previous: false,
        }],
        layout_density_score: 1,
        spacing_alignment_score: 1,
        typography_contrast_score: 1,
        visual_hierarchy_score: 1,
        blueprint_consistency_score: 1,
        overall_score: 5,
        findings: vec![StudioArtifactRenderFinding {
            code: "capture_missing".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary:
                "Desktop and mobile render captures must both exist before Studio can trust the surfaced first paint."
                    .to_string(),
        }],
        acceptance_obligations: Vec::new(),
        execution_witnesses: Vec::new(),
        summary:
            "Render evaluation blocked the primary view after desktop/mobile capture with an overall score of 5/25."
                .to_string(),
    observation: None,
    acceptance_policy: None,
};
    let promoted = finalize_presentation_assessment(
        &request,
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Pass,
            request_faithfulness: 5,
            concept_coverage: 4,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness: 4,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths: vec!["Acceptance cleared the artifact for primary presentation.".to_string()],
            blocked_reasons: Vec::new(),
            file_findings: Vec::new(),
            aesthetic_verdict: "clear_hierarchy_and_density".to_string(),
            interaction_verdict: "request_aligned".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: None,
            strongest_contradiction: None,
            rationale: "acceptance cleared the artifact".to_string(),
        },
        Some(&render_evaluation),
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert!(promoted.summary.contains("render evaluation blocked"));
    assert!(promoted
        .findings
        .iter()
        .any(|finding| finding.contains("Desktop and mobile render captures must both exist")));
}

#[test]
fn html_presentation_assessment_does_not_rederive_duplicate_mapped_view_token_blockers() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;background:#f6f1e7;color:#1b1a17;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside,footer{padding:1rem;border:1px solid #d7ccb8;border-radius:16px;background:#fffdf8;}button{border:1px solid #8c6f48;background:#f0dfc0;border-radius:999px;padding:0.45rem 0.85rem;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness, operators, risks, and adoption metrics without leaving the artifact surface. The default state opens with enough written evidence to support a real first paint while the alternate state stays pre-rendered for later comparison. This assessment intentionally exercises presentation scoring rather than upstream payload validation, so the layout remains dense, styled, and semantically complete.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here with launch sequencing, operator ownership, and an explanation of why the current baseline matters before any interaction runs.</p><p>The overview panel also includes a concise narrative about adoption momentum, risk posture, and the commitments needed before the release can advance.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"overview\" hidden><article><h2>Metrics</h2><p>Metrics evidence is still pre-rendered here with retention, latency, and completion-rate notes. The duplicated token should be rejected by payload validation upstream, but presentation assessment should not re-derive that blocker when the rendered surface is otherwise substantial.</p><p>This extra paragraph keeps the document dense enough to avoid skeletal-output blocking.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default with readiness evidence and operator notes already visible.</p></aside><footer><p>Footer note summarizing next steps, ownership, and verification posture for the launch review.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>"
                    .to_string(),
            ),
        }],
    );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Ready
    );
    assert!(!assessment.has_structural_blocker);
}

#[test]
fn html_prefilter_marks_shim_heavy_output_as_partial() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;background:#f6f1e7;color:#1b1a17;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside,footer{padding:1rem;border:1px solid #d7ccb8;border-radius:16px;}</style></head><body data-studio-normalized=\"true\"><main><section><h1>Launch review</h1><p>Compare readiness, risk, and adoption metrics without leaving the artifact. The review opens on a populated operational snapshot so the reader can assess baseline momentum before switching views.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here, including deployment confidence, operator trust, and a short narrative about what changed in the latest release.</p><p>The default view gives the artifact enough first-paint density to qualify as a real surface instead of a shell.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics</h2><p>Metrics evidence stays pre-rendered with retention, latency, and completion-rate notes so the comparison panel already exists before any interaction.</p><p>Secondary evidence remains hidden until the user switches views, but the content is still present in the DOM.</p></article></section><aside data-studio-normalized=\"true\"><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default with readiness evidence, deployment confidence, and release notes already visible.</p></aside><footer><p>Footer note summarizing next steps, ownership, and verification posture for the launch review.</p></footer><script data-studio-view-switch-repair=\"true\">const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>"
                    .to_string(),
            ),
        }],
    );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Ready
    );
    assert!(!assessment
        .findings
        .iter()
        .any(|finding| finding.contains("repair shims")));
}

#[test]
fn html_prefilter_marks_unfocusable_rollover_targets_as_partial() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside,footer{padding:1rem;border:1px solid #cbd5e1;border-radius:16px;}svg{width:100%;max-width:320px;height:auto;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness, adoption, and support demand through a narrative artifact with visible evidence marks, a shared detail panel, and enough first-paint density to qualify as a real surface.</p></section><section><article><h2>Evidence</h2><p>The chart surfaces three evidence marks with rollout context, operator notes, and escalation posture already visible before interaction.</p><svg viewBox=\"0 0 320 120\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"24\" y=\"28\" width=\"52\" height=\"64\" fill=\"#2563eb\" data-detail=\"Readiness signal\"></rect><rect x=\"104\" y=\"16\" width=\"52\" height=\"76\" fill=\"#0f766e\" data-detail=\"Adoption signal\"></rect><rect x=\"184\" y=\"36\" width=\"52\" height=\"56\" fill=\"#b45309\" data-detail=\"Support signal\"></rect></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Readiness signal is selected by default with rollout evidence already visible.</p></aside><footer><p>Footer note summarizing next steps, ownership, and verification posture for the launch review.</p></footer><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('focus',()=>{detail.textContent=mark.getAttribute('data-detail');});mark.addEventListener('mouseenter',()=>{detail.textContent=mark.getAttribute('data-detail');});});</script></main></body></html>"
                    .to_string(),
            ),
        }],
    );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "launches Chromium to validate HTML artifact interactions"]
async fn html_headless_validation_probe_confirms_view_switching_without_runtime_errors() {
    let raw_html = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Studio validation probe</title>
    <style>
      body {
        font-family: system-ui, sans-serif;
        background: #f5f3ee;
        color: #1b1a17;
        margin: 0;
      }
      main {
        display: grid;
        gap: 1rem;
        padding: 1.5rem;
      }
      section,
      aside,
      footer {
        border: 1px solid #d7ccb8;
        border-radius: 16px;
        padding: 1rem;
        background: #fffdf8;
      }
      .control-bar {
        display: flex;
        gap: 0.75rem;
      }
      [hidden] {
        display: none !important;
      }
    </style>
  </head>
  <body>
    <main>
      <section>
        <h1>Launch review</h1>
        <p>Compare readiness, momentum, and operating metrics without leaving the artifact surface.</p>
        <div class="control-bar">
          <button type="button" data-view="overview" aria-controls="overview-panel">Overview</button>
          <button type="button" data-view="metrics" aria-controls="metrics-panel">Metrics</button>
        </div>
      </section>
      <section id="overview-panel" data-view-panel="overview">
        <article>
          <h2>Overview</h2>
          <p>Readiness evidence stays visible here with deployment confidence, change notes, and rollout context.</p>
        </article>
      </section>
      <section id="metrics-panel" data-view-panel="metrics" hidden>
        <article>
          <h2>Metrics</h2>
          <p>Metrics evidence stays pre-rendered with completion rate, latency, and incident posture already in the DOM.</p>
        </article>
      </section>
      <aside>
        <h2>Detail</h2>
        <p id="detail-copy">Overview is selected by default with readiness evidence already visible.</p>
      </aside>
      <footer>
        <p>Footer note summarizing next steps, owners, and verification posture.</p>
      </footer>
    </main>
    <script>
      const detail = document.getElementById("detail-copy");
      const panels = Array.from(document.querySelectorAll("[data-view-panel]"));
      document.querySelectorAll("button[data-view]").forEach((button) => {
        button.addEventListener("click", () => {
          panels.forEach((panel) => {
            panel.hidden = panel.dataset.viewPanel !== button.dataset.view;
          });
          detail.textContent = button.dataset.view + " selected with surfaced evidence.";
        });
      });
    </script>
  </body>
</html>
"#;
    let fixture_path = write_temp_studio_html_fixture(
        "studio-html-validation",
        &instrument_html_for_headless_validation(raw_html),
    );
    let fixture_url = format!("file://{}", fixture_path.display());

    let driver = BrowserDriver::new();
    driver.set_lease(true);
    driver
        .navigate(&fixture_url)
        .await
        .expect("fixture should load");

    let initial_errors = driver
        .probe_selector("html[data-studio-validation-error='true']")
        .await
        .expect("probe should succeed");
    assert!(
        !initial_errors.found,
        "fixture should not throw on first paint"
    );

    let overview_before = driver
        .probe_selector("#overview-panel")
        .await
        .expect("overview probe");
    let metrics_before = driver
        .probe_selector("#metrics-panel")
        .await
        .expect("metrics probe");
    assert!(overview_before.visible, "overview panel should be visible");
    assert!(!metrics_before.visible, "metrics panel should start hidden");
    assert_eq!(
        driver
            .selector_text("#detail-copy")
            .await
            .expect("detail copy lookup")
            .as_deref(),
        Some("Overview is selected by default with readiness evidence already visible.")
    );

    driver
        .click_selector("button[data-view='metrics']")
        .await
        .expect("metrics view should click");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let overview_after = driver
        .probe_selector("#overview-panel")
        .await
        .expect("overview probe after click");
    let metrics_after = driver
        .probe_selector("#metrics-panel")
        .await
        .expect("metrics probe after click");
    assert!(
        !overview_after.visible,
        "overview panel should hide after click"
    );
    assert!(
        metrics_after.visible,
        "metrics panel should show after click"
    );

    let detail_after = driver
        .selector_text("#detail-copy")
        .await
        .expect("detail copy after click")
        .unwrap_or_default();
    assert!(
        detail_after.contains("metrics selected"),
        "detail panel should reflect the switched view, got: {detail_after}"
    );

    let post_click_errors = driver
        .probe_selector("html[data-studio-validation-error='true']")
        .await
        .expect("post-click probe should succeed");
    assert!(
        !post_click_errors.found,
        "fixture should stay free of runtime errors after interaction"
    );

    let _ = fs::remove_file(&fixture_path);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "launches Chromium to validate browser-backed render evaluation"]
async fn browser_render_evaluator_captures_desktop_mobile_and_interaction() {
    let evaluator = BrowserStudioArtifactRenderEvaluator::default();
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "inspect an interactive rollout story".to_string(),
        subject_domain: "launch review".to_string(),
        artifact_thesis: "Show desktop and mobile hierarchy with a visible interaction change."
            .to_string(),
        required_concepts: vec!["timeline".to_string(), "metrics".to_string()],
        required_interactions: vec!["view switching".to_string()],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["launch evidence".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["comparison panel".to_string()],
        query_profile: None,
    };
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Interactive rollout explainer".to_string(),
        notes: vec!["browser render evaluation validation pass".to_string()],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><head><meta charset=\"utf-8\"><style>body{margin:0;font-family:Georgia,serif;background:#f6f1e7;color:#1b1a17;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside{background:#fffdf8;border:1px solid #d5c7ad;border-radius:16px;padding:1rem;}button{border:1px solid #8c6f48;background:#f0dfc0;border-radius:999px;padding:0.45rem 0.85rem;}[hidden]{display:none !important;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics without leaving the artifact surface.</p><div><button type=\"button\" data-studio-render-primary-action=\"true\" data-view=\"overview\">Overview</button><button type=\"button\" data-view=\"metrics\">Metrics</button></div></section><section id=\"overview-panel\" data-view-panel=\"overview\"><h2>Overview</h2><p>Readiness evidence stays visible on first paint.</p></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><h2>Metrics</h2><p>Metrics evidence becomes visible after interaction.</p></section><aside><p id=\"detail-copy\">Overview selected.</p></aside></main><script>const detail=document.getElementById('detail-copy');const panels=Array.from(document.querySelectorAll('[data-view-panel]'));document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected';}));</script></body></html>".to_string(),
        }],
    };

    let render_evaluation = evaluator
        .evaluate_candidate_render(&request, &brief, None, None, None, &candidate)
        .await
        .expect("render evaluation should succeed")
        .expect("html render evaluation should be supported");

    assert!(render_evaluation.supported);
    assert!(render_evaluation.first_paint_captured);
    assert!(render_evaluation.overall_score > 0);
    assert!(render_evaluation
        .captures
        .iter()
        .any(|capture| capture.viewport == StudioArtifactRenderCaptureViewport::Desktop));
    assert!(render_evaluation
        .captures
        .iter()
        .any(|capture| capture.viewport == StudioArtifactRenderCaptureViewport::Mobile));
    assert!(render_evaluation
        .captures
        .iter()
        .any(|capture| capture.viewport == StudioArtifactRenderCaptureViewport::Interaction));
}

#[test]
fn mermaid_prefilter_does_not_block_valid_compact_diagram_documents() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::Visual,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::Mermaid,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "approval_pipeline.mermaid".to_string(),
            mime: "text/plain".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "graph TD\n    A[Request] --> B[Review]\n    B --> C[Decision]\n    C --> D[Final Approval]\n"
                    .to_string(),
            ),
        }],
    );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Ready
    );
}

#[test]
fn repairable_acceptance_judge_keeps_html_out_of_ready_state() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
            &request,
            &[MaterializedArtifactQualityFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                renderable: true,
                downloadable: true,
                text_content: Some(
                    "<!doctype html><html><head><style>body { font-family: 'Avenir Next', sans-serif; background: #f6f1e7; color: #1b1a17; } main { display: grid; gap: 1.5rem; padding: 2rem; } .hero, .grid, .evidence, footer { background: #fffdf8; border: 1px solid #d5c7ad; border-radius: 20px; padding: 1.25rem; } .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; } .metric { background: #f0e2c8; border-radius: 14px; padding: 0.85rem; }</style></head><body><main><section class=\"hero\"><h1>Dog shampoo rollout command center</h1><p>The launch page keeps merchandisers, veterinary advisers, and regional channel leads aligned on the first four weeks of the dog shampoo launch. A compact narrative explains the gentle skin positioning, fragrance-free formula, and retail education plan so the first visible artifact already feels like a real launch surface instead of a placeholder shell.</p><p>Operators can compare mass retail, ecommerce, and boutique pet-store readiness without leaving the page, then use the follow-up refinement pass to deepen ingredient and pH evidence.</p></section><section class=\"grid\"><article class=\"metric\"><h2>Mass Retail</h2><p>Floor sets complete in 81% of target doors, with sampling carts scheduled for the highest-volume weekend windows.</p></article><article class=\"metric\"><h2>Ecommerce</h2><p>Subscription attach is pacing above plan because the bundle pairs the shampoo with a coat brush and refill reminder.</p></article><article class=\"metric\"><h2>Boutique</h2><p>Independent stores are asking for more shelf talkers and a clearer ingredient story before launch week.</p></article></section><article class=\"evidence\"><h2>Launch evidence rail</h2><p>Retail readiness notes, customer language, and merchandising checkpoints stay visible together so the surface can support real refinement decisions. Teams can inspect the copy, compare channels, and extend the page with more charts in the next judged revision.</p><button type=\"button\">Inspect rollout detail</button></article><aside><p>Readiness evidence remains visible beside the command surface so approval notes do not drift away from the rendered artifact.</p></aside><footer><p>Current gap: ingredient and pH comparison charts still need a dedicated visual treatment.</p></footer></main></body></html>"
                        .to_string(),
                ),
            }],
        );
    let promoted = finalize_presentation_assessment(
        &request,
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Repairable,
            request_faithfulness: 4,
            concept_coverage: 3,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness: 4,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes: vec!["content_gap".to_string()],
            repair_hints: vec![
                "Add ingredient analysis and pH comparison charts before promoting the artifact."
                    .to_string(),
            ],
            strengths: vec![
                "The launch surface is already coherent enough for a targeted refinement pass."
                    .to_string(),
            ],
            blocked_reasons: Vec::new(),
            file_findings: vec!["Missing ingredient analysis and pH level charts".to_string()],
            aesthetic_verdict: "serviceable_but_needs_more_visual_evidence".to_string(),
            interaction_verdict: "refinement_needed".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: Some("refinement_pass".to_string()),
            strongest_contradiction: Some(
                "Missing ingredient analysis and pH level charts".to_string(),
            ),
            rationale: "Needs another refinement pass.".to_string(),
        },
        None,
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
    assert!(promoted.summary.contains("kept it out of the primary view"));
    assert!(promoted
        .findings
        .iter()
        .any(|finding| finding.contains("Missing ingredient analysis")));
}

#[test]
fn draft_pending_acceptance_surfaces_viable_html_as_partial() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "<!doctype html><html><head><style>body { font-family: 'Avenir Next', sans-serif; background: #f6f1e7; color: #1b1a17; } main { display: grid; gap: 1.5rem; padding: 2rem; } .hero, .grid, .evidence, footer { background: #fffdf8; border: 1px solid #d5c7ad; border-radius: 20px; padding: 1.25rem; } .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; } .metric { background: #f0e2c8; border-radius: 14px; padding: 0.85rem; }</style></head><body><main><section class=\"hero\"><h1>Dog shampoo rollout command center</h1><p>The launch page keeps merchandisers, veterinary advisers, and regional channel leads aligned on the first four weeks of the dog shampoo launch. A compact narrative explains the gentle skin positioning, fragrance-free formula, and retail education plan so the first visible artifact already feels like a real launch surface instead of a placeholder shell.</p><p>Operators can compare mass retail, ecommerce, and boutique pet-store readiness without leaving the page, then use the follow-up refinement pass to deepen ingredient and pH evidence.</p></section><section class=\"grid\"><article class=\"metric\"><h2>Mass Retail</h2><p>Floor sets complete in 81% of target doors, with sampling carts scheduled for the highest-volume weekend windows.</p></article><article class=\"metric\"><h2>Ecommerce</h2><p>Subscription attach is pacing above plan because the bundle pairs the shampoo with a coat brush and refill reminder.</p></article><article class=\"metric\"><h2>Boutique</h2><p>Independent stores are asking for more shelf talkers and a clearer ingredient story before launch week.</p></article></section><article class=\"evidence\"><h2>Launch evidence rail</h2><p>Retail readiness notes, customer language, and merchandising checkpoints stay visible together so the surface can support real refinement decisions. Teams can inspect the copy, compare channels, and extend the page with more charts in the next judged revision.</p><button type=\"button\">Inspect rollout detail</button></article><aside><p>Readiness evidence remains visible beside the command surface so approval notes do not drift away from the rendered artifact.</p></aside><footer><p>Current gap: ingredient and pH comparison charts still need a dedicated visual treatment.</p></footer></main></body></html>"
                    .to_string(),
            ),
        }],
    );
    let promoted = finalize_presentation_assessment(
        &request,
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Repairable,
            request_faithfulness: 4,
            concept_coverage: 4,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness: 4,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes: vec!["acceptance_pending".to_string()],
            repair_hints: vec![
                "Run the acceptance pass before promoting the draft into the ready state."
                    .to_string(),
            ],
            strengths: vec![
                "Production surfaced a request-faithful draft with viable structure.".to_string(),
            ],
            blocked_reasons: Vec::new(),
            file_findings: vec!["Acceptance judging is still pending for this draft.".to_string()],
            aesthetic_verdict: "provisionally_viable".to_string(),
            interaction_verdict: "awaiting_acceptance_confirmation".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: Some("acceptance_pass".to_string()),
            strongest_contradiction: Some(
                "Acceptance judging is still pending for this draft.".to_string(),
            ),
            rationale: "Production surfaced a request-faithful draft.".to_string(),
        },
        None,
        false,
        true,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
    assert!(promoted.summary.contains("request-faithful draft"));
    assert!(promoted
        .findings
        .iter()
        .any(|finding| finding.contains("Acceptance judging is still pending")));
}

#[test]
fn external_runtime_dependency_keeps_html_prefilter_blocked() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
            &request,
            &[MaterializedArtifactQualityFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                renderable: true,
                downloadable: true,
                text_content: Some(
                    "<!doctype html><html><body><main><section><h1>Instacart MCP rollout</h1><button type=\"button\">Inspect</button></section><article><svg id=\"chart\"></svg></article><aside><p>Timeline</p></aside><footer><script>const chart = d3.select('#chart');</script></footer></main></body></html>"
                        .to_string(),
                ),
            }],
        );
    let promoted = finalize_presentation_assessment(
        &request,
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Pass,
            request_faithfulness: 5,
            concept_coverage: 5,
            interaction_relevance: 5,
            layout_coherence: 5,
            visual_hierarchy: 5,
            completeness: 5,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths: vec![
                "Acceptance liked the artifact before renderer-truthfulness checks ran."
                    .to_string(),
            ],
            blocked_reasons: Vec::new(),
            file_findings: Vec::new(),
            aesthetic_verdict: "visually_clear".to_string(),
            interaction_verdict: "request_aligned".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: None,
            strongest_contradiction: None,
            rationale: "acceptance liked the artifact".to_string(),
        },
        None,
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert!(promoted
        .summary
        .contains("blocked the primary presentation"));
}

#[test]
fn pdf_artifact_bytes_include_document_body() {
    let pdf = pdf_artifact_bytes(
        "Launch brief",
        "Executive summary\n\nThis launch brief includes the goals, rollout plan, owner table, and verification notes for the artifact stage.",
    );
    let pdf_text = String::from_utf8_lossy(&pdf);

    assert!(pdf_text.contains("Launch brief"));
    assert!(pdf_text.contains("Executive summary"));
    assert!(pdf.starts_with(b"%PDF-"));
}
