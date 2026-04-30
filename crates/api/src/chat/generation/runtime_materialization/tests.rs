mod tests {
    use super::should_skip_direct_author_continuation;
    use super::*;
    use ioi_types::app::{
        ChatArtifactDeliverableShape, ChatArtifactPersistenceMode, ChatOutcomeArtifactScope,
        ChatOutcomeArtifactVerificationRequest,
    };

    fn sample_html_document_request() -> ChatOutcomeArtifactRequest {
        ChatOutcomeArtifactRequest {
            artifact_class: ChatArtifactClass::Document,
            deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
            renderer: ChatRendererKind::HtmlIframe,
            presentation_surface: ChatPresentationSurface::SidePanel,
            persistence: ChatArtifactPersistenceMode::ArtifactScoped,
            execution_substrate: ChatExecutionSubstrate::ClientSandbox,
            workspace_recipe_id: None,
            presentation_variant_id: None,
            scope: ChatOutcomeArtifactScope {
                target_project: None,
                create_new_workspace: false,
                mutation_boundary: vec!["artifact".to_string()],
            },
            verification: ChatOutcomeArtifactVerificationRequest {
                require_render: false,
                require_build: false,
                require_preview: false,
                require_export: false,
                require_diff_review: false,
            },
        }
    }

    fn sample_brief() -> ChatArtifactBrief {
        ChatArtifactBrief {
            audience: "General users".to_string(),
            job_to_be_done: "Explain the requested concept.".to_string(),
            subject_domain: "Education".to_string(),
            artifact_thesis: "A compact explanatory artifact.".to_string(),
            required_concepts: vec!["Quantum computers".to_string()],
            required_interactions: Vec::new(),
            query_profile: None,
            visual_tone: Vec::new(),
            factual_anchors: Vec::new(),
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        }
    }

    #[test]
    fn local_document_html_with_boundary_skips_continuation() {
        let request = sample_html_document_request();
        let raw = "<!doctype html><html><body><main><section><h1>Quantum</h1></section></main></body></html>";
        let error = "HTML iframe artifacts must contain a closed <main> region.";

        assert!(should_skip_direct_author_continuation(
            &request,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            raw,
            error,
        ));
    }

    #[test]
    fn local_document_html_without_boundary_keeps_continuation_available() {
        let request = sample_html_document_request();
        let raw = "<!doctype html><html><body><main><section><h1>Quantum</h1><p>Explain qubits and superposition.";
        let error =
            "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.";

        assert!(!should_skip_direct_author_continuation(
            &request,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            raw,
            error,
        ));
    }

    #[test]
    fn local_interactive_html_closed_main_settles_without_full_html_stop() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Quantum computers</h1><p>Compare qubits, gates, and measurement.</p></section>
          <section><h2>Explore</h2><p id="detail-content">Use this authored response region to explain the selected quantum idea, including how superposition keeps a qubit in a blend of possible outcomes until measurement, how gates rotate that state, and why a small interaction can still be added by repair if the first local stream stopped after the visible main region. The important runtime behavior is that a clearly closed, request-shaped main document should not keep the user staring at Stop while the model waits for a final html token that may never arrive. This paragraph intentionally keeps the stream substantial enough to represent the local model artifact observed in the GUI probe.</p><p>The runtime can normalize the terminal body and html tags after the stream settles, then pass the document through the usual validation and repair path.</p></section>
        </main>"#;

        assert!(
            direct_author_stream_settle_snapshot(&request, raw).is_some(),
            "a closed, complete-enough <main> stream should settle instead of holding the Stop state open until </html>"
        );
    }

    #[test]
    fn local_interactive_html_closed_main_ignores_trailing_script_start_for_stream_settle() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Understanding quantum computers</h1><p>Qubits, gates, superposition, and measurement are introduced with enough authored copy to preview the artifact.</p></section>
          <section><h2>Explore</h2><p id="detail-content">This visible response region is populated before script repair. It explains how qubits keep probability amplitudes, how gates transform state, and how measurement collapses a distribution into a classical result. The authored copy is already substantial enough for a first preview, and a local repair pass can still add controls or deterministic_repair script wiring after the stream settles. That is the important behavior for desktop local GPU runs: the chat UI should not keep showing Stop only because the model began a trailing script tag after completing the visible main artifact.</p></section>
        </main>

        <script>"#;

        let settled = direct_author_stream_settle_snapshot(&request, raw)
            .expect("closed main should settle even when the stream already started a script tag");

        assert!(
            settled.ends_with("</body></html>"),
            "settled snapshot should normalize terminal body/html closure: {settled}"
        );
        assert!(
            !settled.to_ascii_lowercase().contains("<script"),
            "settled snapshot should drop the unfinished script fragment: {settled}"
        );
    }

    #[test]
    fn local_interactive_html_salvage_prefers_renderable_main_over_partial_script() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Quantum computer playground</h1><p>Explore qubits, gates, amplitudes, and measurement with a visible first paint.</p></section>
          <section><h2>Live evidence</h2><p id="feedback-text">The response region already explains that measuring a qubit collapses probability amplitudes into one classical state, while gates transform the probability distribution before measurement. This is enough authored content for a safe local preview.</p></section>
        </main>
        <div class="overlay" id="overlay"><div class="modal"><p id="overlay-text">Select a tab to learn more.</p></div></div>
        <script>
          const content = {
            intro: {
              heading: "What is a Qubit?",
              text: `Classical computers use bits that are either 0 or 1.<br/>A qubit is a quantum"#;

        let salvaged = salvage_interrupted_direct_author_document(&request, raw);

        assert!(
            salvaged.ends_with("</body></html>"),
            "salvage should normalize a closed renderable prefix: {salvaged}"
        );
        assert!(
            !salvaged.to_ascii_lowercase().contains("<script"),
            "salvage should discard the unfinished script tail: {salvaged}"
        );
        assert!(
            !direct_author_document_is_incomplete(&request, &salvaged, ""),
            "salvaged prefix should be structurally complete enough for validation/repair"
        );
    }

    #[test]
    fn local_interactive_html_raw_document_accepts_without_semantic_repair_heuristics() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Quantum computer playground</h1><p>Explore qubits, gates, amplitudes, and measurement with a compact authored surface.</p></section>
          <section><h2>State evidence</h2><button type="button" id="inspect-state">Inspect state</button><p>A visible default state explains how amplitudes represent possible measurement outcomes before observation.</p></section>
          <aside role="status" aria-live="polite"><p id="state-detail">Use the authored controls to compare the default quantum state.</p></aside>
        </main><script>document.getElementById('inspect-state').addEventListener('click',function(){document.getElementById('state-detail').textContent='Measurement collapses the authored qubit state into one visible classical outcome.';});</script></body></html>"#;

        let generated =
            parse_direct_author_generated_candidate(raw, &request, &sample_brief(), None, "clean")
                .expect(
                    "raw direct-author HTML should package without interaction-count heuristics",
                );
        let body = &generated.files[0].body;

        assert!(body.contains("Quantum computer playground"));
        assert!(
            !body.contains("data-ioi-deterministic-repair"),
            "clean direct-author mode must not inject local heuristic deterministic_repair wiring"
        );
        assert!(generated
            .notes
            .iter()
            .any(|note| note.contains("typed renderer contract checks")));
    }

    #[test]
    fn raw_direct_author_fragment_is_rejected_by_primary_view_contract() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = "<!doctype html><html><head><title>Mortgage Calculator</title>";

        let error = parse_direct_author_generated_candidate(
            raw,
            &request,
            &sample_brief(),
            None,
            "fragment",
        )
        .expect_err("head-only HTML must not satisfy the raw direct-author contract");

        assert!(
            error
                .message
                .contains("HTML sectioning regions are empty shells on first paint."),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn primary_view_contract_deterministic_repair_removes_html_comments_and_adds_response_region() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let raw = r#"<!doctype html><html><body><main>
          <!-- authored notes should not ship -->
          <section><h1>Mortgage Calculator</h1><p>Compare loan amount, rate, and term with a visible monthly payment.</p></section>
          <section><h2>Inputs</h2><label for="amount">Loan amount</label><input id="amount" type="number" value="450000"></section>
          <section><h2>Output</h2><p id="payment">$2,997 monthly payment</p></section>
        </main><script>document.getElementById('amount').addEventListener('input',function(){document.getElementById('payment').textContent='$3,100 monthly payment';});</script></body></html>"#;

        let (repaired, strategy) = try_local_html_primary_view_contract_repair(
            &request,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            raw,
            "HTML still contains placeholder-grade copy or comments on first paint.",
        )
        .expect("comment-only primary-view failure should be locally recoverable");

        assert_eq!(strategy, "primary_view_contract");
        assert!(!repaired.contains("<!--"));
        assert!(repaired.contains("role=\"status\""));
        parse_direct_author_generated_candidate(
            &repaired,
            &request,
            &sample_brief(),
            None,
            "repaired-primary-view",
        )
        .expect("repaired primary view should satisfy typed raw contract");
    }

    #[test]
    fn form_control_deterministic_repair_supports_number_inputs_and_evidence_surfaces() {
        let raw = r#"<!doctype html><html><body><main>
          <!-- deterministic repair should remove authoring comments -->
          <section><h1>Adjustable calculator</h1><p>Change the visible inputs to update the result.</p></section>
          <section><h2>Inputs</h2><label for="amount">Amount</label><input id="amount" type="number" value="450000"><label for="rate">Rate</label><input id="rate" type="number" value="6.5"></section>
          <section><h2>Result</h2><p id="resultbox">$2,844 monthly payment</p></section>
        </main></body></html>"#;

        let repaired = try_local_html_form_control_repair(raw, &raw.to_ascii_lowercase())
            .expect("number-only controls should be eligible for form deterministic_repair");
        let lower = repaired.to_ascii_lowercase();

        assert!(repaired.contains("data-ioi-deterministic-repair=\"form-response\""));
        assert!(!html_contains_placeholder_markers(&lower));
        assert!(count_populated_html_response_regions(&lower) >= 1);
        assert!(count_populated_html_evidence_regions(&lower) >= 2);
    }

    #[test]
    fn form_control_deterministic_repair_marks_visible_result_box_as_live_response() {
        let raw = r#"<!doctype html><html><body><main>
          <section><h1>Mortgage calculator</h1><p>Adjust the principal and rate to update the estimate.</p></section>
          <section><h2>Controls</h2><label for="principal">Principal</label><input id="principal" type="number" value="550000"><label for="rate">Rate</label><input id="rate" type="number" value="6.5"></section>
          <section><h2>Estimate</h2><div id="result-box" class="result-box"><div class="result-label">Estimated monthly payment</div><div id="monthly-payment" class="result-value">$0.00</div></div></section>
        </main></body></html>"#;

        let repaired = try_local_html_form_control_repair(raw, &raw.to_ascii_lowercase())
            .expect("number controls with a visible result box should be recoverable");
        let lower = repaired.to_ascii_lowercase();

        assert!(
            lower.contains(
                "id=\"result-box\" class=\"result-box\" role=\"status\" aria-live=\"polite\""
            ) || lower.contains(
                "id=\"result-box\" class=\"result-box\" aria-live=\"polite\" role=\"status\""
            ),
            "visible result box should be promoted to the live response surface: {repaired}"
        );
        assert!(lower.contains("class~=\"result-value\""));
        assert!(count_populated_html_response_regions(&lower) >= 1);
        assert!(count_populated_html_evidence_regions(&lower) >= 2);
    }

    #[test]
    fn local_interactive_html_direct_author_budget_allows_structural_completion() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;

        assert_eq!(
            materialization_max_tokens_for_execution_strategy(
                request.renderer,
                ChatExecutionStrategy::DirectAuthor,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            3600
        );
        assert_eq!(
            direct_author_stream_timeout_for_request(
                &request,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            Some(Duration::from_secs(220))
        );
    }

    #[test]
    fn local_interactive_html_prefers_complete_stream_buffer_over_return_buffer() {
        let mut request = sample_html_document_request();
        request.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        let returned_raw =
            "<!doctype html><html><body><main><section><h1>Quantum</h1><p>unfinished";
        let streamed_raw = r#"<!doctype html><html><body><main>
          <section><h1>Quantum computers</h1><p>Explore qubits, gates, amplitudes, and measurement.</p></section>
        </main></body></html>"#;

        let candidates =
            direct_author_raw_document_parse_candidates(&request, returned_raw, streamed_raw);

        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.contains("</main></body></html>")),
            "stream collector should remain available as a raw structural candidate"
        );
        assert!(candidates.iter().any(|candidate| {
            parse_direct_author_generated_candidate(
                candidate,
                &request,
                &sample_brief(),
                None,
                "stream",
            )
            .is_ok()
        }));
    }
}
