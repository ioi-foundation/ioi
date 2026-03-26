fn build_ctx<'a>(services: &'a ServiceDirectory) -> TxContext<'a> {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    TxContext {
        block_height: 1,
        block_timestamp: now_ns,
        chain_id: ioi_types::app::ChainId(0),
        signer_account_id: ioi_types::app::AccountId::default(),
        services,
        simulation: false,
        is_internal: false,
    }
}

fn read_agent_state(state: &IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) -> AgentState {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    codec::from_bytes_canonical(&bytes).expect("agent state should decode")
}

fn read_incident_pending_gate_hash(
    state: &IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
) -> Option<[u8; 32]> {
    let key = [INCIDENT_PREFIX, session_id.as_slice()].concat();
    let bytes = state.get(&key).ok().flatten()?;
    let incident: IncidentState = codec::from_bytes_canonical(&bytes).ok()?;
    if !incident.active {
        return None;
    }
    incident
        .pending_gate
        .as_ref()
        .and_then(|gate| parse_hex_hash_32(&gate.request_hash))
}

fn has_review_request_for_hash(
    state: &IAVLTree<HashCommitmentScheme>,
    request_hash: [u8; 32],
) -> bool {
    let key = ioi_services::agentic::desktop::keys::pii::review::request(&request_hash);
    state.get(&key).ok().flatten().is_some()
}

fn seeded_required_capabilities(scope: IntentScopeProfile, intent_id: &str) -> Vec<CapabilityId> {
    let normalized_intent_id = intent_id.trim().to_ascii_lowercase();
    if normalized_intent_id == "automation.monitor" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("automation.monitor.install"),
        ];
    }
    if normalized_intent_id == "mail.read.latest" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.read.latest"),
        ];
    }
    if normalized_intent_id == "mail.list.recent" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.list.recent"),
        ];
    }
    if normalized_intent_id == "mail.delete.spam" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.delete.spam"),
        ];
    }
    if normalized_intent_id == "mail.reply" {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.reply"),
        ];
    }
    if normalized_intent_id == "gmail.send_email"
        || normalized_intent_id == "google.gmail.send_email"
    {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.reply"),
            CapabilityId::from("mail.send"),
            CapabilityId::from("gmail.write"),
        ];
    }
    if normalized_intent_id == "gmail.draft_email"
        || normalized_intent_id == "google.gmail.draft_email"
    {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("mail.reply"),
            CapabilityId::from("mail.send"),
            CapabilityId::from("gmail.write"),
        ];
    }
    if normalized_intent_id == "calendar.create_event"
        || normalized_intent_id == "google.calendar.create_event"
    {
        return vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("calendar.write"),
        ];
    }

    let mut caps = match scope {
        IntentScopeProfile::Conversation => vec![CapabilityId::from("conversation.reply")],
        IntentScopeProfile::WebResearch => vec![
            CapabilityId::from("web.retrieve"),
            CapabilityId::from("browser.interact"),
            CapabilityId::from("browser.inspect"),
            CapabilityId::from("conversation.reply"),
            CapabilityId::from("sys.time.read"),
        ],
        IntentScopeProfile::WorkspaceOps => vec![
            CapabilityId::from("filesystem.read"),
            CapabilityId::from("filesystem.write"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::AppLaunch => vec![
            CapabilityId::from("app.launch"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::UiInteraction => vec![
            CapabilityId::from("ui.interact"),
            CapabilityId::from("ui.inspect"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::CommandExecution => vec![
            CapabilityId::from("command.exec"),
            CapabilityId::from("command.probe"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::Delegation => vec![
            CapabilityId::from("delegation.manage"),
            CapabilityId::from("conversation.reply"),
        ],
        IntentScopeProfile::Unknown => vec![CapabilityId::from("conversation.reply")],
    };

    let install_intent = normalized_intent_id.contains("install");
    if install_intent && matches!(scope, IntentScopeProfile::CommandExecution) {
        caps.push(CapabilityId::from("system.install_package"));
    }

    caps
}

fn seed_resolved_intent(
    state: &mut IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
    intent_id: &str,
    scope: IntentScopeProfile,
) {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    let mut agent_state: AgentState =
        codec::from_bytes_canonical(&bytes).expect("agent state should decode");
    agent_state.resolved_intent = Some(ResolvedIntentState {
        intent_id: intent_id.to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: seeded_required_capabilities(scope, intent_id),
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "test".to_string(),
        embedding_model_id: "test-embed".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    });
    agent_state.awaiting_intent_clarification = false;
    agent_state.status = AgentStatus::Running;
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&agent_state).expect("state encode"),
        )
        .expect("state insert should not fail");
}

fn apply_capabilities_policy(state: &mut IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) {
    let mut rules = default_safe_policy();
    // Dedicated live capabilities suite should validate execution success without
    // interactive approval gates blocking baseline command/app flows.
    rules.defaults = DefaultPolicy::AllowAll;
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state
        .insert(
            &policy_key,
            &codec::to_bytes_canonical(&rules).expect("policy encode"),
        )
        .expect("policy insert should not fail");
}

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, sink: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        sink.push(event);
    }
}

async fn drain_events_until_quiescent(
    rx: &mut broadcast::Receiver<KernelEvent>,
    sink: &mut Vec<KernelEvent>,
    max_wait: Duration,
    idle_poll: Duration,
    required_idle_polls: usize,
) {
    let started = Instant::now();
    let mut idle_polls = 0usize;

    loop {
        let before = sink.len();
        drain_events(rx, sink);
        if sink.len() > before {
            idle_polls = 0;
        } else {
            idle_polls = idle_polls.saturating_add(1);
            if idle_polls >= required_idle_polls || started.elapsed() >= max_wait {
                break;
            }
        }
        tokio::time::sleep(idle_poll).await;
    }
}

fn requires_human_intervention(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    [
        "waiting for approval",
        "waiting for user intervention",
        "human verification",
        "captcha",
        "sudo password",
        "credential",
        "clarification",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn truncate_for_log(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        compact
    } else {
        compact.chars().take(max_chars).collect::<String>() + "..."
    }
}

fn event_log_line(event: &KernelEvent, max_chars: usize) -> String {
    match event {
        KernelEvent::AgentActionResult {
            tool_name,
            output,
            error_class,
            agent_status,
            ..
        } => format!(
            "action tool={} status={} error_class={} output={}",
            tool_name,
            agent_status,
            error_class.as_deref().unwrap_or("none"),
            truncate_for_log(output, max_chars)
        ),
        KernelEvent::RoutingReceipt(RoutingReceiptEvent {
            tool_name,
            policy_decision,
            post_state,
            ..
        }) => format!(
            "routing tool={} decision={} success={} checks={}",
            tool_name,
            policy_decision,
            post_state.success,
            truncate_for_log(&post_state.verification_checks.join(","), max_chars)
        ),
        KernelEvent::WorkloadReceipt(workload) => match &workload.receipt {
            WorkloadReceipt::WebRetrieve(web) => format!(
                "workload web tool={} success={} sources={} docs={}",
                web.tool_name, web.success, web.sources_count, web.documents_count
            ),
            WorkloadReceipt::Adapter(adapter) => format!(
                "workload adapter tool={} adapter={} success={}",
                adapter.tool_name, adapter.adapter_id, adapter.success
            ),
            _ => "workload other".to_string(),
        },
        KernelEvent::IntentResolutionReceipt(receipt) => {
            format!("intent scope={:?} band={:?}", receipt.scope, receipt.band)
        }
        _ => {
            let debug_payload = format!("{:?}", event);
            format!(
                "event(other) payload={}",
                truncate_for_log(&debug_payload, max_chars)
            )
        }
    }
}

fn event_summary_line(event: &KernelEvent) -> String {
    event_log_line(event, 280)
}

fn event_full_line(event: &KernelEvent) -> String {
    event_log_line(event, 2_000)
}

fn extract_json_prefix_object(input: &str) -> Option<&str> {
    let trimmed = input.trim_start();
    let mut chars = trimmed.char_indices();
    let (start_idx, first_char) = chars.next()?;
    if start_idx != 0 || first_char != '{' {
        return None;
    }

    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in chars {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&trimmed[..=idx]);
                }
            }
            _ => {}
        }
    }

    None
}

fn extract_command_history_evidence(output: &str) -> Option<CommandHistoryEvidence> {
    let payload = output.strip_prefix("COMMAND_HISTORY:")?;
    let json_fragment = extract_json_prefix_object(payload)?;
    let parsed: CommandHistoryPayload = serde_json::from_str(json_fragment).ok()?;
    Some(CommandHistoryEvidence {
        command: parsed.command,
        exit_code: parsed.exit_code,
        stdout: parsed.stdout,
        stderr: parsed.stderr,
    })
}

fn command_history_key(entry: &CommandHistoryEvidence) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        entry.command, entry.exit_code, entry.stdout, entry.stderr
    )
}

fn push_command_history_evidence(
    command_history_evidence: &mut Vec<CommandHistoryEvidence>,
    command_history_keys: &mut BTreeSet<String>,
    entry: CommandHistoryEvidence,
) {
    let key = command_history_key(&entry);
    if command_history_keys.insert(key) {
        command_history_evidence.push(entry);
    }
}

fn command_history_from_exec_workload(
    exec: &WorkloadExecReceipt,
    evidence: Option<&ExecWorkloadEvidence>,
) -> CommandHistoryEvidence {
    let command = if !exec.command_preview.trim().is_empty() {
        exec.command_preview.clone()
    } else if exec.args.is_empty() {
        exec.command.clone()
    } else {
        format!("{} {}", exec.command, exec.args.join(" "))
    };
    let exit_code = evidence
        .and_then(|item| item.exit_code)
        .or(exec.exit_code)
        .unwrap_or(if exec.success { 0 } else { 1 });
    let stdout = evidence
        .map(ExecWorkloadEvidence::stdout_text)
        .unwrap_or_default();
    let stderr = evidence
        .map(ExecWorkloadEvidence::stderr_text)
        .unwrap_or_default();
    CommandHistoryEvidence {
        command,
        exit_code,
        stdout,
        stderr,
    }
}

pub async fn run_case(
    case: &QueryCase,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
) -> Result<RunObservation> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let memory_runtime = build_memory_runtime()?;
    let service = DesktopAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        agent_runtime.clone(),
        agent_runtime,
    )
    .with_memory_runtime(memory_runtime)
    .with_event_sender(event_tx);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let wallet_service = Arc::new(WalletNetworkService::default());
    let services_dir =
        ServiceDirectory::new(vec![wallet_service.clone() as Arc<dyn BlockchainService>]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = session_id_for_index(run_index);
    let run_timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let run_unique_num = run_unique_num(run_index, run_timestamp_ms);
    let mut run_query = render_query_for_run(case.query, run_index, run_timestamp_ms);
    let mut runtime_setup_verification_checks = Vec::<String>::new();
    let mut runtime_setup_environment_receipts = Vec::<EnvironmentReceiptObservation>::new();
    let vlc_install_fixture = bootstrap_optional_fixture(
        should_bootstrap_vlc_install_fixture(case.id),
        bootstrap_vlc_install_fixture_runtime,
        |fixture| {
            environment_evidence_batch_from_checks(vlc_install_fixture_preflight_checks(
                fixture,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let desktop_project_create_fixture = bootstrap_optional_fixture(
        should_bootstrap_desktop_project_create_fixture(case.id),
        || bootstrap_desktop_project_create_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(desktop_project_create_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let projects_zip_fixture = bootstrap_optional_fixture(
        should_bootstrap_projects_zip_fixture(case.id),
        bootstrap_projects_zip_fixture_runtime,
        |fixture| {
            environment_evidence_batch_from_checks(projects_zip_fixture_preflight_checks(
                fixture,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let downloads_lowercase_fixture = bootstrap_optional_fixture(
        should_bootstrap_downloads_lowercase_fixture(case.id),
        || bootstrap_downloads_lowercase_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(downloads_lowercase_fixture_preflight_checks(
                fixture,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let downloads_png_move_fixture = bootstrap_optional_fixture(
        should_bootstrap_downloads_png_move_fixture(case.id),
        || bootstrap_downloads_png_move_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(downloads_png_move_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = downloads_png_move_fixture.as_ref() {
        run_query = run_query.replace(
            "{DOWNLOADS_PNG_MOVE_FIXTURE_DIR}",
            &fixture.target_dir.to_string_lossy(),
        );
    }
    let desktop_documents_backup_fixture = bootstrap_optional_fixture(
        should_bootstrap_desktop_documents_backup_fixture(case.id),
        || bootstrap_desktop_documents_backup_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(
                desktop_documents_backup_fixture_preflight_checks(
                    fixture,
                    &run_unique_num,
                    run_timestamp_ms,
                ),
            )
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = desktop_documents_backup_fixture.as_ref() {
        run_query = run_query.replace(
            "{BACKUP_EXTERNAL_DRIVE_PATH}",
            &fixture.external_drive_path.to_string_lossy(),
        );
        run_query = run_query.replace(
            "{BACKUP_DESTINATION_PATH}",
            &fixture.backup_root.to_string_lossy(),
        );
    }
    let documents_summary_fixture = bootstrap_optional_fixture(
        should_bootstrap_documents_summary_fixture(case.id),
        || bootstrap_documents_summary_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(documents_summary_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = documents_summary_fixture.as_ref() {
        run_query = run_query.replace("{DOCS_FIXTURE_DIR}", &fixture.fixture_dir.to_string_lossy());
    }
    let pdf_last_week_fixture = bootstrap_optional_fixture(
        should_bootstrap_pdf_last_week_fixture(case.id),
        || bootstrap_pdf_last_week_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(pdf_last_week_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = pdf_last_week_fixture.as_ref() {
        run_query = run_query.replace(
            "{PDF_LAST_WEEK_FIXTURE_DIR}",
            &fixture.fixture_dir.to_string_lossy(),
        );
    }
    let spotify_uninstall_fixture = bootstrap_optional_fixture(
        should_bootstrap_spotify_uninstall_fixture(case.id),
        || bootstrap_spotify_uninstall_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(spotify_uninstall_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = spotify_uninstall_fixture.as_ref() {
        run_query = run_query.replace(
            "{SPOTIFY_UNINSTALL_FIXTURE_ROOT}",
            &fixture.fixture_root.to_string_lossy(),
        );
    }
    let top_memory_apps_fixture = bootstrap_optional_fixture(
        should_bootstrap_top_memory_apps_fixture(case.id),
        || bootstrap_top_memory_apps_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(top_memory_apps_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let media_transcript_fixture = bootstrap_optional_fixture(
        should_bootstrap_media_transcript_fixture(case.id),
        || bootstrap_media_transcript_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(media_transcript_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = top_memory_apps_fixture.as_ref() {
        run_query = run_query.replace(
            "{TOP_MEMORY_APPS_PROBE_PATH}",
            &fixture.probe_script_path.to_string_lossy(),
        );
    }
    let shutdown_schedule_fixture = bootstrap_optional_fixture(
        should_bootstrap_shutdown_schedule_fixture(case.id),
        || bootstrap_shutdown_schedule_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(shutdown_schedule_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    if let Some(fixture) = shutdown_schedule_fixture.as_ref() {
        run_query = run_query.replace(
            "{SHUTDOWN_SCHEDULE_PROBE_PATH}",
            &fixture.probe_script_path.to_string_lossy(),
        );
    }
    let hacker_news_monitor_fixture = bootstrap_optional_fixture(
        should_bootstrap_hacker_news_monitor_fixture(case.id),
        || bootstrap_hacker_news_monitor_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(hacker_news_monitor_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let mail_reply_mock_fixture = bootstrap_optional_fixture(
        should_bootstrap_mail_reply_mock_fixture(case.id),
        || bootstrap_mail_reply_mock_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(mail_reply_mock_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let google_connector_fixture = bootstrap_optional_fixture(
        should_bootstrap_google_connector_fixture(case.id),
        || bootstrap_google_connector_fixture_runtime(&run_unique_num),
        |fixture| {
            environment_evidence_batch_from_checks(google_connector_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            ))
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let restaurants_near_me_fixture = bootstrap_optional_fixture(
        should_bootstrap_restaurants_near_me_fixture(case.id),
        || bootstrap_restaurants_near_me_fixture_runtime(&run_unique_num),
        |fixture| {
            restaurants_near_me_fixture_preflight_checks(fixture, &run_unique_num, run_timestamp_ms)
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let latest_nist_pqc_briefing_fixture = bootstrap_optional_fixture(
        should_bootstrap_latest_nist_pqc_briefing_fixture(case.id),
        || bootstrap_latest_nist_pqc_briefing_fixture_runtime(&run_unique_num),
        |fixture| {
            latest_nist_pqc_briefing_fixture_preflight_checks(
                fixture,
                &run_unique_num,
                run_timestamp_ms,
            )
        },
        &mut runtime_setup_verification_checks,
        &mut runtime_setup_environment_receipts,
    )?;
    let mail_provider_driver_override = mail_reply_mock_fixture.as_ref().map(|_| "mock");
    if should_bootstrap_mailbox_runtime(&run_query) {
        extend_environment_evidence_batch(
            &mut runtime_setup_verification_checks,
            &mut runtime_setup_environment_receipts,
            bootstrap_mailbox_runtime_state(
                &mut state,
                &mut ctx,
                wallet_service.as_ref(),
                run_index,
                run_timestamp_ms,
                mail_provider_driver_override,
                Some(case.seeded_intent_id),
            )
            .await?,
        );
    }

    let start_params = StartAgentParams {
        session_id,
        goal: run_query.clone(),
        max_steps: case.max_steps,
        parent_session_id: None,
        initial_budget: 4_000,
        mode: AgentMode::Agent,
    };

    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params)
                .map_err(|e| anyhow!("failed to encode start params: {}", e))?,
            &mut ctx,
        )
        .await?;

    apply_capabilities_policy(&mut state, session_id);
    if case.seed_resolved_intent {
        seed_resolved_intent(
            &mut state,
            session_id,
            case.seeded_intent_id,
            case.intent_scope,
        );
    }

    let started = Instant::now();
    let deadline = Duration::from_secs(case.sla_seconds);
    let mut captured_events: Vec<KernelEvent> = Vec::new();
    let mut paused_reason: Option<String> = None;
    let mut auto_resume_count = 0usize;
    let mut duplicate_incident_retry_count = 0usize;
    const MAX_AUTO_APPROVAL_RESUMES: usize = 2;
    const MAX_DUPLICATE_INCIDENT_RETRY_COUNT: usize = 3;

    loop {
        drain_events(&mut event_rx, &mut captured_events);
        let current = read_agent_state(&state, session_id);

        if matches!(current.status, AgentStatus::Completed(_))
            || matches!(current.status, AgentStatus::Failed(_))
        {
            break;
        }
        if started.elapsed() > deadline {
            break;
        }

        match &current.status {
            AgentStatus::Running => {}
            AgentStatus::Paused(reason) => {
                let waiting_for_approval = reason.to_ascii_lowercase().contains("approval");
                if waiting_for_approval && auto_resume_count < MAX_AUTO_APPROVAL_RESUMES {
                    if let Some(tool_hash) = current.pending_tool_hash {
                        let request_hash = read_incident_pending_gate_hash(&state, session_id)
                            .unwrap_or(tool_hash);
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let pii_action = if has_review_request_for_hash(&state, request_hash) {
                            Some(PiiApprovalAction::ApproveTransform)
                        } else {
                            None
                        };
                        let approval_token = build_approval_token_for_resume(
                            request_hash,
                            now_ms,
                            current.pending_visual_hash,
                            pii_action,
                        );
                        service
                            .handle_service_call(
                                &mut state,
                                "resume@v1",
                                &codec::to_bytes_canonical(&ResumeAgentParams {
                                    session_id,
                                    approval_token: Some(approval_token),
                                })
                                .map_err(|e| anyhow!("failed to encode resume params: {}", e))?,
                                &mut ctx,
                            )
                            .await?;
                        auto_resume_count = auto_resume_count.saturating_add(1);
                        continue;
                    }
                }
                paused_reason = Some(reason.clone());
                break;
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                break;
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }

        let step_result = service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await;
        if let Err(err) = step_result {
            let err_text = err.to_string();
            if err_text.contains("Duplicate incident remedy fingerprint")
                && duplicate_incident_retry_count < MAX_DUPLICATE_INCIDENT_RETRY_COUNT
            {
                duplicate_incident_retry_count = duplicate_incident_retry_count.saturating_add(1);
                continue;
            }
            return Err(err.into());
        }
        duplicate_incident_retry_count = 0;
    }

    let terminal_state = read_agent_state(&state, session_id);
    if matches!(terminal_state.status, AgentStatus::Completed(_))
        || matches!(terminal_state.status, AgentStatus::Failed(_))
    {
        // Terminal chat + receipt events can lag the state transition by a short interval.
        drain_events_until_quiescent(
            &mut event_rx,
            &mut captured_events,
            Duration::from_millis(300),
            Duration::from_millis(20),
            3,
        )
        .await;
    } else {
        drain_events(&mut event_rx, &mut captured_events);
    }
    let elapsed_ms = started.elapsed().as_millis();

    let final_state = read_agent_state(&state, session_id);

    let mut action_tools = BTreeSet::new();
    let mut planned_tool_calls = Vec::new();
    let mut routing_tools = BTreeSet::new();
    let mut workload_tools = BTreeSet::new();
    let mut routing_policy_decisions = BTreeSet::new();
    let mut routing_failure_classes = BTreeSet::new();
    let mut routing_stop_condition_hits = 0usize;
    let mut verification_checks = BTreeSet::new();
    let mut action_evidence = Vec::new();
    let mut action_error_classes = BTreeSet::new();
    let mut command_history_evidence = Vec::new();
    let mut command_history_keys = BTreeSet::new();
    let mut exec_workload_evidence = BTreeMap::<(u32, String), ExecWorkloadEvidence>::new();
    let mut cec_receipts = Vec::new();
    let mut intent_resolution_evidence = Vec::new();
    let mut environment_receipts = runtime_setup_environment_receipts;
    let mut final_reply = String::new();
    let mut chat_reply_count = 0usize;
    let mut approval_required_events = 0usize;
    let mut mail_read_latest_success_count = 0usize;
    let mut mail_read_latest_failure_count = 0usize;
    let mut mail_reply_success_count = 0usize;
    let mut mail_reply_failure_count = 0usize;
    let mut mail_read_latest_payloads = Vec::<MailReadLatestPayloadObservation>::new();
    let mut mail_reply_payloads = Vec::<MailReplyPayloadObservation>::new();
    let mut google_gmail_draft_success_count = 0usize;
    let mut google_gmail_draft_failure_count = 0usize;
    let mut google_gmail_send_success_count = 0usize;
    let mut google_gmail_send_failure_count = 0usize;
    let mut google_calendar_create_success_count = 0usize;
    let mut google_calendar_create_failure_count = 0usize;
    let mut google_gmail_draft_payloads = Vec::<GoogleGmailPayloadObservation>::new();
    let mut google_gmail_send_payloads = Vec::<GoogleGmailPayloadObservation>::new();
    let mut google_calendar_create_payloads = Vec::<GoogleCalendarPayloadObservation>::new();

    for event in &captured_events {
        match event {
            KernelEvent::AgentStep(trace) => {
                if let Some(entry) = planned_tool_call_from_step(trace) {
                    planned_tool_calls.push(entry);
                }
                if let Some(payload) = parse_google_gmail_draft_payload(&trace.raw_output) {
                    google_gmail_draft_success_count =
                        google_gmail_draft_success_count.saturating_add(1);
                    google_gmail_draft_payloads.push(payload);
                }
                if let Some(payload) = parse_google_gmail_send_payload(&trace.raw_output) {
                    google_gmail_send_success_count =
                        google_gmail_send_success_count.saturating_add(1);
                    google_gmail_send_payloads.push(payload);
                }
                if let Some(payload) = parse_google_calendar_create_payload(&trace.raw_output) {
                    google_calendar_create_success_count =
                        google_calendar_create_success_count.saturating_add(1);
                    google_calendar_create_payloads.push(payload);
                }
            }
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                error_class,
                agent_status,
                ..
            } => {
                action_tools.insert(tool_name.clone());
                if tool_name.starts_with("sys__exec") {
                    if let Some(entry) = extract_command_history_evidence(output) {
                        push_command_history_evidence(
                            &mut command_history_evidence,
                            &mut command_history_keys,
                            entry,
                        );
                    }
                }
                if let Some(class_name) = error_class.as_ref() {
                    action_error_classes.insert(class_name.clone());
                }
                let hard_error = error_class
                    .as_deref()
                    .map(|value| !is_no_effect_after_action_error(Some(value)))
                    .unwrap_or(false);
                if is_mail_read_latest_tool_name(tool_name) {
                    if !hard_error {
                        if let Some(payload) = parse_mail_read_latest_payload(output) {
                            mail_read_latest_success_count =
                                mail_read_latest_success_count.saturating_add(1);
                            mail_read_latest_payloads.push(payload);
                        } else if agent_status.eq_ignore_ascii_case("failed") {
                            mail_read_latest_failure_count =
                                mail_read_latest_failure_count.saturating_add(1);
                        }
                    } else {
                        mail_read_latest_failure_count =
                            mail_read_latest_failure_count.saturating_add(1);
                    }
                }
                if is_mail_reply_tool_name(tool_name) {
                    if !hard_error {
                        if let Some(payload) = parse_mail_reply_payload(output) {
                            mail_reply_success_count = mail_reply_success_count.saturating_add(1);
                            mail_reply_payloads.push(payload);
                        } else if agent_status.eq_ignore_ascii_case("failed") {
                            mail_reply_failure_count = mail_reply_failure_count.saturating_add(1);
                        }
                    } else {
                        mail_reply_failure_count = mail_reply_failure_count.saturating_add(1);
                    }
                }
                if is_google_gmail_draft_tool_name(tool_name) {
                    if !hard_error {
                        if let Some(payload) = parse_google_gmail_draft_payload(output) {
                            google_gmail_draft_success_count =
                                google_gmail_draft_success_count.saturating_add(1);
                            google_gmail_draft_payloads.push(payload);
                        } else if agent_status.eq_ignore_ascii_case("failed") {
                            google_gmail_draft_failure_count =
                                google_gmail_draft_failure_count.saturating_add(1);
                        }
                    } else {
                        google_gmail_draft_failure_count =
                            google_gmail_draft_failure_count.saturating_add(1);
                    }
                }
                if is_google_gmail_send_tool_name(tool_name) {
                    if !hard_error {
                        if let Some(payload) = parse_google_gmail_send_payload(output) {
                            google_gmail_send_success_count =
                                google_gmail_send_success_count.saturating_add(1);
                            google_gmail_send_payloads.push(payload);
                        } else if agent_status.eq_ignore_ascii_case("failed") {
                            google_gmail_send_failure_count =
                                google_gmail_send_failure_count.saturating_add(1);
                        }
                    } else {
                        google_gmail_send_failure_count =
                            google_gmail_send_failure_count.saturating_add(1);
                    }
                }
                if is_google_calendar_create_tool_name(tool_name) {
                    if !hard_error {
                        if let Some(payload) = parse_google_calendar_create_payload(output) {
                            google_calendar_create_success_count =
                                google_calendar_create_success_count.saturating_add(1);
                            google_calendar_create_payloads.push(payload);
                        } else if agent_status.eq_ignore_ascii_case("failed") {
                            google_calendar_create_failure_count =
                                google_calendar_create_failure_count.saturating_add(1);
                        }
                    } else {
                        google_calendar_create_failure_count =
                            google_calendar_create_failure_count.saturating_add(1);
                    }
                }
                action_evidence.push(ActionEvidence {
                    tool_name: tool_name.clone(),
                    agent_status: agent_status.clone(),
                    output_excerpt: truncate_for_log(
                        output,
                        action_output_excerpt_limit(tool_name),
                    ),
                    error_class: error_class.clone(),
                });
                if tool_name == "chat__reply" && agent_status.eq_ignore_ascii_case("completed") {
                    chat_reply_count = chat_reply_count.saturating_add(1);
                    final_reply = output.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                routing_tools.insert(receipt.tool_name.clone());
                routing_policy_decisions.insert(receipt.policy_decision.clone());
                if !receipt.failure_class_name.trim().is_empty() {
                    routing_failure_classes.insert(receipt.failure_class_name.clone());
                }
                if receipt.stop_condition_hit {
                    routing_stop_condition_hits = routing_stop_condition_hits.saturating_add(1);
                }
                for check in &receipt.post_state.verification_checks {
                    verification_checks.insert(check.clone());
                }
                if receipt
                    .policy_decision
                    .eq_ignore_ascii_case("require_approval")
                {
                    approval_required_events = approval_required_events.saturating_add(1);
                }
            }
            KernelEvent::WorkloadReceipt(workload) => match &workload.receipt {
                WorkloadReceipt::WebRetrieve(web) => {
                    workload_tools.insert(web.tool_name.clone());
                    if let Some(error_class) = web.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
                WorkloadReceipt::FsWrite(fs) => {
                    workload_tools.insert(fs.tool_name.clone());
                    if let Some(error_class) = fs.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
                WorkloadReceipt::Exec(exec) => {
                    workload_tools.insert(exec.tool_name.clone());
                    if let Some(error_class) = exec.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                    let workload_key = (workload.step_index, workload.workload_id.clone());
                    let entry = command_history_from_exec_workload(
                        exec,
                        exec_workload_evidence.get(&workload_key),
                    );
                    push_command_history_evidence(
                        &mut command_history_evidence,
                        &mut command_history_keys,
                        entry,
                    );
                }
                WorkloadReceipt::NetFetch(fetch) => {
                    workload_tools.insert(fetch.tool_name.clone());
                    if let Some(error_class) = fetch.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
                WorkloadReceipt::MemoryRetrieve(scs) => {
                    workload_tools.insert(scs.tool_name.clone());
                    if let Some(error_class) = scs.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
                WorkloadReceipt::Adapter(adapter) => {
                    workload_tools.insert(adapter.tool_name.clone());
                    if let Some(error_class) = adapter.error_class.as_ref() {
                        action_error_classes.insert(error_class.clone());
                    }
                }
            },
            KernelEvent::WorkloadActivity(activity) => match &activity.kind {
                WorkloadActivityKind::Lifecycle { exit_code, .. } => {
                    let workload_key = (activity.step_index, activity.workload_id.clone());
                    exec_workload_evidence
                        .entry(workload_key)
                        .or_default()
                        .set_exit_code(*exit_code);
                }
                WorkloadActivityKind::Stdio {
                    stream,
                    chunk,
                    seq,
                    exit_code,
                    ..
                } => {
                    let workload_key = (activity.step_index, activity.workload_id.clone());
                    exec_workload_evidence
                        .entry(workload_key)
                        .or_default()
                        .append_chunk(stream, *seq, chunk, *exit_code);
                }
            },
            KernelEvent::ExecutionContractReceipt(receipt) => {
                cec_receipts.push(CecReceiptEvidence {
                    contract_version: receipt.contract_version.clone(),
                    stage: receipt.stage.clone(),
                    key: receipt.key.clone(),
                    satisfied: receipt.satisfied,
                    timestamp_ms: receipt.timestamp_ms,
                    probe_source: receipt.probe_source.clone(),
                    observed_value: receipt.observed_value.clone(),
                    evidence_type: receipt.evidence_type.clone(),
                    provider_id: receipt.provider_id.clone(),
                });
            }
            KernelEvent::IntentResolutionReceipt(receipt) => {
                intent_resolution_evidence.push(IntentResolutionEvidence {
                    intent_id: receipt.intent_id.clone(),
                    selected_intent_id: receipt.selected_intent_id.clone(),
                    scope: format!("{:?}", receipt.scope),
                    band: format!("{:?}", receipt.band),
                    score: receipt.score,
                    error_class: receipt.error_class.clone(),
                });
            }
            KernelEvent::FirewallInterception { verdict, .. } => {
                if verdict.eq_ignore_ascii_case("require_approval") {
                    approval_required_events = approval_required_events.saturating_add(1);
                }
            }
            _ => {}
        }
    }

    let terminal_pause_reason = if let AgentStatus::Paused(reason) = &final_state.status {
        Some(reason.clone())
    } else {
        paused_reason.clone()
    };
    let terminal_failure_reason = if let AgentStatus::Failed(reason) = &final_state.status {
        Some(reason.clone())
    } else {
        None
    };

    if let Some(reason) = paused_reason {
        if requires_human_intervention(&reason) {
            approval_required_events = approval_required_events.saturating_add(1);
            verification_checks.insert(format!("human_intervention_pause_reason={}", reason));
        } else {
            verification_checks.insert(format!("terminal_pause_reason={}", reason));
        }
    }
    for check in runtime_setup_verification_checks {
        verification_checks.insert(check);
    }
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        vlc_install_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(vlc_install_fixture_post_run_checks(fixture))
        },
        None,
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        desktop_project_create_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(desktop_project_create_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(desktop_project_create_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        projects_zip_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(projects_zip_fixture_post_run_checks(fixture))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(projects_zip_fixture_cleanup_checks(fixture))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        downloads_lowercase_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(downloads_lowercase_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(downloads_lowercase_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        downloads_png_move_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(downloads_png_move_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(downloads_png_move_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        desktop_documents_backup_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(
                desktop_documents_backup_fixture_post_run_checks(fixture),
            )
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(desktop_documents_backup_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        documents_summary_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(documents_summary_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(documents_summary_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        pdf_last_week_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(pdf_last_week_fixture_post_run_checks(fixture))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(pdf_last_week_fixture_cleanup_checks(fixture))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        spotify_uninstall_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(spotify_uninstall_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(spotify_uninstall_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        top_memory_apps_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(top_memory_apps_fixture_post_run_checks(fixture))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(top_memory_apps_fixture_cleanup_checks(fixture))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        media_transcript_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(media_transcript_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(media_transcript_fixture_cleanup_checks(fixture))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        shutdown_schedule_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(shutdown_schedule_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(shutdown_schedule_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        hacker_news_monitor_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(hacker_news_monitor_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(hacker_news_monitor_fixture_cleanup_checks(
                fixture,
            ))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        mail_reply_mock_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(mail_reply_mock_fixture_post_run_checks(fixture))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(mail_reply_mock_fixture_cleanup_checks(fixture))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        google_connector_fixture.as_ref(),
        |fixture| {
            environment_evidence_batch_from_checks(google_connector_fixture_post_run_checks(
                fixture,
            ))
        },
        Some(|fixture| {
            environment_evidence_batch_from_checks(google_connector_fixture_cleanup_checks(fixture))
        }),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        restaurants_near_me_fixture.as_ref(),
        restaurants_near_me_fixture_post_run_checks,
        Some(restaurants_near_me_fixture_cleanup_checks),
    );
    insert_fixture_evidence(
        &mut verification_checks,
        &mut environment_receipts,
        latest_nist_pqc_briefing_fixture.as_ref(),
        latest_nist_pqc_briefing_fixture_post_run_checks,
        Some(latest_nist_pqc_briefing_fixture_cleanup_checks),
    );

    let event_excerpt = captured_events
        .iter()
        .rev()
        .take(24)
        .map(event_summary_line)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let kernel_log_lines = captured_events
        .iter()
        .map(event_full_line)
        .collect::<Vec<_>>();

    let verification_checks = verification_checks.into_iter().collect::<Vec<_>>();
    let verification_facts = parse_verification_facts(&verification_checks);
    let mut observation = RunObservation {
        case_id: case.id.to_string(),
        query: run_query,
        run_timestamp_ms,
        run_timestamp_iso_utc: iso_datetime_from_unix_ms(run_timestamp_ms),
        elapsed_ms,
        completed: matches!(final_state.status, AgentStatus::Completed(_)),
        failed: matches!(final_state.status, AgentStatus::Failed(_)),
        final_status: format!("{:?}", final_state.status),
        terminal_pause_reason,
        terminal_failure_reason,
        final_reply,
        chat_reply_count,
        action_tools: action_tools.into_iter().collect(),
        planned_tool_calls,
        routing_tools: routing_tools.into_iter().collect(),
        workload_tools: workload_tools.into_iter().collect(),
        routing_policy_decisions: routing_policy_decisions.into_iter().collect(),
        routing_failure_classes: routing_failure_classes.into_iter().collect(),
        routing_stop_condition_hits,
        verification_checks,
        verification_facts,
        approval_required_events,
        action_evidence,
        action_error_classes: action_error_classes.into_iter().collect(),
        command_history_evidence,
        cec_receipts,
        intent_resolution_evidence,
        environment_receipts,
        web: None,
        screenshot: None,
        mail: None,
        google: None,
        event_excerpt,
        kernel_event_count: captured_events.len(),
        kernel_log_lines,
    };
    observation.web = derive_web_observation(&observation);
    observation.screenshot = derive_screenshot_observation(&observation);
    observation.mail = derive_mail_observation(
        &observation,
        mail_read_latest_success_count,
        mail_read_latest_failure_count,
        mail_reply_success_count,
        mail_reply_failure_count,
        mail_read_latest_payloads,
        mail_reply_payloads,
    );
    observation.google = derive_google_observation(
        &observation,
        google_gmail_draft_success_count,
        google_gmail_draft_failure_count,
        google_gmail_send_success_count,
        google_gmail_send_failure_count,
        google_calendar_create_success_count,
        google_calendar_create_failure_count,
        google_gmail_draft_payloads,
        google_gmail_send_payloads,
        google_calendar_create_payloads,
    );

    Ok(observation)
}
