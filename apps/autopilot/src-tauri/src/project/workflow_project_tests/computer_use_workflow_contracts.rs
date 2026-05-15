#[test]
fn workflow_run_compiles_computer_use_manifest_to_runtime_events() {
    let root = temp_root("computer-use-runtime-events");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Browser Use Trace".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node(
        "browser-source",
        "source",
        "Prompt",
        80,
        180,
        "Input",
        "manual",
    );
    logic_mut(&mut source).insert(
        "payload".to_string(),
        json!({"prompt": "Inspect https://example.test with Browser Use and summarize targets."}),
    );
    let mut browser = workflow_node(
        "browser-use",
        "plugin_tool",
        "Browser Use",
        320,
        180,
        "Computer",
        "browser",
    );
    logic_mut(&mut browser).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "ioi.computer_use.native_browser",
            "bindingKind": "plugin_tool",
            "mockBinding": true,
            "credentialReady": false,
            "capabilityScope": [
                "computer_use.native_browser.read",
                "computer_use.action_proposal",
                "computer_use.cleanup"
            ],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": {
                "computerUse": true,
                "computerUseLane": "native_browser",
                "computerUseSessionMode": "owned_hermetic_browser",
                "observationRetentionMode": "local_redacted_artifacts",
                "failClosedWhenUnavailable": true
            }
        }),
    );
    let output = workflow_node(
        "browser-output",
        "output",
        "Output",
        560,
        180,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, browser, output];
    workflow.edges = vec![
        workflow_edge("edge-browser-source-use", "browser-source", "browser-use"),
        workflow_edge("edge-browser-use-output", "browser-use", "browser-output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    assert_eq!(run.runtime_thread_events.len(), 11);

    let event_kinds = run
        .runtime_thread_events
        .iter()
        .map(|event| event.get("eventKind").and_then(Value::as_str).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        event_kinds,
        vec![
            "computer_use.environment_selected",
            "computer_use.lease_acquired",
            "computer_use.run_state",
            "computer_use.observation",
            "computer_use.affordance_graph",
            "computer_use.action_proposed",
            "computer_use.action_executed",
            "computer_use.verification",
            "computer_use.commit_gate",
            "computer_use.trajectory_written",
            "computer_use.cleanup",
        ]
    );

    let run_state_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.run_state")
        })
        .expect("run state event should exist");
    let payload = run_state_event
        .get("payload")
        .expect("payload should exist");
    assert_eq!(
        payload
            .get("workflowNodeId")
            .and_then(Value::as_str)
            .unwrap(),
        "browser-use"
    );
    assert_eq!(
        payload.get("toolRef").and_then(Value::as_str).unwrap(),
        "ioi.computer_use.native_browser"
    );
    assert_eq!(
        payload
            .get("computer_use_run_state")
            .and_then(|value| value.get("user_goal"))
            .and_then(Value::as_str)
            .unwrap(),
        "Inspect https://example.test with Browser Use and summarize targets."
    );
    assert_eq!(
        payload
            .get("computer_use_run_state")
            .and_then(|value| value.get("current_target_index_ref"))
            .and_then(Value::as_str)
            .unwrap(),
        payload
            .get("computer_use_target_index_ref")
            .and_then(Value::as_str)
            .unwrap()
    );

    let observation_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.observation")
        })
        .expect("observation event should exist");
    assert_eq!(
        observation_event
            .get("payload")
            .and_then(|value| value.get("target_index"))
            .and_then(|value| value.get("targets"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );

    let commit_gate_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.commit_gate")
        })
        .expect("commit gate event should exist");
    let commit_payload = commit_gate_event
        .get("payload")
        .expect("payload should exist");
    assert_eq!(
        commit_payload
            .get("commit_gate")
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str),
        Some("not_required")
    );
    assert_eq!(
        commit_payload
            .get("outcome_contract")
            .and_then(|value| value.get("external_effect_policy"))
            .and_then(Value::as_str),
        Some("confirmation_required")
    );
}

#[test]
fn workflow_run_gates_mutating_native_browser_action_before_execution() {
    let root = temp_root("computer-use-mutating-gate");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Browser Use Gated Action".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node(
        "browser-source",
        "source",
        "Prompt",
        80,
        180,
        "Input",
        "manual",
    );
    logic_mut(&mut source).insert(
        "payload".to_string(),
        json!({"prompt": "Click the submit button at https://example.test."}),
    );
    let mut browser = workflow_node(
        "browser-use",
        "plugin_tool",
        "Browser Use",
        320,
        180,
        "Computer",
        "browser",
    );
    logic_mut(&mut browser).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "ioi.computer_use.native_browser",
            "bindingKind": "plugin_tool",
            "mockBinding": true,
            "credentialReady": false,
            "capabilityScope": [
                "computer_use.native_browser.read",
                "computer_use.native_browser.act",
                "computer_use.action_proposal",
                "computer_use.cleanup"
            ],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": {
                "computerUse": true,
                "computerUseLane": "native_browser",
                "computerUseSessionMode": "owned_hermetic_browser",
                "computerUseActionKind": "click",
                "observationRetentionMode": "local_redacted_artifacts",
                "failClosedWhenUnavailable": true
            }
        }),
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, browser];
    workflow.edges = vec![workflow_edge(
        "edge-browser-source-use",
        "browser-source",
        "browser-use",
    )];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    let event_kinds = run
        .runtime_thread_events
        .iter()
        .map(|event| event.get("eventKind").and_then(Value::as_str).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(event_kinds.len(), 10);
    assert!(!event_kinds.contains(&"computer_use.action_executed"));
    assert!(event_kinds.contains(&"computer_use.action_proposed"));
    assert!(event_kinds.contains(&"computer_use.commit_gate"));

    let proposal_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.action_proposed")
        })
        .expect("proposal event should exist");
    assert_eq!(
        proposal_event
            .get("payload")
            .and_then(|value| value.get("action_proposal"))
            .and_then(|value| value.get("risk_assessment"))
            .and_then(Value::as_str),
        Some("possible_external_effect")
    );

    let commit_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.commit_gate")
        })
        .expect("commit gate event should exist");
    assert_eq!(
        commit_event
            .get("payload")
            .and_then(|value| value.get("commit_gate"))
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str),
        Some("pending_confirmation")
    );
    assert_eq!(
        commit_event
            .get("payload")
            .and_then(|value| value.get("human_handoff_state"))
            .and_then(|value| value.get("reason"))
            .and_then(Value::as_str),
        Some("mutating_browser_action_requires_confirmation")
    );
}

#[test]
fn workflow_run_executes_approved_mutating_native_browser_action() {
    let root = temp_root("computer-use-mutating-approved");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Browser Use Approved Action".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node(
        "browser-source",
        "source",
        "Prompt",
        80,
        180,
        "Input",
        "manual",
    );
    logic_mut(&mut source).insert(
        "payload".to_string(),
        json!({"prompt": "Click the submit button at https://example.test."}),
    );
    let mut browser = workflow_node(
        "browser-use",
        "plugin_tool",
        "Browser Use",
        320,
        180,
        "Computer",
        "browser",
    );
    logic_mut(&mut browser).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "ioi.computer_use.native_browser",
            "bindingKind": "plugin_tool",
            "mockBinding": true,
            "credentialReady": false,
            "capabilityScope": [
                "computer_use.native_browser.read",
                "computer_use.native_browser.act",
                "computer_use.action_proposal",
                "computer_use.cleanup"
            ],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": {
                "computerUse": true,
                "computerUseLane": "native_browser",
                "computerUseSessionMode": "owned_hermetic_browser",
                "computerUseActionKind": "click",
                "computerUseApprovalRef": "approval-browser-click",
                "targetRef": "#submit",
                "selector": "#submit",
                "text": "hello",
                "cdpEndpointUrl": "http://127.0.0.1:9222",
                "cdpTimeoutMs": 5000,
                "observationRetentionMode": "local_redacted_artifacts",
                "failClosedWhenUnavailable": true
            }
        }),
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, browser];
    workflow.edges = vec![workflow_edge(
        "edge-browser-source-use",
        "browser-source",
        "browser-use",
    )];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    let event_kinds = run
        .runtime_thread_events
        .iter()
        .map(|event| event.get("eventKind").and_then(Value::as_str).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(event_kinds.len(), 11);
    assert!(event_kinds.contains(&"computer_use.action_executed"));

    let action_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.action_executed")
        })
        .expect("action event should exist");
    assert_eq!(
        action_event
            .get("payload")
            .and_then(|value| value.get("computer_action"))
            .and_then(|value| value.get("approval_ref"))
            .and_then(Value::as_str),
        Some("approval-browser-click")
    );
    assert_eq!(
        action_event
            .get("payload")
            .and_then(|value| value.get("computer_action"))
            .and_then(|value| value.get("target_ref"))
            .and_then(Value::as_str),
        Some("#submit")
    );

    let proposal_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.action_proposed")
        })
        .expect("proposal event should exist");
    assert_eq!(
        proposal_event
            .get("payload")
            .and_then(|value| value.get("policy_gate"))
            .and_then(|value| value.get("outcome"))
            .and_then(Value::as_str),
        Some("approved_after_confirmation")
    );
    assert_eq!(
        proposal_event
            .get("payload")
            .and_then(|value| value.get("selector"))
            .and_then(Value::as_str),
        Some("#submit")
    );
    assert_eq!(
        proposal_event
            .get("payload")
            .and_then(|value| value.get("text"))
            .and_then(Value::as_str),
        Some("hello")
    );
    assert_eq!(
        proposal_event
            .get("payload")
            .and_then(|value| value.get("cdpEndpointUrl"))
            .and_then(Value::as_str),
        Some("http://127.0.0.1:9222")
    );
    assert_eq!(
        proposal_event
            .get("payload")
            .and_then(|value| value.get("cdpTimeoutMs"))
            .and_then(Value::as_u64),
        Some(5000)
    );

    let commit_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.commit_gate")
        })
        .expect("commit gate event should exist");
    assert_eq!(
        commit_event
            .get("payload")
            .and_then(|value| value.get("commit_gate"))
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str),
        Some("completed")
    );
    assert!(
        commit_event
            .get("payload")
            .and_then(|value| value.get("human_handoff_state"))
            .is_some_and(Value::is_null)
    );
}

#[test]
fn workflow_run_fails_closed_unavailable_computer_use_lanes() {
    let root = temp_root("computer-use-unavailable");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Hosted Computer Trace".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut hosted = workflow_node(
        "hosted-computer",
        "plugin_tool",
        "Sandboxed Computer",
        120,
        180,
        "Computer",
        "hosted",
    );
    logic_mut(&mut hosted).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "ioi.computer_use.sandboxed_hosted",
            "bindingKind": "plugin_tool",
            "mockBinding": true,
            "credentialReady": false,
            "capabilityScope": [
                "computer_use.sandboxed_hosted.observe",
                "computer_use.sandboxed_hosted.propose_action",
                "computer_use.cleanup"
            ],
            "sideEffectClass": "external_write",
            "requiresApproval": true,
            "arguments": {
                "computerUse": true,
                "computerUseLane": "sandboxed_hosted",
                "computerUseSessionMode": "hosted_sandbox",
                "observationRetentionMode": "no_persistence",
                "failClosedWhenUnavailable": true
            }
        }),
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![hosted];
    workflow.edges = Vec::new();
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.runtime_thread_events.len(), 5);
    let unavailable_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str)
                == Some("computer_use.environment_unavailable")
        })
        .expect("unavailable event should exist");
    assert_eq!(
        unavailable_event.get("status").and_then(Value::as_str),
        Some("blocked")
    );
    let payload = unavailable_event
        .get("payload")
        .expect("payload should exist");
    assert_eq!(
        payload.get("computer_use_lane").and_then(Value::as_str),
        Some("sandboxed_hosted")
    );
    assert_eq!(
        payload
            .get("recovery_policy")
            .and_then(|value| value.get("failure_class"))
            .and_then(Value::as_str),
        Some("environment")
    );
    assert_eq!(
        payload.get("workflowNodeId").and_then(Value::as_str),
        Some("hosted-computer")
    );
}

#[test]
fn workflow_run_projects_browser_discovery_primitive_to_receipts() {
    let root = temp_root("browser-discovery-runtime-events");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Browser Discovery Trace".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut discovery = workflow_node(
        "browser-discovery",
        "plugin_tool",
        "Browser Discovery",
        120,
        180,
        "Computer",
        "browser",
    );
    logic_mut(&mut discovery).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "ioi.computer_use.browser_discovery",
            "bindingKind": "plugin_tool",
            "mockBinding": false,
            "credentialReady": true,
            "capabilityScope": [
                "computer_use.browser_discovery.read",
                "computer_use.native_browser.discovery"
            ],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": {
                "computerUseBrowserDiscovery": true,
                "probe": false,
                "includeTabs": false,
                "revealTabTitles": false,
                "retentionMode": "prompt_visible_summary_only"
            }
        }),
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![discovery];
    workflow.edges = Vec::new();
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    assert_eq!(run.runtime_thread_events.len(), 4);

    let event_kinds = run
        .runtime_thread_events
        .iter()
        .map(|event| event.get("eventKind").and_then(Value::as_str).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        event_kinds,
        vec![
            "computer_use.environment_selected",
            "computer_use.browser_discovery",
            "computer_use.verification",
            "computer_use.cleanup",
        ]
    );

    let discovery_event = run
        .runtime_thread_events
        .iter()
        .find(|event| {
            event.get("eventKind").and_then(Value::as_str) == Some("computer_use.browser_discovery")
        })
        .expect("browser discovery event should exist");
    assert_eq!(
        discovery_event
            .get("workflowNodeId")
            .and_then(Value::as_str),
        Some("browser-discovery")
    );
    assert_eq!(
        discovery_event.get("toolName").and_then(Value::as_str),
        Some("ioi.computer_use.browser_discovery")
    );
    let payload = discovery_event
        .get("payload")
        .expect("payload should exist");
    assert_eq!(
        payload.get("computer_use_step").and_then(Value::as_str),
        Some("discover_browser")
    );
    assert_eq!(
        payload
            .get("computer_use_session_mode")
            .and_then(Value::as_str),
        Some("discovery_only")
    );
    assert_eq!(
        payload
            .get("browser_discovery_report")
            .and_then(|value| value.get("object"))
            .and_then(Value::as_str),
        Some("ioi.computer_use.browser_discovery_report")
    );
    assert_eq!(
        payload
            .get("browser_discovery_report")
            .and_then(|value| value.get("safety"))
            .and_then(|value| value.get("read_only"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(discovery_event
        .get("receiptRefs")
        .and_then(Value::as_array)
        .expect("receipt refs should exist")
        .iter()
        .any(|value| {
            value
                .as_str()
                .is_some_and(|entry| entry.contains("browser_discovery"))
        }));
}
