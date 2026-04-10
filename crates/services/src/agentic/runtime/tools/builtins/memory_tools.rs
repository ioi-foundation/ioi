{
    // Memory Tools
    let mem_search_params = json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "description": "Semantic search query (e.g. 'error message from last run', 'login button location')" }
        },
        "required": ["query"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__search".to_string(),
        description:
            "Search durable memory for prior facts, summaries, UI structure, or learned procedures. Prefer inspecting the live environment first when the answer depends on the current screen."
                .to_string(),
        parameters: mem_search_params.to_string(),
    });

    let mem_inspect_params = json!({
        "type": "object",
        "properties": {
            "frame_id": { "type": "integer", "description": "The archival record ID returned by memory__search to inspect in detail" }
        },
        "required": ["frame_id"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__inspect".to_string(),
        description: "Retrieve the full content of a specific archival memory record returned by memory__search so you can verify details before acting.".to_string(),
        parameters: mem_inspect_params.to_string(),
    });

    let mem_replace_core_params = json!({
        "type": "object",
        "properties": {
            "section": {
                "type": "string",
                "description": "Typed core-memory section to replace. Allowed: workflow.stage, environment.invariants, user.preferences.safe, site.learned_constraints, workflow.notes"
            },
            "content": {
                "type": "string",
                "description": "Small durable content for the section. Never store passwords, API keys, or secrets."
            }
        },
        "required": ["section", "content"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__replace_core".to_string(),
        description: "Replace a typed core-memory register. Use for small durable facts or workflow state, not long transcripts or secrets.".to_string(),
        parameters: mem_replace_core_params.to_string(),
    });

    let mem_append_core_params = json!({
        "type": "object",
        "properties": {
            "section": {
                "type": "string",
                "description": "Appendable core-memory section. Allowed: environment.invariants, user.preferences.safe, site.learned_constraints, workflow.notes"
            },
            "content": {
                "type": "string",
                "description": "New line of durable content to append. Never store passwords, API keys, or secrets."
            }
        },
        "required": ["section", "content"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__append_core".to_string(),
        description: "Append a new durable note to an appendable core-memory section without rewriting the whole section.".to_string(),
        parameters: mem_append_core_params.to_string(),
    });

    let mem_clear_core_params = json!({
        "type": "object",
        "properties": {
            "section": {
                "type": "string",
                "description": "Typed core-memory section to clear."
            }
        },
        "required": ["section"]
    });
    tools.push(LlmToolDefinition {
        name: "memory__clear_core".to_string(),
        description: "Clear a typed core-memory section when it is no longer valid.".to_string(),
        parameters: mem_clear_core_params.to_string(),
    });

    let delegate_params = json!({
        "type": "object",
        "properties": {
            "goal": { "type": "string" },
            "budget": { "type": "integer" },
            "playbook_id": {
                "type": "string",
                "description": "Optional higher-order parent playbook id such as 'evidence_audited_patch' when the parent is orchestrating a multi-worker sequence."
            },
            "template_id": {
                "type": "string",
                "description": "Optional bounded worker template id such as 'researcher'."
            },
            "workflow_id": {
                "type": "string",
                "description": "Optional playbook id within the selected template, such as 'live_research_brief' for 'researcher'."
            },
            "role": {
                "type": "string",
                "description": "Optional explicit worker role label when no template is used."
            },
            "success_criteria": {
                "type": "string",
                "description": "Optional explicit completion criteria that the child worker must satisfy."
            },
            "merge_mode": {
                "type": "string",
                "description": "Optional deterministic parent merge mode such as 'append_summary_to_parent'."
            },
            "expected_output": {
                "type": "string",
                "description": "Optional expected output shape, artifact, or summary contract."
            }
        },
        "required": ["goal", "budget"]
    });
    tools.push(LlmToolDefinition {
        name: "agent__delegate".to_string(),
        description: format!(
            "Spawn a bounded child worker for a complex, multi-step subtask. Prefer a parent playbook and worker template when available so orchestration, role, playbook, success criteria, and merge semantics stay deterministic. Available templates: {}. Do NOT use for simple atomic actions like clicking or opening apps.",
            delegation_template_hint()
        ),
        parameters: delegate_params.to_string(),
    });
}
