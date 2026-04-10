fn core_memory_schema(section: &str) -> Option<&'static CoreMemorySectionSchema> {
    CORE_MEMORY_SCHEMAS
        .iter()
        .find(|schema| schema.section == section)
}

fn normalize_core_memory_content(content: &str, max_chars: usize) -> String {
    let collapsed = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let trimmed = collapsed.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        let mut truncated: String = trimmed.chars().take(max_chars.saturating_sub(3)).collect();
        if max_chars > 3 {
            truncated.push_str("...");
        }
        truncated
    }
}

fn content_looks_secret_like(content: &str) -> bool {
    let lowered = content.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "api key",
        "api_key",
        "token",
        "secret",
        "private key",
        "bearer ",
        "authorization:",
        "ssh-rsa",
        "-----begin",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn digest_hex(input: &str) -> String {
    sha256(input.as_bytes())
        .ok()
        .map(hex::encode)
        .unwrap_or_default()
}

fn unix_timestamp_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn diagnostics_thread_id(thread_id: Option<[u8; 32]>) -> [u8; 32] {
    thread_id.unwrap_or(MEMORY_RUNTIME_GLOBAL_DIAGNOSTICS_THREAD)
}

fn persist_checkpoint_json<T: Serialize>(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    checkpoint_name: &str,
    value: &T,
) -> Result<(), TransactionError> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    memory_runtime
        .upsert_checkpoint_blob(thread_id, checkpoint_name, &payload)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))
}

fn load_checkpoint_json<T: DeserializeOwned>(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    checkpoint_name: &str,
) -> Result<Option<T>, TransactionError> {
    let Some(blob) = memory_runtime
        .load_checkpoint_blob(thread_id, checkpoint_name)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
    else {
        return Ok(None);
    };
    serde_json::from_slice::<T>(&blob)
        .map(Some)
        .map_err(|error| TransactionError::Serialization(error.to_string()))
}

fn load_core_memory_pin_state(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
) -> Result<CoreMemoryPinState, TransactionError> {
    let Some(blob) = memory_runtime
        .load_checkpoint_blob(thread_id, MEMORY_RUNTIME_CORE_PINS_CHECKPOINT)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
    else {
        return Ok(CoreMemoryPinState::default());
    };
    serde_json::from_slice::<CoreMemoryPinState>(&blob)
        .map_err(|error| TransactionError::Serialization(error.to_string()))
}

fn persist_core_memory_pin_state(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    pin_state: &CoreMemoryPinState,
) -> Result<(), TransactionError> {
    let payload = serde_json::to_vec(pin_state)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    memory_runtime
        .upsert_checkpoint_blob(thread_id, MEMORY_RUNTIME_CORE_PINS_CHECKPOINT, &payload)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))
}

pub fn pin_core_memory_section(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    pinned: bool,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.prompt_eligible {
        return Err(TransactionError::Invalid(format!(
            "Section '{}' is not prompt eligible and cannot be pinned.",
            section
        )));
    }
    let mut pin_state = load_core_memory_pin_state(memory_runtime, thread_id)?;
    pin_state
        .pinned_sections
        .insert(section.to_string(), pinned);
    persist_core_memory_pin_state(memory_runtime, thread_id, &pin_state)
}

fn effective_core_memory_pin(
    pin_state: &CoreMemoryPinState,
    schema: &CoreMemorySectionSchema,
) -> bool {
    pin_state
        .pinned_sections
        .get(schema.section)
        .copied()
        .unwrap_or(schema.default_pinned)
}

fn audit_core_memory_write(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    action: &str,
    source: &str,
    accepted: bool,
    previous_content: Option<&str>,
    new_content: Option<&str>,
    rejection_reason: Option<&str>,
) {
    let metadata_json = serde_json::to_string(&json!({
        "trust_level": "runtime_controlled",
        "section": section,
        "action": action,
        "source": source,
        "accepted": accepted,
        "previous_hash": previous_content.map(digest_hex),
        "new_hash": new_content.map(digest_hex),
        "rejection_reason": rejection_reason,
    }))
    .unwrap_or_else(|_| "{}".to_string());
    let content = if accepted {
        format!(
            "section={section}\naction={action}\nsource={source}\nprevious={}\ncurrent={}",
            previous_content.unwrap_or("<empty>"),
            new_content.unwrap_or("<empty>")
        )
    } else {
        format!(
            "section={section}\naction={action}\nsource={source}\nrejected={}",
            rejection_reason.unwrap_or("unknown")
        )
    };
    if let Err(error) = memory_runtime.insert_archival_record(&NewArchivalMemoryRecord {
        scope: MEMORY_RUNTIME_CORE_AUDIT_SCOPE.to_string(),
        thread_id: Some(thread_id),
        kind: "core_memory_update".to_string(),
        content,
        metadata_json,
    }) {
        log::warn!("Failed to audit core memory write: {}", error);
    }
}

fn replace_core_memory_governed(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    content: &str,
    source: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    let normalized = normalize_core_memory_content(content, schema.max_chars);
    let previous = memory_runtime
        .load_core_memory_section(thread_id, section)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    let previous_content = previous.as_ref().map(|section| section.content.as_str());

    if content_looks_secret_like(&normalized) {
        audit_core_memory_write(
            memory_runtime,
            thread_id,
            section,
            "replace",
            source,
            false,
            previous_content,
            None,
            Some("secret_like_content"),
        );
        return Err(TransactionError::Invalid(format!(
            "Rejected core-memory update for '{}': content appears secret-bearing.",
            section
        )));
    }

    if normalized.is_empty() {
        memory_runtime
            .delete_core_memory_section(thread_id, section)
            .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
        audit_core_memory_write(
            memory_runtime,
            thread_id,
            section,
            "clear",
            source,
            true,
            previous_content,
            None,
            None,
        );
        return Ok(());
    }

    memory_runtime
        .replace_core_memory_section(thread_id, section, &normalized)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    audit_core_memory_write(
        memory_runtime,
        thread_id,
        section,
        "replace",
        source,
        true,
        previous_content,
        Some(&normalized),
        None,
    );
    Ok(())
}

fn append_core_memory_governed(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    content: &str,
    source: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.append_allowed {
        return Err(TransactionError::Invalid(format!(
            "Core-memory section '{}' does not allow append operations.",
            section
        )));
    }
    let current = memory_runtime
        .load_core_memory_section(thread_id, section)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        .map(|section| section.content)
        .unwrap_or_default();
    let appended = if current.trim().is_empty() {
        content.trim().to_string()
    } else if current.contains(content.trim()) {
        current
    } else {
        format!("{}\n{}", current.trim(), content.trim())
    };
    replace_core_memory_governed(memory_runtime, thread_id, section, &appended, source)
}

pub fn clear_core_memory_section(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    source: &str,
) -> Result<(), TransactionError> {
    replace_core_memory_governed(memory_runtime, thread_id, section, "", source)
}

pub fn replace_core_memory_from_tool(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    content: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.tool_writable {
        return Err(TransactionError::Invalid(format!(
            "Core-memory section '{}' is runtime-owned and not tool-writable.",
            section
        )));
    }
    replace_core_memory_governed(memory_runtime, thread_id, section, content, "tool_request")
}

pub fn append_core_memory_from_tool(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    content: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.tool_writable {
        return Err(TransactionError::Invalid(format!(
            "Core-memory section '{}' is runtime-owned and not tool-writable.",
            section
        )));
    }
    append_core_memory_governed(memory_runtime, thread_id, section, content, "tool_request")
}

pub fn clear_core_memory_from_tool(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.tool_writable {
        return Err(TransactionError::Invalid(format!(
            "Core-memory section '{}' is runtime-owned and not tool-writable.",
            section
        )));
    }
    clear_core_memory_section(memory_runtime, thread_id, section, "tool_request")
}

fn format_prompt_eligible_core_memory(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
) -> Result<String, TransactionError> {
    let pin_state = load_core_memory_pin_state(memory_runtime, thread_id)?;
    let mut lines = Vec::new();
    for schema in CORE_MEMORY_SCHEMAS
        .iter()
        .filter(|schema| schema.prompt_eligible && effective_core_memory_pin(&pin_state, schema))
    {
        let Some(section) = memory_runtime
            .load_core_memory_section(thread_id, schema.section)
            .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        else {
            continue;
        };
        let content = section.content.trim();
        if content.is_empty() {
            continue;
        }
        lines.push(format!("- {}: {}", schema.label, content));
    }
    if lines.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("CORE MEMORY:\n{}", lines.join("\n")))
    }
}

