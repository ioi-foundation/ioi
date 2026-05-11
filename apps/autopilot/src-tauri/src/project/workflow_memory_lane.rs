// apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs

use super::workflow_value_helpers::{
    workflow_sha256_hex, workflow_value_bool_any, workflow_value_string_any, workflow_value_u64_any,
};
use super::*;

pub(super) fn workflow_memory_send_options(logic: &Value, node_id: &str) -> Value {
    let injection_enabled =
        workflow_value_bool_any(logic, &["memoryInjectionEnabled", "injectionEnabled"])
            .unwrap_or(true);
    let disabled = workflow_value_bool_any(logic, &["memoryDisabled", "disabled"])
        .unwrap_or(!injection_enabled);
    json!({
        "memoryKey": workflow_value_string_any(logic, &["memoryKey", "memory_key"]),
        "scope": workflow_value_string_any(logic, &["memoryScope", "scope"]).unwrap_or_else(|| "thread".to_string()),
        "injectionEnabled": injection_enabled,
        "disabled": disabled,
        "readOnly": workflow_value_bool_any(logic, &["memoryReadOnly", "readOnly"]).unwrap_or(false),
        "writeRequiresApproval": workflow_value_bool_any(
            logic,
            &["memoryWriteRequiresApproval", "writeRequiresApproval"],
        )
        .unwrap_or(false),
        "writeApproved": workflow_value_bool_any(logic, &["memoryWriteApproved", "writeApproved"]).unwrap_or(false),
        "subagentInheritance": workflow_value_string_any(
            logic,
            &["memorySubagentInheritance", "subagentInheritance"],
        )
        .unwrap_or_else(|| "explicit".to_string()),
        "retention": workflow_value_string_any(logic, &["memoryRetention", "retention"]),
        "redaction": workflow_value_string_any(logic, &["memoryRedaction", "redaction"])
            .unwrap_or_else(|| "none".to_string()),
        "workflowNodeId": node_id,
    })
}

pub(super) fn workflow_memory_query_output(
    logic: &Value,
    input: &Value,
    node_id: &str,
    evidence_kind: &str,
) -> Value {
    let operation = workflow_value_string_any(logic, &["stateOperation", "memoryOperation"])
        .unwrap_or_else(|| "memory_search".to_string());
    let state_key = workflow_value_string_any(logic, &["stateKey", "memoryKey"])
        .unwrap_or_else(|| "memory".to_string());
    let memory_key = workflow_value_string_any(logic, &["memoryKey", "stateKey"]);
    let scope = workflow_value_string_any(logic, &["memoryScope", "scope"]);
    let query = workflow_value_string_any(logic, &["query", "memoryQuery"]);
    let limit = workflow_value_u64_any(logic, &["limit", "memoryLimit"])
        .map(|value| value.clamp(1, 200) as usize);
    let redaction = workflow_value_string_any(logic, &["memoryRedaction", "redaction"])
        .unwrap_or_else(|| "none".to_string());
    let mut records = Vec::new();
    workflow_collect_memory_records(input, &mut records);
    if let Some(initial_value) = logic.get("initialValue") {
        workflow_collect_memory_records(initial_value, &mut records);
    }
    let query_lower = query.as_ref().map(|value| value.to_lowercase());
    let mut filtered = records
        .into_iter()
        .filter(|record| {
            scope
                .as_ref()
                .map(|expected| {
                    record
                        .get("scope")
                        .and_then(Value::as_str)
                        .map(|actual| actual == expected)
                        .unwrap_or(false)
                })
                .unwrap_or(true)
        })
        .filter(|record| {
            memory_key
                .as_ref()
                .map(|expected| {
                    record
                        .get("memoryKey")
                        .or_else(|| record.get("stateKey"))
                        .and_then(Value::as_str)
                        .map(|actual| actual == expected)
                        .unwrap_or(false)
                })
                .unwrap_or(true)
        })
        .filter(|record| {
            if operation == "memory_list" {
                return true;
            }
            query_lower
                .as_ref()
                .map(|expected| workflow_memory_record_search_text(record).contains(expected))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    if let Some(limit) = limit {
        filtered.truncate(limit);
    }
    if redaction == "redacted" {
        filtered = filtered
            .into_iter()
            .map(|record| workflow_redacted_memory_record(&record))
            .collect();
    }
    let value_records = filtered.clone();
    json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "stateKey": state_key,
        "operation": operation,
        "reducer": "replace",
        "memoryQuery": {
            "scope": scope,
            "memoryKey": memory_key,
            "query": query,
            "limit": limit,
            "redaction": redaction,
            "matchCount": filtered.len()
        },
        "records": filtered,
        "value": {
            "records": value_records
        }
    })
}

fn workflow_collect_memory_records(value: &Value, records: &mut Vec<Value>) {
    match value {
        Value::Array(items) => {
            for item in items {
                workflow_collect_memory_records(item, records);
            }
        }
        Value::Object(object) => {
            if object
                .get("fact")
                .or_else(|| object.get("text"))
                .and_then(Value::as_str)
                .is_some()
            {
                records.push(Value::Object(object.clone()));
            }
            for key in ["records", "memoryRecords", "memories"] {
                if let Some(items) = object.get(key).and_then(Value::as_array) {
                    for item in items {
                        workflow_collect_memory_records(item, records);
                    }
                }
            }
            if let Some(payload) = object.get("payload") {
                workflow_collect_memory_records(payload, records);
            }
            if let Some(value) = object.get("value") {
                workflow_collect_memory_records(value, records);
            }
        }
        _ => {}
    }
}

fn workflow_memory_record_search_text(record: &Value) -> String {
    [
        "fact",
        "text",
        "id",
        "scope",
        "memoryKey",
        "workflowNodeId",
        "source",
    ]
    .iter()
    .filter_map(|key| record.get(*key).and_then(Value::as_str))
    .map(str::to_lowercase)
    .collect::<Vec<_>>()
    .join("\n")
}

fn workflow_redacted_memory_record(record: &Value) -> Value {
    let mut redacted = record.as_object().cloned().unwrap_or_default();
    if let Some(fact) = record
        .get("fact")
        .or_else(|| record.get("text"))
        .and_then(Value::as_str)
    {
        redacted.insert("factHash".to_string(), json!(workflow_sha256_hex(fact)));
    }
    redacted.insert("fact".to_string(), json!("[REDACTED]"));
    redacted.insert("redaction".to_string(), json!("redacted"));
    Value::Object(redacted)
}
