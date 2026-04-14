use crate::autopilot_data_dir_for;
use crate::kernel::artifacts::upsert_named_file_artifact;
use crate::models::{AgentTask, Artifact, ChatMessage, KnowledgeCollectionRecord};
use crate::orchestrator;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_memory::{HybridArchivalMemoryQuery, MemoryRuntime};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{AppHandle, Runtime};

pub(crate) const PLAN_MODE_DIRECTIVE: &str =
    "Plan mode is active. Produce or update an explicit execution plan before execution, call out blockers, validation, evidence, and next steps, and do not claim completion until the plan is validated.";

const PLAN_FILENAMES: [&str; 3] = ["implementation_plan.md", "task.md", "walkthrough.md"];
const KI_SUMMARY_FILENAME: &str = "active_knowledge.md";
const KI_LIMIT: usize = 10;
const KNOWLEDGE_PREVIEW_LIMIT: usize = 220;

#[derive(Debug, Clone)]
pub(crate) struct AmbientKnowledgeInjection {
    pub prompt_prefix: String,
    pub announcement: String,
    pub summary_artifact: Artifact,
}

#[derive(Debug, Clone)]
struct AmbientKnowledgeMatch {
    collection_id: String,
    collection_label: String,
    entry_id: String,
    title: String,
    kind: String,
    summary: String,
    content: String,
    updated_at_ms: u64,
    score: f32,
    source_uris: Vec<String>,
}

fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn preview_text(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut preview: String = compact.chars().take(max_chars).collect();
    if compact.chars().count() > max_chars {
        preview.push_str("...");
    }
    preview
}

fn latest_agent_message(task: &AgentTask) -> Option<&ChatMessage> {
    task.history
        .iter()
        .rev()
        .find(|message| message.role == "agent" && !message.text.trim().is_empty())
}

fn latest_system_message<'a>(task: &'a AgentTask, needle: &str) -> Option<&'a ChatMessage> {
    task.history.iter().rev().find(|message| {
        message.role == "system" && message.text.to_ascii_lowercase().contains(needle)
    })
}

fn conversation_artifact_root<R: Runtime>(app: &AppHandle<R>, thread_id: &str) -> PathBuf {
    autopilot_data_dir_for(app)
        .join("conversation-artifacts")
        .join(thread_id)
}

fn write_markdown(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create {}: {}", parent.display(), error))?;
    }
    fs::write(path, content)
        .map_err(|error| format!("Failed to write {}: {}", path.display(), error))
}

fn replace_or_insert_artifact(task: &mut AgentTask, artifact: Artifact) {
    let target_path = artifact
        .metadata
        .get("path")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(path) = target_path.as_deref() {
        if let Some(existing) = task.artifacts.iter_mut().find(|candidate| {
            candidate.artifact_type == artifact.artifact_type
                && candidate.metadata.get("path").and_then(Value::as_str) == Some(path)
        }) {
            *existing = artifact;
            return;
        }
    }
    task.artifacts.push(artifact);
}

fn should_materialize_plan_artifacts(task: &AgentTask) -> bool {
    let intent = task.intent.trim();
    if intent.is_empty() {
        return false;
    }
    if intent.starts_with(PLAN_MODE_DIRECTIVE) {
        return true;
    }

    let word_count = intent.split_whitespace().count();
    let lower = intent.to_ascii_lowercase();
    word_count >= 12
        || intent.contains('\n')
        || [
            "implement",
            "execute plan",
            "parity",
            "compare",
            "review",
            "refactor",
            "migrate",
            "deploy",
            "debug",
            "investigate",
            "workflow",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn render_checklist(task: &AgentTask) -> String {
    if task.session_checklist.is_empty() {
        return "- None\n".to_string();
    }
    task.session_checklist
        .iter()
        .map(|item| {
            let detail = item.detail.clone().unwrap_or_default();
            if detail.trim().is_empty() {
                format!("- [{}] {}", item.status, item.label)
            } else {
                format!("- [{}] {} — {}", item.status, item.label, detail.trim())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn render_background_tasks(task: &AgentTask) -> String {
    if task.background_tasks.is_empty() {
        return "- None\n".to_string();
    }
    task.background_tasks
        .iter()
        .map(|item| {
            let detail = item.detail.clone().unwrap_or_default();
            if detail.trim().is_empty() {
                format!("- [{}] {}", item.status, item.label)
            } else {
                format!("- [{}] {} — {}", item.status, item.label, detail.trim())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn render_recent_history(task: &AgentTask, count: usize) -> String {
    let recent = task
        .history
        .iter()
        .rev()
        .take(count)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|message| {
            let body = message.text.trim();
            if body.is_empty() {
                format!("- {}: [empty]", message.role)
            } else {
                format!("- {}: {}", message.role, preview_text(body, 200))
            }
        })
        .collect::<Vec<_>>();
    if recent.is_empty() {
        "- None\n".to_string()
    } else {
        recent.join("\n") + "\n"
    }
}

fn render_artifact_inventory(task: &AgentTask) -> String {
    if task.artifacts.is_empty() {
        return "- None\n".to_string();
    }
    task.artifacts
        .iter()
        .map(|artifact| {
            let path = artifact
                .metadata
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("");
            if path.is_empty() {
                format!("- {} ({:?})", artifact.title, artifact.artifact_type)
            } else {
                format!(
                    "- {} ({:?}) — {}",
                    artifact.title, artifact.artifact_type, path
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn build_implementation_plan(task: &AgentTask) -> String {
    let goal = task
        .intent
        .trim()
        .strip_prefix(PLAN_MODE_DIRECTIVE)
        .unwrap_or(task.intent.trim())
        .trim();
    let latest_agent = latest_agent_message(task)
        .map(|message| message.text.trim().to_string())
        .unwrap_or_else(|| {
            "Plan artifact created before the agent returned a full implementation outline."
                .to_string()
        });
    format!(
        "# Implementation Plan\n\n\
         Session: `{session}`\n\
         Phase: `{phase}`\n\
         Current step: {step}\n\n\
         ## Goal\n\n\
         {goal}\n\n\
         ## Plan\n\n\
         {plan}\n\n\
         ## Validation\n\n\
         - Keep receipts and artifacts attached to the session.\n\
         - Verify commands, tests, and review checkpoints before marking complete.\n\
         - Surface blockers or approval needs before risky execution.\n",
        session = task.session_id.as_deref().unwrap_or(task.id.as_str()),
        phase = format!("{:?}", task.phase),
        step = task.current_step.trim(),
        goal = if goal.is_empty() {
            task.intent.trim()
        } else {
            goal
        },
        plan = latest_agent,
    )
}

fn build_task_tracker(task: &AgentTask) -> String {
    format!(
        "# Task Tracker\n\n\
         Session: `{session}`\n\
         Phase: `{phase}`\n\
         Progress: {progress}/{total_steps}\n\
         Current step: {step}\n\n\
         ## Checklist\n\n\
         {checklist}\n\
         ## Background Tasks\n\n\
         {background_tasks}\n\
         ## Recent Conversation\n\n\
         {history}\n\
         ## Artifacts\n\n\
         {artifacts}",
        session = task.session_id.as_deref().unwrap_or(task.id.as_str()),
        phase = format!("{:?}", task.phase),
        progress = task.progress,
        total_steps = task.total_steps,
        step = task.current_step.trim(),
        checklist = render_checklist(task),
        background_tasks = render_background_tasks(task),
        history = render_recent_history(task, 8),
        artifacts = render_artifact_inventory(task),
    )
}

fn build_walkthrough(task: &AgentTask) -> String {
    let latest_agent = latest_agent_message(task)
        .map(|message| message.text.trim().to_string())
        .unwrap_or_else(|| "No final agent walkthrough has been captured yet.".to_string());
    format!(
        "# Walkthrough\n\n\
         Session: `{session}`\n\
         Outcome phase: `{phase}`\n\
         Latest step: {step}\n\n\
         ## Outcome Summary\n\n\
         {summary}\n\n\
         ## Evidence\n\n\
         - History messages: {history_count}\n\
         - Events: {event_count}\n\
         - Artifacts: {artifact_count}\n\
         - Background tasks: {background_count}\n\n\
         ## Artifact References\n\n\
         {artifacts}",
        session = task.session_id.as_deref().unwrap_or(task.id.as_str()),
        phase = format!("{:?}", task.phase),
        step = task.current_step.trim(),
        summary = latest_agent,
        history_count = task.history.len(),
        event_count = task.events.len(),
        artifact_count = task.artifacts.len(),
        background_count = task.background_tasks.len(),
        artifacts = render_artifact_inventory(task),
    )
}

pub(crate) fn sync_planning_artifacts<R: Runtime>(
    app: &AppHandle<R>,
    memory_runtime: &Arc<MemoryRuntime>,
    task: &mut AgentTask,
) -> Result<(), String> {
    if !should_materialize_plan_artifacts(task) {
        return Ok(());
    }

    let thread_id = task
        .session_id
        .as_deref()
        .unwrap_or(task.id.as_str())
        .to_string();
    let artifact_root = conversation_artifact_root(app, &thread_id).join("planning");
    let files = BTreeMap::from([
        (PLAN_FILENAMES[0], build_implementation_plan(task)),
        (PLAN_FILENAMES[1], build_task_tracker(task)),
        (PLAN_FILENAMES[2], build_walkthrough(task)),
    ]);

    for (filename, content) in files {
        let path = artifact_root.join(filename);
        write_markdown(&path, &content)?;
        let artifact = upsert_named_file_artifact(
            memory_runtime,
            &thread_id,
            &slash_path(&path),
            Some("text/markdown"),
            None,
            content.as_bytes(),
        );
        replace_or_insert_artifact(task, artifact);
    }

    if latest_system_message(task, "planning artifacts ready").is_none() {
        task.history.push(ChatMessage {
            role: "system".to_string(),
            text: format!(
                "Planning artifacts ready: {}, {}, {}",
                slash_path(&artifact_root.join(PLAN_FILENAMES[0])),
                slash_path(&artifact_root.join(PLAN_FILENAMES[1])),
                slash_path(&artifact_root.join(PLAN_FILENAMES[2])),
            ),
            timestamp: crate::kernel::state::now(),
        });
    }

    Ok(())
}

fn repo_affinity_boost(
    collection: &KnowledgeCollectionRecord,
    workspace_root: Option<&Path>,
) -> f32 {
    let Some(workspace_root) = workspace_root else {
        return 0.0;
    };
    let repo_name = workspace_root
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if repo_name.is_empty() {
        return 0.0;
    }

    let sources_match = collection
        .sources
        .iter()
        .any(|source| source.uri.to_ascii_lowercase().contains(repo_name.as_str()));
    let label_match = collection
        .label
        .to_ascii_lowercase()
        .contains(repo_name.as_str())
        || collection
            .description
            .to_ascii_lowercase()
            .contains(repo_name.as_str());
    if sources_match || label_match {
        0.12
    } else {
        0.0
    }
}

fn recency_boost(updated_at_ms: u64) -> f32 {
    let age_ms = now_ms().saturating_sub(updated_at_ms);
    if age_ms <= 86_400_000 {
        0.08
    } else if age_ms <= 7 * 86_400_000 {
        0.05
    } else if age_ms <= 30 * 86_400_000 {
        0.02
    } else {
        0.0
    }
}

async fn select_relevant_knowledge(
    memory_runtime: &Arc<MemoryRuntime>,
    inference: &Arc<dyn InferenceRuntime>,
    query: &str,
    workspace_root: Option<&Path>,
    limit: usize,
) -> Result<Vec<AmbientKnowledgeMatch>, String> {
    let collections = orchestrator::load_knowledge_collections(memory_runtime)
        .into_iter()
        .filter(|collection| collection.active && !collection.entries.is_empty())
        .collect::<Vec<_>>();
    if collections.is_empty() {
        return Ok(Vec::new());
    }

    let embedding = inference
        .embed_text(query)
        .await
        .map_err(|error| format!("Knowledge summary embedding failed: {}", error))?;
    let mut best_by_entry = BTreeMap::<(String, String), AmbientKnowledgeMatch>::new();

    for collection in &collections {
        let scopes = collection
            .entries
            .iter()
            .map(|entry| entry.scope.clone())
            .collect::<Vec<_>>();
        if scopes.is_empty() {
            continue;
        }

        let hits = memory_runtime
            .hybrid_search_archival_memory(&HybridArchivalMemoryQuery {
                scopes,
                thread_id: None,
                text: query.to_string(),
                embedding: Some(embedding.clone()),
                limit: limit.min(4).max(1),
                candidate_limit: (limit * 8).max(24),
                allowed_trust_levels: vec![
                    "standard".to_string(),
                    "runtime_observed".to_string(),
                    "runtime_derived".to_string(),
                    "runtime_controlled".to_string(),
                ],
            })
            .map_err(|error| format!("Knowledge summary search failed: {}", error))?;

        let collection_boost = repo_affinity_boost(collection, workspace_root);
        for hit in hits {
            let metadata = serde_json::from_str::<Value>(&hit.record.metadata_json)
                .unwrap_or_else(|_| Value::Object(Default::default()));
            let Some(entry_id) = metadata
                .get("entry_id")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };
            let Some(entry) = collection
                .entries
                .iter()
                .find(|candidate| candidate.entry_id == entry_id)
            else {
                continue;
            };
            let Some(bytes) = memory_runtime
                .load_artifact_blob(&entry.artifact_id)
                .map_err(|error| format!("Knowledge artifact load failed: {}", error))?
            else {
                continue;
            };
            let content = String::from_utf8_lossy(&bytes).to_string();
            let score = hit.score + collection_boost + recency_boost(entry.updated_at_ms);
            let candidate = AmbientKnowledgeMatch {
                collection_id: collection.collection_id.clone(),
                collection_label: collection.label.clone(),
                entry_id: entry.entry_id.clone(),
                title: entry.title.clone(),
                kind: entry.kind.clone(),
                summary: if hit.record.content.trim().is_empty() {
                    entry.content_preview.clone()
                } else {
                    preview_text(&hit.record.content, KNOWLEDGE_PREVIEW_LIMIT)
                },
                content,
                updated_at_ms: entry.updated_at_ms,
                score,
                source_uris: collection
                    .sources
                    .iter()
                    .filter(|source| source.enabled)
                    .map(|source| source.uri.clone())
                    .collect(),
            };

            best_by_entry
                .entry((candidate.collection_id.clone(), candidate.entry_id.clone()))
                .and_modify(|current| {
                    if candidate.score > current.score {
                        *current = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
    }

    let mut matches = best_by_entry.into_values().collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
    });
    matches.truncate(limit);
    Ok(matches)
}

pub(crate) async fn inject_ambient_knowledge<R: Runtime>(
    app: &AppHandle<R>,
    memory_runtime: &Arc<MemoryRuntime>,
    inference: &Arc<dyn InferenceRuntime>,
    thread_id: &str,
    intent: &str,
) -> Result<Option<AmbientKnowledgeInjection>, String> {
    let trimmed = intent.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let workspace_root = std::env::current_dir().ok();
    let matches = select_relevant_knowledge(
        memory_runtime,
        inference,
        trimmed,
        workspace_root.as_deref(),
        KI_LIMIT,
    )
    .await?;
    if matches.is_empty() {
        return Ok(None);
    }

    let knowledge_root = conversation_artifact_root(app, thread_id).join("knowledge");
    let mut rendered_items = Vec::new();
    for (index, item) in matches.iter().enumerate() {
        let entry_path = knowledge_root
            .join(&item.collection_id)
            .join(format!("{}-{}.md", item.entry_id, item.kind));
        let entry_markdown = format!(
            "# {title}\n\n\
             Collection: `{collection}`\n\
             Entry ID: `{entry_id}`\n\
             Kind: `{kind}`\n\
             Score: `{score:.3}`\n\
             Source URIs: {sources}\n\n\
             ## Summary\n\n\
             {summary}\n\n\
             ## Content\n\n\
             {content}\n",
            title = item.title,
            collection = item.collection_label,
            entry_id = item.entry_id,
            kind = item.kind,
            score = item.score,
            sources = if item.source_uris.is_empty() {
                "none".to_string()
            } else {
                item.source_uris.join(", ")
            },
            summary = item.summary,
            content = item.content.trim(),
        );
        write_markdown(&entry_path, &entry_markdown)?;
        rendered_items.push(format!(
            "{}. {} ({})\n   Summary: {}\n   Artifact path: {}\n   Source hints: {}",
            index + 1,
            item.title,
            item.collection_label,
            item.summary,
            slash_path(&entry_path),
            if item.source_uris.is_empty() {
                "none".to_string()
            } else {
                item.source_uris.join(", ")
            },
        ));
    }

    let summary_path = knowledge_root.join(KI_SUMMARY_FILENAME);
    let summary_markdown = format!(
        "# Active Knowledge Context\n\n\
         Query: `{query}`\n\n\
         The runtime selected the following knowledge items before broader rediscovery:\n\n\
         {items}\n",
        query = trimmed,
        items = rendered_items.join("\n\n"),
    );
    write_markdown(&summary_path, &summary_markdown)?;
    let summary_artifact = upsert_named_file_artifact(
        memory_runtime,
        thread_id,
        &slash_path(&summary_path),
        Some("text/markdown"),
        None,
        summary_markdown.as_bytes(),
    );

    let prompt_prefix = format!(
        "ACTIVE KNOWLEDGE ITEM SUMMARIES:\n\
         {items}\n\n\
         Prefer inspecting these knowledge files before broader repo or web rediscovery when they are relevant to the current request.\n",
        items = rendered_items.join("\n\n"),
    );
    let announcement = format!(
        "Loaded {} knowledge items into session context. Summary file: {}",
        matches.len(),
        slash_path(&summary_path),
    );

    Ok(Some(AmbientKnowledgeInjection {
        prompt_prefix,
        announcement,
        summary_artifact,
    }))
}

#[cfg(test)]
mod tests;
