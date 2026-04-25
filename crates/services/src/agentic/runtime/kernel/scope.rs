use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeScopeKind {
    FilesystemPath,
    ArtifactRegion,
    BrowserSession,
    ConnectorResource,
    WorkflowResource,
    GraphNodeOutput,
    Clipboard,
    GuiForegroundWindow,
    ModelBudget,
    MemoryNamespace,
}

impl RuntimeScopeKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::FilesystemPath => "filesystem_path",
            Self::ArtifactRegion => "artifact_region",
            Self::BrowserSession => "browser_session",
            Self::ConnectorResource => "connector_resource",
            Self::WorkflowResource => "workflow_resource",
            Self::GraphNodeOutput => "graph_node_output",
            Self::Clipboard => "clipboard",
            Self::GuiForegroundWindow => "gui_foreground_window",
            Self::ModelBudget => "model_budget",
            Self::MemoryNamespace => "memory_namespace",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuntimeScope {
    pub kind: RuntimeScopeKind,
    pub value: String,
}

impl RuntimeScope {
    pub fn new(kind: RuntimeScopeKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: normalize_scope_value(value.into()),
        }
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        if self.kind != other.kind {
            return false;
        }
        match self.kind {
            RuntimeScopeKind::FilesystemPath => path_scopes_overlap(&self.value, &other.value),
            _ => self.value == other.value || self.value == "*" || other.value == "*",
        }
    }

    pub fn label(&self) -> String {
        format!("{}:{}", self.kind.label(), self.value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLeaseMode {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeLease {
    pub lease_id: String,
    pub scope: RuntimeScope,
    pub mode: ScopeLeaseMode,
    pub holder: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeConflictReceipt {
    pub requested_scope: RuntimeScope,
    pub requested_mode: ScopeLeaseMode,
    pub requested_holder: String,
    pub conflicting_lease_id: String,
    pub conflicting_scope: RuntimeScope,
    pub conflicting_mode: ScopeLeaseMode,
    pub reason: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("scope lease conflict: {receipt:?}")]
pub struct ScopeLeaseConflict {
    pub receipt: ScopeConflictReceipt,
}

#[derive(Debug, Default, Clone)]
pub struct ScopeLeaseRegistry {
    active: BTreeMap<String, ScopeLease>,
    next_id: u64,
}

impl ScopeLeaseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn acquire_read(
        &mut self,
        scope: RuntimeScope,
        holder: impl Into<String>,
    ) -> Result<ScopeLease, ScopeLeaseConflict> {
        self.acquire(scope, ScopeLeaseMode::Read, holder)
    }

    pub fn acquire_write(
        &mut self,
        scope: RuntimeScope,
        holder: impl Into<String>,
    ) -> Result<ScopeLease, ScopeLeaseConflict> {
        self.acquire(scope, ScopeLeaseMode::Write, holder)
    }

    pub fn release(&mut self, lease_id: &str) -> Option<ScopeLease> {
        self.active.remove(lease_id)
    }

    pub fn active_leases(&self) -> impl Iterator<Item = &ScopeLease> {
        self.active.values()
    }

    pub fn detect_conflict(
        &self,
        scope: &RuntimeScope,
        mode: ScopeLeaseMode,
    ) -> Option<&ScopeLease> {
        self.active.values().find(|lease| {
            scope.conflicts_with(&lease.scope)
                && (mode == ScopeLeaseMode::Write || lease.mode == ScopeLeaseMode::Write)
        })
    }

    fn acquire(
        &mut self,
        scope: RuntimeScope,
        mode: ScopeLeaseMode,
        holder: impl Into<String>,
    ) -> Result<ScopeLease, ScopeLeaseConflict> {
        let holder = holder.into();
        if let Some(conflicting) = self.detect_conflict(&scope, mode) {
            return Err(ScopeLeaseConflict {
                receipt: ScopeConflictReceipt {
                    requested_scope: scope,
                    requested_mode: mode,
                    requested_holder: holder,
                    conflicting_lease_id: conflicting.lease_id.clone(),
                    conflicting_scope: conflicting.scope.clone(),
                    conflicting_mode: conflicting.mode,
                    reason: "overlapping_write_scope".to_string(),
                },
            });
        }
        self.next_id = self.next_id.saturating_add(1);
        let lease = ScopeLease {
            lease_id: format!("scope-lease-{}", self.next_id),
            scope,
            mode,
            holder,
        };
        self.active.insert(lease.lease_id.clone(), lease.clone());
        Ok(lease)
    }
}

fn normalize_scope_value(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "*".to_string();
    }
    trimmed.replace('\\', "/")
}

fn path_scopes_overlap(left: &str, right: &str) -> bool {
    if left == "*" || right == "*" {
        return true;
    }
    if left == right {
        return true;
    }
    let left = left.trim_end_matches('/');
    let right = right.trim_end_matches('/');
    right.starts_with(&format!("{}/", left)) || left.starts_with(&format!("{}/", right))
}
