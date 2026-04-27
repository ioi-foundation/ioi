use crate::agentic::runtime::agent_playbooks::builtin_agent_playbook;
use crate::agentic::runtime::keys::{
    get_parent_playbook_run_key, get_session_result_key, get_state_key, get_worker_assignment_key,
};
use crate::agentic::runtime::service::step::action::command_contract::extract_error_class_token;
use crate::agentic::runtime::service::step::action::execution_evidence_value;
use crate::agentic::runtime::service::step::handle_step;
use crate::agentic::runtime::service::step::queue::web_pipeline::merge_pending_search_completion;
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{
    AgentPlaybookDefinition, AgentPlaybookStepDefinition, AgentState, AgentStatus,
    ParentPlaybookRun, ParentPlaybookStatus, ParentPlaybookStepRun, ParentPlaybookStepStatus,
    StepAgentParams, WorkerAssignment, WorkerCompletionContract, WorkerMergeMode,
    WorkerSessionResult, WorkerTemplateWorkflowDefinition,
};
use crate::agentic::runtime::utils::{
    load_agent_state_with_runtime_preference, persist_agent_state,
};
use crate::agentic::runtime::worker_context::{
    collect_goal_literals, extract_worker_context_field, looks_like_command_literal,
    normalize_whitespace, split_parent_playbook_context, PARENT_PLAYBOOK_CONTEXT_MARKER,
};
use crate::agentic::runtime::worker_templates::{
    builtin_worker_template, builtin_worker_workflow, default_worker_role_label,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::MemoryRuntime;
use ioi_types::app::{
    ArtifactGenerationSummary, ArtifactQualityScorecard, ArtifactRepairSummary,
    CodingVerificationScorecard, ComputerUsePerceptionSummary, ComputerUseRecoverySummary,
    ComputerUseVerificationScorecard, KernelEvent, PatchSynthesisSummary,
    ResearchVerificationScorecard, WorkloadParentPlaybookReceipt, WorkloadReceipt,
    WorkloadReceiptEvent, WorkloadWorkerReceipt,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use super::delegation::{spawn_delegated_child_session, DelegatedChildPrepBundle};
use super::parent_playbook_receipts::{
    build_parent_playbook_prep_receipt_metadata, build_parent_playbook_route_receipt_metadata,
};

mod await_loop;
mod evidence;
mod merge;
mod parent_playbook;
mod scorecard_support;
mod scorecards;
mod state;

pub(crate) use await_loop::await_child_worker_result;
pub(crate) use merge::register_parent_playbook_step_spawn;
pub(crate) use parent_playbook::*;
pub(crate) use scorecard_support::*;
pub(crate) use state::*;

use evidence::{
    emit_parent_playbook_blocked_receipt, emit_parent_playbook_completed_receipt,
    emit_parent_playbook_started_receipt, emit_parent_playbook_step_completed_receipt,
    emit_parent_playbook_step_spawned_receipt, emit_worker_completion_receipt,
    emit_worker_merge_receipt, worker_receipt_summary,
};
use merge::{
    advance_parent_playbook_after_worker_merge, block_parent_playbook_after_worker_failure,
    load_or_materialize_worker_result,
};

#[cfg(test)]
mod tests;
