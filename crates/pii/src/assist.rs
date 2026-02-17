// Submodule: assist (CIM assist seam + receipts)

use anyhow::Result;
use parity_scale_codec::Encode;
use std::future::Future;
use std::pin::Pin;

use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_types::app::agentic::{EvidenceGraph, PiiControls, PiiTarget, Stage2Decision};

use crate::hashing::{graph_hash, sha256_array};

pub enum RiskSurface {
    LocalProcessing,
    Egress,
}

/// Boxed async inspector future used by `inspect_and_route_with`.
pub type InspectFuture<'a> = Pin<Box<dyn Future<Output = Result<EvidenceGraph>> + Send + 'a>>;

/// Assist invocation context for Stage A -> A' refinement.
pub struct CimAssistContext<'a> {
    pub target: &'a PiiTarget,
    pub risk_surface: RiskSurface,
    pub policy: &'a PiiControls,
    pub supports_transform: bool,
}

/// Structured result returned by a CIM assist provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimAssistResult {
    pub output_graph: EvidenceGraph,
    pub assist_applied: bool,
}

/// Deterministic assist receipt bound into decision hash material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimAssistReceipt {
    pub assist_invoked: bool,
    pub assist_applied: bool,
    pub assist_kind: String,
    pub assist_version: String,
    pub assist_identity_hash: [u8; 32],
    pub assist_config_hash: [u8; 32],
    pub assist_module_hash: [u8; 32],
    pub assist_input_graph_hash: [u8; 32],
    pub assist_output_graph_hash: [u8; 32],
}

/// Seam for deterministic Stage A -> A' assist providers.
pub trait CimAssistProvider: Send + Sync {
    fn assist_kind(&self) -> &str;
    fn assist_version(&self) -> &str;
    fn assist_config_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }
    fn assist_module_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }
    fn assist_identity_hash(&self) -> [u8; 32] {
        assist_identity_hash(
            self.assist_kind(),
            self.assist_version(),
            self.assist_config_hash(),
            self.assist_module_hash(),
        )
    }
    fn assist(&self, graph: &EvidenceGraph, ctx: &CimAssistContext<'_>) -> Result<CimAssistResult>;
}

/// Default deterministic no-op assist provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCimAssistProvider;

impl CimAssistProvider for NoopCimAssistProvider {
    fn assist_kind(&self) -> &str {
        "noop"
    }

    fn assist_version(&self) -> &str {
        "noop-v1"
    }

    fn assist(
        &self,
        graph: &EvidenceGraph,
        _ctx: &CimAssistContext<'_>,
    ) -> Result<CimAssistResult> {
        Ok(CimAssistResult {
            output_graph: graph.clone(),
            assist_applied: false,
        })
    }
}

/// Stage B/C rules-only routing outcome for the local PII firewall.
#[derive(Debug, Clone)]
pub(crate) fn risk_surface_label(risk_surface: RiskSurface) -> &'static str {
    match risk_surface {
        RiskSurface::LocalProcessing => "local_processing",
        RiskSurface::Egress => "egress",
    }
}

pub(crate) fn stage2_kind(stage2: Option<&Stage2Decision>) -> Option<String> {
    stage2.map(|d| {
        match d {
            Stage2Decision::ApproveTransformPlan { .. } => "approve_transform_plan",
            Stage2Decision::Deny { .. } => "deny",
            Stage2Decision::RequestMoreInfo { .. } => "request_more_info",
            Stage2Decision::GrantScopedException { .. } => "grant_scoped_exception",
        }
        .to_string()
    })
}

pub(crate) fn assist_identity_hash(
    kind: &str,
    version: &str,
    config_hash: [u8; 32],
    module_hash: [u8; 32],
) -> [u8; 32] {
    let material = (
        kind.to_string(),
        version.to_string(),
        config_hash,
        module_hash,
    )
        .encode();
    sha256_array(&material).unwrap_or([0u8; 32])
}

pub(crate) fn build_assist_receipt<P: CimAssistProvider + ?Sized>(
    provider: &P,
    input_graph: &EvidenceGraph,
    output_graph: &EvidenceGraph,
    assist_applied: bool,
) -> CimAssistReceipt {
    let assist_config_hash = provider.assist_config_hash();
    let assist_module_hash = provider.assist_module_hash();
    CimAssistReceipt {
        assist_invoked: true,
        assist_applied,
        assist_kind: provider.assist_kind().to_string(),
        assist_version: provider.assist_version().to_string(),
        assist_identity_hash: assist_identity_hash(
            provider.assist_kind(),
            provider.assist_version(),
            assist_config_hash,
            assist_module_hash,
        ),
        assist_config_hash,
        assist_module_hash,
        assist_input_graph_hash: graph_hash(input_graph),
        assist_output_graph_hash: graph_hash(output_graph),
    }
}
