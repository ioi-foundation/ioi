// Path: crates/types/src/app/workload.rs

use crate::app::ActionTarget;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Canonical execution substrate selected for a workload call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTarget {
    /// Local or managed model inference substrate.
    Inference,
    /// Local or managed media processing substrate.
    Media,
    /// Model, backend, and gallery lifecycle control substrate.
    ModelRegistry,
    /// Local filesystem mutation/read substrate.
    Filesystem,
    /// Local system command/session substrate.
    System,
    /// Local desktop GUI/input substrate.
    DesktopUi,
    /// Browser automation substrate.
    Browser,
    /// Network retrieval substrate.
    Network,
    /// Memory retrieval substrate.
    Memory,
    /// External adapter substrate (for example MCP wrappers).
    McpAdapter,
    /// Agent lifecycle/control-plane substrate.
    ControlPlane,
    /// Generic external adapter substrate.
    Adapter,
}

impl RuntimeTarget {
    /// Returns a stable, deterministic label for receipts and policy checks.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Inference => "inference",
            Self::Media => "media",
            Self::ModelRegistry => "model_registry",
            Self::Filesystem => "filesystem",
            Self::System => "system",
            Self::DesktopUi => "desktop_ui",
            Self::Browser => "browser",
            Self::Network => "network",
            Self::Memory => "memory",
            Self::McpAdapter => "mcp_adapter",
            Self::ControlPlane => "control_plane",
            Self::Adapter => "adapter",
        }
    }
}

/// Network mode bound to a workload invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum NetMode {
    /// No outbound network is allowed.
    Disabled,
    /// Outbound network is allowed only for domains present in the lease allowlist.
    AllowListed,
    /// Outbound network is allowed without a domain allowlist restriction.
    AllowAny,
}

impl NetMode {
    /// Returns a stable, deterministic label for receipts and policy checks.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AllowListed => "allow_listed",
            Self::AllowAny => "allow_any",
        }
    }
}

/// Lease mode defining the authorization lifetime semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLeaseMode {
    /// Lease is intended for a single action.
    OneShot,
    /// Lease may authorize multiple actions until expiry.
    Session,
}

/// Bounded authorization attached to a workload call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct CapabilityLease {
    /// Deterministic lease identifier.
    pub lease_id: [u8; 32],
    /// Lease issuance timestamp (milliseconds since UNIX epoch).
    pub issued_at_ms: u64,
    /// Lease expiry timestamp (milliseconds since UNIX epoch).
    pub expires_at_ms: u64,
    /// Lease lifetime mode.
    pub mode: CapabilityLeaseMode,
    /// Canonical capability labels authorized by this lease.
    #[serde(default)]
    pub capability_allowlist: Vec<String>,
    /// Optional domain allowlist used with `NetMode::AllowListed`.
    #[serde(default)]
    pub domain_allowlist: Vec<String>,
}

impl CapabilityLease {
    /// Returns true when the lease can authorize `capability_label`.
    pub fn allows_capability(&self, capability_label: &str) -> bool {
        let Some(candidate) = normalize_capability_label(capability_label) else {
            return false;
        };
        self.capability_allowlist
            .iter()
            .filter_map(|value| normalize_capability_label(value))
            .any(|allowed| allowed == candidate)
    }

    /// Returns true when the lease is active at `timestamp_ms`.
    pub fn is_active_at(&self, timestamp_ms: u64) -> bool {
        timestamp_ms >= self.issued_at_ms && timestamp_ms <= self.expires_at_ms
    }

    /// Returns true when `domain` is within the lease domain allowlist.
    pub fn allows_domain(&self, domain: &str) -> bool {
        let Some(candidate) = normalize_domain(domain) else {
            return false;
        };
        self.domain_allowlist
            .iter()
            .filter_map(|value| normalize_domain(value))
            .any(|allowed| candidate == allowed || candidate.ends_with(&format!(".{}", allowed)))
    }
}

/// Optional UI-surface binding used for foreground-dependent actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct UiSurfaceSpec {
    /// Optional deterministic binding hash/id for the active window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_id: Option<u64>,
    /// Optional target app/window hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_hint: Option<String>,
    /// Whether the action requires a focused foreground window.
    #[serde(default)]
    pub requires_focused_window: bool,
}

/// Canonical workload envelope that binds runtime target, lease, and network mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WorkloadSpec {
    /// Runtime substrate selected for execution.
    pub runtime_target: RuntimeTarget,
    /// Network mode for this workload.
    pub net_mode: NetMode,
    /// Capability lease attached to this workload call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_lease: Option<CapabilityLease>,
    /// Optional UI-surface binding for interactive workloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_surface: Option<UiSurfaceSpec>,
}

/// Structured lease evaluation evidence used by execution receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WorkloadLeaseCheck {
    /// Short observed summary value for auditing.
    pub observed_value: String,
    /// Source identifier for the probe/evaluation implementation.
    pub probe_source: String,
    /// Milliseconds since UNIX epoch for the evaluation.
    pub timestamp_ms: u64,
    /// Whether the check is satisfied.
    pub satisfied: bool,
    /// Optional machine-readable failure reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WorkloadSpec {
    /// Evaluates the workload lease contract for `target` at `timestamp_ms`.
    ///
    /// This check is fail-closed:
    /// - missing lease -> denied
    /// - out-of-window lease -> denied
    /// - capability not present in lease allowlist -> denied
    /// - network target with incompatible `net_mode` -> denied
    pub fn evaluate_lease(
        &self,
        target: &ActionTarget,
        observed_domain: Option<&str>,
        timestamp_ms: u64,
    ) -> WorkloadLeaseCheck {
        let target_label = target.canonical_label();
        let base_observed_value = format!(
            "target={};runtime_target={};net_mode={}",
            target_label,
            self.runtime_target.as_label(),
            self.net_mode.as_label()
        );
        let probe_source = "workload_spec.evaluate_lease.v1".to_string();

        let Some(lease) = self.capability_lease.as_ref() else {
            return WorkloadLeaseCheck {
                observed_value: base_observed_value,
                probe_source,
                timestamp_ms,
                satisfied: false,
                reason: Some("missing_capability_lease".to_string()),
            };
        };

        if !lease.is_active_at(timestamp_ms) {
            return WorkloadLeaseCheck {
                observed_value: base_observed_value,
                probe_source,
                timestamp_ms,
                satisfied: false,
                reason: Some("capability_lease_expired".to_string()),
            };
        }

        if !lease.allows_capability(&target_label) {
            return WorkloadLeaseCheck {
                observed_value: base_observed_value,
                probe_source,
                timestamp_ms,
                satisfied: false,
                reason: Some("capability_out_of_scope".to_string()),
            };
        }

        if is_network_target(target) {
            match self.net_mode {
                NetMode::Disabled => {
                    return WorkloadLeaseCheck {
                        observed_value: base_observed_value,
                        probe_source,
                        timestamp_ms,
                        satisfied: false,
                        reason: Some("net_mode_disabled".to_string()),
                    };
                }
                NetMode::AllowListed => {
                    let Some(domain) = observed_domain.and_then(normalize_domain) else {
                        return WorkloadLeaseCheck {
                            observed_value: base_observed_value,
                            probe_source,
                            timestamp_ms,
                            satisfied: false,
                            reason: Some("observed_domain_missing".to_string()),
                        };
                    };
                    if !lease.allows_domain(&domain) {
                        return WorkloadLeaseCheck {
                            observed_value: format!(
                                "{};observed_domain={}",
                                base_observed_value, domain
                            ),
                            probe_source,
                            timestamp_ms,
                            satisfied: false,
                            reason: Some("domain_out_of_scope".to_string()),
                        };
                    }
                }
                NetMode::AllowAny => {}
            }
        }

        WorkloadLeaseCheck {
            observed_value: base_observed_value,
            probe_source,
            timestamp_ms,
            satisfied: true,
            reason: None,
        }
    }
}

fn normalize_capability_label(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn is_network_target(target: &ActionTarget) -> bool {
    match target {
        ActionTarget::NetFetch
        | ActionTarget::WebRetrieve
        | ActionTarget::MediaExtractTranscript
        | ActionTarget::MediaExtractMultimodalEvidence
        | ActionTarget::BrowserInteract
        | ActionTarget::BrowserInspect
        | ActionTarget::CommerceDiscovery
        | ActionTarget::CommerceCheckout => true,
        ActionTarget::Custom(label) => {
            let normalized = label.trim().to_ascii_lowercase();
            normalized.starts_with("net::")
                || normalized.starts_with("web::")
                || normalized.starts_with("browser::")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec() -> WorkloadSpec {
        WorkloadSpec {
            runtime_target: RuntimeTarget::Network,
            net_mode: NetMode::AllowListed,
            capability_lease: Some(CapabilityLease {
                lease_id: [7u8; 32],
                issued_at_ms: 100,
                expires_at_ms: 1_000,
                mode: CapabilityLeaseMode::OneShot,
                capability_allowlist: vec!["net::fetch".to_string()],
                domain_allowlist: vec!["example.com".to_string()],
            }),
            ui_surface: None,
        }
    }

    #[test]
    fn lease_check_fails_when_capability_lease_missing() {
        let spec = WorkloadSpec {
            runtime_target: RuntimeTarget::Network,
            net_mode: NetMode::AllowListed,
            capability_lease: None,
            ui_surface: None,
        };
        let check = spec.evaluate_lease(&ActionTarget::NetFetch, Some("example.com"), 500);
        assert!(!check.satisfied);
        assert_eq!(check.reason.as_deref(), Some("missing_capability_lease"));
    }

    #[test]
    fn lease_check_fails_when_expired() {
        let spec = sample_spec();
        let check = spec.evaluate_lease(&ActionTarget::NetFetch, Some("example.com"), 1_001);
        assert!(!check.satisfied);
        assert_eq!(check.reason.as_deref(), Some("capability_lease_expired"));
    }

    #[test]
    fn lease_check_fails_when_domain_out_of_scope() {
        let spec = sample_spec();
        let check = spec.evaluate_lease(&ActionTarget::NetFetch, Some("evil.com"), 500);
        assert!(!check.satisfied);
        assert_eq!(check.reason.as_deref(), Some("domain_out_of_scope"));
    }

    #[test]
    fn lease_check_succeeds_for_allowlisted_domain() {
        let spec = sample_spec();
        let check = spec.evaluate_lease(&ActionTarget::NetFetch, Some("api.example.com"), 500);
        assert!(check.satisfied);
        assert!(check.reason.is_none());
    }

    #[test]
    fn runtime_target_labels_include_absorbed_localai_capability_families() {
        assert_eq!(RuntimeTarget::Inference.as_label(), "inference");
        assert_eq!(RuntimeTarget::Media.as_label(), "media");
        assert_eq!(RuntimeTarget::ModelRegistry.as_label(), "model_registry");
    }
}
