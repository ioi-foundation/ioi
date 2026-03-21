/// A signed attestation for a specific AI model snapshot.
/// Used to authorize the loading of large weights into the Workload container.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModelAttestation {
    /// The canonical account ID of the validator issuing this attestation.
    pub validator_id: AccountId,
    /// The SHA-256 hash of the model weights file.
    pub model_hash: [u8; 32],
    /// The UNIX timestamp when the attestation was generated.
    pub timestamp: u64,
    /// The cryptographic signature over the attestation data.
    pub signature: Vec<u8>,
}

// --- Guardian Container ---

/// Holds open file handles to the binaries to prevent modification while running.
/// On Linux, writing to an executing file returns ETXTBSY.
pub struct BinaryGuard {
    _handles: Vec<File>,
}

/// The GuardianContainer is the root of trust.
#[derive(Clone)]
pub struct GuardianContainer {
    /// The secure channel to the Orchestrator container.
    pub orchestration_channel: SecurityChannel,
    /// The secure channel to the Workload container.
    pub workload_channel: SecurityChannel,
    is_running: Arc<AtomicBool>,
    /// The path to the directory containing configuration and keys.
    config_dir: PathBuf,
    /// Backend authority for secrets and signing material.
    key_authority: Arc<dyn KeyAuthority>,
    /// Append-only witness logs for receipts and checkpoints.
    transparency_logs: BTreeMap<String, Arc<dyn TransparencyLog>>,
    /// Default transparency log id used for non-committee effects.
    default_transparency_log_id: String,
    /// TLS and attestation verification policy for egress and runtime evidence.
    verifier_policy: GuardianVerifierPolicyConfig,
    /// Deployment profile controlling local fallbacks.
    production_mode: GuardianProductionMode,
    /// Threshold committee used to issue guardianized decisions.
    committee_client: Option<GuardianCommitteeClient>,
    /// Research-only witness committees that can cross-sign guardian decisions.
    witness_committee_clients: HashMap<[u8; 32], GuardianWitnessCommitteeClient>,
    /// Monotonic decision stream shared across consensus and egress certificates.
    decision_state: Arc<TokioMutex<GuardianDecisionState>>,
    /// Replay-safe nullifiers for proof-carrying sealed effects emitted by this guardian.
    sealed_effect_nullifiers: Arc<TokioMutex<BTreeSet<[u8; 32]>>>,
    /// Reused gRPC channels for remote equal-authority observer collection.
    observer_rpc_channels: Arc<TokioMutex<HashMap<String, Channel>>>,
}
