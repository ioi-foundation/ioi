// Path: crates/cli/src/testing/cluster.rs

// REMOVE: use super::assert::wait_for_height;
use super::genesis::GenesisBuilder;
use super::validator::{
    reserve_validator_ports, TestValidator, ValidatorGuard, VALIDATOR_PORT_FANOUT,
};
use anyhow::{anyhow, Result};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use dcrypt::sign::eddsa::Ed25519SecretKey;
use futures_util::{stream::FuturesUnordered, StreamExt};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::bls::BlsKeyPair;
use ioi_crypto::sign::guardian_committee::{
    canonical_manifest_hash, canonical_witness_manifest_hash,
};
use ioi_types::config::ValidatorRole;
use ioi_types::config::{
    AftSafetyMode, GuardianCommitteeConfig, GuardianCommitteeMemberConfig,
    GuardianWitnessCommitteeConfig, InitialServiceConfig, ServicePolicy,
};
// [FIX] Add imports for default genesis setup
use ioi_types::app::{
    account_id_from_key_material, guardian_registry_asymptote_policy_key,
    guardian_registry_committee_account_key, guardian_registry_committee_key,
    guardian_registry_log_key, guardian_registry_witness_key, guardian_registry_witness_seed_key,
    guardian_registry_witness_set_key, AccountId, ActiveKeyRecord, AsymptoteObserverSealingMode,
    AsymptotePolicy, BlockTimingParams, BlockTimingRuntime, FinalityTier,
    GuardianCommitteeManifest, GuardianCommitteeMember, GuardianTransparencyLogDescriptor,
    GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed, GuardianWitnessSet, SignatureSuite,
    ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
};
use ioi_types::keys::CURRENT_EPOCH_KEY;
use ioi_validator::config::{AttestationSignaturePolicy, GuardianConfig};
use libp2p::{
    identity::{self, ed25519, Keypair},
    Multiaddr,
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

const VALIDATOR_PORT_STRIDE: u16 = 100;
struct ValidatorPortAllocation {
    bases: Vec<u16>,
    reservations: Vec<Vec<TcpListener>>,
    lock_path: PathBuf,
}

fn process_is_alive(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

fn reclaim_stale_port_block_lock(lock_path: &PathBuf) {
    let Ok(contents) = fs::read_to_string(lock_path) else {
        return;
    };
    let Some(pid) = contents
        .trim()
        .strip_prefix("pid=")
        .and_then(|value| value.parse::<u32>().ok())
    else {
        let _ = fs::remove_file(lock_path);
        return;
    };

    if !process_is_alive(pid) {
        let _ = fs::remove_file(lock_path);
    }
}

fn allocate_validator_port_bases(num_validators: usize) -> Result<ValidatorPortAllocation> {
    let lock_dir = std::env::temp_dir().join("ioi-test-port-blocks");
    fs::create_dir_all(&lock_dir)?;

    for block_start in (20_000u16..55_000u16).step_by(1_000) {
        let lock_path = lock_dir.join(format!("{block_start}.lock"));
        if lock_path.exists() {
            reclaim_stale_port_block_lock(&lock_path);
        }
        let mut lock_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(_) => continue,
        };

        let mut bases = Vec::with_capacity(num_validators);
        let mut validator_reservations = Vec::with_capacity(num_validators);
        let mut available = true;

        for validator_index in 0..num_validators {
            let base_port = block_start
                .checked_add((validator_index as u16) * VALIDATOR_PORT_STRIDE)
                .ok_or_else(|| anyhow!("validator port allocation overflow"))?;
            let block_end = base_port
                .checked_add(VALIDATOR_PORT_FANOUT)
                .ok_or_else(|| anyhow!("validator port allocation overflow"))?;
            if block_end >= u16::MAX {
                available = false;
                break;
            }

            match reserve_validator_ports(base_port) {
                Ok(listeners) => validator_reservations.push(listeners),
                Err(_) => {
                    available = false;
                    break;
                }
            }
            bases.push(base_port);
        }

        if available {
            use std::io::Write as _;
            writeln!(lock_file, "pid={}", std::process::id())?;
            return Ok(ValidatorPortAllocation {
                bases,
                reservations: validator_reservations,
                lock_path,
            });
        }

        drop(lock_file);
        let _ = fs::remove_file(&lock_path);
    }

    Err(anyhow!(
        "failed to allocate a free validator port block for {} validators",
        num_validators
    ))
}

// Helper to fetch peer count from metrics
async fn fetch_peer_count(metrics_addr: &str) -> String {
    let url = format!("http://{}/metrics", metrics_addr);
    match reqwest::get(&url).await {
        Ok(resp) => {
            if let Ok(text) = resp.text().await {
                for line in text.lines() {
                    // Prometheus metric format: ioi_networking_connected_peers 2
                    if line.starts_with("ioi_networking_connected_peers ") {
                        return line.split_whitespace().last().unwrap_or("?").to_string();
                    }
                }
                "0".to_string() // Metric missing implies 0 or not yet reported
            } else {
                "Err".to_string()
            }
        }
        Err(_) => "Down".to_string(),
    }
}

/// A type alias for a closure that modifies the genesis state.
type GenesisModifier = Box<dyn FnOnce(&mut GenesisBuilder, &Vec<identity::Keypair>) + Send>;

pub struct TestCluster {
    pub validators: Vec<ValidatorGuard>,
    pub genesis_content: String,
    _shared_artifacts: Option<Arc<TempDir>>,
    _port_block_lock_path: Option<PathBuf>,
}

impl TestCluster {
    pub fn builder() -> TestClusterBuilder {
        TestClusterBuilder::new()
    }

    pub async fn shutdown(self) -> Result<()> {
        for guard in self.validators {
            guard.shutdown().await?;
        }
        if let Some(lock_path) = self._port_block_lock_path {
            let _ = fs::remove_file(lock_path);
        }
        Ok(())
    }
}

pub struct TestClusterBuilder {
    num_validators: usize,
    keypairs: Option<Vec<identity::Keypair>>,
    chain_id: ioi_types::app::ChainId,
    genesis_modifiers: Vec<GenesisModifier>,
    consensus_type: String,
    agentic_model_path: Option<String>,
    use_docker: bool,
    state_tree: String,
    commitment_scheme: String,
    ibc_gateway_addr: Option<String>,
    initial_services: Vec<InitialServiceConfig>,
    use_malicious_workload: bool,
    extra_features: Vec<String>,
    validator0_key_override: Option<identity::Keypair>,
    epoch_size: Option<u64>,
    keep_recent_heights: Option<u64>,
    gc_interval_secs: Option<u64>,
    min_finality_depth: Option<u64>,
    service_policies_override: BTreeMap<String, ServicePolicy>,
    workload_env: BTreeMap<String, String>,
    roles: BTreeMap<usize, ValidatorRole>,
    aft_safety_mode: AftSafetyMode,
    guardian_config_toml: Option<String>,
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self {
            num_validators: 1,
            keypairs: None,
            chain_id: ioi_types::app::ChainId(1),
            genesis_modifiers: Vec::new(),
            consensus_type: "Aft".to_string(),
            agentic_model_path: None,
            use_docker: false,
            state_tree: "IAVL".to_string(),
            commitment_scheme: "Hash".to_string(),
            ibc_gateway_addr: None,
            initial_services: Vec::new(),
            use_malicious_workload: false,
            extra_features: Vec::new(),
            validator0_key_override: None,
            epoch_size: None,
            keep_recent_heights: None,
            gc_interval_secs: None,
            min_finality_depth: None,
            service_policies_override: BTreeMap::new(),
            workload_env: BTreeMap::new(),
            roles: BTreeMap::new(),
            aft_safety_mode: AftSafetyMode::GuardianMajority,
            guardian_config_toml: None,
        }
    }
}

fn libp2p_keypair_from_dcrypt_seed(seed: [u8; 32]) -> libp2p::identity::Keypair {
    let sk = Ed25519SecretKey::from_seed(&seed).expect("dcrypt ed25519 from seed");
    let pk = sk.public_key().expect("dcrypt(ed25519) public");
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&seed);
    bytes[32..].copy_from_slice(&pk.to_bytes());
    let ed = ed25519::Keypair::try_from_bytes(&mut bytes[..])
        .expect("libp2p ed25519 keypair from (seed||pub)");
    Keypair::from(ed)
}

struct AutoGuardianHarness {
    temp_dir: Arc<TempDir>,
    guardian_config_toml: String,
    transparency_log_descriptors: Vec<(Vec<u8>, Vec<u8>)>,
    committee_manifests: Vec<(Vec<u8>, Vec<u8>)>,
    witness_manifests: Vec<(Vec<u8>, Vec<u8>)>,
    witness_seed: Option<(Vec<u8>, Vec<u8>)>,
    witness_set: Option<(Vec<u8>, Vec<u8>)>,
    asymptote_policy: Option<(Vec<u8>, Vec<u8>)>,
}

fn digest_to_array(digest: impl AsRef<[u8]>) -> Result<[u8; 32]> {
    digest
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("sha256 digest was not 32 bytes"))
}

fn derive_guardian_policy_hash(config: &GuardianConfig) -> Result<[u8; 32]> {
    digest_to_array(
        Sha256::digest(&serde_json::to_vec(&(
            config.production_mode,
            &config.hardening,
            &config.verifier_policy,
            &config.transparency_log,
        ))?)
        .map_err(|e| anyhow!(e.to_string()))?,
    )
}

fn derive_guardian_measurement_root(config: &GuardianConfig) -> Result<[u8; 32]> {
    digest_to_array(
        Sha256::digest(&serde_json::to_vec(&(
            config.approved_orchestrator_hash.clone(),
            config.approved_workload_hash.clone(),
            config.hardening.measured_boot_required,
        ))?)
        .map_err(|e| anyhow!(e.to_string()))?,
    )
}

fn derive_witness_policy_hash(
    config: &GuardianConfig,
    witness_config: &GuardianWitnessCommitteeConfig,
) -> Result<[u8; 32]> {
    if let Some(policy_hash) = witness_config.policy_hash {
        return Ok(policy_hash);
    }
    digest_to_array(
        Sha256::digest(&serde_json::to_vec(&(
            &witness_config.committee_id,
            witness_config.epoch,
            witness_config.threshold,
            &config.verifier_policy,
            &config.transparency_log,
        ))?)
        .map_err(|e| anyhow!(e.to_string()))?,
    )
}

fn build_auto_guardian_harness(
    validator_keys: &[identity::Keypair],
    validator_base_ports: &[u16],
    safety_mode: AftSafetyMode,
) -> Result<AutoGuardianHarness> {
    let temp_dir = Arc::new(tempfile::tempdir()?);
    let committee_keys = [BlsKeyPair::generate()?, BlsKeyPair::generate()?];
    let transparency_log_key = identity::Keypair::generate_ed25519();
    let transparency_log_key_path = temp_dir.path().join("guardian-log.key");
    std::fs::write(
        &transparency_log_key_path,
        transparency_log_key.to_protobuf_encoding()?,
    )?;

    let committee_members = committee_keys
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            let private_key_path = temp_dir.path().join(format!("guardian-member-{index}.bls"));
            std::fs::write(
                &private_key_path,
                hex::encode(SigningKeyPair::private_key(keypair).to_bytes()),
            )?;
            Ok::<_, anyhow::Error>(GuardianCommitteeMemberConfig {
                member_id: format!("guardian-member-{index}"),
                endpoint: None,
                public_key: SigningKeyPair::public_key(keypair).to_bytes(),
                private_key_path: Some(private_key_path.to_string_lossy().to_string()),
                provider: Some(format!("provider-{index}")),
                region: Some(format!("region-{index}")),
                host_class: Some(format!("host-class-{index}")),
                key_authority_kind: Some(ioi_types::app::KeyAuthorityKind::DevMemory),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut guardian_config = GuardianConfig {
        signature_policy: AttestationSignaturePolicy::FollowChain,
        production_mode: ioi_types::app::GuardianProductionMode::Compatibility,
        key_authority: None,
        committee: GuardianCommitteeConfig {
            threshold: 2,
            members: committee_members,
            transparency_log_id: "guardian-test-log".to_string(),
        },
        experimental_witness_committees: Vec::new(),
        hardening: Default::default(),
        transparency_log: ioi_types::config::GuardianTransparencyLogConfig {
            log_id: "guardian-test-log".to_string(),
            endpoint: None,
            signing_key_path: Some(transparency_log_key_path.to_string_lossy().to_string()),
            required: true,
        },
        verifier_policy: Default::default(),
        enforce_binary_integrity: false,
        approved_orchestrator_hash: None,
        approved_workload_hash: None,
        binary_dir_override: None,
    };

    if matches!(
        safety_mode,
        AftSafetyMode::ExperimentalNestedGuardian | AftSafetyMode::Asymptote
    ) {
        let witness_committee_count = if matches!(safety_mode, AftSafetyMode::Asymptote) {
            4
        } else {
            1
        };
        for committee_index in 0..witness_committee_count {
            let witness_members = (0..2)
                .map(|member_index| {
                    let keypair = BlsKeyPair::generate()?;
                    let global_index = (committee_index * 2) + member_index;
                    let private_key_path = temp_dir
                        .path()
                        .join(format!("witness-member-{global_index}.bls"));
                    std::fs::write(
                        &private_key_path,
                        hex::encode(SigningKeyPair::private_key(&keypair).to_bytes()),
                    )?;
                    Ok::<_, anyhow::Error>(GuardianCommitteeMemberConfig {
                        member_id: format!("witness-member-{global_index}"),
                        endpoint: None,
                        public_key: SigningKeyPair::public_key(&keypair).to_bytes(),
                        private_key_path: Some(private_key_path.to_string_lossy().to_string()),
                        provider: Some(format!("witness-provider-{}", global_index % 4)),
                        region: Some(format!("witness-region-{}", global_index % 4)),
                        host_class: Some(format!("witness-host-class-{}", global_index % 4)),
                        key_authority_kind: Some(ioi_types::app::KeyAuthorityKind::DevMemory),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            guardian_config
                .experimental_witness_committees
                .push(GuardianWitnessCommitteeConfig {
                    committee_id: format!("witness-{}", (b'a' + committee_index as u8) as char),
                    stratum_id: format!("stratum-{}", (b'a' + committee_index as u8) as char),
                    epoch: 1,
                    threshold: 2,
                    members: witness_members,
                    transparency_log_id: format!("witness-test-log-{committee_index}"),
                    policy_hash: None,
                });
        }
    }

    let measurement_profile_root = derive_guardian_measurement_root(&guardian_config)?;
    let guardian_policy_hash = derive_guardian_policy_hash(&guardian_config)?;
    let mut committee_manifests = Vec::new();
    for (index, key) in validator_keys.iter().enumerate() {
        let validator_account_id = AccountId(account_id_from_key_material(
            SignatureSuite::ED25519,
            &key.public().encode_protobuf(),
        )?);
        let guardian_endpoint = format!("http://127.0.0.1:{}", validator_base_ports[index] + 4);
        let manifest_members = guardian_config
            .committee
            .members
            .iter()
            .map(|member| GuardianCommitteeMember {
                member_id: member.member_id.clone(),
                signature_suite: SignatureSuite::BLS12_381,
                public_key: member.public_key.clone(),
                endpoint: Some(guardian_endpoint.clone()),
                provider: member.provider.clone(),
                region: member.region.clone(),
                host_class: member.host_class.clone(),
                key_authority_kind: member.key_authority_kind,
            })
            .collect::<Vec<_>>();
        let manifest = GuardianCommitteeManifest {
            validator_account_id,
            epoch: 1,
            threshold: guardian_config.committee.threshold,
            members: manifest_members,
            measurement_profile_root,
            policy_hash: guardian_policy_hash,
            transparency_log_id: guardian_config.committee.transparency_log_id.clone(),
        };
        let manifest_hash =
            canonical_manifest_hash(&manifest).map_err(|e| anyhow!(e.to_string()))?;
        committee_manifests.push((
            guardian_registry_committee_key(&manifest_hash),
            ioi_types::codec::to_bytes_canonical(&manifest).map_err(|e| anyhow!(e.to_string()))?,
        ));
        committee_manifests.push((
            guardian_registry_committee_account_key(&validator_account_id),
            manifest_hash.to_vec(),
        ));
    }

    let mut witness_manifests = Vec::new();
    let mut witness_seed = None;
    let mut witness_set = None;
    let mut asymptote_policy = None;
    if !guardian_config.experimental_witness_committees.is_empty() {
        let mut witness_manifest_hashes = Vec::new();
        for witness_config in &guardian_config.experimental_witness_committees {
            let witness_manifest = GuardianWitnessCommitteeManifest {
                committee_id: witness_config.committee_id.clone(),
                stratum_id: witness_config.stratum_id.clone(),
                epoch: witness_config.epoch,
                threshold: witness_config.threshold,
                members: witness_config
                    .members
                    .iter()
                    .map(|member| GuardianCommitteeMember {
                        member_id: member.member_id.clone(),
                        signature_suite: SignatureSuite::BLS12_381,
                        public_key: member.public_key.clone(),
                        endpoint: member.endpoint.clone(),
                        provider: member.provider.clone(),
                        region: member.region.clone(),
                        host_class: member.host_class.clone(),
                        key_authority_kind: member.key_authority_kind,
                    })
                    .collect(),
                policy_hash: derive_witness_policy_hash(&guardian_config, witness_config)?,
                transparency_log_id: witness_config.transparency_log_id.clone(),
            };
            let witness_manifest_hash = canonical_witness_manifest_hash(&witness_manifest)
                .map_err(|e| anyhow!(e.to_string()))?;
            witness_manifest_hashes.push(witness_manifest_hash);
            witness_manifests.push((
                guardian_registry_witness_key(&witness_manifest_hash),
                ioi_types::codec::to_bytes_canonical(&witness_manifest)
                    .map_err(|e| anyhow!(e.to_string()))?,
            ));
        }
        let seed = GuardianWitnessEpochSeed {
            epoch: 1,
            seed: [7u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 0,
        };
        let set = GuardianWitnessSet {
            epoch: 1,
            manifest_hashes: witness_manifest_hashes,
            checkpoint_interval_blocks: 1,
        };
        witness_seed = Some((
            guardian_registry_witness_seed_key(1),
            ioi_types::codec::to_bytes_canonical(&seed).map_err(|e| anyhow!(e.to_string()))?,
        ));
        witness_set = Some((
            guardian_registry_witness_set_key(1),
            ioi_types::codec::to_bytes_canonical(&set).map_err(|e| anyhow!(e.to_string()))?,
        ));
        if matches!(safety_mode, AftSafetyMode::Asymptote) {
            let observer_committee_size =
                usize::min(2, validator_keys.len().saturating_sub(1)) as u16;
            let policy = AsymptotePolicy {
                epoch: 1,
                high_risk_effect_tier: FinalityTier::SealedFinal,
                required_witness_strata: Vec::new(),
                escalation_witness_strata: Vec::new(),
                observer_rounds: if observer_committee_size > 0 { 1 } else { 0 },
                observer_committee_size,
                observer_correlation_budget: Default::default(),
                observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
                observer_challenge_window_ms: 500,
                max_reassignment_depth: 0,
                max_checkpoint_staleness_ms: 120_000,
            };
            asymptote_policy = Some((
                guardian_registry_asymptote_policy_key(1),
                ioi_types::codec::to_bytes_canonical(&policy)
                    .map_err(|e| anyhow!(e.to_string()))?,
            ));
        }
    }

    let mut transparency_log_descriptors = vec![(
        guardian_registry_log_key(&guardian_config.committee.transparency_log_id),
        ioi_types::codec::to_bytes_canonical(&GuardianTransparencyLogDescriptor {
            log_id: guardian_config.committee.transparency_log_id.clone(),
            signature_suite: SignatureSuite::ED25519,
            public_key: transparency_log_key.public().encode_protobuf(),
        })
        .map_err(|e| anyhow!(e.to_string()))?,
    )];
    for witness_config in &guardian_config.experimental_witness_committees {
        if witness_config.transparency_log_id != guardian_config.committee.transparency_log_id {
            transparency_log_descriptors.push((
                guardian_registry_log_key(&witness_config.transparency_log_id),
                ioi_types::codec::to_bytes_canonical(&GuardianTransparencyLogDescriptor {
                    log_id: witness_config.transparency_log_id.clone(),
                    signature_suite: SignatureSuite::ED25519,
                    public_key: transparency_log_key.public().encode_protobuf(),
                })
                .map_err(|e| anyhow!(e.to_string()))?,
            ));
        }
    }

    Ok(AutoGuardianHarness {
        temp_dir,
        guardian_config_toml: toml::to_string(&guardian_config)?,
        transparency_log_descriptors,
        committee_manifests,
        witness_manifests,
        witness_seed,
        witness_set,
        asymptote_policy,
    })
}

impl TestClusterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_validator_seed(mut self, seed: [u8; 32]) -> Self {
        self.validator0_key_override = Some(libp2p_keypair_from_dcrypt_seed(seed));
        self
    }

    pub fn with_validator_keypair(mut self, kp: libp2p::identity::Keypair) -> Self {
        self.validator0_key_override = Some(kp);
        self
    }

    pub fn with_validators(mut self, count: usize) -> Self {
        self.num_validators = count;
        self
    }

    pub fn with_keypairs(mut self, keypairs: Vec<identity::Keypair>) -> Self {
        self.num_validators = keypairs.len();
        self.keypairs = Some(keypairs);
        self
    }

    pub fn with_chain_id(mut self, id: u32) -> Self {
        self.chain_id = id.into();
        self
    }

    pub fn with_random_chain_id(mut self) -> Self {
        use rand::Rng;
        self.chain_id = (rand::thread_rng().gen::<u32>() | 1).into();
        self
    }

    pub fn use_docker_backend(mut self, use_docker: bool) -> Self {
        self.use_docker = use_docker;
        self
    }

    pub fn with_consensus_type(mut self, consensus: &str) -> Self {
        self.consensus_type = consensus.to_string();
        self
    }

    pub fn with_state_tree(mut self, state: &str) -> Self {
        self.state_tree = state.to_string();
        self
    }

    pub fn with_commitment_scheme(mut self, scheme: &str) -> Self {
        self.commitment_scheme = scheme.to_string();
        self
    }

    pub fn with_agentic_model_path(mut self, path: &str) -> Self {
        self.agentic_model_path = Some(path.to_string());
        self
    }

    pub fn with_ibc_gateway(mut self, addr: &str) -> Self {
        self.ibc_gateway_addr = Some(addr.to_string());
        self
    }

    pub fn with_initial_service(mut self, service_config: InitialServiceConfig) -> Self {
        if let InitialServiceConfig::Ibc(_) = &service_config {
            if !self.extra_features.contains(&"ibc-deps".to_string()) {
                self.extra_features.push("ibc-deps".to_string());
            }
        }
        self.initial_services.push(service_config);
        self
    }

    pub fn with_malicious_workload(mut self, use_malicious: bool) -> Self {
        self.use_malicious_workload = use_malicious;
        self
    }

    pub fn with_extra_feature(mut self, feature: impl Into<String>) -> Self {
        self.extra_features.push(feature.into());
        self
    }

    pub fn with_genesis_modifier<F>(mut self, modifier: F) -> Self
    where
        F: FnOnce(&mut GenesisBuilder, &Vec<identity::Keypair>) + Send + 'static,
    {
        self.genesis_modifiers.push(Box::new(modifier));
        self
    }

    pub fn with_epoch_size(mut self, size: u64) -> Self {
        self.epoch_size = Some(size);
        self
    }

    pub fn with_keep_recent_heights(mut self, keep: u64) -> Self {
        self.keep_recent_heights = Some(keep);
        self
    }

    pub fn with_gc_interval(mut self, interval: u64) -> Self {
        self.gc_interval_secs = Some(interval);
        self
    }

    pub fn with_min_finality_depth(mut self, depth: u64) -> Self {
        self.min_finality_depth = Some(depth);
        self
    }

    pub fn with_service_policy(mut self, service_id: &str, policy: ServicePolicy) -> Self {
        self.service_policies_override
            .insert(service_id.to_string(), policy);
        self
    }

    pub fn with_workload_env(mut self, key: &str, value: &str) -> Self {
        self.workload_env.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_role(mut self, index: usize, role: ValidatorRole) -> Self {
        self.roles.insert(index, role);
        self
    }

    pub fn with_aft_safety_mode(mut self, mode: AftSafetyMode) -> Self {
        self.aft_safety_mode = mode;
        self
    }

    pub fn with_guardian_config_toml(mut self, guardian_config_toml: impl Into<String>) -> Self {
        self.guardian_config_toml = Some(guardian_config_toml.into());
        self
    }

    pub async fn build(mut self) -> Result<TestCluster> {
        let guardianized_mode = !matches!(self.aft_safety_mode, AftSafetyMode::ClassicBft);
        let mut validator_keys = self.keypairs.take().unwrap_or_else(|| {
            (0..self.num_validators)
                .map(|_| identity::Keypair::generate_ed25519())
                .collect()
        });

        if let Some(kp0) = self.validator0_key_override.take() {
            if !validator_keys.is_empty() {
                validator_keys[0] = kp0;
            } else if self.num_validators > 0 {
                validator_keys.push(kp0);
            }
        }

        validator_keys.sort_by(|a, b| {
            let pk_a = a.public().encode_protobuf();
            let pk_b = b.public().encode_protobuf();
            let id_a =
                account_id_from_key_material(SignatureSuite::ED25519, &pk_a).unwrap_or([0; 32]);
            let id_b =
                account_id_from_key_material(SignatureSuite::ED25519, &pk_b).unwrap_or([0; 32]);
            id_a.cmp(&id_b)
        });

        let ValidatorPortAllocation {
            bases: validator_base_ports,
            reservations: validator_port_reservations,
            lock_path: validator_port_lock_path,
        } = allocate_validator_port_bases(validator_keys.len())?;
        let mut validator_port_reservations = validator_port_reservations
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();

        let shared_guardian_harness = if guardianized_mode && self.guardian_config_toml.is_none() {
            let harness = build_auto_guardian_harness(
                &validator_keys,
                &validator_base_ports,
                self.aft_safety_mode,
            )
            .map_err(|error| {
                let _ = fs::remove_file(&validator_port_lock_path);
                error
            })?;
            self.guardian_config_toml = Some(harness.guardian_config_toml.clone());
            if !self
                .initial_services
                .iter()
                .any(|service| matches!(service, InitialServiceConfig::GuardianRegistry(_)))
            {
                self.initial_services
                    .push(InitialServiceConfig::GuardianRegistry(Default::default()));
            }
            let transparency_log_descriptors = harness.transparency_log_descriptors.clone();
            let committee_manifests = harness.committee_manifests.clone();
            let witness_manifests = harness.witness_manifests.clone();
            let witness_seed = harness.witness_seed.clone();
            let witness_set = harness.witness_set.clone();
            let asymptote_policy = harness.asymptote_policy.clone();
            self.genesis_modifiers.push(Box::new(move |builder, _keys| {
                builder.insert_typed(CURRENT_EPOCH_KEY, &1u64);
                for (key, value) in &transparency_log_descriptors {
                    builder.insert_raw(key, value);
                }
                for (key, value) in &committee_manifests {
                    builder.insert_raw(key, value);
                }
                for (key, value) in &witness_manifests {
                    builder.insert_raw(key, value);
                }
                if let Some((key, value)) = &witness_seed {
                    builder.insert_raw(key, value);
                }
                if let Some((key, value)) = &witness_set {
                    builder.insert_raw(key, value);
                }
                if let Some((key, value)) = &asymptote_policy {
                    builder.insert_raw(key, value);
                }
            }));
            Some(harness)
        } else {
            None
        };

        // [FIX] Insert default genesis configuration to register validators
        // and set block timing. This ensures nodes don't stall on startup.
        self.genesis_modifiers.insert(
            0,
            Box::new(
                |builder: &mut GenesisBuilder, keys: &Vec<identity::Keypair>| {
                    let mut validators = Vec::new();
                    for key in keys {
                        let account_id = builder.add_identity(key);
                        validators.push(ValidatorV1 {
                            account_id,
                            weight: 1,
                            consensus_key: ActiveKeyRecord {
                                suite: SignatureSuite::ED25519,
                                public_key_hash: account_id.0,
                                since_height: 0,
                            },
                        });
                    }

                    // Sort to ensure canonical order
                    validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

                    let vs = ValidatorSetsV1 {
                        current: ValidatorSetV1 {
                            effective_from_height: 1,
                            total_weight: validators.iter().map(|v| v.weight).sum(),
                            validators,
                        },
                        next: None,
                    };
                    builder.set_validators(&vs);

                    // Set default block timing (1s blocks for fast tests)
                    let timing_params = BlockTimingParams {
                        base_interval_secs: 1,
                        min_interval_secs: 1,
                        max_interval_secs: 5,
                        target_gas_per_block: 10_000_000,
                        ..Default::default()
                    };
                    let timing_runtime = BlockTimingRuntime {
                        effective_interval_secs: 1,
                        effective_interval_ms: 1_000,
                        ema_gas_used: 0,
                    };
                    builder.set_block_timing(&timing_params, &timing_runtime);
                },
            ),
        );

        let mut builder = GenesisBuilder::new();
        for modifier in self.genesis_modifiers.drain(..) {
            modifier(&mut builder, &validator_keys);
        }
        let genesis_content = serde_json::json!({
            "genesis_state": builder
        })
        .to_string();

        let mut service_policies = ioi_types::config::default_service_policies();
        for (k, v) in self.service_policies_override.clone() {
            service_policies.insert(k, v);
        }

        let mut validators: Vec<ValidatorGuard> = Vec::new();
        let mut bootnode_addrs: Vec<Multiaddr> = Vec::new();
        let benchmark_harness_mode = std::env::var_os("IOI_AFT_BENCH_SCENARIO").is_some()
            || std::env::var_os("IOI_AFT_BENCH_LANE").is_some()
            || std::env::var_os("IOI_AFT_BENCH_TRACE").is_some();
        let ready_height_lag_max = std::env::var("IOI_TEST_READY_HEIGHT_LAG_MAX")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_else(|| if benchmark_harness_mode { 16 } else { 1 });

        let full_mesh_bootnodes = std::env::var("IOI_TEST_FULL_MESH_BOOTNODES")
            .ok()
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false);

        if !full_mesh_bootnodes && !validator_keys.is_empty() {
            let boot_peer_id = validator_keys[0].public().to_peer_id();
            let boot_listen_addr: Multiaddr =
                format!("/ip4/127.0.0.1/tcp/{}", validator_base_ports[0])
                    .parse()
                    .expect("validator p2p multiaddr should parse");
            bootnode_addrs
                .push(boot_listen_addr.with(libp2p::multiaddr::Protocol::P2p(boot_peer_id.into())));
        }

        let full_mesh_bootnode_addrs = if full_mesh_bootnodes {
            Some(
                validator_keys
                    .iter()
                    .enumerate()
                    .map(|(index, key)| {
                        let peer_id = key.public().to_peer_id();
                        let listen_addr: Multiaddr =
                            format!("/ip4/127.0.0.1/tcp/{}", validator_base_ports[index])
                                .parse()
                                .expect("validator p2p multiaddr should parse");
                        listen_addr.with(libp2p::multiaddr::Protocol::P2p(peer_id.into()))
                    })
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };

        if validator_keys.len() == 1 {
            let key_clone = validator_keys[0].clone();
            let captured_genesis = genesis_content.clone();
            let captured_consensus = self.consensus_type.clone();
            let captured_state_tree = self.state_tree.clone();
            let captured_commitment = self.commitment_scheme.clone();
            let captured_ibc_gateway = self.ibc_gateway_addr.clone();
            let captured_agentic_path = self.agentic_model_path.clone();
            let captured_use_docker = self.use_docker;
            let captured_services = self.initial_services.clone();
            let captured_malicious = self.use_malicious_workload;
            let captured_extra_features = self.extra_features.clone();
            let captured_epoch_size = self.epoch_size;
            let captured_keep_recent = self.keep_recent_heights;
            let captured_gc_interval = self.gc_interval_secs;
            let captured_min_finality = self.min_finality_depth;
            let captured_policies = service_policies.clone();
            let captured_workload_env = self.workload_env.clone();
            let captured_safety_mode = self.aft_safety_mode;
            let captured_guardian_config = self.guardian_config_toml.clone();
            let base_port = validator_base_ports[0];
            let port_reservations = validator_port_reservations[0]
                .take()
                .expect("validator port reservations should exist");
            let role = self
                .roles
                .get(&0)
                .cloned()
                .unwrap_or(ValidatorRole::Consensus);

            let guard = TestValidator::launch(
                key_clone,
                captured_genesis,
                base_port,
                port_reservations,
                self.chain_id,
                None,
                &captured_consensus,
                &captured_state_tree,
                &captured_commitment,
                captured_ibc_gateway.as_deref(),
                captured_agentic_path.as_deref(),
                captured_use_docker,
                captured_services,
                captured_malicious,
                benchmark_harness_mode,
                &captured_extra_features,
                captured_epoch_size,
                captured_keep_recent,
                captured_gc_interval,
                captured_min_finality,
                captured_policies,
                captured_workload_env,
                role,
                captured_safety_mode,
                captured_guardian_config,
            )
            .await
            .map_err(|error| {
                let _ = fs::remove_file(&validator_port_lock_path);
                error
            })?;
            validators.push(guard);
        } else if validator_keys.len() > 1 && full_mesh_bootnodes {
            let launch_with_bootnodes = |index: usize| {
                full_mesh_bootnode_addrs
                    .as_ref()
                    .map(|all_addrs| {
                        all_addrs
                            .iter()
                            .enumerate()
                            .filter(|(peer_index, _)| *peer_index != index)
                            .map(|(_, addr)| addr.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };

            let mut launch_futures = FuturesUnordered::new();
            for (i, key) in validator_keys.iter().enumerate() {
                let key_clone = key.clone();
                let captured_genesis = genesis_content.clone();
                let captured_consensus = self.consensus_type.clone();
                let captured_state_tree = self.state_tree.clone();
                let captured_commitment = self.commitment_scheme.clone();
                let captured_ibc_gateway = self.ibc_gateway_addr.clone();
                let captured_agentic_path = self.agentic_model_path.clone();
                let captured_use_docker = self.use_docker;
                let captured_services = self.initial_services.clone();
                let captured_malicious = self.use_malicious_workload;
                let captured_extra_features = self.extra_features.clone();
                let captured_epoch_size = self.epoch_size;
                let captured_keep_recent = self.keep_recent_heights;
                let captured_gc_interval = self.gc_interval_secs;
                let captured_min_finality = self.min_finality_depth;
                let captured_policies = service_policies.clone();
                let captured_workload_env = self.workload_env.clone();
                let captured_safety_mode = self.aft_safety_mode;
                let captured_guardian_config = self.guardian_config_toml.clone();
                let captured_chain_id = self.chain_id;
                let base_port = validator_base_ports[i];
                let port_reservations = validator_port_reservations[i]
                    .take()
                    .expect("validator port reservations should exist");
                let node_bootnodes = launch_with_bootnodes(i);
                let role = self
                    .roles
                    .get(&i)
                    .cloned()
                    .unwrap_or(ValidatorRole::Consensus);

                let fut = async move {
                    TestValidator::launch(
                        key_clone,
                        captured_genesis,
                        base_port,
                        port_reservations,
                        captured_chain_id,
                        Some(&node_bootnodes),
                        &captured_consensus,
                        &captured_state_tree,
                        &captured_commitment,
                        captured_ibc_gateway.as_deref(),
                        captured_agentic_path.as_deref(),
                        captured_use_docker,
                        captured_services,
                        captured_malicious,
                        benchmark_harness_mode,
                        &captured_extra_features,
                        captured_epoch_size,
                        captured_keep_recent,
                        captured_gc_interval,
                        captured_min_finality,
                        captured_policies,
                        captured_workload_env,
                        role,
                        captured_safety_mode,
                        captured_guardian_config,
                    )
                    .await
                };
                launch_futures.push(fut);
            }

            while let Some(result) = launch_futures.next().await {
                match result {
                    Ok(guard) => {
                        bootnode_addrs.push(guard.validator().p2p_addr.clone());
                        validators.push(guard);
                    }
                    Err(error) => {
                        for guard in validators {
                            let _ = guard.shutdown().await;
                        }
                        let _ = fs::remove_file(&validator_port_lock_path);
                        return Err(error);
                    }
                }
            }
        } else if validator_keys.len() > 1 {
            let mut launch_futures = FuturesUnordered::new();
            for (i, key) in validator_keys.iter().enumerate() {
                let base_port = validator_base_ports[i];
                let captured_bootnodes = bootnode_addrs.clone();
                let captured_chain_id = self.chain_id;
                let captured_genesis = genesis_content.clone();
                let captured_consensus = self.consensus_type.clone();
                let captured_state_tree = self.state_tree.clone();
                let captured_commitment = self.commitment_scheme.clone();
                let captured_agentic_path = self.agentic_model_path.clone();
                let captured_ibc_gateway = self.ibc_gateway_addr.clone();
                let captured_use_docker = self.use_docker;
                let captured_services = self.initial_services.clone();
                let captured_malicious = self.use_malicious_workload;
                let captured_extra_features = self.extra_features.clone();
                let captured_epoch_size = self.epoch_size;
                let captured_keep_recent = self.keep_recent_heights;
                let captured_gc_interval = self.gc_interval_secs;
                let captured_min_finality = self.min_finality_depth;
                let captured_policies = service_policies.clone();
                let captured_workload_env = self.workload_env.clone();
                let captured_safety_mode = self.aft_safety_mode;
                let captured_guardian_config = self.guardian_config_toml.clone();
                let key_clone = key.clone();
                let port_reservations = validator_port_reservations[i]
                    .take()
                    .expect("validator port reservations should exist");

                let role = self
                    .roles
                    .get(&i)
                    .cloned()
                    .unwrap_or(ValidatorRole::Consensus);

                let fut = async move {
                    TestValidator::launch(
                        key_clone,
                        captured_genesis,
                        base_port,
                        port_reservations,
                        captured_chain_id,
                        if i == 0 {
                            None
                        } else {
                            Some(&captured_bootnodes)
                        },
                        &captured_consensus,
                        &captured_state_tree,
                        &captured_commitment,
                        captured_ibc_gateway.as_deref(),
                        captured_agentic_path.as_deref(),
                        captured_use_docker,
                        captured_services,
                        captured_malicious,
                        benchmark_harness_mode,
                        &captured_extra_features,
                        captured_epoch_size,
                        captured_keep_recent,
                        captured_gc_interval,
                        captured_min_finality,
                        captured_policies,
                        captured_workload_env,
                        role,
                        captured_safety_mode,
                        captured_guardian_config,
                    )
                    .await
                };
                launch_futures.push(fut);
            }

            while let Some(result) = launch_futures.next().await {
                match result {
                    Ok(guard) => validators.push(guard),
                    Err(e) => {
                        for guard in validators {
                            let _ = guard.shutdown().await;
                        }
                        let _ = fs::remove_file(&validator_port_lock_path);
                        return Err(e);
                    }
                }
            }
        }

        // Sort by AccountID (same as launch order) instead of PeerID to ensure index stability
        validators.sort_by(|a, b| {
            let pk_a = a.validator().keypair.public().encode_protobuf();
            let pk_b = b.validator().keypair.public().encode_protobuf();
            let id_a =
                account_id_from_key_material(SignatureSuite::ED25519, &pk_a).unwrap_or([0; 32]);
            let id_b =
                account_id_from_key_material(SignatureSuite::ED25519, &pk_b).unwrap_or([0; 32]);
            id_a.cmp(&id_b)
        });

        let skip_shared_tip_wait = std::env::var("IOI_TEST_SKIP_SHARED_TIP_WAIT")
            .ok()
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(false);

        if validators.len() > 1 {
            if skip_shared_tip_wait {
                println!("--- Skipping cluster shared-tip convergence wait by override ---");
            } else {
                println!("--- Waiting for cluster to converge on a shared tip ---");
                let allow_zero_height_ready = std::env::var("IOI_TEST_ALLOW_ZERO_HEIGHT_READY")
                    .ok()
                    .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
                    .unwrap_or(false);

                // [DEBUG] Parallel wait with status logging
                let timeout = Duration::from_secs(180); // Increased for 4-node
                let start = std::time::Instant::now();
                let mut ticker = tokio::time::interval(Duration::from_secs(2));
                let mut sync_success = false;

                loop {
                    ticker.tick().await;

                    if start.elapsed() > timeout {
                        break;
                    }

                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_secs())
                        .unwrap_or_default();
                    let mut all_reached = true;
                    let mut status_lines = Vec::new();
                    let mut observed_heights = Vec::new();
                    let mut observed_timestamps = Vec::new();
                    let mut observed_peer_counts = Vec::new();
                    let mut zero_height_indices = Vec::new();

                    for (i, v_guard) in validators.iter().enumerate() {
                        let rpc_addr = &v_guard.validator().rpc_addr;
                        let metrics_addr = &v_guard.validator().orchestration_telemetry_addr;

                        let peers = fetch_peer_count(metrics_addr).await;

                        // Use the existing rpc helper
                        match crate::testing::rpc::get_status(rpc_addr).await {
                            Ok(status) => {
                                let peer_count = peers.parse::<usize>().unwrap_or_default();
                                observed_heights.push(status.height);
                                observed_timestamps.push(status.latest_timestamp);
                                observed_peer_counts.push(peer_count);
                                status_lines.push(format!(
                                    "Node {}: Height={} Peers={} Ts={}",
                                    i, status.height, peers, status.latest_timestamp
                                ));
                                if status.height == 0 {
                                    zero_height_indices.push(i);
                                } else if status.height < 1 && !allow_zero_height_ready {
                                    all_reached = false;
                                }
                            }
                            Err(e) => {
                                status_lines
                                    .push(format!("Node {}: RPC Error {} (Peers={})", i, e, peers));
                                all_reached = false;
                            }
                        }
                    }

                    if all_reached
                        && !zero_height_indices.is_empty()
                        && observed_heights.iter().copied().any(|height| height > 0)
                    {
                        for index in zero_height_indices.iter().copied() {
                            let rpc_addr = &validators[index].validator().rpc_addr;
                            match crate::testing::rpc::tip_height_resilient(rpc_addr).await {
                                Ok(probed_height) if probed_height > 0 => {
                                    observed_heights[index] = probed_height;
                                    status_lines.push(format!(
                                    "Node {}: get_status.height=0 looked stale; resilient tip probe found height {}",
                                    index, probed_height
                                ));
                                }
                                Ok(_) => {
                                    status_lines.push(format!(
                                    "Node {}: get_status.height=0 and resilient tip probe also found no committed blocks yet",
                                    index
                                ));
                                }
                                Err(error) => {
                                    status_lines.push(format!(
                                    "Node {}: get_status.height=0 and resilient tip probe failed: {}",
                                    index, error
                                ));
                                }
                            }
                        }
                    }

                    if all_reached
                        && !allow_zero_height_ready
                        && observed_heights.iter().copied().any(|height| height < 1)
                    {
                        all_reached = false;
                    }

                    if all_reached {
                        if full_mesh_bootnodes && validators.len() > 1 {
                            let expected_peer_count = validators.len().saturating_sub(1);
                            let min_peers = observed_peer_counts.iter().copied().min().unwrap_or(0);
                            if min_peers < expected_peer_count {
                                all_reached = false;
                                status_lines.push(format!(
                                    "Mesh not converged yet: min_peers={} expected={}",
                                    min_peers, expected_peer_count
                                ));
                            }
                        }
                    }

                    if all_reached {
                        let min_height = observed_heights.iter().copied().min().unwrap_or(0);
                        let max_height = observed_heights.iter().copied().max().unwrap_or(0);
                        let height_lag = max_height.saturating_sub(min_height);
                        if height_lag > ready_height_lag_max {
                            all_reached = false;
                            status_lines.push(format!(
                            "Heights diverged beyond readiness lag: min={} max={} lag={} allowed={}",
                            min_height, max_height, height_lag, ready_height_lag_max
                        ));
                        } else if min_height == 0 && max_height > 0 {
                            all_reached = false;
                            status_lines.push(format!(
                                "Mixed zero/non-zero heights are not readiness-safe: min={} max={}",
                                min_height, max_height
                            ));
                        } else if max_height == 0
                            && (allow_zero_height_ready
                                || observed_timestamps
                                    .iter()
                                    .copied()
                                    .min()
                                    .map(|timestamp| timestamp > now_secs)
                                    .unwrap_or(false))
                        {
                            status_lines.push(
                            "Canonical shared floor at height 0 => future-genesis benchmark cluster is synchronized"
                                .to_string(),
                        );
                        } else {
                            let shared_height = min_height;
                            let mut shared_tip_hash: Option<Vec<u8>> = None;
                            for (i, v_guard) in validators.iter().enumerate() {
                                let rpc_addr = &v_guard.validator().rpc_addr;
                                match crate::testing::rpc::get_block_by_height_resilient(
                                    rpc_addr,
                                    shared_height,
                                )
                                .await
                                {
                                    Ok(Some(block)) => {
                                        let Ok(hash) = block.header.hash() else {
                                            all_reached = false;
                                            status_lines.push(format!(
                                                "Node {}: failed to hash block {}",
                                                i, shared_height
                                            ));
                                            continue;
                                        };
                                        match &shared_tip_hash {
                                            Some(expected) if expected != &hash => {
                                                all_reached = false;
                                                status_lines.push(format!(
                                                "Node {}: block hash mismatch at height {} | got={} expected={} producer=0x{} view={}",
                                                i,
                                                shared_height,
                                                hex::encode(&hash[..4]),
                                                hex::encode(&expected[..4]),
                                                hex::encode(&block.header.producer_account_id.0[..4]),
                                                block.header.view
                                            ));
                                            }
                                            None => {
                                                status_lines.push(format!(
                                                "Canonical shared floor at height {} => hash={} producer=0x{} view={} lag={}",
                                                shared_height,
                                                hex::encode(&hash[..4]),
                                                hex::encode(&block.header.producer_account_id.0[..4]),
                                                block.header.view,
                                                height_lag
                                            ));
                                                shared_tip_hash = Some(hash);
                                            }
                                            _ => {}
                                        }
                                    }
                                    Ok(None) => {
                                        all_reached = false;
                                        status_lines.push(format!(
                                            "Node {}: missing block {} during convergence check",
                                            i, shared_height
                                        ));
                                    }
                                    Err(error) => {
                                        all_reached = false;
                                        status_lines.push(format!(
                                        "Node {}: failed to fetch block {} during convergence check: {}",
                                        i, shared_height, error
                                    ));
                                    }
                                }
                            }
                        }
                    }

                    if all_reached {
                        sync_success = true;
                        break;
                    }

                    println!(
                        "[Sync Wait {:?}] Status:\n{}",
                        start.elapsed(),
                        status_lines.join("\n")
                    );
                }

                if !sync_success {
                    for guard in validators {
                        let _ = guard.shutdown().await;
                    }
                    let _ = fs::remove_file(&validator_port_lock_path);
                    return Err(anyhow::anyhow!("Timeout waiting for cluster sync"));
                }

                println!("--- All nodes synced. Cluster is ready. ---");
            }
        }

        Ok(TestCluster {
            validators,
            genesis_content,
            _shared_artifacts: shared_guardian_harness.map(|harness| harness.temp_dir),
            _port_block_lock_path: Some(validator_port_lock_path),
        })
    }
}
