// Path: crates/forge/src/testing/cluster.rs

use super::assert::wait_for_height;
use super::genesis::GenesisBuilder; // Use the new Builder
use super::validator::{TestValidator, ValidatorGuard};
use anyhow::Result;
use dcrypt::sign::eddsa::Ed25519SecretKey;
use futures_util::{stream::FuturesUnordered, StreamExt};
use ioi_types::config::{InitialServiceConfig, ServicePolicy}; // [FIX] Import ServicePolicy
use libp2p::{
    identity::{self, ed25519, Keypair},
    Multiaddr,
};
use std::collections::BTreeMap; // [FIX] Import BTreeMap
use std::time::Duration;

/// A type alias for a closure that modifies the genesis state.
type GenesisModifier = Box<dyn FnOnce(&mut GenesisBuilder, &Vec<identity::Keypair>) + Send>;

pub struct TestCluster {
    pub validators: Vec<ValidatorGuard>,
    pub genesis_content: String,
}

impl TestCluster {
    pub fn builder() -> TestClusterBuilder {
        TestClusterBuilder::new()
    }

    pub async fn shutdown(self) -> Result<()> {
        for guard in self.validators {
            guard.shutdown().await?;
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
    // [FIX] Add override field
    service_policies_override: BTreeMap<String, ServicePolicy>,
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self {
            num_validators: 1,
            keypairs: None,
            chain_id: ioi_types::app::ChainId(1),
            genesis_modifiers: Vec::new(),
            consensus_type: "ProofOfAuthority".to_string(),
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

    // [FIX] Add method to override service policy
    pub fn with_service_policy(mut self, service_id: &str, policy: ServicePolicy) -> Self {
        self.service_policies_override.insert(service_id.to_string(), policy);
        self
    }

    pub async fn build(mut self) -> Result<TestCluster> {
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
            let id_a = ioi_types::app::account_id_from_key_material(
                ioi_types::app::SignatureSuite::Ed25519,
                &pk_a,
            )
            .unwrap_or([0; 32]);
            let id_b = ioi_types::app::account_id_from_key_material(
                ioi_types::app::SignatureSuite::Ed25519,
                &pk_b,
            )
            .unwrap_or([0; 32]);
            id_a.cmp(&id_b)
        });

        let mut builder = GenesisBuilder::new();
        for modifier in self.genesis_modifiers.drain(..) {
            modifier(&mut builder, &validator_keys);
        }
        let genesis_content = serde_json::json!({
            "genesis_state": builder
        })
        .to_string();

        // [FIX] Merge default policies with overrides
        let mut service_policies = ioi_types::config::default_service_policies();
        for (k, v) in self.service_policies_override.clone() {
            service_policies.insert(k, v);
        }

        let mut validators: Vec<ValidatorGuard> = Vec::new();
        let mut bootnode_addrs: Vec<Multiaddr> = Vec::new();

        if let Some(boot_key) = validator_keys.first() {
            let bootnode_guard = TestValidator::launch(
                boot_key.clone(),
                genesis_content.clone(),
                5000,
                self.chain_id,
                None,
                &self.consensus_type,
                &self.state_tree,
                &self.commitment_scheme,
                self.ibc_gateway_addr.as_deref(),
                self.agentic_model_path.as_deref(),
                self.use_docker,
                self.initial_services.clone(),
                self.use_malicious_workload,
                false,
                &self.extra_features,
                self.epoch_size,
                self.keep_recent_heights,
                self.gc_interval_secs,
                self.min_finality_depth,
                // [FIX] Pass the merged policies
                service_policies.clone(),
            )
            .await?;

            bootnode_addrs.push(bootnode_guard.validator().p2p_addr.clone());
            validators.push(bootnode_guard);
        }

        if validator_keys.len() > 1 {
            let mut launch_futures = FuturesUnordered::new();
            for (i, key) in validator_keys.iter().enumerate().skip(1) {
                let base_port = 5000 + (i * 100) as u16;
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
                let key_clone = key.clone();

                let fut = async move {
                    TestValidator::launch(
                        key_clone,
                        captured_genesis,
                        base_port,
                        captured_chain_id,
                        Some(&captured_bootnodes),
                        &captured_consensus,
                        &captured_state_tree,
                        &captured_commitment,
                        captured_ibc_gateway.as_deref(),
                        captured_agentic_path.as_deref(),
                        captured_use_docker,
                        captured_services,
                        captured_malicious,
                        false,
                        &captured_extra_features,
                        captured_epoch_size,
                        captured_keep_recent,
                        captured_gc_interval,
                        captured_min_finality,
                        captured_policies,
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
                        return Err(e);
                    }
                }
            }
        }
        validators.sort_by(|a, b| a.validator().peer_id.cmp(&b.validator().peer_id));

        if validators.len() > 1 {
            println!("--- Waiting for cluster to sync to height 2 ---");
            for v_guard in &validators {
                if let Err(e) =
                    wait_for_height(&v_guard.validator().rpc_addr, 1, Duration::from_secs(60)).await
                {
                    for guard in validators {
                        let _ = guard.shutdown().await;
                    }
                    return Err(e);
                }
            }
            for v_guard in &validators {
                if let Err(e) =
                    wait_for_height(&v_guard.validator().rpc_addr, 2, Duration::from_secs(60)).await
                {
                    for guard in validators {
                        let _ = guard.shutdown().await;
                    }
                    return Err(e);
                }
            }
            println!("--- All nodes synced. Cluster is ready. ---");
        }

        Ok(TestCluster {
            validators,
            genesis_content,
        })
    }
}