// Path: crates/forge/src/testing/cluster.rs

use super::assert::wait_for_height;
use super::validator::TestValidator;
use anyhow::Result;
use futures_util::{stream::FuturesUnordered, StreamExt};
use ioi_types::config::InitialServiceConfig;
use libp2p::{identity, Multiaddr};
use serde_json::Value;
use std::time::Duration;

/// A type alias for a closure that modifies the genesis state.
type GenesisModifier = Box<dyn FnOnce(&mut Value, &Vec<identity::Keypair>) + Send>;

pub struct TestCluster {
    pub validators: Vec<TestValidator>,
    pub genesis_content: String,
}

impl TestCluster {
    pub fn builder() -> TestClusterBuilder {
        TestClusterBuilder::new()
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
    // [+] MODIFIED: a generic list for extra features
    extra_features: Vec<String>,
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
            // [+] MODIFIED: Initialize the new field
            extra_features: Vec::new(),
        }
    }
}

impl TestClusterBuilder {
    pub fn new() -> Self {
        Self::default()
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
        self.chain_id = (rand::thread_rng().gen::<u32>() | 1).into(); // Avoid 0
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
        // [+] MODIFIED: Automatically detect required features.
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

    pub fn with_genesis_modifier<F>(mut self, modifier: F) -> Self
    where
        F: FnOnce(&mut Value, &Vec<identity::Keypair>) + Send + 'static,
    {
        self.genesis_modifiers.push(Box::new(modifier));
        self
    }

    pub async fn build(mut self) -> Result<TestCluster> {
        let validator_keys = self.keypairs.take().unwrap_or_else(|| {
            (0..self.num_validators)
                .map(|_| identity::Keypair::generate_ed25519())
                .collect()
        });

        let mut genesis = serde_json::json!({ "genesis_state": {} });
        for modifier in self.genesis_modifiers.drain(..) {
            modifier(&mut genesis, &validator_keys);
        }
        let genesis_content = genesis.to_string();
        let mut validators = Vec::new();

        let mut bootnode_addrs: Vec<Multiaddr> = Vec::new();

        if let Some(boot_key) = validator_keys.first() {
            let bootnode = TestValidator::launch(
                boot_key.clone(),
                genesis_content.clone(),
                5000,
                self.chain_id,
                None, // No bootnode for the bootnode itself
                &self.consensus_type,
                &self.state_tree,
                &self.commitment_scheme,
                self.ibc_gateway_addr.as_deref(),
                self.agentic_model_path.as_deref(),
                self.use_docker,
                self.initial_services.clone(),
                self.use_malicious_workload,
                false, // Full readiness check for the bootnode
                &self.extra_features,
            )
            .await?;

            bootnode_addrs.push(bootnode.p2p_addr.clone());
            validators.push(bootnode);
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
                        false, // Full readiness check for subsequent nodes
                        &captured_extra_features,
                    )
                    .await
                };
                launch_futures.push(fut);
            }

            while let Some(result) = launch_futures.next().await {
                validators.push(result?);
            }
        }
        validators.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

        // Wait for all nodes in the cluster to reach a common height.
        if validators.len() > 1 {
            println!("--- Waiting for cluster to sync to height 2 ---");
            // Wait for each node to see at least height 1, then height 2 overall.
            // This is more robust than just waiting for height 2 on all, as it ensures
            // the genesis block was processed by all before expecting further progress.
            for v in &validators {
                wait_for_height(&v.rpc_addr, 1, Duration::from_secs(30)).await?;
            }
            for v in &validators {
                wait_for_height(&v.rpc_addr, 2, Duration::from_secs(30)).await?;
            }
            println!("--- All nodes synced. Cluster is ready. ---");
        }

        Ok(TestCluster {
            validators,
            genesis_content,
        })
    }
}