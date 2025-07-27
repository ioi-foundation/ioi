//! # Minimum Viable Single-Node Chain (MVSC)
//!
//! Now with persistence and P2P networking!
//!
//! This binary runs a blockchain node that can:
//! 1. Persist its state to `state.json` and resume after a restart.
//! 2. Discover other nodes on the local network using mDNS.
//! 3. Gossip new blocks to peers using libp2p.
//! 4. Process blocks received from peers.

use clap::Parser;
use depin_sdk_chain::app::{Block, SovereignAppChain};
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_core::crypto::{SerializableKey, SigningKeyPair, SigningKey};
use depin_sdk_core::validator::{ValidatorModel, ValidatorType};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use depin_sdk_state_trees::file::FileStateTree; // Use our new FileStateTree
use depin_sdk_transaction_models::utxo::{UTXOInput, UTXOOutput, UTXOTransaction, UTXOModel, UTXOOperations};
use std::fs;

use futures::stream::StreamExt;
use libp2p::{gossipsub, mdns, swarm::SwarmEvent};
use std::hash::{Hash, Hasher};
use std::sync::{atomic::{AtomicU64, Ordering}, Arc};
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Notify};


// --- LIBP2P NETWORKING SETUP ---

// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

const BLOCK_TOPIC: &str = "blocks";
const KEYPAIR_SEED_FILE: &str = "keypair.seed";

// --- COMMAND LINE ARGUMENTS ---

#[derive(Parser, Debug)]
#[clap(name = "mvsc", about = "A minimum viable sovereign chain node.")]
struct Opts {
    /// Listening port for the p2p network.
    #[clap(long, default_value = "0")]
    listen_port: u16,

    /// Flag to indicate if this node should produce blocks.
    #[clap(long)]
    is_producer: bool,

    /// Path to the state file.
    #[clap(long, default_value = "state.json")]
    state_file: String,

    /// Path to the keypair seed file.
    #[clap(long, default_value = "keypair.seed")]
    keypair_file: String,
}


// --- MOCK VALIDATOR MODEL ---
// A simple validator model implementation for the in-memory chain.
struct MockValidatorModel {
    running: std::cell::RefCell<bool>,
}

impl MockValidatorModel {
    fn new() -> Self { Self { running: std::cell::RefCell::new(false) } }
}

impl ValidatorModel for MockValidatorModel {
    fn start(&self) -> Result<(), String> { *self.running.borrow_mut() = true; Ok(()) }
    fn stop(&self) -> Result<(), String> { *self.running.borrow_mut() = false; Ok(()) }
    fn is_running(&self) -> bool { *self.running.borrow() }
    fn validator_type(&self) -> ValidatorType { ValidatorType::Standard }
}

// --- TRANSACTION CREATION HELPERS ---
fn create_dummy_transaction(
    keypair: &Ed25519KeyPair,
    nonce: u64,
    prev_txid: Vec<u8>,
) -> UTXOTransaction {
    let mut tx = UTXOTransaction {
        txid: Vec::new(),
        inputs: vec![UTXOInput {
            prev_txid,
            prev_index: 0,
            signature: Vec::new(),
        }],
        outputs: vec![UTXOOutput {
            value: 100,
            lock_script: keypair.public_key().to_bytes(),
        }],
    };
    let mut digest_data = Vec::new();
    digest_data.extend_from_slice(&tx.inputs[0].prev_txid);
    
    let digest = sha256(&digest_data);
    let signature = keypair.sign(&digest);
    tx.inputs[0].signature = signature.to_bytes();
    let mut txid_data = Vec::new();
    txid_data.extend_from_slice(&digest);
    txid_data.extend_from_slice(&tx.inputs[0].signature);
    tx.txid = sha256(&txid_data);
    tx
}

fn create_genesis_transaction(keypair: &Ed25519KeyPair) -> UTXOTransaction {
    let mut tx = UTXOTransaction {
        txid: Vec::new(),
        inputs: vec![],
        outputs: vec![UTXOOutput {
            value: 1_000_000,
            lock_script: keypair.public_key().to_bytes(),
        }],
    };
    let mut digest_data = Vec::new();
    digest_data.extend_from_slice(b"GENESIS");
    digest_data.extend_from_slice(&tx.outputs[0].value.to_le_bytes());
    digest_data.extend_from_slice(&tx.outputs[0].lock_script);
    tx.txid = sha256(&digest_data);
    tx
}

/// Loads a keypair from a seed file, or creates a new one if it doesn't exist.
fn load_or_create_keypair(path: &str) -> Ed25519KeyPair {
    match fs::read(path) {
        Ok(seed_bytes) => {
            log::info!("Loading persistent keypair from {}", path);
            let private_key = Ed25519PrivateKey::from_bytes(&seed_bytes)
                .expect("Failed to create private key from seed file");
            Ed25519KeyPair::from_private_key(&private_key)
        }
        Err(_) => {
            log::info!("No keypair found at {}, creating a new one.", path);
            let keypair = Ed25519KeyPair::generate();
            fs::write(path, keypair.private_key().to_bytes())
                .expect("Failed to write new keypair seed to file");
            keypair
        }
    }
}


// --- MAIN APPLICATION ---
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let opts = Opts::parse();

    // --- CHAIN SETUP ---
    log::info!("Starting Minimum Viable Sovereign Chain (MVSC)...");
    let commitment_scheme = HashCommitmentScheme::new();
    let state_tree = FileStateTree::new(&opts.state_file, commitment_scheme.clone());
    let transaction_model = UTXOModel::new(commitment_scheme.clone());
    let validator_model = MockValidatorModel::new();

    let chain = Arc::new(Mutex::new(SovereignAppChain::new(
        commitment_scheme,
        state_tree,
        transaction_model,
        validator_model,
        "mvsc-chain-1",
        vec![],
    )));

    // --- P2P NETWORK SETUP ---
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = std::collections::hash_map::DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .message_id_fn(message_id_fn)
                // For a small test network, we don't need to wait for a mesh to form to publish.
                .mesh_outbound_min(1)
                .build()?;
            Ok(MyBehaviour {
                gossipsub: gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?,
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    
    let topic = gossipsub::IdentTopic::new(BLOCK_TOPIC);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", opts.listen_port);
    swarm.listen_on(listen_addr.parse()?)?;
    log::info!("Local Peer ID: {}", swarm.local_peer_id());

    // Channel for the block producer to send new blocks to the main event loop.
    let (block_tx, mut block_rx) = mpsc::channel::<Vec<u8>>(32);

    // Notifier to signal the producer task when it's okay to start.
    let producer_start_signal = Arc::new(Notify::new());

    // --- BLOCK PRODUCTION (if enabled) ---
    if opts.is_producer {
        let chain_clone = Arc::clone(&chain);
        let start_signal_clone = Arc::clone(&producer_start_signal);
        let keypair_file = opts.keypair_file.clone();
        tokio::spawn(async move {
            let keypair = load_or_create_keypair(&keypair_file);
            let nonce = AtomicU64::new(0);
            let mut last_txid: Vec<u8>;

            // Create and process genesis block if chain is new
            {
                let mut chain_lock = chain_clone.lock().await;
                if chain_lock.status().height == 0 {
                    log::info!("Block producer is waiting for the first peer to connect...");
                    start_signal_clone.notified().await;
                    
                    // Give gossipsub a moment to establish the connection fully.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    log::info!("Peer connected! Creating and gossiping genesis block.");

                    log::info!("Chain is at genesis height, creating genesis block...");
                    let genesis_tx = create_genesis_transaction(&keypair);
                    last_txid = genesis_tx.txid.clone();
                    let genesis_block = chain_lock.create_block(vec![genesis_tx]);
                    chain_lock.process_block(genesis_block.clone()).expect("Failed to process genesis block");
                    
                    let block_bytes = serde_json::to_vec(&genesis_block).unwrap();
                    if let Err(e) = block_tx.send(block_bytes).await {
                         log::error!("Failed to send genesis block to main loop: {:?}", e);
                    }
                } else {
                    log::info!("Chain is at height {}, resuming block production.", chain_lock.status().height);
                    // Find the last UTXO owned by this keypair to continue the transaction chain.
                    // This is a naive scan; a real wallet would use an index.
                    let tm = chain_lock.transaction_model();
                    let pk_bytes = keypair.public_key().to_bytes();
                    
                    // This is a placeholder for finding the last txid.
                    // For this demo, we'll restart with a new "coinbase" tx in the next block.
                    // A proper implementation would require iterating through the state.
                    let coinbase_tx = create_genesis_transaction(&keypair);
                    last_txid = coinbase_tx.txid.clone();
                    let block = chain_lock.create_block(vec![coinbase_tx]);
                    chain_lock.process_block(block).expect("Failed to create resumption block");
                }
            }


            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let current_nonce = nonce.fetch_add(1, Ordering::SeqCst);
                let dummy_tx = create_dummy_transaction(&keypair, current_nonce, last_txid.clone());
                last_txid = dummy_tx.txid.clone();

                let mut chain_lock = chain_clone.lock().await;
                let block = chain_lock.create_block(vec![dummy_tx]);
                
                log::info!("Producing Block #{}", block.header.height);

                match chain_lock.process_block(block.clone()) {
                    Ok(_) => {
                        let status = chain_lock.status();
                        let state_commitment = chain_lock.get_state_commitment();
                        let state_root: &[u8] = state_commitment.as_ref();
                        log::info!(
                            "Locally processed Block #{}. New State Root: 0x{}",
                            status.height,
                            hex::encode(state_root)
                        );

                        let block_bytes = serde_json::to_vec(&block).unwrap();
                        if let Err(e) = block_tx.send(block_bytes).await {
                            log::error!("Failed to send block to main loop: {:?}", e);
                        }
                    }
                    Err(e) => {
                        log::error!("Error processing locally produced block: {}", e);
                    }
                }
            }
        });
    }

    // --- MAIN EVENT LOOP ---
    loop {
        tokio::select! {
            // Handle events from the p2p network
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, _multiaddr) in list {
                            log::info!("mDNS discovered a new peer: {}", peer_id);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);

                            producer_start_signal.notify_one();
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            log::info!("mDNS discover peer has expired: {}", peer_id);
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: peer_id,
                        message_id: id,
                        message,
                    })) => {
                        log::info!(
                            "Got new gossip message with id: {} from peer: {}",
                            id,
                            peer_id
                        );
                        
                        type AppBlock = Block<UTXOTransaction>;
                        match serde_json::from_slice::<AppBlock>(&message.data) {
                            Ok(block) => {
                                let mut chain_lock = chain.lock().await;
                                log::info!("Received Block #{} from network.", block.header.height);

                                if block.header.height <= chain_lock.status().height {
                                    log::info!("Ignoring old or duplicate block (height {}). Current height is {}.", block.header.height, chain_lock.status().height);
                                    continue;
                                }

                                match chain_lock.process_block(block) {
                                    Ok(_) => {
                                        let status = chain_lock.status();
                                        let state_commitment = chain_lock.get_state_commitment();
                                        let state_root: &[u8] = state_commitment.as_ref();
                                        log::info!(
                                            "Processed network Block #{}. New State Root: 0x{}",
                                            status.height,
                                            hex::encode(state_root)
                                        );
                                    }
                                    Err(e) => {
                                        log::error!("Error processing block from network: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to deserialize block: {:?}", e);
                            }
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        log::info!("Local node is listening on {}", address);
                    }
                    _ => {}
                }
            },
            // Handle blocks produced locally that need to be gossiped
            Some(block_to_gossip) = block_rx.recv() => {
                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), block_to_gossip) {
                    log::error!("Failed to publish block: {:?}", e);
                }
            }
        }
    }
}