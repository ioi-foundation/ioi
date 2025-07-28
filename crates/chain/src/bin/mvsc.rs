//! # Minimum Viable Single-Node Chain (MVSC)
//!
//! Now with persistence and P2P networking!
//!
//! This binary runs a blockchain node that can:
//! 1. Persist its state to `state.json` and resume after a restart.
//! 2. Discover other nodes on the local network using mDNS.
//! 3. Gossip new blocks to peers using libp2p.
//! 4. Process blocks received from peers.

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_chain::app::SovereignAppChain;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_state_trees::file::FileStateTree; // Use our new FileStateTree
use depin_sdk_transaction_models::utxo::{UTXOModel, UTXOTransaction};
use depin_sdk_validator::standard::StandardValidator;

use futures::stream::StreamExt;
use libp2p::{gossipsub, mdns, swarm::SwarmEvent};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

// --- LIBP2P NETWORKING SETUP ---

// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

const BLOCK_TOPIC: &str = "blocks";

// --- COMMAND LINE ARGUMENTS ---

#[derive(Parser, Debug)]
#[clap(name = "mvsc", about = "A minimum viable sovereign chain node.")]
struct Opts {
    /// Listening port for the p2p network.
    #[clap(long, default_value = "0")]
    listen_port: u16,

    /// Path to the state file.
    #[clap(long, default_value = "state.json")]
    state_file: String,

    /// Path to the directory containing validator configuration files (guardian.toml, orchestration.toml, workload.toml).
    #[clap(long, default_value = "./config")]
    config_dir: String,
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
    let validator_model =
        StandardValidator::new(&opts.config_dir).map_err(|e| anyhow!(e))?;

    let chain = Arc::new(Mutex::new(SovereignAppChain::new(
        commitment_scheme,
        state_tree,
        transaction_model,
        validator_model,
        "mvsc-chain-1",
        vec![],
    )));

    // Start the validator model, which in turn starts its containers.
    chain.lock().await.start().map_err(|e| anyhow!(e))?;

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
                let mut s = std::hash::DefaultHasher::new();
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

                        type AppBlock = depin_sdk_chain::app::Block<UTXOTransaction>;
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
        }
    }
}