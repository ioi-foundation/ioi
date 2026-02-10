// Path: crates/networking/src/libp2p/mod.rs

//! A libp2p-based implementation of the network traits.

// Declare submodules
pub mod behaviour;
pub mod mempool;
pub mod swarm;
pub mod sync;
pub mod transport;
pub mod types;

use crate::traits::NodeState;
use ioi_api::transaction::TransactionModel;
use ioi_tx::unified::UnifiedTransactionModel;
// [FIX] Removed unused Block and ChainTransaction imports
use ioi_types::app::{ConfidenceVote, ConsensusVote, EchoMessage, OracleAttestation, PanicMessage};
use ioi_types::codec;
use libp2p::{identity, Multiaddr, PeerId};
use std::{collections::HashSet, sync::Arc};
use tokio::{
    sync::{mpsc, watch, Mutex},
    task::JoinHandle,
    time::Duration,
};

// Re-export specific types
pub use self::behaviour::{SyncBehaviour, SyncBehaviourEvent};
pub use self::sync::{SyncCodec, SyncRequest, SyncResponse};
pub use self::types::{NetworkEvent, SwarmCommand, SwarmInternalEvent};

// Import ViewChangeVote for use in forwarder
use ioi_consensus::admft::ViewChangeVote;

/// The main networking struct.
pub struct Libp2pSync {
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    node_state: Arc<Mutex<NodeState>>,
    known_peers: Arc<Mutex<HashSet<PeerId>>>,
    local_peer_id: PeerId,
}

impl Libp2pSync {
    pub fn new(
        local_key: identity::Keypair,
        listen_addr: Multiaddr,
        dial_addrs: Option<&[Multiaddr]>,
    ) -> anyhow::Result<(
        Arc<Self>,
        mpsc::Sender<SwarmCommand>,
        mpsc::Receiver<NetworkEvent>,
    )> {
        let (shutdown_sender, _) = watch::channel(false);
        let (swarm_command_sender, swarm_command_receiver) = mpsc::channel(100);
        let (internal_event_sender, mut internal_event_receiver) = mpsc::channel(100);
        let (network_event_sender, network_event_receiver) = mpsc::channel(100);

        let local_peer_id = local_key.public().to_peer_id();
        let node_state = Arc::new(Mutex::new(NodeState::Initializing));
        let known_peers = Arc::new(Mutex::new(HashSet::new()));

        let swarm = self::transport::build_swarm(local_key.clone())?;

        let swarm_task = tokio::spawn(self::swarm::run_swarm_loop(
            swarm,
            swarm_command_receiver,
            internal_event_sender,
            shutdown_sender.subscribe(),
        ));

        let swarm_command_sender_clone = swarm_command_sender.clone();

        // Event Forwarder: Translates SwarmInternalEvent -> NetworkEvent and handles internal logic
        let event_forwarder_task = tokio::spawn(async move {
            while let Some(event) = internal_event_receiver.recv().await {
                // Handle complex translations and acks
                if let SwarmInternalEvent::AgenticPrompt {
                    from,
                    prompt,
                    channel,
                } = event
                {
                    let translated = NetworkEvent::AgenticPrompt { from, prompt };
                    if network_event_sender.send(translated).await.is_err() {
                        break;
                    }
                    let _ = swarm_command_sender_clone
                        .send(SwarmCommand::SendAgenticAck(channel))
                        .await;
                    continue;
                }

                if let SwarmInternalEvent::AgenticConsensusVote {
                    from,
                    prompt_hash,
                    vote_hash,
                } = event
                {
                    let translated = NetworkEvent::AgenticConsensusVote {
                        from,
                        prompt_hash,
                        vote_hash,
                    };
                    if network_event_sender.send(translated).await.is_err() {
                        break;
                    }
                    continue;
                }

                if let SwarmInternalEvent::GossipOracleAttestation(data, from) = event {
                    if let Ok(attestation) = codec::from_bytes_canonical::<OracleAttestation>(&data)
                    {
                        let _ = network_event_sender
                            .send(NetworkEvent::OracleAttestationReceived { from, attestation })
                            .await;
                    }
                    continue;
                }

                // Standard Translations
                let translated_event = match event {
                    SwarmInternalEvent::ConnectionEstablished(p) => {
                        Some(NetworkEvent::ConnectionEstablished(p))
                    }
                    SwarmInternalEvent::ConnectionClosed(p) => {
                        Some(NetworkEvent::ConnectionClosed(p))
                    }
                    SwarmInternalEvent::StatusRequest(p, c) => {
                        Some(NetworkEvent::StatusRequest(p, c))
                    }
                    SwarmInternalEvent::BlocksRequest {
                        peer,
                        since,
                        max_blocks,
                        max_bytes,
                        channel,
                    } => Some(NetworkEvent::BlocksRequest {
                        peer,
                        since,
                        max_blocks,
                        max_bytes,
                        channel,
                    }),
                    SwarmInternalEvent::StatusResponse {
                        peer,
                        height,
                        head_hash,
                        chain_id,
                        genesis_root,
                    } => Some(NetworkEvent::StatusResponse {
                        peer,
                        height,
                        head_hash,
                        chain_id,
                        genesis_root,
                    }),
                    SwarmInternalEvent::BlocksResponse(p, b) => {
                        Some(NetworkEvent::BlocksResponse(p, b))
                    }

                    SwarmInternalEvent::GossipBlock(data, _source, mirror_id) => {
                        codec::from_bytes_canonical(&data)
                            .ok()
                            .map(|block| NetworkEvent::GossipBlock { block, mirror_id })
                    }
                    SwarmInternalEvent::GossipTransaction(data, _source) => {
                        let dummy = UnifiedTransactionModel::new(
                            ioi_state::primitives::hash::HashCommitmentScheme::new(),
                        );
                        dummy
                            .deserialize_transaction(&data)
                            .ok()
                            .map(|tx| NetworkEvent::GossipTransaction(Box::new(tx)))
                    }
                    SwarmInternalEvent::ConsensusVoteReceived(data, source) => {
                        codec::from_bytes_canonical::<ConsensusVote>(&data)
                            .ok()
                            .map(|vote| NetworkEvent::ConsensusVoteReceived { vote, from: source })
                    }
                    SwarmInternalEvent::ViewChangeVoteReceived(data, source) => {
                        codec::from_bytes_canonical::<ViewChangeVote>(&data)
                            .ok()
                            .map(|vote| NetworkEvent::ViewChangeVoteReceived { vote, from: source })
                    }
                    SwarmInternalEvent::EchoReceived(data, source) => {
                        codec::from_bytes_canonical::<EchoMessage>(&data)
                            .ok()
                            .map(|echo| NetworkEvent::EchoReceived { echo, from: source })
                    }
                    SwarmInternalEvent::PanicReceived(data, source) => {
                        codec::from_bytes_canonical::<PanicMessage>(&data)
                            .ok()
                            .map(|panic| NetworkEvent::PanicReceived {
                                panic,
                                from: source,
                            })
                    }
                    SwarmInternalEvent::SampleRequest(peer, height, channel) => {
                        Some(NetworkEvent::SampleRequestReceived {
                            peer,
                            height,
                            channel,
                        })
                    }
                    SwarmInternalEvent::SampleResponse(peer, block_hash, confidence) => {
                        Some(NetworkEvent::SampleResponseReceived {
                            peer,
                            block_hash,
                            confidence,
                        })
                    }
                    SwarmInternalEvent::ConfidenceVoteReceived(data, _source) => {
                        codec::from_bytes_canonical::<ConfidenceVote>(&data)
                            .ok()
                            .map(NetworkEvent::ConfidenceVoteReceived)
                    }
                    SwarmInternalEvent::OutboundFailure(peer) => {
                        Some(NetworkEvent::OutboundFailure(peer))
                    }
                    SwarmInternalEvent::RequestMissingTxs {
                        peer,
                        indices,
                        channel,
                    } => Some(NetworkEvent::RequestMissingTxs {
                        peer,
                        indices,
                        channel,
                    }),

                    // Already handled above or unreachable
                    SwarmInternalEvent::AgenticPrompt { .. } => None,
                    SwarmInternalEvent::AgenticConsensusVote { .. } => None,
                    SwarmInternalEvent::GossipOracleAttestation(..) => None,
                };

                if let Some(ev) = translated_event {
                    if network_event_sender.send(ev).await.is_err() {
                        break;
                    }
                }
            }
        });

        let initial_cmds_task = tokio::spawn({
            let cmd_sender = swarm_command_sender.clone();
            let listen_addr_clone = listen_addr.clone();
            let dial_addrs_owned = dial_addrs.map(|s| s.to_vec());
            async move {
                let _ = cmd_sender
                    .send(SwarmCommand::Listen(listen_addr_clone))
                    .await;
                if let Some(addrs) = dial_addrs_owned {
                    for _ in 0..100 {
                        for addr in &addrs {
                            let _ = cmd_sender.send(SwarmCommand::Dial(addr.clone())).await;
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        });

        let sync_service = Arc::new(Self {
            swarm_command_sender: swarm_command_sender.clone(),
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(vec![
                swarm_task,
                event_forwarder_task,
                initial_cmds_task,
            ])),
            node_state,
            known_peers,
            local_peer_id,
        });

        Ok((sync_service, swarm_command_sender, network_event_receiver))
    }
}
