// Path: crates/networking/src/libp2p/transport.rs

use crate::libp2p::behaviour::SyncBehaviour;
use anyhow::Result;
use libp2p::{
    gossipsub,
    identity,
    noise,
    ping, // [NEW] Import
    request_response,
    tcp,
    yamux,
    Swarm,
    SwarmBuilder,
    Transport,
};
use std::iter;
use std::time::Duration;

fn aft_gossip_max_transmit_bytes() -> usize {
    std::env::var("IOI_AFT_GOSSIP_MAX_TRANSMIT_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 1024 * 1024)
        .unwrap_or(16 * 1024 * 1024)
}

fn aft_request_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("IOI_AFT_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value >= 10)
            .unwrap_or(60),
    )
}

fn yamux_max_num_streams() -> usize {
    std::env::var("IOI_YAMUX_MAX_STREAMS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 512)
        .unwrap_or(4_096)
}

pub fn build_swarm(local_key: identity::Keypair) -> Result<Swarm<SyncBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(|key| {
            let noise_config = noise::Config::new(key)?;

            // Enable TCP_NODELAY
            let tcp_config = tcp::Config::default().nodelay(true);
            let mut yamux_config = yamux::Config::default();
            yamux_config.set_max_num_streams(yamux_max_num_streams());

            let transport = tcp::tokio::Transport::new(tcp_config)
                .upgrade(libp2p::core::upgrade::Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux_config)
                .timeout(Duration::from_secs(20))
                .boxed();
            Ok(transport)
        })?
        .with_behaviour(|key| {
            // Optimize Gossipsub for small test clusters (3 nodes)
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(1000))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(aft_gossip_max_transmit_bytes())
                // Lower mesh limits to allow full mesh in small cluster
                .mesh_n_low(1)
                .mesh_n(2)
                .mesh_n_high(3)
                // Lower outbound limit to match mesh_n_low
                .mesh_outbound_min(1)
                .build()
                .map_err(|e| anyhow::anyhow!("Gossipsub config error: {}", e))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let cfg =
                request_response::Config::default().with_request_timeout(aft_request_timeout());

            let request_response = request_response::Behaviour::new(
                iter::once(("/ioi/sync/2", request_response::ProtocolSupport::Full)),
                cfg,
            );

            // [NEW] Configure Ping
            let ping =
                ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(1)));

            Ok(SyncBehaviour {
                gossipsub,
                request_response,
                ping,
            })
        })?
        // .with_idle_connection_timeout(Duration::from_secs(60)) // Removed due to version compat
        .build();
    Ok(swarm)
}
