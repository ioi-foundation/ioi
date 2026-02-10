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

pub fn build_swarm(local_key: identity::Keypair) -> Result<Swarm<SyncBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(|key| {
            let noise_config = noise::Config::new(key)?;

            // Enable TCP_NODELAY
            let tcp_config = tcp::Config::default().nodelay(true);

            let transport = tcp::tokio::Transport::new(tcp_config)
                .upgrade(libp2p::core::upgrade::Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux::Config::default())
                .timeout(Duration::from_secs(20))
                .boxed();
            Ok(transport)
        })?
        .with_behaviour(|key| {
            // Optimize Gossipsub for small test clusters (3 nodes)
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(1000))
                .validation_mode(gossipsub::ValidationMode::Strict)
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
                request_response::Config::default().with_request_timeout(Duration::from_secs(30));

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
