// Path: crates/networking/src/libp2p/behaviour.rs

use crate::libp2p::sync::{SyncCodec, SyncRequest, SyncResponse};
use libp2p::{
    gossipsub,
    ping, // [NEW] Import ping
    request_response,
    swarm::NetworkBehaviour,
};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "SyncBehaviourEvent")]
pub struct SyncBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub request_response: request_response::Behaviour<SyncCodec>,
    pub ping: ping::Behaviour, // [NEW] Add Ping behaviour
}

#[derive(Debug)]
pub enum SyncBehaviourEvent {
    Gossipsub(gossipsub::Event),
    RequestResponse(request_response::Event<SyncRequest, SyncResponse>),
    Ping(ping::Event), // [NEW] Add Ping event
}

impl From<gossipsub::Event> for SyncBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        SyncBehaviourEvent::Gossipsub(event)
    }
}

impl From<request_response::Event<SyncRequest, SyncResponse>> for SyncBehaviourEvent {
    fn from(event: request_response::Event<SyncRequest, SyncResponse>) -> Self {
        SyncBehaviourEvent::RequestResponse(event)
    }
}

impl From<ping::Event> for SyncBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        SyncBehaviourEvent::Ping(event)
    }
}
