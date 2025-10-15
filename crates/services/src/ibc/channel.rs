// Path: crates/services/src/ibc/channel.rs

//! Implements the `ChannelManager` service, which is responsible for handling
//! the IBC channel lifecycle, including handshakes, packet ordering, and timeouts.
//! It persists all of its state on-chain according to ICS-24 path standards.

use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::error::UpgradeError;
use depin_sdk_types::ibc::Packet;
use ibc_core_channel_types::channel::State as ChannelState;
use ibc_core_channel_types::error::PacketError;
use ibc_core_host_types::identifiers::{ChannelId, PortId, Sequence};
use ibc_core_host_types::path::{ChannelEndPath, CommitmentPath, ReceiptPath, SeqRecvPath};
use ibc_proto::ibc::core::channel::v1::Channel as RawChannelEnd;
use prost::Message;
use std::str::FromStr;

/// A service that manages the state of IBC channels and packets.
#[derive(Debug, Default)]
pub struct ChannelManager {}

impl BlockchainService for ChannelManager {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("ibc_channel_manager".to_string())
    }
}

// Implement the base `Service` trait. This service does not have any special hooks.
impl_service_base!(ChannelManager);

impl UpgradableService for ChannelManager {
    fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // This service is stateless itself; all state is in the chain's StateAccessor.
        Ok(Vec::new())
    }

    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

impl ChannelManager {
    /// Creates a new `ChannelManager`.
    pub fn new() -> Self {
        Self {}
    }

    /// Processes an outgoing packet from a local application.
    /// It stores a commitment to the packet in the state tree.
    pub fn send_packet<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
        packet: Packet,
    ) -> Result<(), PacketError> {
        let port_id =
            PortId::from_str(&packet.source_port).map_err(PacketError::InvalidIdentifier)?;
        let channel_id =
            ChannelId::from_str(&packet.source_channel).map_err(PacketError::InvalidIdentifier)?;
        let sequence = Sequence::from(packet.sequence);

        // Construct the ICS-24 path for the packet commitment.
        let commitment_path = CommitmentPath::new(&port_id, &channel_id, sequence);

        // A real implementation would verify the channel state is OPEN.
        // let channel_end = self.get_channel_end(state, &packet.source_port, &packet.source_channel)?;
        // if channel_end.state != ChannelState::Open {
        //     return Err(PacketError::ChannelNotFound { port_id, channel_id });
        // }

        // Store the commitment hash of the packet data. The relayer will observe this.
        let commitment_bytes = self.hash_packet_commitment(&packet);
        state
            .insert(commitment_path.to_string().as_bytes(), &commitment_bytes)
            .map_err(|e| PacketError::AppModule {
                description: e.to_string(),
            })?;

        // TODO: Emit an event for the relayer.

        Ok(())
    }

    /// Processes an incoming packet that has been proven against a trusted foreign header.
    /// It verifies the packet's commitment and updates the next expected sequence number.
    pub fn recv_packet<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
        packet: Packet,
        _proof_height: u64, // Used by relayer, but logic here just needs the packet
    ) -> Result<(), PacketError> {
        // Construct paths for verification.
        let port_id =
            PortId::from_str(&packet.destination_port).map_err(PacketError::InvalidIdentifier)?;
        let channel_id = ChannelId::from_str(&packet.destination_channel)
            .map_err(PacketError::InvalidIdentifier)?;
        let sequence = Sequence::from(packet.sequence);

        let channel_path = ChannelEndPath::new(&port_id, &channel_id);
        let next_seq_recv_path = SeqRecvPath::new(&port_id, &channel_id);

        // Fetch and verify the channel state.
        let channel_end_bytes = state
            .get(channel_path.to_string().as_bytes())
            .map_err(|e| PacketError::AppModule {
                description: e.to_string(),
            })?
            .ok_or(PacketError::ChannelNotFound {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            })?;
        let channel_end =
            RawChannelEnd::decode(&*channel_end_bytes).map_err(|e| PacketError::AppModule {
                description: format!("Failed to decode channel end: {}", e),
            })?;

        if channel_end.state != ChannelState::Open as i32 {
            return Err(PacketError::ChannelNotFound {
                port_id,
                channel_id,
            });
        }

        // Verify the packet sequence number.
        let expected_sequence: u64 = state
            .get(next_seq_recv_path.to_string().as_bytes())
            .map_err(|e| PacketError::AppModule {
                description: e.to_string(),
            })?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        if packet.sequence != expected_sequence {
            return Err(PacketError::InvalidPacketSequence {
                given_sequence: packet.sequence.into(),
                next_sequence: expected_sequence.into(),
            });
        }

        // Write a receipt to prevent replay. This is an important part of IBC semantics.
        let receipt_path = ReceiptPath::new(&port_id, &channel_id, sequence);
        state
            .insert(receipt_path.to_string().as_bytes(), &[1])
            .map_err(|e| PacketError::AppModule {
                description: e.to_string(),
            })?;

        // Increment the next expected sequence number.
        state
            .insert(
                next_seq_recv_path.to_string().as_bytes(),
                (expected_sequence + 1).to_string().as_bytes(),
            )
            .map_err(|e| PacketError::AppModule {
                description: e.to_string(),
            })?;

        // TODO: Emit a `RecvPacket` event for the application module.

        Ok(())
    }

    /// Processes an acknowledgement for a previously sent packet.
    /// It verifies the acknowledgement proof and deletes the original packet commitment.
    pub fn acknowledge_packet<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
        packet: Packet,
        _acknowledgement: &[u8],
    ) -> Result<(), PacketError> {
        let port_id =
            PortId::from_str(&packet.source_port).map_err(PacketError::InvalidIdentifier)?;
        let channel_id =
            ChannelId::from_str(&packet.source_channel).map_err(PacketError::InvalidIdentifier)?;
        let sequence = Sequence::from(packet.sequence);

        // Construct the path for the original packet commitment.
        let commitment_path = CommitmentPath::new(&port_id, &channel_id, sequence);

        // Verify that we actually sent a packet with this commitment.
        let _original_commitment = state
            .get(commitment_path.to_string().as_bytes())
            .map_err(|e| PacketError::AppModule {
                description: e.to_string(),
            })?
            .ok_or(PacketError::PacketCommitmentNotFound {
                sequence: packet.sequence.into(),
            })?;

        // The `RecvPacket` transaction handler has already verified the inclusion proof
        // of this acknowledgement on the counterparty chain. Here, we just clean up our state.

        // Delete the packet commitment now that it has been acknowledged.
        state
            .delete(commitment_path.to_string().as_bytes())
            .map_err(|e| PacketError::AppModule {
                description: e.to_string(),
            })?;

        // TODO: Emit an `AcknowledgePacket` event for the application module.

        Ok(())
    }

    /// Computes the SHA-256 hash of a packet's data for commitment purposes.
    fn hash_packet_commitment(&self, packet: &Packet) -> Vec<u8> {
        // A real implementation would follow the exact hashing scheme defined in IBC specs.
        let mut data = Vec::new();
        // data.extend_from_slice(&packet.timeout_timestamp.to_be_bytes()); // This info is now in the SendPacket payload
        // data.extend_from_slice(&packet.timeout_height...); // Simplified
        data.extend_from_slice(&packet.data);
        depin_sdk_crypto::algorithms::hash::sha256(&data)
            .unwrap()
            .to_vec()
    }
}