// Path: crates/services/src/ibc/core/context.rs
#![forbid(unsafe_code)]
//! IBC <-> IOI Kernel context adapter (ibc-rs v0.57+ compatible)

use core::fmt::Display;
use std::collections::BTreeMap;
use std::time::Duration;

use byte_slice_cast::AsByteSlice;
use ioi_api::state::StateAccess;

use ibc_client_tendermint::client_state::ClientState as TmClientState;
use ibc_client_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc_core_client_context::{
    ClientExecutionContext, ClientValidationContext, ExtClientValidationContext,
};
use ibc_core_client_types::Height;

use ibc_core_commitment_types::commitment::CommitmentPrefix;

use ibc_core_handler_types::events::IbcEvent;

// [FIX] Use HostError as ContextError is removed in 0.57
use ibc::core::host::types::error::HostError;

use ibc_core_host::{
    ExecutionContext as HostExecutionContext, ValidationContext as HostValidationContext,
};

use ibc_core_host_types::{
    identifiers::{ClientId, ConnectionId, PortId, Sequence},
    path::{
        AckPath, ChannelEndPath, ClientConnectionPath, ClientConsensusStatePath, ClientStatePath,
        CommitmentPath, ConnectionPath, NextChannelSequencePath, NextClientSequencePath,
        NextConnectionSequencePath, ReceiptPath, SeqAckPath, SeqRecvPath, SeqSendPath,
    },
};

use ibc_core_router::{module::Module, router::Router};
use ibc_core_router_types::module::ModuleId;

use ibc_core_channel_types::{
    channel::ChannelEnd,
    commitment::{AcknowledgementCommitment, PacketCommitment},
    packet::Receipt,
};

use ibc_core_connection_types::ConnectionEnd;

use ibc_primitives::{proto::Any, Signer, Timestamp};

use ibc_proto::ibc::core::{
    channel::v1::Channel as RawChannelEnd, connection::v1::ConnectionEnd as RawConnectionEnd,
};
use prost::Message;

/// Transaction-scoped IBC execution/validation context.
pub struct IbcExecutionContext<'a, S: StateAccess + ?Sized> {
    pub state: &'a mut S,
    pub host_height: Height,
    pub host_timestamp: Timestamp,
    pub events: Vec<IbcEvent>,
    pub modules: BTreeMap<ModuleId, Box<dyn Module>>,
    pub port_to_module: BTreeMap<PortId, ModuleId>,
    pub commitment_prefix: CommitmentPrefix,
}

impl<'a, S: StateAccess + ?Sized> Router for IbcExecutionContext<'a, S> {
    fn get_route(&self, module_id: &ModuleId) -> Option<&dyn Module> {
        self.modules.get(module_id).map(|b| b.as_ref())
    }

    fn get_route_mut(&mut self, module_id: &ModuleId) -> Option<&mut (dyn Module + '_)> {
        if let Some(b) = self.modules.get_mut(module_id) {
            Some(&mut **b)
        } else {
            None
        }
    }

    fn lookup_module(&self, port_id: &PortId) -> Option<ModuleId> {
        self.port_to_module.get(port_id).cloned()
    }
}

impl<'a, S: StateAccess + ?Sized> IbcExecutionContext<'a, S> {
    pub fn new(state_overlay: &'a mut S, host_height: Height, host_timestamp: Timestamp) -> Self {
        Self {
            state: state_overlay,
            host_height,
            host_timestamp,
            events: Vec::new(),
            modules: BTreeMap::new(),
            port_to_module: BTreeMap::new(),
            commitment_prefix: CommitmentPrefix::try_from(b"ibc".to_vec()).unwrap(),
        }
    }

    pub fn bind_port_to_module(&mut self, port_id: PortId, module_id: ModuleId) {
        self.port_to_module.insert(port_id, module_id);
    }

    #[inline]
    fn path_bytes<P: Display>(&self, path: &P) -> Vec<u8> {
        path.to_string().into_bytes()
    }

    #[inline]
    fn get_raw<P: Display>(&self, path: &P) -> Result<Option<Vec<u8>>, HostError> {
        self.state
            .get(&self.path_bytes(path))
            .map_err(|e| HostError::failed_to_retrieve(format!("state get error: {}", e)))
    }

    #[inline]
    fn must_get_raw<P: Display>(&self, path: &P) -> Result<Vec<u8>, HostError> {
        self.get_raw(path)?
            .ok_or_else(|| HostError::missing_state(format!("Key not found: {}", path)))
    }

    #[inline]
    fn put_raw<P: Display>(&mut self, path: &P, value: &[u8]) -> Result<(), HostError> {
        self.state
            .insert(&self.path_bytes(path), value)
            .map_err(|e| HostError::failed_to_store(format!("state insert error: {}", e)))
    }

    #[inline]
    fn del_raw<P: Display>(&mut self, path: &P) -> Result<(), HostError> {
        self.state
            .delete(&self.path_bytes(path))
            .map_err(|e| HostError::failed_to_store(format!("state delete error: {}", e)))
    }

    #[inline]
    fn read_u64_be<P: Display>(&self, path: &P) -> Result<u64, HostError> {
        match self.get_raw(path)? {
            // [FIX] Explicitly type the slice to avoid inference errors
            Some(bytes) if bytes.len() == 8 => {
                let mut arr: [u8; 8] = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(arr))
            }
            Some(bytes) => Err(HostError::invalid_state(format!(
                "Invalid u64 at {} ({} bytes)",
                path,
                bytes.len()
            ))),
            None => Ok(0),
        }
    }

    #[inline]
    fn write_u64_be<P: Display>(&mut self, path: &P, value: u64) -> Result<(), HostError> {
        self.put_raw(path, &value.to_be_bytes())
    }
}

impl<'a, S: StateAccess + ?Sized> ClientValidationContext for IbcExecutionContext<'a, S> {
    type ClientStateRef = TmClientState;
    type ConsensusStateRef = TmConsensusState;

    fn client_state(&self, client_id: &ClientId) -> Result<Self::ClientStateRef, HostError> {
        let bytes = self.must_get_raw(&ClientStatePath::new(client_id.clone()))?;
        let any: Any = Any::decode(&*bytes)
            .map_err(|e| HostError::invalid_state(format!("decode ClientState Any: {e}")))?;
        TmClientState::try_from(any)
            .map_err(|e| HostError::invalid_state(format!("into Tendermint ClientState: {e}")))
    }

    fn consensus_state(
        &self,
        path: &ClientConsensusStatePath,
    ) -> Result<Self::ConsensusStateRef, HostError> {
        let bytes = self.must_get_raw(path)?;
        let any: Any = Any::decode(&*bytes)
            .map_err(|e| HostError::invalid_state(format!("decode ConsensusState Any: {e}")))?;
        TmConsensusState::try_from(any)
            .map_err(|e| HostError::invalid_state(format!("into Tendermint ConsensusState: {e}")))
    }

    fn client_update_meta(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<(Timestamp, Height), HostError> {
        Err(HostError::missing_state(format!(
            "Update metadata not found for {client_id} at {height}"
        )))
    }
}

impl<'a, S: StateAccess + ?Sized> ClientExecutionContext for IbcExecutionContext<'a, S> {
    type ClientStateMut = TmClientState;

    fn store_client_state(
        &mut self,
        path: ClientStatePath,
        client_state: Self::ClientStateMut,
    ) -> Result<(), HostError> {
        let any: Any = client_state.into();
        self.put_raw(&path, &any.encode_to_vec())
    }

    fn store_consensus_state(
        &mut self,
        path: ClientConsensusStatePath,
        consensus_state: TmConsensusState,
    ) -> Result<(), HostError> {
        let any: Any = consensus_state.into();
        self.put_raw(&path, &any.encode_to_vec())
    }

    fn delete_consensus_state(&mut self, path: ClientConsensusStatePath) -> Result<(), HostError> {
        self.del_raw(&path)
    }

    fn store_update_meta(
        &mut self,
        _client_id: ClientId,
        _height: Height,
        _host_timestamp: Timestamp,
        _host_height: Height,
    ) -> Result<(), HostError> {
        Ok(())
    }

    fn delete_update_meta(
        &mut self,
        _client_id: ClientId,
        _height: Height,
    ) -> Result<(), HostError> {
        Ok(())
    }
}

impl<'a, S: StateAccess + ?Sized> HostValidationContext for IbcExecutionContext<'a, S> {
    type V = Self;
    type HostClientState = TmClientState;
    type HostConsensusState = TmConsensusState;

    fn get_client_validation_context(&self) -> &Self::V {
        self
    }

    fn host_height(&self) -> Result<Height, HostError> {
        Ok(self.host_height)
    }

    fn host_timestamp(&self) -> Result<Timestamp, HostError> {
        Ok(self.host_timestamp)
    }

    fn host_consensus_state(
        &self,
        _height: &Height,
    ) -> Result<Self::HostConsensusState, HostError> {
        Err(HostError::missing_state(
            "host_consensus_state not available",
        ))
    }

    fn commitment_prefix(&self) -> CommitmentPrefix {
        self.commitment_prefix.clone()
    }

    fn validate_self_client(&self, _state: Self::HostClientState) -> Result<(), HostError> {
        Ok(())
    }

    fn client_counter(&self) -> Result<u64, HostError> {
        self.read_u64_be(&NextClientSequencePath)
    }

    fn connection_end(&self, connection_id: &ConnectionId) -> Result<ConnectionEnd, HostError> {
        let path = ConnectionPath::new(connection_id);
        let bytes = self.must_get_raw(&path)?;
        let raw = RawConnectionEnd::decode(&*bytes)
            .map_err(|e| HostError::invalid_state(format!("decode ConnectionEnd: {e}")))?;
        ConnectionEnd::try_from(raw)
            .map_err(|e| HostError::invalid_state(format!("try_from ConnectionEnd: {e}")))
    }

    fn validate_message_signer(&self, _signer: &Signer) -> Result<(), HostError> {
        Ok(())
    }

    fn connection_counter(&self) -> Result<u64, HostError> {
        self.read_u64_be(&NextConnectionSequencePath)
    }

    fn channel_end(&self, path: &ChannelEndPath) -> Result<ChannelEnd, HostError> {
        let bytes = self.must_get_raw(path)?;
        let raw = RawChannelEnd::decode(&*bytes)
            .map_err(|e| HostError::invalid_state(format!("decode ChannelEnd: {e}")))?;
        ChannelEnd::try_from(raw)
            .map_err(|e| HostError::invalid_state(format!("try_from ChannelEnd: {e}")))
    }

    fn get_next_sequence_send(&self, path: &SeqSendPath) -> Result<Sequence, HostError> {
        Ok(Sequence::from(self.read_u64_be(path)?))
    }

    fn get_next_sequence_recv(&self, path: &SeqRecvPath) -> Result<Sequence, HostError> {
        Ok(Sequence::from(self.read_u64_be(path)?))
    }

    fn get_next_sequence_ack(&self, path: &SeqAckPath) -> Result<Sequence, HostError> {
        Ok(Sequence::from(self.read_u64_be(path)?))
    }

    fn get_packet_commitment(&self, path: &CommitmentPath) -> Result<PacketCommitment, HostError> {
        Ok(PacketCommitment::from(self.must_get_raw(path)?))
    }

    fn get_packet_receipt(&self, path: &ReceiptPath) -> Result<Receipt, HostError> {
        match self.get_raw(path)? {
            Some(_) => Ok(Receipt::Ok),
            None => Err(HostError::missing_state(format!(
                "packet receipt not found (port={}, channel={}, seq={})",
                path.port_id, path.channel_id, path.sequence
            ))),
        }
    }

    fn get_packet_acknowledgement(
        &self,
        path: &AckPath,
    ) -> Result<AcknowledgementCommitment, HostError> {
        Ok(AcknowledgementCommitment::from(self.must_get_raw(path)?))
    }

    fn channel_counter(&self) -> Result<u64, HostError> {
        self.read_u64_be(&NextChannelSequencePath)
    }

    fn max_expected_time_per_block(&self) -> Duration {
        Duration::from_secs(6)
    }
}

impl<'a, S: StateAccess + ?Sized> HostExecutionContext for IbcExecutionContext<'a, S> {
    type E = Self;

    fn get_client_execution_context(&mut self) -> &mut Self::E {
        self
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), HostError> {
        self.events.push(event);
        Ok(())
    }

    fn log_message(&mut self, msg: String) -> Result<(), HostError> {
        tracing::debug!(target: "ibc", "{msg}");
        Ok(())
    }

    fn increase_client_counter(&mut self) -> Result<(), HostError> {
        let path = NextClientSequencePath;
        let v = self.read_u64_be(&path)? + 1;
        self.write_u64_be(&path, v)
    }

    fn increase_connection_counter(&mut self) -> Result<(), HostError> {
        let path = NextConnectionSequencePath;
        let v = self.read_u64_be(&path)? + 1;
        self.write_u64_be(&path, v)
    }

    fn increase_channel_counter(&mut self) -> Result<(), HostError> {
        let path = NextChannelSequencePath;
        let v = self.read_u64_be(&path)? + 1;
        self.write_u64_be(&path, v)
    }

    fn store_connection(
        &mut self,
        path: &ConnectionPath,
        end: ConnectionEnd,
    ) -> Result<(), HostError> {
        let raw: RawConnectionEnd = end.into();
        self.put_raw(path, &raw.encode_to_vec())
    }

    fn store_connection_to_client(
        &mut self,
        path: &ClientConnectionPath,
        connection_id: ConnectionId,
    ) -> Result<(), HostError> {
        self.put_raw(path, connection_id.as_str().as_bytes())
    }

    fn store_channel(&mut self, path: &ChannelEndPath, end: ChannelEnd) -> Result<(), HostError> {
        let raw: RawChannelEnd = end.into();
        self.put_raw(path, &raw.encode_to_vec())
    }

    fn store_next_sequence_send(
        &mut self,
        path: &SeqSendPath,
        v: Sequence,
    ) -> Result<(), HostError> {
        self.write_u64_be(path, v.into())
    }

    fn store_next_sequence_recv(
        &mut self,
        path: &SeqRecvPath,
        v: Sequence,
    ) -> Result<(), HostError> {
        self.write_u64_be(path, v.into())
    }

    fn store_next_sequence_ack(&mut self, path: &SeqAckPath, v: Sequence) -> Result<(), HostError> {
        self.write_u64_be(path, v.into())
    }

    fn store_packet_commitment(
        &mut self,
        path: &CommitmentPath,
        c: PacketCommitment,
    ) -> Result<(), HostError> {
        self.put_raw(path, c.as_byte_slice())
    }

    fn delete_packet_commitment(&mut self, path: &CommitmentPath) -> Result<(), HostError> {
        self.del_raw(path)
    }

    fn store_packet_receipt(&mut self, path: &ReceiptPath, r: Receipt) -> Result<(), HostError> {
        match r {
            Receipt::Ok => self.put_raw(path, b"\x01"),
            Receipt::None => Err(HostError::invalid_state(
                "Cannot store Receipt::None".to_string(),
            )),
        }
    }

    fn store_packet_acknowledgement(
        &mut self,
        path: &AckPath,
        ack: AcknowledgementCommitment,
    ) -> Result<(), HostError> {
        self.put_raw(path, ack.as_byte_slice())
    }

    fn delete_packet_acknowledgement(&mut self, path: &AckPath) -> Result<(), HostError> {
        self.del_raw(path)
    }
}

impl<'a, S: StateAccess + ?Sized> ExtClientValidationContext for IbcExecutionContext<'a, S> {
    fn host_height(&self) -> Result<Height, HostError> {
        Ok(self.host_height)
    }
    fn host_timestamp(&self) -> Result<ibc_primitives::Timestamp, HostError> {
        Ok(self.host_timestamp)
    }

    fn consensus_state_heights(&self, _client_id: &ClientId) -> Result<Vec<Height>, HostError> {
        Ok(Vec::new())
    }

    fn next_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<Self::ConsensusStateRef>, HostError> {
        Ok(None)
    }

    fn prev_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<Self::ConsensusStateRef>, HostError> {
        Ok(None)
    }
}
