// Path: crates/services/src/ibc/context.rs
#![forbid(unsafe_code)]
//! IBC <-> IOI SDK context adapter (ibc-rs v0.50+ compatible)

use core::fmt::Display;
use std::collections::BTreeMap;
use std::time::Duration;

use byte_slice_cast::AsByteSlice; // for `as_byte_slice()` on commitments
use ioi_api::state::StateAccessor;

use ibc_client_tendermint::client_state::ClientState as TmClientState;
use ibc_client_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc_core_client_context::{
    ClientExecutionContext, ClientValidationContext, ExtClientValidationContext,
};
use ibc_core_client_types::{error::ClientError, Height};

use ibc_core_commitment_types::commitment::CommitmentPrefix;

use ibc_core_handler_types::{error::ContextError, events::IbcEvent};

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
    error::ChannelError,
    packet::Receipt,
};

use ibc_core_connection_types::{error::ConnectionError, ConnectionEnd};

use ibc_primitives::{proto::Any, Signer, Timestamp};

use ibc_proto::ibc::core::{
    channel::v1::Channel as RawChannelEnd, connection::v1::ConnectionEnd as RawConnectionEnd,
};
use prost::Message;

/// Transaction-scoped IBC execution/validation context.
pub struct IbcExecutionContext<'a, S: StateAccessor + ?Sized> {
    /// Transaction-local state view (usually a StateOverlay you commit on success).
    pub state: &'a mut S,
    /// Deterministic host height (e.g., `{revision_number: 0, revision_height: block_height}`).
    pub host_height: Height,
    /// Deterministic host timestamp (from block header), *not* wall-clock.
    pub host_timestamp: Timestamp,
    /// IBC events accumulated during dispatch.
    pub events: Vec<IbcEvent>,
    /// Router: application modules by ModuleId (ICS-26).
    pub modules: BTreeMap<ModuleId, Box<dyn Module>>,
    /// Router: which module owns which port.
    pub port_to_module: BTreeMap<PortId, ModuleId>,
    /// Commitment prefix used for ICS-23 proofs (commonly "ibc").
    pub commitment_prefix: CommitmentPrefix,
}

/// Implement the `Router` trait required by `dispatch`.
impl<'a, S: StateAccessor + ?Sized> Router for IbcExecutionContext<'a, S> {
    fn get_route(&self, module_id: &ModuleId) -> Option<&dyn Module> {
        self.modules.get(module_id).map(|b| b.as_ref())
    }

    fn get_route_mut(&mut self, module_id: &ModuleId) -> Option<&mut (dyn Module + '_)> {
        // Avoid closure lifetime inference issues by spelling it out.
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

// ----------------------------- Small helpers -----------------------------
impl<'a, S: StateAccessor + ?Sized> IbcExecutionContext<'a, S> {
    /// Convenience builder for tests and service wiring.
    pub fn new(state_overlay: &'a mut S, host_height: Height, host_timestamp: Timestamp) -> Self {
        Self {
            state: state_overlay,
            host_height,
            host_timestamp,
            events: Vec::new(),
            modules: BTreeMap::new(),
            port_to_module: BTreeMap::new(),
            // Most Cosmos chains use "ibc" commitment store prefix
            commitment_prefix: CommitmentPrefix::try_from(b"ibc".to_vec()).unwrap(),
        }
    }

    /// Bind a `PortId` to a `ModuleId` (when you wire a real app module).
    pub fn bind_port_to_module(&mut self, port_id: PortId, module_id: ModuleId) {
        self.port_to_module.insert(port_id, module_id);
    }

    #[inline]
    fn path_bytes<P: Display>(&self, path: &P) -> Vec<u8> {
        path.to_string().into_bytes()
    }

    #[inline]
    fn get_raw<P: Display>(&self, path: &P) -> Result<Option<Vec<u8>>, ContextError> {
        self.state.get(&self.path_bytes(path)).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: e.to_string(),
            })
        })
    }

    #[inline]
    fn must_get_raw<P: Display>(&self, path: &P) -> Result<Vec<u8>, ContextError> {
        self.get_raw(path)?.ok_or_else(|| {
            ContextError::from(ClientError::Other {
                description: format!("Key not found: {}", path),
            })
        })
    }

    #[inline]
    fn put_raw<P: Display>(&mut self, path: &P, value: &[u8]) -> Result<(), ContextError> {
        self.state
            .insert(&self.path_bytes(path), value)
            .map_err(|e| {
                ContextError::from(ClientError::Other {
                    description: e.to_string(),
                })
            })
    }

    #[inline]
    fn del_raw<P: Display>(&mut self, path: &P) -> Result<(), ContextError> {
        self.state.delete(&self.path_bytes(path)).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: e.to_string(),
            })
        })
    }

    #[inline]
    fn read_u64_be<P: Display>(&self, path: &P) -> Result<u64, ContextError> {
        match self.get_raw(path)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(arr))
            }
            Some(bytes) => Err(ContextError::from(ClientError::Other {
                description: format!("Invalid u64 at {} ({} bytes)", path, bytes.len()),
            })),
            None => Ok(0),
        }
    }

    #[inline]
    fn write_u64_be<P: Display>(&mut self, path: &P, value: u64) -> Result<(), ContextError> {
        self.put_raw(path, &value.to_be_bytes())
    }
}

// ----------------------- ClientValidationContext ------------------------
impl<'a, S: StateAccessor + ?Sized> ClientValidationContext for IbcExecutionContext<'a, S> {
    type ClientStateRef = TmClientState;
    type ConsensusStateRef = TmConsensusState;

    fn client_state(&self, client_id: &ClientId) -> Result<Self::ClientStateRef, ContextError> {
        let bytes = self.must_get_raw(&ClientStatePath::new(client_id.clone()))?;
        let any: Any = Any::decode(&*bytes).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: format!("decode ClientState Any: {e}"),
            })
        })?;
        TmClientState::try_from(any).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: format!("into Tendermint ClientState: {e}"),
            })
        })
    }

    fn consensus_state(
        &self,
        path: &ClientConsensusStatePath,
    ) -> Result<Self::ConsensusStateRef, ContextError> {
        let bytes = self.must_get_raw(path)?;
        let any: Any = Any::decode(&*bytes).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: format!("decode ConsensusState Any: {e}"),
            })
        })?;
        TmConsensusState::try_from(any).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: format!("into Tendermint ConsensusState: {e}"),
            })
        })
    }

    fn client_update_meta(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<(Timestamp, Height), ContextError> {
        Err(ContextError::from(ClientError::UpdateMetaDataNotFound {
            client_id: client_id.clone(),
            height: *height,
        }))
    }
}

// ------------------------ ClientExecutionContext ------------------------
impl<'a, S: StateAccessor + ?Sized> ClientExecutionContext for IbcExecutionContext<'a, S> {
    type ClientStateMut = TmClientState;

    fn store_client_state(
        &mut self,
        path: ClientStatePath,
        client_state: Self::ClientStateMut,
    ) -> Result<(), ContextError> {
        let any: Any = client_state.into();
        self.put_raw(&path, &any.encode_to_vec())
    }

    fn store_consensus_state(
        &mut self,
        path: ClientConsensusStatePath,
        consensus_state: TmConsensusState,
    ) -> Result<(), ContextError> {
        let any: Any = consensus_state.into();
        self.put_raw(&path, &any.encode_to_vec())
    }

    fn delete_consensus_state(
        &mut self,
        path: ClientConsensusStatePath,
    ) -> Result<(), ContextError> {
        self.del_raw(&path)
    }

    fn store_update_meta(
        &mut self,
        _client_id: ClientId,
        _height: Height,
        _host_timestamp: Timestamp,
        _host_height: Height,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn delete_update_meta(
        &mut self,
        _client_id: ClientId,
        _height: Height,
    ) -> Result<(), ContextError> {
        Ok(())
    }
}

// --------------------------- Host Validation ----------------------------
// In v0.50+, HostValidationContext also exposes channel/connection/packet getters/setters.
impl<'a, S: StateAccessor + ?Sized> HostValidationContext for IbcExecutionContext<'a, S> {
    type V = Self;
    type HostClientState = TmClientState;
    type HostConsensusState = TmConsensusState;

    fn get_client_validation_context(&self) -> &Self::V {
        self
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        Ok(self.host_height)
    }

    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        Ok(self.host_timestamp)
    }

    fn host_consensus_state(
        &self,
        _height: &Height,
    ) -> Result<Self::HostConsensusState, ContextError> {
        // Not wired yet; return an error that callers can surface.
        Err(ContextError::from(ClientError::Other {
            description: "host_consensus_state not available".into(),
        }))
    }

    fn commitment_prefix(&self) -> CommitmentPrefix {
        self.commitment_prefix.clone()
    }

    fn validate_self_client(&self, _state: Self::HostClientState) -> Result<(), ContextError> {
        // Accept by default; tighten if you need self-client checks.
        Ok(())
    }

    fn client_counter(&self) -> Result<u64, ContextError> {
        self.read_u64_be(&NextClientSequencePath)
    }

    fn connection_end(&self, connection_id: &ConnectionId) -> Result<ConnectionEnd, ContextError> {
        let path = ConnectionPath::new(connection_id);
        let bytes = self.must_get_raw(&path)?;
        let raw = RawConnectionEnd::decode(&*bytes).map_err(|e| {
            ContextError::from(ConnectionError::Other {
                description: format!("decode ConnectionEnd: {e}"),
            })
        })?;
        ConnectionEnd::try_from(raw).map_err(|e| {
            ContextError::from(ConnectionError::Other {
                description: format!("try_from ConnectionEnd: {e}"),
            })
        })
    }

    fn validate_message_signer(&self, _signer: &Signer) -> Result<(), ContextError> {
        // Your chain may enforce signer authorization; accept by default.
        Ok(())
    }

    fn connection_counter(&self) -> Result<u64, ContextError> {
        self.read_u64_be(&NextConnectionSequencePath)
    }

    fn channel_end(&self, path: &ChannelEndPath) -> Result<ChannelEnd, ContextError> {
        let bytes = self.must_get_raw(path)?;
        let raw = RawChannelEnd::decode(&*bytes).map_err(|e| {
            ContextError::from(ChannelError::Other {
                description: format!("decode ChannelEnd: {e}"),
            })
        })?;
        ChannelEnd::try_from(raw).map_err(|e| {
            ContextError::from(ChannelError::Other {
                description: format!("try_from ChannelEnd: {e}"),
            })
        })
    }

    fn get_next_sequence_send(&self, path: &SeqSendPath) -> Result<Sequence, ContextError> {
        Ok(Sequence::from(self.read_u64_be(path)?))
    }

    fn get_next_sequence_recv(&self, path: &SeqRecvPath) -> Result<Sequence, ContextError> {
        Ok(Sequence::from(self.read_u64_be(path)?))
    }

    fn get_next_sequence_ack(&self, path: &SeqAckPath) -> Result<Sequence, ContextError> {
        Ok(Sequence::from(self.read_u64_be(path)?))
    }

    fn get_packet_commitment(
        &self,
        path: &CommitmentPath,
    ) -> Result<PacketCommitment, ContextError> {
        Ok(PacketCommitment::from(self.must_get_raw(path)?))
    }

    fn get_packet_receipt(&self, path: &ReceiptPath) -> Result<Receipt, ContextError> {
        match self.get_raw(path)? {
            Some(_) => Ok(Receipt::Ok),
            None => Err(ContextError::from(ChannelError::Other {
                description: format!(
                    "packet receipt not found (port={}, channel={}, seq={})",
                    path.port_id, path.channel_id, path.sequence
                ),
            })),
        }
    }

    fn get_packet_acknowledgement(
        &self,
        path: &AckPath,
    ) -> Result<AcknowledgementCommitment, ContextError> {
        Ok(AcknowledgementCommitment::from(self.must_get_raw(path)?))
    }

    fn channel_counter(&self) -> Result<u64, ContextError> {
        self.read_u64_be(&NextChannelSequencePath)
    }

    fn max_expected_time_per_block(&self) -> Duration {
        // Tune to your chain's block time. 6s is a safe default.
        Duration::from_secs(6)
    }
}

// --------------------------- Host Execution -----------------------------
impl<'a, S: StateAccessor + ?Sized> HostExecutionContext for IbcExecutionContext<'a, S> {
    type E = Self;

    fn get_client_execution_context(&mut self) -> &mut Self::E {
        self
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), ContextError> {
        self.events.push(event);
        Ok(())
    }

    fn log_message(&mut self, msg: String) -> Result<(), ContextError> {
        tracing::debug!(target: "ibc", "{msg}");
        Ok(())
    }

    // ---- Counters ----
    fn increase_client_counter(&mut self) -> Result<(), ContextError> {
        let path = NextClientSequencePath;
        let v = self.read_u64_be(&path)? + 1;
        self.write_u64_be(&path, v)
    }

    fn increase_connection_counter(&mut self) -> Result<(), ContextError> {
        let path = NextConnectionSequencePath;
        let v = self.read_u64_be(&path)? + 1;
        self.write_u64_be(&path, v)
    }

    fn increase_channel_counter(&mut self) -> Result<(), ContextError> {
        let path = NextChannelSequencePath;
        let v = self.read_u64_be(&path)? + 1;
        self.write_u64_be(&path, v)
    }

    // ---- Connection storage ----
    fn store_connection(
        &mut self,
        path: &ConnectionPath,
        end: ConnectionEnd,
    ) -> Result<(), ContextError> {
        let raw: RawConnectionEnd = end.into();
        self.put_raw(path, &raw.encode_to_vec())
    }

    fn store_connection_to_client(
        &mut self,
        path: &ClientConnectionPath,
        connection_id: ConnectionId,
    ) -> Result<(), ContextError> {
        // Store connection id bytes; adjust if you later need a list/append semantics.
        self.put_raw(path, connection_id.as_str().as_bytes())
    }

    // ---- Channel storage ----
    fn store_channel(
        &mut self,
        path: &ChannelEndPath,
        end: ChannelEnd,
    ) -> Result<(), ContextError> {
        let raw: RawChannelEnd = end.into();
        self.put_raw(path, &raw.encode_to_vec())
    }

    fn store_next_sequence_send(
        &mut self,
        path: &SeqSendPath,
        v: Sequence,
    ) -> Result<(), ContextError> {
        self.write_u64_be(path, v.into())
    }

    fn store_next_sequence_recv(
        &mut self,
        path: &SeqRecvPath,
        v: Sequence,
    ) -> Result<(), ContextError> {
        self.write_u64_be(path, v.into())
    }

    fn store_next_sequence_ack(
        &mut self,
        path: &SeqAckPath,
        v: Sequence,
    ) -> Result<(), ContextError> {
        self.write_u64_be(path, v.into())
    }

    // ---- Packet storage ----
    fn store_packet_commitment(
        &mut self,
        path: &CommitmentPath,
        c: PacketCommitment,
    ) -> Result<(), ContextError> {
        self.put_raw(path, c.as_byte_slice())
    }

    fn delete_packet_commitment(&mut self, path: &CommitmentPath) -> Result<(), ContextError> {
        self.del_raw(path)
    }

    fn store_packet_receipt(&mut self, path: &ReceiptPath, r: Receipt) -> Result<(), ContextError> {
        match r {
            Receipt::Ok => self.put_raw(path, b"\x01"), // presence byte
        }
    }

    fn store_packet_acknowledgement(
        &mut self,
        path: &AckPath,
        ack: AcknowledgementCommitment,
    ) -> Result<(), ContextError> {
        self.put_raw(path, ack.as_byte_slice())
    }

    fn delete_packet_acknowledgement(&mut self, path: &AckPath) -> Result<(), ContextError> {
        self.del_raw(path)
    }
}

// Tendermint’s client needs this tiny extension trait:
impl<'a, S: StateAccessor + ?Sized> ExtClientValidationContext for IbcExecutionContext<'a, S> {
    fn host_height(&self) -> Result<Height, ContextError> {
        Ok(self.host_height)
    }
    fn host_timestamp(&self) -> Result<ibc_primitives::Timestamp, ContextError> {
        Ok(self.host_timestamp)
    }

    // If your StateAccessor can't enumerate keys yet, return "no data".
    // These stubs are acceptable until you wire iteration over ClientConsensusStatePath.
    fn consensus_state_heights(&self, _client_id: &ClientId) -> Result<Vec<Height>, ContextError> {
        Ok(Vec::new())
    }

    fn next_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<Self::ConsensusStateRef>, ContextError> {
        Ok(None)
    }

    fn prev_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<Self::ConsensusStateRef>, ContextError> {
        Ok(None)
    }
}
