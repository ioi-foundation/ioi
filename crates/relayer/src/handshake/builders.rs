// Path: crates/relayer/src/handshake/builders.rs

//! Helper functions for building IBC protobuf messages.

use crate::handshake::proofs::query_proof_bytes_at;
use crate::gateway::Gateway;
use anyhow::Result;
use ibc_core_client_types::Height;
use ibc_proto::{
    google::protobuf::Any as PbAny,
    ibc::core::{
        channel::v1 as pbchan, client::v1 as pbclient, client::v1::Height as PbHeight,
        commitment::v1::MerklePrefix, connection::v1 as pbconn,
    },
};
// [FIX] Import Message to enable encode_to_vec()
use prost::Message;

// Export message types for convenience
pub use ibc_proto::ibc::core::{
    channel::v1::{
        MsgChannelOpenAck, MsgChannelOpenConfirm, MsgChannelOpenInit, MsgChannelOpenTry,
    },
    client::v1::{MsgCreateClient, MsgUpdateClient},
    connection::v1::{
        MsgConnectionOpenAck, MsgConnectionOpenConfirm, MsgConnectionOpenInit, MsgConnectionOpenTry,
    },
};

pub const IBC_PREFIX: &[u8] = b"ibc";

pub fn build_create_client_any(
    client_state_any: PbAny,
    consensus_state_any: PbAny,
    signer: &str,
) -> Result<PbAny> {
    let msg = MsgCreateClient {
        client_state: Some(client_state_any),
        consensus_state: Some(consensus_state_any),
        signer: signer.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.client.v1.MsgCreateClient".into(),
        value: msg.encode_to_vec(),
    })
}

pub fn build_update_client_any(
    client_id: &str,
    client_message_any: PbAny,
    signer: &str,
) -> Result<PbAny> {
    let msg = MsgUpdateClient {
        client_id: client_id.to_string(),
        client_message: Some(client_message_any),
        signer: signer.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.client.v1.MsgUpdateClient".into(),
        value: msg.encode_to_vec(),
    })
}

pub fn build_conn_open_init_any(
    client_id_a: &str,
    counterparty_client_b: &str,
    signer: &str,
) -> Result<PbAny> {
    let cp = pbconn::Counterparty {
        client_id: counterparty_client_b.to_string(),
        connection_id: "".to_string(),
        prefix: Some(MerklePrefix {
            key_prefix: IBC_PREFIX.to_vec(),
        }),
    };
    let version = Some(pbconn::Version {
        identifier: "1".into(),
        features: vec!["ORDER_ORDERED".into(), "ORDER_UNORDERED".into()],
    });
    let msg = MsgConnectionOpenInit {
        client_id: client_id_a.to_string(),
        counterparty: Some(cp),
        version,
        delay_period: 0,
        signer: signer.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.connection.v1.MsgConnectionOpenInit".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_conn_open_try_any(
    gw_a: &Gateway,
    client_id_b: &str,
    client_a_on_b: &str,
    conn_id_a: &str,
    counterparty_client_a: &str,
    proof_height_on_a: u64,
    signer_b: &str,
) -> Result<PbAny> {
    // 1. Proof of Init on A
    let conn_path_a = format!("connections/{}", conn_id_a);
    let proof_init = query_proof_bytes_at(gw_a, &conn_path_a, proof_height_on_a).await?;

    // 2. ClientState(A) on A
    let cs_path_on_a = format!("clients/{}/clientState", counterparty_client_a);
    let (client_state_any_bytes, _proof_cs, _h_cs) = gw_a
        .query_at_height(&cs_path_on_a, proof_height_on_a)
        .await?;
    let client_state_any = <PbAny as prost::Message>::decode(client_state_any_bytes.as_slice())?;
    let proof_client = query_proof_bytes_at(gw_a, &cs_path_on_a, proof_height_on_a).await?;

    // 3. ConsensusState(A) on A
    let consensus_height = PbHeight {
        revision_number: 0,
        revision_height: 1,
    };
    let ccs_path = format!("clients/{}/consensusStates/0-1", counterparty_client_a);
    let proof_consensus = query_proof_bytes_at(gw_a, &ccs_path, proof_height_on_a).await?;

    let cp = pbconn::Counterparty {
        client_id: client_a_on_b.to_string(),
        connection_id: conn_id_a.to_string(),
        prefix: Some(MerklePrefix {
            key_prefix: IBC_PREFIX.to_vec(),
        }),
    };
    let versions = vec![pbconn::Version {
        identifier: "1".into(),
        features: vec!["ORDER_ORDERED".into(), "ORDER_UNORDERED".into()],
    }];

    #[allow(deprecated)]
    let msg = MsgConnectionOpenTry {
        client_id: client_id_b.to_string(),
        client_state: Some(client_state_any),
        counterparty: Some(cp),
        delay_period: 0,
        previous_connection_id: String::new(),
        counterparty_versions: versions,
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_a,
        }),
        consensus_height: Some(consensus_height),
        proof_init,
        proof_client,
        proof_consensus,
        host_consensus_state_proof: vec![],
        signer: signer_b.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.connection.v1.MsgConnectionOpenTry".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_conn_open_ack_any(
    gw_b: &Gateway,
    conn_id_a: &str,
    conn_id_b: &str,
    client_a_on_b: &str,
    proof_height_on_b: u64,
    signer_a: &str,
) -> Result<PbAny> {
    let conn_path_b = format!("connections/{}", conn_id_b);
    let proof_try = query_proof_bytes_at(gw_b, &conn_path_b, proof_height_on_b).await?;

    let cs_path_b = format!("clients/{}/clientState", client_a_on_b);
    let proof_client = query_proof_bytes_at(gw_b, &cs_path_b, proof_height_on_b).await?;
    let (client_state_any_bytes, _proof_cs, _h_cs) =
        gw_b.query_at_height(&cs_path_b, proof_height_on_b).await?;
    let client_state_any = <PbAny as prost::Message>::decode(client_state_any_bytes.as_slice())?;

    let consensus_height = PbHeight {
        revision_number: 0,
        revision_height: 1,
    };
    let ccs_path = format!("clients/{}/consensusStates/0-1", client_a_on_b);
    let proof_consensus = query_proof_bytes_at(gw_b, &ccs_path, proof_height_on_b).await?;

    let version = Some(pbconn::Version {
        identifier: "1".into(),
        features: vec!["ORDER_ORDERED".into(), "ORDER_UNORDERED".into()],
    });

    let msg = MsgConnectionOpenAck {
        connection_id: conn_id_a.to_string(),
        counterparty_connection_id: conn_id_b.to_string(),
        version,
        client_state: Some(client_state_any),
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_b,
        }),
        consensus_height: Some(consensus_height),
        proof_try,
        proof_client,
        proof_consensus,
        host_consensus_state_proof: vec![],
        signer: signer_a.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.connection.v1.MsgConnectionOpenAck".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_conn_open_confirm_any(
    gw_a: &Gateway,
    conn_id_b: &str,
    conn_id_a: &str,
    proof_height_on_a: u64,
    signer_b: &str,
) -> Result<PbAny> {
    let conn_path_a = format!("connections/{}", conn_id_a);
    let proof_ack = query_proof_bytes_at(gw_a, &conn_path_a, proof_height_on_a).await?;

    let msg = MsgConnectionOpenConfirm {
        connection_id: conn_id_b.to_string(),
        proof_ack,
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_a,
        }),
        signer: signer_b.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.connection.v1.MsgConnectionOpenConfirm".into(),
        value: msg.encode_to_vec(),
    })
}

pub fn build_chan_open_init_any(
    port_id_a: &str,
    connection_id_a: &str,
    counterparty_port_b: &str,
    version: &str,
    ordering: i32,
    signer_a: &str,
) -> Result<PbAny> {
    let channel = pbchan::Channel {
        state: pbchan::State::Init as i32,
        ordering,
        counterparty: Some(pbchan::Counterparty {
            port_id: counterparty_port_b.to_string(),
            channel_id: "".to_string(),
        }),
        connection_hops: vec![connection_id_a.to_string()],
        version: version.to_string(),
        upgrade_sequence: 0,
    };
    let msg = MsgChannelOpenInit {
        port_id: port_id_a.to_string(),
        channel: Some(channel),
        signer: signer_a.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.channel.v1.MsgChannelOpenInit".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_chan_open_try_any(
    gw_a: &Gateway,
    port_id_b: &str,
    connection_id_b: &str,
    counterparty_port_a: &str,
    channel_id_a: &str,
    version: &str,
    ordering: i32,
    proof_height_on_a: u64,
    signer_b: &str,
) -> Result<PbAny> {
    let cp = pbchan::Counterparty {
        port_id: counterparty_port_a.to_string(),
        channel_id: channel_id_a.to_string(),
    };
    let channel = pbchan::Channel {
        state: pbchan::State::Tryopen as i32,
        ordering,
        counterparty: Some(cp),
        connection_hops: vec![connection_id_b.to_string()],
        version: version.to_string(),
        upgrade_sequence: 0,
    };

    let ch_path_a = format!(
        "channelEnds/ports/{}/channels/{}",
        counterparty_port_a, channel_id_a
    );
    let proof_init = query_proof_bytes_at(gw_a, &ch_path_a, proof_height_on_a).await?;

    #[allow(deprecated)]
    let msg = MsgChannelOpenTry {
        port_id: port_id_b.to_string(),
        channel: Some(channel),
        counterparty_version: version.to_string(),
        previous_channel_id: String::new(),
        proof_init,
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_a,
        }),
        signer: signer_b.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.channel.v1.MsgChannelOpenTry".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_chan_open_ack_any(
    gw_b: &Gateway,
    port_id_a: &str,
    channel_id_a: &str,
    counterparty_port_b: &str,
    channel_id_b: &str,
    version: &str,
    proof_height_on_b: u64,
    signer_a: &str,
) -> Result<PbAny> {
    let ch_path_b = format!(
        "channelEnds/ports/{}/channels/{}",
        counterparty_port_b, channel_id_b
    );
    let proof_try = query_proof_bytes_at(gw_b, &ch_path_b, proof_height_on_b).await?;

    let msg = MsgChannelOpenAck {
        port_id: port_id_a.to_string(),
        channel_id: channel_id_a.to_string(),
        counterparty_channel_id: channel_id_b.to_string(),
        counterparty_version: version.to_string(),
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_b,
        }),
        proof_try,
        signer: signer_a.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.channel.v1.MsgChannelOpenAck".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_chan_open_confirm_any(
    gw_a: &Gateway,
    port_id_b: &str,
    channel_id_b: &str,
    counterparty_port_a: &str,
    channel_id_a: &str,
    proof_height_on_a: u64,
    signer_b: &str,
) -> Result<PbAny> {
    let ch_path_a = format!(
        "channelEnds/ports/{}/channels/{}",
        counterparty_port_a, channel_id_a
    );
    let proof_ack = query_proof_bytes_at(gw_a, &ch_path_a, proof_height_on_a).await?;

    let msg = MsgChannelOpenConfirm {
        port_id: port_id_b.to_string(),
        channel_id: channel_id_b.to_string(),
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_a,
        }),
        proof_ack,
        signer: signer_b.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.channel.v1.MsgChannelOpenConfirm".into(),
        value: msg.encode_to_vec(),
    })
}