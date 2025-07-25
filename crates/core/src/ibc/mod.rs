// In core/src/ibc/mod.rs
pub trait CrossChainCommunication: BlockchainService {
    fn verify_proof(&self, proof: &CrossChainProof) -> Result<bool, Error>;
    fn create_packet(&self, data: &[u8], destination: ChainId) -> Result<Packet, Error>;
}

pub trait CrossChainProof {
    fn source_chain(&self) -> ChainId;
    fn proof_type(&self) -> ProofType;
}
