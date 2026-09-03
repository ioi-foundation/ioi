use super::gf256::{evaluate, interpolate_at};
use ioi_types::app::{aft_async_asks_secret, aft_async_asks_share_commitment, AftAsyncGeometryV1};
use ioi_types::codec;
use std::collections::BTreeMap;
use zeroize::Zeroize;

const ASKS_COEFFICIENT_DOMAIN_V1: &[u8] = b"ioi/aft/async-asks-coefficient/v1";

fn hash_bytes(bytes: &[u8]) -> Result<[u8; 32], String> {
    ioi_crypto::algorithms::hash::sha256(bytes).map_err(|error| error.to_string())
}

/// Dealer-side material for one ASKS instance. The seed must be sampled from
/// the operating system and never derived from public protocol state.
#[derive(Debug, Clone)]
pub struct AsksDealerMaterial {
    pub commitments: Vec<[u8; 32]>,
    pub shares: Vec<[u8; 32]>,
}

impl Drop for AsksDealerMaterial {
    fn drop(&mut self) {
        self.shares.zeroize();
    }
}

impl AsksDealerMaterial {
    pub fn derive(
        instance_hash: [u8; 32],
        geometry: AftAsyncGeometryV1,
        view: u64,
        dealer: u16,
        secret_seed: [u8; 32],
    ) -> Result<Self, String> {
        geometry.validate()?;
        if geometry.n > 255 || !geometry.contains(dealer) {
            return Err("ASKS requires 1 <= n <= 255 and an in-range dealer".into());
        }
        let mut coefficients = Vec::with_capacity(geometry.f as usize + 1);
        for coefficient in 0..=geometry.f {
            coefficients.push(hash_bytes(&codec::to_bytes_canonical(&(
                ASKS_COEFFICIENT_DOMAIN_V1.to_vec(),
                instance_hash,
                view,
                dealer,
                coefficient,
                secret_seed,
            ))?)?);
        }
        let mut shares = Vec::with_capacity(geometry.n as usize);
        let mut commitments = Vec::with_capacity(geometry.n as usize);
        for owner in 0..geometry.n {
            let share = evaluate(&coefficients, (owner + 1) as u8);
            commitments.push(aft_async_asks_share_commitment(
                instance_hash,
                view,
                dealer,
                owner,
                &share,
            )?);
            shares.push(share);
        }
        Ok(Self {
            commitments,
            shares,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsksReconstruction {
    /// A globally consistent degree-f polynomial was recovered.
    Secret([u8; 32]),
    /// The committed shares did not describe one degree-f polynomial. This is
    /// the paper's public zero-sentinel outcome for a malicious dealer.
    MalformedDealer([u8; 32]),
}

/// Participant-side ASKS verification and reconstruction state. RBC and RA
/// transport are deliberately composed outside this object.
#[derive(Debug, Clone)]
pub struct AsksParticipant {
    instance_hash: [u8; 32],
    geometry: AftAsyncGeometryV1,
    local: u16,
    view: u64,
    dealer: u16,
    commitments: Option<Vec<[u8; 32]>>,
    private_share: Option<[u8; 32]>,
    sharing_finished: bool,
    reconstruction_started: bool,
    reconstruction_shares: BTreeMap<u16, [u8; 32]>,
    output: Option<AsksReconstruction>,
}

impl Drop for AsksParticipant {
    fn drop(&mut self) {
        if let Some(share) = self.private_share.as_mut() {
            share.zeroize();
        }
        for share in self.reconstruction_shares.values_mut() {
            share.zeroize();
        }
        if let Some(output) = self.output.as_mut() {
            match output {
                AsksReconstruction::Secret(secret)
                | AsksReconstruction::MalformedDealer(secret) => secret.zeroize(),
            }
        }
    }
}

impl AsksParticipant {
    pub fn new(
        instance_hash: [u8; 32],
        geometry: AftAsyncGeometryV1,
        local: u16,
        view: u64,
        dealer: u16,
    ) -> Result<Self, String> {
        geometry.validate()?;
        if geometry.n > 255 || !geometry.contains(local) || !geometry.contains(dealer) {
            return Err("ASKS participant, dealer, or field geometry is invalid".into());
        }
        Ok(Self {
            instance_hash,
            geometry,
            local,
            view,
            dealer,
            commitments: None,
            private_share: None,
            sharing_finished: false,
            reconstruction_started: false,
            reconstruction_shares: BTreeMap::new(),
            output: None,
        })
    }

    pub fn accept_commitments(&mut self, commitments: Vec<[u8; 32]>) -> Result<bool, String> {
        if commitments.len() != self.geometry.n as usize || commitments.contains(&[0; 32]) {
            return Err("ASKS commitment vector has invalid length or an empty member".into());
        }
        match &self.commitments {
            Some(previous) if previous != &commitments => {
                return Err("ASKS commitment vector was rebound".into());
            }
            Some(_) => return self.local_share_is_valid(),
            None => self.commitments = Some(commitments),
        }
        self.local_share_is_valid()
    }

    pub fn accept_private_share(
        &mut self,
        authenticated_sender: u16,
        share: [u8; 32],
    ) -> Result<bool, String> {
        if authenticated_sender != self.dealer {
            return Err("ASKS private share was not sent by its dealer".into());
        }
        match self.private_share {
            Some(previous) if previous != share => {
                return Err("ASKS dealer equivocated on the local private share".into());
            }
            Some(_) => return self.local_share_is_valid(),
            None => self.private_share = Some(share),
        }
        self.local_share_is_valid()
    }

    fn local_share_is_valid(&self) -> Result<bool, String> {
        let (Some(commitments), Some(share)) = (&self.commitments, self.private_share) else {
            return Ok(false);
        };
        let commitment = commitments
            .get(self.local as usize)
            .ok_or_else(|| "ASKS local commitment is absent".to_string())?;
        Ok(*commitment
            == aft_async_asks_share_commitment(
                self.instance_hash,
                self.view,
                self.dealer,
                self.local,
                &share,
            )?)
    }

    /// Called only after the corresponding RA outputs one.
    pub fn finish_sharing(&mut self) -> Result<(), String> {
        if self.commitments.is_none() {
            return Err("ASKS sharing cannot finish before commitment RBC delivery".into());
        }
        self.sharing_finished = true;
        Ok(())
    }

    pub fn start_reconstruction(&mut self) -> Result<Option<[u8; 32]>, String> {
        if !self.sharing_finished {
            return Err("ASKS reconstruction cannot precede sharing agreement".into());
        }
        self.reconstruction_started = true;
        if self.local_share_is_valid()? {
            Ok(self.private_share)
        } else {
            Ok(None)
        }
    }

    pub fn accept_reconstruction_share(
        &mut self,
        authenticated_owner: u16,
        share: [u8; 32],
    ) -> Result<Option<AsksReconstruction>, String> {
        if !self.reconstruction_started || !self.geometry.contains(authenticated_owner) {
            return Err(
                "ASKS reconstruction share arrived before start or from outside membership".into(),
            );
        }
        let commitments = self
            .commitments
            .as_ref()
            .ok_or_else(|| "ASKS reconstruction lacks commitments".to_string())?;
        let expected = aft_async_asks_share_commitment(
            self.instance_hash,
            self.view,
            self.dealer,
            authenticated_owner,
            &share,
        )?;
        if commitments.get(authenticated_owner as usize) != Some(&expected) {
            return Err("ASKS reconstruction share does not open its commitment".into());
        }
        match self
            .reconstruction_shares
            .insert(authenticated_owner, share)
        {
            Some(previous) if previous != share => {
                self.reconstruction_shares
                    .insert(authenticated_owner, previous);
                return Err("ASKS reconstruction owner equivocated".into());
            }
            _ => {}
        }
        if let Some(output) = self.output {
            return Ok(Some(output));
        }
        if self.reconstruction_shares.len() < self.geometry.f as usize + 1 {
            return Ok(None);
        }
        let points = self
            .reconstruction_shares
            .iter()
            .take(self.geometry.f as usize + 1)
            .map(|(owner, share)| ((*owner + 1) as u8, *share))
            .collect::<Vec<_>>();
        let constant = interpolate_at(&points, 0)?;
        let mut globally_consistent = true;
        for owner in 0..self.geometry.n {
            let predicted = interpolate_at(&points, (owner + 1) as u8)?;
            let commitment = aft_async_asks_share_commitment(
                self.instance_hash,
                self.view,
                self.dealer,
                owner,
                &predicted,
            )?;
            globally_consistent &= commitments.get(owner as usize) == Some(&commitment);
        }
        let secret = if globally_consistent {
            aft_async_asks_secret(self.instance_hash, self.view, self.dealer, &constant)?
        } else {
            [0; 32]
        };
        let output = if globally_consistent {
            AsksReconstruction::Secret(secret)
        } else {
            AsksReconstruction::MalformedDealer(secret)
        };
        self.output = Some(output);
        Ok(Some(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asks_reconstructs_one_secret_from_any_f_plus_one_valid_shares() {
        let geometry = AftAsyncGeometryV1::exact(4).unwrap();
        let material = AsksDealerMaterial::derive([1; 32], geometry, 0, 0, [9; 32]).unwrap();
        let mut participant = AsksParticipant::new([1; 32], geometry, 3, 0, 0).unwrap();
        assert!(!participant
            .accept_commitments(material.commitments.clone())
            .unwrap());
        assert!(participant
            .accept_private_share(0, material.shares[3])
            .unwrap());
        participant.finish_sharing().unwrap();
        assert_eq!(
            participant.start_reconstruction().unwrap(),
            Some(material.shares[3])
        );
        assert!(participant
            .accept_reconstruction_share(1, material.shares[1])
            .unwrap()
            .is_none());
        assert!(matches!(
            participant
                .accept_reconstruction_share(3, material.shares[3])
                .unwrap(),
            Some(AsksReconstruction::Secret(secret)) if secret != [0; 32]
        ));
    }

    #[test]
    fn asks_refuses_cross_owner_openings_and_reports_non_polynomial_dealer() {
        let geometry = AftAsyncGeometryV1::exact(4).unwrap();
        let mut material = AsksDealerMaterial::derive([2; 32], geometry, 4, 1, [7; 32]).unwrap();
        material.shares[3][0] ^= 1;
        material.commitments[3] =
            aft_async_asks_share_commitment([2; 32], 4, 1, 3, &material.shares[3]).unwrap();
        let mut participant = AsksParticipant::new([2; 32], geometry, 0, 4, 1).unwrap();
        participant
            .accept_commitments(material.commitments.clone())
            .unwrap();
        participant
            .accept_private_share(1, material.shares[0])
            .unwrap();
        participant.finish_sharing().unwrap();
        participant.start_reconstruction().unwrap();
        participant
            .accept_reconstruction_share(0, material.shares[0])
            .unwrap();
        assert!(matches!(
            participant
                .accept_reconstruction_share(3, material.shares[3])
                .unwrap(),
            Some(AsksReconstruction::MalformedDealer(secret)) if secret == [0; 32]
        ));
        assert!(participant.accept_reconstruction_share(1, [8; 32]).is_err());
    }
}
