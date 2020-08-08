use serde::{Serialize, Deserialize};
use cryptid::elgamal::Ciphertext;
use crate::voter::VoterId;
use cryptid::Scalar;
use uuid::Uuid;
use cryptid::threshold::DecryptShare;
use crate::sign::{SigningPubKey, SigningKeypair, Signature};
use cryptid::zkp::PrfEqDlogs;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct EcCommit {
    pub voter_id: VoterId,
    pub enc_vote: Ciphertext,
    pub enc_mac: Ciphertext,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CtOpening {
    pub ct: Ciphertext,
    pub r1: Scalar,
    pub r2: Scalar,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct SignedDecryptShareSet {
    pub trustee_id: Uuid,
    pub signature: Signature,
    pub shares: Vec<DecryptShare>,
}

impl SignedDecryptShareSet {
    pub fn new(trustee_id: Uuid, keypair: &SigningKeypair, shares: Vec<DecryptShare>) -> Self {
        let mut bytes = Vec::new();
        for share in shares.iter() {
            bytes.extend_from_slice(serde_json::to_string(&share).unwrap().as_bytes());
    }

        let signature = keypair.sign(&bytes);
        Self { trustee_id, signature, shares }
    }
    pub fn verify(&self, pubkey: &SigningPubKey) -> bool {
        let mut bytes = Vec::new();
        for share in self.shares.iter() {
            bytes.extend_from_slice(serde_json::to_string(&share).unwrap().as_bytes());
        }

        pubkey.verify(&bytes, &self.signature)
    }
}


#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct SignedPetOpening {
    pub signature: Signature,
    pub vote_opening: CtOpening,
    pub mac_opening: CtOpening,
    pub vote_proof: PrfEqDlogs,
    pub mac_proof: PrfEqDlogs,
}

impl SignedPetOpening {
    pub fn new(
        keypair: &SigningKeypair,
        voter_id: &VoterId,
        vote_opening: CtOpening,
        mac_opening: CtOpening,
        vote_proof: PrfEqDlogs,
        mac_proof: PrfEqDlogs
    ) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(voter_id.to_string().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&vote_opening).unwrap().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&mac_opening).unwrap().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&vote_proof).unwrap().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&mac_proof).unwrap().as_bytes());
        let signature = keypair.sign(&bytes);

        Self { signature, vote_opening, mac_opening, vote_proof, mac_proof }
    }

    pub fn verify(&self, pubkey: &SigningPubKey, voter_id: &VoterId) -> bool {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(voter_id.to_string().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&self.vote_opening).unwrap().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&self.mac_opening).unwrap().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&self.vote_proof).unwrap().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&self.mac_proof).unwrap().as_bytes());

        pubkey.verify(&bytes, &self.signature)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct SignedPetDecryptShare {
    pub vote_share: DecryptShare,
    pub mac_share: DecryptShare,
    pub signature: Signature
}

impl SignedPetDecryptShare {
    pub fn new(
        keypair: &SigningKeypair,
        voter_id: &VoterId,
        vote_share: DecryptShare,
        mac_share: DecryptShare
    ) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(voter_id.to_string().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&vote_share).unwrap().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&mac_share).unwrap().as_bytes());
        let signature = keypair.sign(&bytes);

        Self { vote_share, mac_share, signature }
    }

    pub fn verify(&self, pubkey: &SigningPubKey, voter_id: &VoterId) -> bool {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(voter_id.to_string().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&self.vote_share).unwrap().as_bytes());
        bytes.extend_from_slice(serde_json::to_string(&self.mac_share).unwrap().as_bytes());

        pubkey.verify(&bytes, &self.signature)
    }
}
