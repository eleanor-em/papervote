use crate::sign::{SignedMessage, SigningPubKey, Signature};
use uuid::Uuid;
use cryptid::threshold::{KeygenCommitment, DecryptShare, PubkeyProof};
use cryptid::{Scalar, AsBase64};
use cryptid::elgamal::{PublicKey, Ciphertext};
use serde::{Serialize, Deserialize};
use crate::voter::{VoterId, VoterIdent};
use cryptid::shuffle::ShuffleProof;
use cryptid::commit::CtCommitment;
use std::collections::HashMap;
use crate::trustee::{EcCommit, SignedDecryptShareSet, SignedPetOpening, SignedPetDecryptShare};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TrusteeMessage {
    Info {
        info: TrusteeInfo,
    },
    KeygenCommit {
        commitment: KeygenCommitment,
    },
    KeygenShare {
        share: Scalar,
    },
    KeygenSign {
        pubkey: PublicKey,
        pubkey_proof: PubkeyProof,
    },
    EcCommit(EcCommit),
    EcVote {
        vote: String,
        enc_vote: Ciphertext,
        prf_enc_vote: Scalar,
        enc_id: Ciphertext,
        enc_a: Ciphertext,
        enc_b: Ciphertext,
        enc_r_a: Ciphertext,
        enc_r_b: Ciphertext,
    },
    EcVoteMix {
        mix_index: i16,
        enc_votes: Vec<Ciphertext>,
        enc_voter_ids: Vec<Ciphertext>,
        enc_as: Vec<Ciphertext>,
        enc_bs: Vec<Ciphertext>,
        enc_r_as: Vec<Ciphertext>,
        enc_r_bs: Vec<Ciphertext>,
        proof: ShuffleProof,
    },
    EcVoteDecrypt {
        shares: Vec<Vec<DecryptShare>>,
        signatures: Vec<Signature>,
    },
    EcPetCommit {
        voter_ids: Vec<VoterId>,
        vote_commits: Vec<CtCommitment>,
        mac_commits: Vec<CtCommitment>,
        signatures: Vec<Signature>,
    },
    EcPetOpening {
        voter_ids: Vec<VoterId>,
        openings: Vec<SignedPetOpening>,
    },
    EcPetDecrypt {
        voter_ids: Vec<VoterId>,
        shares: Vec<SignedPetDecryptShare>,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrusteeInfo {
    pub id: Uuid,
    pub pubkey: SigningPubKey,
    pub pubkey_proof: Option<PubkeyProof>,
    pub index: usize,
    pub address: String,
}

impl TrusteeInfo {
    pub fn into_signed_msg(self, signature: String) -> Result<SignedMessage, base64::DecodeError> {
        let sender_id = self.id.clone();
        let signature = Signature::try_from_base64(&signature)?;

        Ok(SignedMessage {
            inner: TrusteeMessage::Info { info: self },
            signature,
            sender_id,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedResponse {
    pub status: bool,
    pub msg: Response,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    PublicKey(SigningPubKey),
    ResultSet(Vec<SignedMessage>),
    Ciphertexts(Vec<Vec<Ciphertext>>),
    DecryptShares(Vec<Vec<SignedDecryptShareSet>>),
    Idents(Vec<VoterIdent>),
    PetCommits(HashMap<Uuid, HashMap<VoterId, (Signature, CtCommitment, CtCommitment)>>),
    PetOpenings(HashMap<Uuid, HashMap<VoterId, SignedPetOpening>>),
    PetDecryptions(HashMap<Uuid, HashMap<VoterId, SignedPetDecryptShare>>),
    Count(i64),
    Outcome(bool),
    Ok,
    SessionExists,
    NotReady,
    UnknownId,
    TrusteeMissing,
    InvalidSession,
    InvalidData,
    InvalidRequest,
    InvalidSignature,
    FailedInsertion,
    ParseError,
    MiscError,
}

#[derive(Serialize, Deserialize)]
pub struct NewSessionRequest {
    pub min_trustees: usize,
    pub trustee_count: usize,
}
