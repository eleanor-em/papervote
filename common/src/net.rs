use crate::sign::{SignedMessage, SigningPubKey, Signature};
use uuid::Uuid;
use cryptid::threshold::{KeygenCommitment, DecryptShare, PubkeyProof};
use cryptid::{Scalar, AsBase64};
use cryptid::elgamal::{PublicKey, Ciphertext};
use serde::{Serialize, Deserialize};
use crate::voter::{VoterId, VoterIdent, Vote};
use cryptid::shuffle::ShuffleProof;
use cryptid::commit::CtCommitment;
use std::collections::HashMap;
use crate::trustee::{EcCommit, SignedDecryptShareSet, SignedPetOpening, SignedPetDecryptShare, AcceptedMixRow, AcceptedRow, SignedDecryptShare};

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
    },
    Accepted {
        rows: Vec<AcceptedRow>,
    },
    AcceptedMix {
        mix_index: i16,
        rows: Vec<AcceptedMixRow>,
        proof: ShuffleProof,
    },
    AcceptedDecrypt {
        shares: Vec<SignedDecryptShare>,
    },
    Tally(Vec<Vote>),
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

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct VoteMixProof {
    pub index: i16,
    pub enc_votes: Vec<Ciphertext>,
    pub enc_voter_ids: Vec<Ciphertext>,
    pub enc_as: Vec<Ciphertext>,
    pub enc_bs: Vec<Ciphertext>,
    pub enc_r_as: Vec<Ciphertext>,
    pub enc_r_bs: Vec<Ciphertext>,
    pub proof: ShuffleProof,
    pub signed_by: Uuid,
    pub signature: Signature,
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct AcceptedMixProof {
    pub index: i16,
    pub enc_votes: Vec<Ciphertext>,
    pub enc_voter_ids: Vec<Ciphertext>,
    pub proof: ShuffleProof,
    pub signed_by: Uuid,
    pub signature: Signature,
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    PublicKey(SigningPubKey),
    ResultSet(Vec<SignedMessage>),
    Ciphertexts(Vec<Vec<Ciphertext>>),
    VoteMixProofs(Vec<VoteMixProof>),
    AcceptedRows(Vec<AcceptedRow>),
    AcceptedMixRows(Vec<AcceptedMixRow>),
    AcceptedMixProofs(Vec<AcceptedMixProof>),
    DecryptShares(Vec<Vec<SignedDecryptShareSet>>),
    Idents(Vec<VoterIdent>),
    PetCommits(HashMap<Uuid, HashMap<VoterId, (Signature, CtCommitment, CtCommitment)>>),
    PetOpenings(HashMap<Uuid, HashMap<VoterId, SignedPetOpening>>),
    PetDecryptions(HashMap<Uuid, HashMap<VoterId, SignedPetDecryptShare>>),
    AcceptedDecryptions(HashMap<Uuid, HashMap<i32, SignedDecryptShare>>),
    Votes(Vec<Vote>),
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
