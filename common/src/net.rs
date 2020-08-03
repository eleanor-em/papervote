use crate::sign::{SignedMessage, SigningPubKey};
use uuid::Uuid;
use cryptid::threshold::{KeygenCommitment, DecryptShare};
use cryptid::Scalar;
use cryptid::elgamal::{PublicKey, Ciphertext, CurveElem};
use serde::{Serialize, Deserialize};
use crate::vote::VoterId;
use cryptid::shuffle::ShuffleProof;

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
        pubkey_share: CurveElem,
    },
    EcCommit {
        voter_id: VoterId,
        enc_mac: Ciphertext,
        enc_vote: Ciphertext,
    },
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
        signatures: Vec<Vec<u8>>,
        shares: Vec<Vec<DecryptShare>>,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrusteeInfo {
    pub id: Uuid,
    pub pubkey: SigningPubKey,
    pub pubkey_share: Option<CurveElem>,
    pub index: usize,
    pub address: String,
}

impl TrusteeInfo {
    pub fn into_signed_msg(self, signature: String) -> Result<SignedMessage, base64::DecodeError> {
        let sender_id = self.id.clone();
        let signature = base64::decode(&signature)?;

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
