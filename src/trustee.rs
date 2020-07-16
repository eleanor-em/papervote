use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Formatter, Display};

use cryptid::{CryptoError, zkp, Scalar};
use cryptid::elgamal::{CryptoContext, CurveElem};
use cryptid::threshold::ThresholdGenerator;
use eyre::Result;
use reqwest::Client;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Serialize, Deserialize};
use tokio::time;
use tokio::time::Duration;
use uuid::Uuid;

use crate::sign;
use crate::sign::{SigningPubKey, SignedMessage};
use crate::wbb::{Response, WrappedResponse};

fn address(session_id: &Uuid, path: &str) -> String {
    format!("http://localhost:8000/api/{}{}", session_id, path)
}

#[derive(Clone, Copy, Debug)]
pub enum TrusteeError {
    NoSuchTrustee(Uuid),
    Crypto(CryptoError),
    InvalidSignature,
    InvalidResponse,
}

impl Display for TrusteeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<CryptoError> for TrusteeError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl Error for TrusteeError {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TrusteeMessage {
    Info {
        info: TrusteeInfo,
    },
    KeygenCommit {
        commitment: Vec<CurveElem>
    },
    KeygenShare {
        share: Scalar,
    },
    DecryptShare {
        a_i: CurveElem,
        proof: zkp::PrfEqDlogs,
    },
    PetCommit {
        // commitment: Commitment
    },
    PetShare {
        d_i: CurveElem,
        e_i: CurveElem,
        proof: zkp::PrfEqDlogs,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrusteeInfo {
    pub id: Uuid,
    pub pubkey: SigningPubKey,
    pub index: usize,
}

pub struct GeneratingTrustee {
    session_id: Uuid,
    id: Uuid,
    signing_keypair: Ed25519KeyPair,
    trustee_info: HashMap<Uuid, TrusteeInfo>,
    generator: ThresholdGenerator,
}

impl GeneratingTrustee {
    pub fn new(session_id: Uuid, ctx: &CryptoContext, index: usize, k: usize, n: usize) -> Result<GeneratingTrustee, CryptoError> {
        let mut ctx = ctx.cloned();
        let id = Uuid::new_v4();

        // Generate a signature keypair
        let signing_keypair = sign::new_keypair(ctx.rng())?;

        // Create identification for this trustee
        let mut trustee_info = HashMap::new();
        let my_info = TrusteeInfo {
            id,
            pubkey: signing_keypair.public_key().into(),
            index
        };
        trustee_info.insert(id, my_info);

        let generator = ThresholdGenerator::new(&mut ctx, index, k, n)?;

        Ok(Self {
            session_id,
            id,
            signing_keypair,
            trustee_info,
            generator,
        })
    }

    pub fn session_id(&self) -> &Uuid {
        &self.session_id
    }

    pub fn verify_all(&self, messages: &[SignedMessage]) -> Result<bool, TrusteeError> {
        for message in messages {
            if let Some(info) = self.trustee_info.get(&message.sender_id) {
                if !message.verify(&info.pubkey)? {
                    return Ok(false);
                }
            } else {
                return Err(TrusteeError::NoSuchTrustee(message.sender_id));
            }
        }

        Ok(true)
    }

    pub fn gen_registration(&self) -> SignedMessage {
        let msg = TrusteeMessage::Info { info: self.trustee_info.get(&self.id).unwrap().clone() };
        self.sign(msg)
    }

    pub fn add_info(&mut self, info: TrusteeInfo) {
        self.trustee_info.insert(info.id, info);
    }

    pub fn received_info(&self) -> bool {
        self.trustee_info.len() == self.generator.trustee_count()
    }

    pub fn gen_commitment(&self) -> SignedMessage {
        let commitment = self.generator.get_commitment();
        let msg = TrusteeMessage::KeygenCommit { commitment };
        self.sign(msg)
    }

    pub fn add_commitment(&mut self, id: &Uuid, commitment: &Vec<CurveElem>) -> Result<(), TrusteeError> {
        Ok(self.generator.receive_commitment(self.trustee_info[id].index, commitment)?)
    }

    pub fn received_commitments(&self) -> bool {
        self.generator.received_commitments()
    }

    pub fn gen_shares(&self) -> Result<HashMap<Uuid, Scalar>, TrusteeError> {
        let mut result = HashMap::new();
        for (id, info) in self.trustee_info.iter() {
            result.insert(id.clone(), self.generator.get_polynomial_share(info.index)?);
        }

        Ok(result)
    }

    // Sign the given message
    fn sign(&self, message: TrusteeMessage) -> SignedMessage {
        let data = serde_json::to_string(&message).unwrap().as_bytes().to_vec();
        let signature = self.signing_keypair.sign(&data).as_ref().to_vec();

        SignedMessage {
            inner: message,
            signature,
            sender_id: self.id,
        }
    }
}

pub async fn run(session_id: Uuid,
                 ctx: CryptoContext,
                 index: usize,
                 min_trustees: usize,
                 num_trustees: usize) -> Result<()> {
    let mut trustee = GeneratingTrustee::new(session_id.clone(), &ctx, index, min_trustees, num_trustees)?;
    let client = reqwest::Client::new();

    // 1. Registration
    let msg = trustee.gen_registration();
    let _receipt: WrappedResponse = client.post(&address(trustee.session_id(), "/trustee/register"))
        .json(&msg).send().await?
        .json().await?;
    // TODO: Check receipt signature, store in database
    get_registrations(&client, &mut trustee).await?;
    assert!(trustee.received_info());

    // 2. Commitment
    let msg = trustee.gen_commitment();
    let _receipt: WrappedResponse = client.post(&address(trustee.session_id(), "/keygen/commitment"))
        .json(&msg).send().await?
        .json().await?;
    // TODO: Check receipt signature, store in database
    get_commitments(&client, &mut trustee).await?;
    assert!(trustee.received_commitments());

    // 3. Shares
    // TODO: Trustees need to communicate directly with each other here.
    let _shares = trustee.gen_shares()?;

    println!("Trustee {} done", index);
    Ok(())
}

async fn get_registrations(client: &Client, trustee: &mut GeneratingTrustee) -> Result<()> {
    loop {
        // Wait a moment for other registrations
        time::delay_for(Duration::from_millis(200)).await;
        let res: WrappedResponse = client.get(&address(trustee.session_id(), "/trustee/all"))
            .send().await?
            .json().await?;

        // Check signatures
        if let Response::ResultSet(results) = res.msg {
            for result in results {
                if let TrusteeMessage::Info { info } = &result.inner {
                    if result.verify(&info.pubkey)? {
                        trustee.add_info(info.clone());
                    }
                }
            }
            break;
        }
    }

    Ok(())
}

async fn get_commitments(client: &Client, trustee: &mut GeneratingTrustee) -> Result<()> {
    loop {
        // Wait a moment for other registrations
        time::delay_for(Duration::from_millis(200)).await;
        let res: WrappedResponse = client.get(&address(trustee.session_id(), "/keygen/commitment"))
            .send().await?
            .json().await?;

        // Check signatures
        if let Response::ResultSet(results) = res.msg {
            if trustee.verify_all(&results)? {
                for result in results {
                    if let TrusteeMessage::KeygenCommit { commitment } = result.inner {
                        trustee.add_commitment(&result.sender_id, &commitment)?;
                    } else {
                        return Err(TrusteeError::InvalidResponse)?;
                    }
                }
                return Ok(());
            } else {
                return Err(TrusteeError::InvalidSignature)?;
            }
        }
    }
}